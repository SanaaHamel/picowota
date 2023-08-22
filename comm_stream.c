/**
 * Copyright (c) 2022 Brian Starkey <stark3y@gmail.com>
 *
 * Parts based on the Pico W tcp_server example:
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "comm_stream.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef NDEBUG
#include <stdio.h>
#define DEBUG_printf(...) printf(__VA_ARGS__)
#else
#define DEBUG_printf(...)                                                      \
  {}
#endif

#define COMM_BUF_OPCODE(_buf) ((uint32_t *)((uint8_t *)(_buf)))
#define COMM_BUF_ARGS(_buf) ((uint32_t *)((uint8_t *)(_buf) + sizeof(uint32_t)))
#define COMM_BUF_BODY(_buf, _nargs)                                            \
  ((uint8_t *)(_buf) + (sizeof(uint32_t) * ((_nargs) + 1)))

static uint32_t g_streams_active = 0;

static const struct comm_command *find_command_desc(stream_comm_ctx *ctx,
                                                    uint32_t opcode) {
  for (size_t i = 0; i < ctx->n_cmds; i++) {
    if (ctx->cmds[i]->opcode == opcode) {
      return ctx->cmds[i];
    }
  }

  return NULL;
}

static bool is_error(uint32_t status) { return status == STREAM_COMM_RSP_ERR; }

static int stream_comm_sync_begin(stream_comm_ctx *ctx);
static int stream_comm_sync_complete(stream_comm_ctx *ctx);
static int stream_comm_opcode_begin(stream_comm_ctx *ctx);
static int stream_comm_opcode_complete(stream_comm_ctx *ctx);
static int stream_comm_args_begin(stream_comm_ctx *ctx);
static int stream_comm_args_complete(stream_comm_ctx *ctx);
static int stream_comm_data_begin(stream_comm_ctx *ctx, uint32_t data_len);
static int stream_comm_data_complete(stream_comm_ctx *ctx);
static int stream_comm_response_begin(stream_comm_ctx *ctx);
static int stream_comm_response_complete(stream_comm_ctx *ctx);
static int stream_comm_error_begin(stream_comm_ctx *ctx);

static int stream_comm_sync_begin(stream_comm_ctx *ctx) {
  ctx->conn.state = CONN_STATE_WAIT_FOR_SYNC;
  ctx->conn.rx_needed = sizeof(uint32_t);

  return 0;
}

static int stream_comm_sync_complete(stream_comm_ctx *ctx) {
  if (ctx->sync_opcode != *COMM_BUF_OPCODE(ctx->conn.buf)) {
    DEBUG_printf("sync not correct: %c%c%c%c\n", ctx->conn.buf[0],
                 ctx->conn.buf[1], ctx->conn.buf[2], ctx->conn.buf[3]);
    return stream_comm_error_begin(ctx);
  }

  return stream_comm_opcode_complete(ctx);
}

static int stream_comm_opcode_begin(stream_comm_ctx *ctx) {
  ctx->conn.state = CONN_STATE_READ_OPCODE;
  ctx->conn.rx_needed = sizeof(uint32_t);

  return 0;
}

static int stream_comm_opcode_complete(stream_comm_ctx *ctx) {
  ctx->cmd = find_command_desc(ctx, *COMM_BUF_OPCODE(ctx->conn.buf));
  if (!ctx->cmd) {
    DEBUG_printf("no command for '%c%c%c%c'\n", ctx->conn.buf[0],
                 ctx->conn.buf[1], ctx->conn.buf[2], ctx->conn.buf[3]);
    return stream_comm_error_begin(ctx);
  }

  DEBUG_printf("got command '%c%c%c%c'\n", ctx->conn.buf[0], ctx->conn.buf[1],
               ctx->conn.buf[2], ctx->conn.buf[3]);
  return stream_comm_args_begin(ctx);
}

static int stream_comm_args_begin(stream_comm_ctx *ctx) {
  ctx->conn.state = CONN_STATE_READ_ARGS;
  ctx->conn.rx_needed = ctx->cmd->nargs * sizeof(uint32_t);

  if (ctx->cmd->nargs == 0) {
    return stream_comm_args_complete(ctx);
  }

  return 0;
}

static int stream_comm_args_complete(stream_comm_ctx *ctx) {
  const struct comm_command *cmd = ctx->cmd;

  uint32_t data_len = 0;

  if (cmd->size) {
    ctx->conn.resp_data_len = 0;
    uint32_t status = cmd->size(COMM_BUF_ARGS(ctx->conn.buf), &data_len,
                                &ctx->conn.resp_data_len);
    if (is_error(status)) {
      return stream_comm_error_begin(ctx);
    }
  }

  return stream_comm_data_begin(ctx, data_len);
}

static int stream_comm_data_begin(stream_comm_ctx *ctx, uint32_t data_len) {
  ctx->conn.state = CONN_STATE_READ_DATA;
  ctx->conn.rx_needed = data_len;

  if (data_len == 0) {
    return stream_comm_data_complete(ctx);
  }

  return 0;
}

static int stream_comm_data_complete(stream_comm_ctx *ctx) {
  const struct comm_command *cmd = ctx->cmd;

  if (cmd->handle) {
    uint32_t status = cmd->handle(
        COMM_BUF_ARGS(ctx->conn.buf), COMM_BUF_BODY(ctx->conn.buf, cmd->nargs),
        COMM_BUF_ARGS(ctx->conn.buf),
        COMM_BUF_BODY(ctx->conn.buf, cmd->resp_nargs));
    if (is_error(status)) {
      return stream_comm_error_begin(ctx);
    }

    *COMM_BUF_OPCODE(ctx->conn.buf) = status;
  } else {
    // TODO: Should we just assert(desc->handle)?
    *COMM_BUF_OPCODE(ctx->conn.buf) = STREAM_COMM_RSP_OK;
  }

  return stream_comm_response_begin(ctx);
}

static int stream_comm_send_begin(stream_comm_ctx *ctx, size_t len) {
  assert(len <= UINT16_MAX && "response too large");

  ctx->conn.tx_sent = 0;
  ctx->conn.tx_remaining = len;

  int err = ctx->write(ctx, ctx->conn.buf, ctx->conn.tx_remaining);
  if (err) {
    DEBUG_printf("stream_comm_send_begin failed err=%d\n", err);
    return -1;
  }

  return 0;
}

static int stream_comm_response_begin(stream_comm_ctx *ctx) {
  assert(ctx->cmd);
  ctx->conn.state = CONN_STATE_WRITE_RESP;
  return stream_comm_send_begin(
      ctx, ctx->conn.resp_data_len +
               ((ctx->cmd->resp_nargs + 1) * sizeof(uint32_t)));
}

static int stream_comm_error_begin(stream_comm_ctx *ctx) {
  *COMM_BUF_OPCODE(ctx->conn.buf) = STREAM_COMM_RSP_ERR;
  ctx->conn.state = CONN_STATE_WRITE_ERROR;
  return stream_comm_send_begin(ctx, sizeof(uint32_t));
}

static int stream_comm_response_complete(stream_comm_ctx *ctx) {
  return stream_comm_opcode_begin(ctx);
}

static int comm_rx_complete(stream_comm_ctx *ctx) {
  switch (ctx->conn.state) {
  case CONN_STATE_WAIT_FOR_SYNC:
    return stream_comm_sync_complete(ctx);
  case CONN_STATE_READ_OPCODE:
    return stream_comm_opcode_complete(ctx);
  case CONN_STATE_READ_ARGS:
    return stream_comm_args_complete(ctx);
  case CONN_STATE_READ_DATA:
    return stream_comm_data_complete(ctx);
  default:
    DEBUG_printf("comm_rx_complete state=%u\n", ctx->conn.state);
    return -1;
  }
}

static int stream_comm_tx_complete(stream_comm_ctx *ctx) {
  switch (ctx->conn.state) {
  case CONN_STATE_WRITE_RESP:
    return stream_comm_response_complete(ctx);
  case CONN_STATE_WRITE_ERROR:
    return -1;
  default:
    return -1;
  }
}

int stream_comm_sent(stream_comm_ctx *ctx, size_t len) {
  DEBUG_printf("comm_server_sent %u\n", len);

  assert(ctx->conn.tx_remaining <= len);
  if (len > ctx->conn.tx_remaining) {
    DEBUG_printf("tx len %d > remaining %d\n", len, ctx->conn.tx_remaining);
    return -16; // ERR_ARG;
  }

  ctx->conn.tx_remaining -= len;
  ctx->conn.tx_sent += len;

  if (ctx->conn.tx_remaining == 0) {
    int res = stream_comm_tx_complete(ctx);
    if (res) {
      return -16; // ERR_ARG;
    }
  }

  return 0; // ERR_OK;
}

// returns pointer to buffer for write, if no errors
uint8_t *stream_comm_recv_prepare(stream_comm_ctx *ctx, size_t len) {
  DEBUG_printf("stream_comm_recv_prepare %d\n", len);
  if (len <= 0)
    return ctx->conn.buf + ctx->conn.rx_start_offs +
           ctx->conn.rx_received; // boring/no-op

  if (len > (sizeof(ctx->conn.buf) - ctx->conn.rx_received)) {
    // Doesn't fit in buffer at all. Protocol error.
    DEBUG_printf("not enough space in buffer: %d vs %d\n", len,
                 sizeof(ctx->conn.buf) - ctx->conn.rx_received);

    // old protocol sent an error response, then just leaked/dropped the buffer
    // entirely. lovely. this whole thing is crap and really shouldn't be use
    // outside of toys. We, instead, just say f*k it, and report an error. The
    // concrete transport should terminate the connection since this protocol
    // blows for error recovery anyways.
    stream_comm_error_begin(ctx);
    return NULL;
  }

  // There will be space, but we need to shift the data back to the start of
  // the buffer
  if (len > (sizeof(ctx->conn.buf) -
             (ctx->conn.rx_start_offs + ctx->conn.rx_received))) {
    DEBUG_printf("memmove %d bytes to make space for %d bytes\n",
                 ctx->conn.rx_received, len);
    memmove(ctx->conn.buf, ctx->conn.buf + ctx->conn.rx_start_offs,
            ctx->conn.rx_received);
    ctx->conn.rx_start_offs = 0;
  }

  uint8_t *dst =
      ctx->conn.buf + ctx->conn.rx_start_offs + ctx->conn.rx_received;
  ctx->conn.rx_received += len;
  return dst;
}

int stream_comm_recv_process(stream_comm_ctx *ctx) {
  while (ctx->conn.rx_received >= ctx->conn.rx_needed) {
    size_t consumed = ctx->conn.rx_needed;

    int res = comm_rx_complete(ctx);
    if (res) {
      return -16; // ERR_ARG;
    }

    ctx->conn.rx_start_offs += consumed;
    ctx->conn.rx_received -= consumed;

    if (ctx->conn.rx_received == 0) {
      ctx->conn.rx_start_offs = 0;
      break;
    }
  }

  return 0; // ERR_OK;
}

void stream_comm_ctor(stream_comm_ctx *ctx, stream_comm_write write,
                      const struct comm_command *const *cmds, size_t n_cmds,
                      uint32_t sync_opcode) {
  assert(ctx);
  assert(write);
  if (!ctx)
    return;

  memset(ctx, 0, sizeof(*ctx));

  for (size_t i = 0; i < n_cmds; i++) {
    assert(cmds[i]->nargs <= COMM_MAX_NARG);
    assert(cmds[i]->resp_nargs <= COMM_MAX_NARG);
  }

  ctx->cmds = cmds;
  ctx->n_cmds = n_cmds;
  ctx->sync_opcode = sync_opcode;
  ctx->write = write;
}

void stream_comm_open(stream_comm_ctx *ctx) {
  memset(&ctx->conn, 0, sizeof(ctx->conn));

  stream_comm_sync_begin(ctx);

  g_streams_active++;
}

void stream_comm_close(stream_comm_ctx *ctx) {
  if (ctx->conn.state == CONN_STATE_CLOSED)
    return;

  ctx->conn.state = CONN_STATE_CLOSED;

  assert(0 < g_streams_active && "unbalanced");
  g_streams_active--;
}

uint32_t stream_comm_active() { return g_streams_active; }
