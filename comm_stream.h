/**
 * Copyright (c) 2022 Brian Starkey <stark3y@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#include "hardware/flash.h"
#include <stdbool.h>
#include <stdint.h>

// #define STREAM_COMM_MAX_DATA_LEN MIN(FLASH_BLOCK_SIZE, UINT16_MAX / 2)
#define STREAM_COMM_MAX_DATA_LEN FLASH_SECTOR_SIZE
#define STREAM_COMM_RSP_OK (('O' << 0) | ('K' << 8) | ('O' << 16) | ('K' << 24))
#define STREAM_COMM_RSP_ERR                                                    \
  (('E' << 0) | ('R' << 8) | ('R' << 16) | ('!' << 24))

#define COMM_MAX_NARG 6

typedef struct comm_command {
  uint32_t opcode;
  uint32_t nargs;
  uint32_t resp_nargs;
  uint32_t (*size)(uint32_t const *args_in, uint32_t *data_len_out,
                   uint32_t *resp_data_len_out);
  uint32_t (*handle)(uint32_t const *args_in, uint8_t const *data_in,
                     uint32_t *resp_args_out, uint8_t *resp_data_out);
} comm_command;

enum conn_state {
  CONN_STATE_WAIT_FOR_SYNC,
  CONN_STATE_READ_OPCODE,
  CONN_STATE_READ_ARGS,
  CONN_STATE_READ_DATA,
  CONN_STATE_HANDLE,
  CONN_STATE_WRITE_RESP,
  CONN_STATE_WRITE_ERROR,
  CONN_STATE_CLOSED,
};

typedef struct stream_comm_connection_data {
  // Note: sizeof(buf) is used elsewhere, so if this is changed to not
  // be an array, those will need updating
  uint8_t
      buf[(sizeof(uint32_t) * (1 + COMM_MAX_NARG)) + STREAM_COMM_MAX_DATA_LEN];

  size_t rx_start_offs;
  size_t rx_received;
  size_t rx_needed;

  size_t tx_sent;
  size_t tx_remaining;

  uint32_t resp_data_len;

  enum conn_state state;
} stream_comm_connection_data;

struct stream_comm_ctx;
typedef int (*stream_comm_write)(struct stream_comm_ctx *ctx,
                                 uint8_t const *data, uint16_t len);

typedef struct stream_comm_ctx {
  stream_comm_connection_data conn;

  const struct comm_command *cmd;
  const struct comm_command *const *cmds;
  size_t n_cmds;

  uint32_t sync_opcode;

  stream_comm_write write;
} stream_comm_ctx;

void stream_comm_ctor(stream_comm_ctx *, stream_comm_write write,
                      comm_command const *const *cmds, size_t n_cmds,
                      uint32_t sync_opcode);
void stream_comm_open(stream_comm_ctx *);
void stream_comm_close(stream_comm_ctx *);

// returns pointer to buffer for write, if no errors
uint8_t *stream_comm_recv_prepare(stream_comm_ctx *, size_t len);
int stream_comm_recv_process(stream_comm_ctx *);
int stream_comm_sent(stream_comm_ctx *, size_t len);

uint32_t stream_comm_active();
