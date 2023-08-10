/**
 * Copyright (c) 2022 Brian Starkey <stark3y@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TCP_COMM_H__
#define __TCP_COMM_H__

#if PICOWOTA_TCP

#include <stdint.h>
#include <stdbool.h>
#include "hardware/flash.h"
#include "lwip/err.h"
#include "comm_stream.h"

struct tcp_comm_ctx;

err_t tcp_comm_listen(struct tcp_comm_ctx *ctx, uint16_t port);
err_t tcp_comm_server_close(struct tcp_comm_ctx *ctx);
bool tcp_comm_server_done(struct tcp_comm_ctx *ctx);

struct tcp_comm_ctx *tcp_comm_new(const struct comm_command *const *cmds,
		size_t n_cmds, uint32_t sync_opcode);
void tcp_comm_delete(struct tcp_comm_ctx *ctx);

#endif

#endif /* __TCP_COMM_H__ */
