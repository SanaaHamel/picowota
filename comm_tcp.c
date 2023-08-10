/**
 * Copyright (c) 2022 Brian Starkey <stark3y@gmail.com>
 *
 * Parts based on the Pico W tcp_server example:
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if PICOWOTA_TCP

#include <stdlib.h>

#include "pico/cyw43_arch.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "comm_tcp.h"
#include "comm_stream.h"

#ifndef NDEBUG
#include <stdio.h>
#define DEBUG_printf(...) printf(__VA_ARGS__)
#else
#define DEBUG_printf(...) { }
#endif

#define POLL_TIME_S 5


struct tcp_comm_ctx {
	stream_comm_ctx ctx; // must be first member for layout
	struct tcp_pcb *serv_pcb;
	struct tcp_pcb *client_pcb;
	volatile bool serv_done;
};

static err_t tcp_comm_client_close(struct tcp_comm_ctx *ctx)
{
	stream_comm_close(&ctx->ctx);

	if (!ctx->client_pcb) {
		return ERR_OK;
	}

	tcp_arg(ctx->client_pcb, NULL);
	tcp_poll(ctx->client_pcb, NULL, 0);
	tcp_sent(ctx->client_pcb, NULL);
	tcp_recv(ctx->client_pcb, NULL);
	tcp_err(ctx->client_pcb, NULL);

	err_t err = tcp_close(ctx->client_pcb);
	if (err != ERR_OK) {
		DEBUG_printf("close failed %d, calling abort\n", err);
		tcp_abort(ctx->client_pcb);
		err = ERR_ABRT;
	}

	ctx->client_pcb = NULL;

	return err;
}

err_t tcp_comm_server_close(struct tcp_comm_ctx *ctx)
{
	err_t err = ERR_OK;

	err = tcp_comm_client_close(ctx);
	if ((err != ERR_OK) && ctx->serv_pcb) {
		tcp_arg(ctx->serv_pcb, NULL);
		tcp_abort(ctx->serv_pcb);
		ctx->serv_pcb = NULL;
		return ERR_ABRT;
	}

	if (!ctx->serv_pcb) {
		return err;
	}

	tcp_arg(ctx->serv_pcb, NULL);
	err = tcp_close(ctx->serv_pcb);
	if (err != ERR_OK) {
		tcp_abort(ctx->serv_pcb);
		err = ERR_ABRT;
	}
	ctx->serv_pcb = NULL;

	return err;
}

static void tcp_comm_server_complete(void *arg, int status)
{
	struct tcp_comm_ctx *ctx = (struct tcp_comm_ctx *)arg;
	if (status == 0) {
		DEBUG_printf("server completed normally\n");
	} else {
		DEBUG_printf("server error %d\n", status);
	}

	tcp_comm_server_close(ctx);
	ctx->serv_done = true;
}

static err_t tcp_comm_client_complete(void *arg, int status)
{
	struct tcp_comm_ctx *ctx = (struct tcp_comm_ctx *)arg;
	if (status == 0) {
		DEBUG_printf("conn completed normally\n");
	} else {
		DEBUG_printf("conn error %d\n", status);
	}
	return tcp_comm_client_close(ctx);
}

static err_t tcp_comm_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
	struct tcp_comm_ctx *ctx = (struct tcp_comm_ctx *)arg;

	cyw43_arch_lwip_check();

	err_t err = stream_comm_sent(&ctx->ctx, len);
	if (err) {
		return tcp_comm_client_complete(ctx, ERR_ARG);
	}

	return ERR_OK;
}

static err_t tcp_comm_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	struct tcp_comm_ctx *ctx = (struct tcp_comm_ctx *)arg;
	if (!p) {
		DEBUG_printf("no pbuf\n");
		return tcp_comm_client_complete(ctx, 0);
	}

	// this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
	// can use this method to cause an assertion in debug mode, if this method is called when
	// cyw43_arch_lwip_begin IS needed
	cyw43_arch_lwip_check();

	uint8_t* dst = stream_comm_recv_prepare(&ctx->ctx, p->tot_len);
	if (!dst) {
		tcp_recved(tpcb, p->tot_len);
		pbuf_free(p);
		return tcp_comm_client_complete(ctx, ERR_ARG);
	}

	// We can always handle the full packet b/c `stream_comm_recv_prepare` errors if it can't
	if (pbuf_copy_partial(p, dst, p->tot_len, 0) != p->tot_len) {
		DEBUG_printf("wrong copy len\n");
		tcp_recved(tpcb, p->tot_len);
		pbuf_free(p);
		return tcp_comm_client_complete(ctx, ERR_ARG);
	}

	tcp_recved(tpcb, p->tot_len);
	pbuf_free(p);

	err_t status = stream_comm_recv_process(&ctx->ctx);
	if (status) {
		return tcp_comm_client_complete(ctx, ERR_ARG);
	}

	return ERR_OK;
}

static err_t tcp_comm_client_poll(void *arg, struct tcp_pcb *tpcb)
{
	DEBUG_printf("tcp_comm_server_poll_fn\n");
	return ERR_OK;
}

static void tcp_comm_client_err(void *arg, err_t err)
{
	struct tcp_comm_ctx *ctx = (struct tcp_comm_ctx *)arg;

	DEBUG_printf("tcp_comm_err %d\n", err);

	ctx->client_pcb = NULL;
	stream_comm_close(&ctx->ctx);
}

static void tcp_comm_client_init(struct tcp_comm_ctx *ctx, struct tcp_pcb *pcb)
{
	ctx->client_pcb = pcb;
	tcp_arg(pcb, ctx);

	tcp_sent(pcb, tcp_comm_client_sent);
	tcp_recv(pcb, tcp_comm_client_recv);
	tcp_poll(pcb, tcp_comm_client_poll, POLL_TIME_S * 2);
	tcp_err(pcb, tcp_comm_client_err);

	stream_comm_open(&ctx->ctx);
}

static err_t tcp_comm_server_accept(void *arg, struct tcp_pcb *client_pcb, err_t err)
{
	struct tcp_comm_ctx *ctx = (struct tcp_comm_ctx *)arg;

	if (err != ERR_OK || client_pcb == NULL) {
		DEBUG_printf("Failure in accept\n");
		tcp_comm_server_complete(ctx, err);
		return ERR_VAL;
	}
	DEBUG_printf("Connection opened\n");

	if (ctx->client_pcb) {
		DEBUG_printf("Already have a connection\n");
		tcp_abort(client_pcb);
		return ERR_ABRT;
	}

	tcp_comm_client_init(ctx, client_pcb);

	return ERR_OK;
}

err_t tcp_comm_listen(struct tcp_comm_ctx *ctx, uint16_t port)
{
	DEBUG_printf("Starting server at %s on port %u\n", ip4addr_ntoa(netif_ip4_addr(netif_list)), port);

	ctx->serv_done = false;

	struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
	if (!pcb) {
		DEBUG_printf("failed to create pcb\n");
		return ERR_MEM;
	}

	err_t err = tcp_bind(pcb, NULL, port);
	if (err) {
		DEBUG_printf("failed to bind to port %d\n", port);
		tcp_abort(pcb);
		return err;
	}

	ctx->serv_pcb = tcp_listen_with_backlog_and_err(pcb, 1, &err);
	if (!ctx->serv_pcb) {
		DEBUG_printf("failed to listen: %d\n", err);
		return err;
	}

	tcp_arg(ctx->serv_pcb, ctx);
	tcp_accept(ctx->serv_pcb, tcp_comm_server_accept);

	return ERR_OK;
}

static int tcp_comm_client_writer(stream_comm_ctx *arg, uint8_t const* data, uint16_t len) {
	struct tcp_comm_ctx* ctx =(struct tcp_comm_ctx*)arg;
	return tcp_write(ctx->client_pcb, data, len, 0);
}

struct tcp_comm_ctx *tcp_comm_new(const struct comm_command *const *cmds,
		size_t n_cmds, uint32_t sync_opcode)
{
	struct tcp_comm_ctx *ctx = calloc(1, sizeof(struct tcp_comm_ctx));
	if (!ctx) {
		return NULL;
	}

	stream_comm_ctor(&ctx->ctx, tcp_comm_client_writer, cmds, n_cmds, sync_opcode);
	return ctx;
}

void tcp_comm_delete(struct tcp_comm_ctx *ctx)
{
	tcp_comm_server_close(ctx);
	free(ctx);
}

bool tcp_comm_server_done(struct tcp_comm_ctx *ctx)
{
	return ctx->serv_done;
}

#endif
