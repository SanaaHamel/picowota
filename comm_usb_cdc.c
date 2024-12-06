#include "device/usbd.h"
#if PICOWOTA_USB_CDC

#include "tusb.h"

#include "comm_stream.h"
#include "comm_usb_cdc.h"
#include <assert.h>

#ifndef NDEBUG
#include <stdio.h>
#define DBG_PRINTF(...) printf(__VA_ARGS__)
#else
#define DBG_PRINTF(...) \
    do {                \
    } while (0)
#endif

// USB CDC interface 1 (interface 0 is stdio)
#define ITF 1

typedef struct usb_cdc_comm_ctx {
    stream_comm_ctx ctx;
    bool open;
} usb_cdc_comm_ctx;

static usb_cdc_comm_ctx g_usb_cdc_comm;  // only support one connection at a time

static int usb_cdc_comm_write(stream_comm_ctx* arg, uint8_t const* data, uint16_t len) {
    struct usb_cdc_comm_ctx* ctx = (struct usb_cdc_comm_ctx*)arg;
    assert(ctx);
    assert(data || len == 0);
    // should be initialised by caller
    assert(ctx->ctx.conn.tx_sent == 0);
    assert(ctx->ctx.conn.tx_remaining == len);

    while (0 < ctx->ctx.conn.tx_remaining) {
        if (!tud_cdc_n_connected(ITF)) return -1;  // don't have anyone to send to

        // wait for space in buffer
        if (!tud_cdc_n_write_available(ITF)) {
            tud_task();
            tud_cdc_n_write_flush(ITF);
            continue;
        }

        uint32_t sent = tud_cdc_n_write(ITF, data + ctx->ctx.conn.tx_sent, ctx->ctx.conn.tx_remaining);
        int err = stream_comm_sent(&ctx->ctx, sent);
        if (err != 0) return err;
    }

    tud_cdc_n_write_flush(ITF);
    return 0;
}

int usb_cdc_comm_init(
        struct comm_command const* const* const cmds, size_t const n_cmds, uint32_t const sync_opcode) {
    stream_comm_ctor(&g_usb_cdc_comm.ctx, usb_cdc_comm_write, cmds, n_cmds, sync_opcode);
    return 0;
}

void usb_cdc_comm_close() {
    if (!g_usb_cdc_comm.open) return;

    DBG_PRINTF("USB CDC - closed\n");

    tud_cdc_n_write_flush(ITF);  // flush writing whatever was left
    tud_cdc_n_read_flush(ITF);   // drop anything inbound

    g_usb_cdc_comm.open = false;
    stream_comm_close(&g_usb_cdc_comm.ctx);
}

void usb_cdc_update() {
    for (;;) {  // read until an error happens, we disconnect, or we run out of input
        if (!tud_cdc_n_connected(ITF)) {
            usb_cdc_comm_close();  // no-op if not open
            break;
        }

        if (!g_usb_cdc_comm.open) {
            g_usb_cdc_comm.open = true;
            stream_comm_open(&g_usb_cdc_comm.ctx);
            DBG_PRINTF("USB CDC - opened\n");
        }

        uint32_t n = tud_cdc_n_available(ITF);
        if (n <= 0) break;  // nothing available, give up for now

        uint8_t* const dst = stream_comm_recv_prepare(&g_usb_cdc_comm.ctx, n);
        if (!dst) {
            usb_cdc_comm_close();
            break;
        }

        uint32_t n_read = tud_cdc_n_read(ITF, dst, n);
        assert(n_read == n);

        int err = stream_comm_recv_process(&g_usb_cdc_comm.ctx);
        if (err) {
            DBG_PRINTF("USB CDC disconnected, status=%d\n", err);
            usb_cdc_comm_close();
            break;
        }

        tud_task();  // see if we can fetch some more
    }
}

#endif
