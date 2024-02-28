#if PICOWOTA_BT_SPP
// more or less ripped from `spp_example.c` and mashed together with `tcp`

#include "comm_bt_spp.h"
#include "btstack.h"
#include "comm_stream.h"
#include "pico/cyw43_arch.h"
#include "platform/embedded/hci_dump_embedded_stdout.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifndef NDEBUG
#include <stdio.h>
#define DEBUG_printf(...) printf(__VA_ARGS__)
#else
#define DEBUG_printf(...)                                                      \
  {}
#endif

#define RFCOMM_SERVER_CHANNEL 1
#define RFCOMM_CID_INVALID 0

static uint8_t g_spp_service_buffer[100];

typedef struct spp_comm_ctx {
  stream_comm_ctx ctx;
  uint16_t rfcomm_cid;
  uint8_t const *send_pending;
} spp_comm_ctx;

static void spp_comm_send_packet(spp_comm_ctx *ctx) {
  assert(ctx);
  if (!ctx)
    return;
  if (ctx->ctx.conn.tx_remaining <= 0)
    return;

  size_t len_max = rfcomm_get_max_frame_size(ctx->rfcomm_cid);
  size_t len = MIN(ctx->ctx.conn.tx_remaining, len_max);
  uint8_t err = rfcomm_send(ctx->rfcomm_cid, (uint8_t *)ctx->send_pending, len);
  if (err) {
    DEBUG_printf("ERR - SPP - failed to send packet err=%u\n", err);
    return;
  }

  ctx->send_pending += len;
  // `stream_comm_sent` adjusts `ctx->ctx.conn.tx_remaining`
  int status = stream_comm_sent(&ctx->ctx, len);
  if (status) {
    DEBUG_printf("SPP disconnected, status=%d\n", status);
    rfcomm_disconnect(ctx->rfcomm_cid);
    return;
  }

  if (0 < ctx->ctx.conn.tx_remaining) {
    rfcomm_request_can_send_now_event(ctx->rfcomm_cid);
  } else {
    ctx->send_pending = NULL;
  }
}

static int spp_comm_write(stream_comm_ctx *arg, uint8_t const *data,
                          uint16_t len) {
  struct spp_comm_ctx *ctx = (struct spp_comm_ctx *)arg;
  assert(ctx->rfcomm_cid != RFCOMM_CID_INVALID && "rfcomm is closed");
  assert(!ctx->send_pending && "already have data pending");
  ctx->send_pending = data;

  uint8_t err = rfcomm_request_can_send_now_event(ctx->rfcomm_cid);
  if (err) {
    DEBUG_printf("ERR - SPP failed to request send-now cid=%d err=%u\n",
                 ctx->rfcomm_cid, err);
    return -1;
  }

  return 0;
}

static spp_comm_ctx g_spp_comm_ctx; // only support one connection at a time
static_assert(MAX_NR_RFCOMM_CHANNELS == 1);

static void packet_handler(uint8_t const packet_type, uint16_t const channel,
                           uint8_t *const packet, uint16_t const size) {
  switch (packet_type) {
  default:
    break;

  case RFCOMM_DATA_PACKET: {
    assert(channel == g_spp_comm_ctx.rfcomm_cid);
    if (channel == g_spp_comm_ctx.rfcomm_cid) {
      uint8_t *const dst = stream_comm_recv_prepare(&g_spp_comm_ctx.ctx, size);
      if (!dst) {
        DEBUG_printf("ERR - SPP recv too much data: channel=%u, size=%u\n", channel,
               size);
        rfcomm_disconnect(channel);
        break;
      }

      memcpy(dst, packet, size);
      int err = stream_comm_recv_process(&g_spp_comm_ctx.ctx);
      if (err) {
        DEBUG_printf("SPP disconnected, status=%d\n", err);
        rfcomm_disconnect(channel);
        break;
      }
    }
  } break;

  case HCI_EVENT_PACKET: {
    switch (hci_event_packet_get_type(packet)) {
    case BTSTACK_EVENT_STATE: {
      switch (btstack_event_state_get_state(packet)) {
      case HCI_STATE_WORKING: {
        bd_addr_t local_addr;
        gap_local_bd_addr(local_addr);
        DEBUG_printf("BTstack up and running on %s\n", bd_addr_to_str(local_addr));
      } break;
      }
    } break;

    case HCI_EVENT_PIN_CODE_REQUEST: { // inform about pin code request
      DEBUG_printf("Pin code request - using '0000'\n");
      bd_addr_t event_addr;
      hci_event_pin_code_request_get_bd_addr(packet, event_addr);
      gap_pin_code_response(event_addr, "0000");
    } break;

      // inform about user confirmation request
    case HCI_EVENT_USER_CONFIRMATION_REQUEST: {
      DEBUG_printf("SSP User Confirmation Request with numeric value '%06u'\n",
             (unsigned)little_endian_read_32(packet, 8));
      DEBUG_printf("SSP User Confirmation Auto accept\n");
    } break;

    case RFCOMM_EVENT_INCOMING_CONNECTION: {
      bd_addr_t event_addr;
      rfcomm_event_incoming_connection_get_bd_addr(packet, event_addr);
      DEBUG_printf("RFCOMM channel 0x%02x requested for %s\n",
             rfcomm_event_incoming_connection_get_server_channel(packet),
             bd_addr_to_str(event_addr));
      assert(rfcomm_event_incoming_connection_get_server_channel(packet) == 1);
      rfcomm_accept_connection(
          rfcomm_event_incoming_connection_get_rfcomm_cid(packet));
    } break;

    case RFCOMM_EVENT_CHANNEL_OPENED: {
      if (rfcomm_event_channel_opened_get_status(packet)) {
        DEBUG_printf("RFCOMM channel open failed, status 0x%02x\n",
               rfcomm_event_channel_opened_get_status(packet));
        break;
      }

      DEBUG_printf("RFCOMM channel open succeeded. New RFCOMM Channel ID 0x%02x, "
             "max frame size %u\n",
             rfcomm_event_channel_opened_get_rfcomm_cid(packet),
             rfcomm_event_channel_opened_get_max_frame_size(packet));

      assert(g_spp_comm_ctx.rfcomm_cid == RFCOMM_CID_INVALID &&
             "connection already open");
      g_spp_comm_ctx.send_pending = NULL;
      g_spp_comm_ctx.rfcomm_cid =
          rfcomm_event_channel_opened_get_rfcomm_cid(packet);
      stream_comm_open(&g_spp_comm_ctx.ctx);

      // disable page/inquiry scan to get max performance
      gap_discoverable_control(0);
      gap_connectable_control(0);
    } break;

    case RFCOMM_EVENT_CAN_SEND_NOW: {
      uint8_t const cid = rfcomm_event_can_send_now_get_rfcomm_cid(packet);
      assert(cid == g_spp_comm_ctx.rfcomm_cid);
      if (cid == g_spp_comm_ctx.rfcomm_cid) {
        spp_comm_send_packet(&g_spp_comm_ctx);
      }
    } break;

    case RFCOMM_EVENT_CHANNEL_CLOSED: {
      uint8_t const cid = rfcomm_event_channel_closed_get_rfcomm_cid(packet);
      DEBUG_printf("RFCOMM channel closed cid=%d\n", cid);
      assert(cid == g_spp_comm_ctx.rfcomm_cid);
      if (cid == g_spp_comm_ctx.rfcomm_cid) {
        stream_comm_close(&g_spp_comm_ctx.ctx);
        g_spp_comm_ctx.rfcomm_cid = 0;
      }

      // re-enable page/inquiry scan again
      gap_discoverable_control(1);
      gap_connectable_control(1);
    } break;

    default:
      break;
    }
  } break;
  }
}

/**
 * RFCOMM can make use for ERTM. Due to the need to re-transmit packets,
 * a large buffer is needed to still get high throughput
 */
#ifdef ENABLE_L2CAP_ENHANCED_RETRANSMISSION_MODE_FOR_RFCOMM
static int ertm_buffer_in_use;
static uint8_t ertm_buffer[20000];

static l2cap_ertm_config_t ertm_config = {
    .ertm_mandatory = 0,
    .max_transmit = 8,
    .retransmission_timeout_ms = 2000,
    .monitor_timeout_ms = 12000,
    .local_mtu = 1000,
    .num_tx_buffers = 8,
    .num_rx_buffers = 8,
    .fcs_option = 0, // No FCS
};

static void
rfcomm_ertm_request_handler(rfcomm_ertm_request_t *const ertm_request) {
  if (ertm_buffer_in_use)
    return;
  ertm_buffer_in_use = 1;

  ertm_request->ertm_config = &ertm_config;
  ertm_request->ertm_buffer = ertm_buffer;
  ertm_request->ertm_buffer_size = sizeof(ertm_buffer);
}

static void rfcomm_ertm_released_handler(uint16_t const ertm_id) {
  ertm_buffer_in_use = 0;
}
#endif

static btstack_packet_callback_registration_t hci_event_callback_registration;

int bt_spp_comm_init(struct comm_command const *const *const cmds,
                     size_t const n_cmds, uint32_t const sync_opcode) {
  stream_comm_ctor(&g_spp_comm_ctx.ctx, spp_comm_write, cmds, n_cmds,
                   sync_opcode);

  hci_dump_init(hci_dump_embedded_stdout_get_instance());
  hci_dump_enable_packet_log(false);
  l2cap_init();

#ifdef ENABLE_BLE
  // Initialize LE Security Manager. Needed for cross-transport key derivation
  sm_init();
#endif

  rfcomm_init();
  rfcomm_register_service(packet_handler, RFCOMM_SERVER_CHANNEL, 0xffff);
#ifdef ENABLE_L2CAP_ENHANCED_RETRANSMISSION_MODE_FOR_RFCOMM
  rfcomm_enable_l2cap_ertm(&rfcomm_ertm_request_handler,
                           &rfcomm_ertm_released_handler);
#endif

  // init SDP, create record for SPP and register with SDP
  sdp_init();
  memset(g_spp_service_buffer, 0, sizeof(g_spp_service_buffer));
  spp_create_sdp_record(g_spp_service_buffer, 0x10001, RFCOMM_SERVER_CHANNEL,
                        "picowota");
  // HACK: `spp_create_sdp_record`'s API blows.
  assert(de_get_len(g_spp_service_buffer) < sizeof(g_spp_service_buffer) &&
         "FATAL - static buffer overrun");
  sdp_register_service(g_spp_service_buffer);

  // register for HCI events
  hci_event_callback_registration.callback = &packet_handler;
  hci_add_event_handler(&hci_event_callback_registration);

  // gap_ssp_set_io_capability(SSP_IO_CAPABILITY_DISPLAY_ONLY);
  gap_set_local_name("picowota 00:00:00:00:00:00");
  gap_discoverable_control(1);

  hci_power_control(HCI_POWER_ON);
  return 0;
}

void bt_spp_comm_close() {
  // HORRIFIC HACK: wait until we've flushed our tx and acknowledged disconnect
  async_context_t *ctx = cyw43_arch_async_context();
  while (g_spp_comm_ctx.send_pending) { // <- implies connected
    async_context_poll(ctx);
    async_context_wait_for_work_until(ctx, at_the_end_of_time);
  }

  if (g_spp_comm_ctx.rfcomm_cid != RFCOMM_CID_INVALID) {
    rfcomm_disconnect(g_spp_comm_ctx.rfcomm_cid);
  }
  while (g_spp_comm_ctx.rfcomm_cid != RFCOMM_CID_INVALID) {
    async_context_poll(ctx);
    async_context_wait_for_work_until(ctx, at_the_end_of_time);
  }
}

#endif
