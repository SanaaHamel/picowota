#pragma once

#if !defined(LIB_TINYUSB_DEVICE)
#error "Who is using this and why?"
#endif

#define CFG_TUSB_RHPORT0_MODE OPT_MODE_DEVICE

// Need 2 CDCs, 1 for stdio, 1 for bootloader protocol
#define CFG_TUD_CDC 2
// bigger buffers for higher throughput
#define CFG_TUD_CDC_RX_BUFSIZE 1024
#define CFG_TUD_CDC_TX_BUFSIZE 1024
#define CFG_TUD_CDC_EP_BUFSIZE 1024
