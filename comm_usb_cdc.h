#pragma once

#if PICOWOTA_USB_CDC

#include <stddef.h>
#include <stdint.h>

struct comm_command;

int usb_cdc_comm_init(struct comm_command const* const* cmds, size_t n_cmds, uint32_t sync_opcode);
void usb_cdc_comm_close();
void usb_cdc_update();

#endif
