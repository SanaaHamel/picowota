#pragma once

#if PICOWOTA_BT_SPP

#include <stddef.h>
#include <stdint.h>

struct comm_command;

int bt_spp_comm_init(struct comm_command const *const *cmds, size_t n_cmds,
                  uint32_t sync_opcode);
void bt_spp_comm_close();

#endif
