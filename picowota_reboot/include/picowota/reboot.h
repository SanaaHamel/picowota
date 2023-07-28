/**
 * Copyright (c) 2022 Brian Starkey <stark3y@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __PICOWOTA_REBOOT_H__
#define __PICOWOTA_REBOOT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#define PICOWOTA_BOOTLOADER_ENTRY_MAGIC 0xb105f00d

void picowota_reboot(bool to_bootloader);

#ifdef __cplusplus
}
#endif

#endif /* __PICOWOTA_REBOOT_H__ */
