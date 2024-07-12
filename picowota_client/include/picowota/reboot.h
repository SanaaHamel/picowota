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
#include <stdint.h>

#define PICOWOTA_BOOTLOADER_ENTRY_MAGIC 0xb105f00d

// Exactly like the SDK's `watchdog_enable`, but reboots into the bootloader.
// FIXME: `watchdog_enable_caused_reboot` will not report true within application
//        after an idle timeout from the bootloader.
void picowota_watchdog_enable_bootloader(uint32_t delay_ms, bool pause_on_debug);

__attribute__((noreturn)) void picowota_reboot(bool to_bootloader);

#ifdef __cplusplus
}
#endif

#endif /* __PICOWOTA_REBOOT_H__ */
