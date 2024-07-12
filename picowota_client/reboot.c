/**
 * Copyright (c) 2022 Brian Starkey <stark3y@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "RP2040.h"
#include "hardware/structs/watchdog.h"
#include "hardware/watchdog.h"

#include "picowota/reboot.h"

// not exposed from the Pico SDK
#define WATCHDOG_NON_REBOOT_MAGIC 0x6ab73121
extern void _watchdog_enable(uint32_t delay_ms, bool pause_on_debug);

// exactly like the SDK's `watchdog_enable`, but reboots into the bootloader
void picowota_watchdog_enable_bootloader(uint32_t delay_ms, bool pause_on_debug)
{
	// FIXME: doesn't seem to satisfy `watchdog_enable_caused_reboot` after jump
	//        to application.
	watchdog_hw->scratch[4] = WATCHDOG_NON_REBOOT_MAGIC;
	watchdog_hw->scratch[5] = PICOWOTA_BOOTLOADER_ENTRY_MAGIC;
	watchdog_hw->scratch[6] = ~PICOWOTA_BOOTLOADER_ENTRY_MAGIC;
	_watchdog_enable(delay_ms, pause_on_debug);
}

void picowota_reboot(bool to_bootloader)
{
	hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
	if (to_bootloader) {
		watchdog_hw->scratch[5] = PICOWOTA_BOOTLOADER_ENTRY_MAGIC;
		watchdog_hw->scratch[6] = ~PICOWOTA_BOOTLOADER_ENTRY_MAGIC;
	} else {
		watchdog_hw->scratch[5] = 0;
		watchdog_hw->scratch[6] = 0;
	}
	watchdog_reboot(0, 0, 0);
	while (1) {
		tight_loop_contents();
		asm("");
	}
}
