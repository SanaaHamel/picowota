/**
 * Copyright (c) 2022 Brian Starkey <stark3y@gmail.com>
 *
 * Based on the Pico W tcp_server example:
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "RP2040.h"
#include "boot/uf2.h"
#include "hardware/regs/addressmap.h"
#include "pico/critical_section.h"
#include "pico/time.h"
#include "pico/util/queue.h"
#include "hardware/dma.h"
#include "hardware/flash.h"
#include "hardware/structs/dma.h"
#include "hardware/structs/watchdog.h"
#include "hardware/gpio.h"
#include "hardware/resets.h"
#include "hardware/uart.h"
#include "hardware/watchdog.h"

#include "pico/stdlib.h"
#include "pico/time.h"

#include "comm_stream.h"
#include "comm_bt_spp.h"
#include "comm_usb_cdc.h"
#include "comm_tcp.h"

#include "picowota/reboot.h"

static_assert(0 <= PICOWOTA_IDLE_TIMEOUT_SEC);

#if PICOWOTA_BT_SPP
	#define PICOWOTA_BLUETOOTH 1
#else
	#define PICOWOTA_BLUETOOTH 0
#endif

#if PICOWOTA_TCP
	#define PICOWOTA_WIFI 1
#else
	#define PICOWOTA_WIFI 0
#endif

#if PICOWOTA_BLUETOOTH
#include "btstack_run_loop.h"
#endif

#define PICWOTA_WIRELESS (PICOWOTA_BLUETOOTH || PICOWOTA_WIFI)

#if PICOWOTA_WIRELESS || defined(CYW43_WL_GPIO_LED_PIN)
	#define PICWOTA_CYW43 1
	#include "pico/cyw43_arch.h"
#else
	#define PICWOTA_CYW43 0
#endif

#if PICOWOTA_USB_CDC
	#include "tusb.h"
	#include "stdio_usb.h"
#endif

static_assert(sizeof(uint32_t) < sizeof(uint64_t), "need to fix overflow checks");

#ifndef PICOWOTA_ENABLE_READ
#define PICOWOTA_ENABLE_READ 0
#endif


static void stdio_usb_init_maybe() {
#if PICOWOTA_USB_CDC
	stdio_usb_init();
#endif
}

#ifndef NDEBUG
#include <stdio.h>
#include "pico/stdio.h"
#define DBG_PRINTF_INIT() do { stdio_init_all(); stdio_usb_init_maybe(); } while (0)
#define DBG_PRINTF(...) printf(__VA_ARGS__)
#else
#define DBG_PRINTF_INIT() { }
#define DBG_PRINTF(...) { }
#endif

#if PICOWOTA_WIFI_AP
#include "dhcpserver.h"
static dhcp_server_t dhcp_server;
#endif

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

#if PICOWOTA_WIFI
#ifndef PICOWOTA_WIFI_SSID
#error "PICOWOTA_WIFI_SSID not defined"
#else
const char *wifi_ssid = STR(PICOWOTA_WIFI_SSID);
#endif

#ifndef PICOWOTA_WIFI_PASS
#error "PICOWOTA_WIFI_PASS not defined"
#else
const char *wifi_pass = STR(PICOWOTA_WIFI_PASS);
#endif
#endif

static critical_section_t critical_section;
static absolute_time_t g_idle_timeout;

static bool idle_reboot_enabled() {
	return memcmp(&g_idle_timeout, &at_the_end_of_time, sizeof(at_the_end_of_time)) != 0;
}

#define EVENT_QUEUE_LENGTH 8
static queue_t event_queue;

enum event_type {
	EVENT_TYPE_REBOOT = 1,
	EVENT_TYPE_GO,
	EVENT_TYPE_SERVER_DONE,
};

struct event {
	enum event_type type;
	union {
		struct {
			bool to_bootloader;
		} reboot;
		struct {
			uint32_t vtor;
		} go;
	};
};

#ifdef PICOWOTA_OTA_PIN
#if PICOWOTA_OTA_PIN < 0 || 30 <= PICOWOTA_OTA_PIN
#error "Invalid pin for `PICOWOTA_OTA_PIN`"
#endif
#endif

#define TCP_PORT 4242

// set by linker

extern char PICOWOTA_BOOTLOADER_CYW43[];
extern char PICOWOTA_BOOTLOADER_CYW43_END[];
extern char PICOWOTA_APP_HEADER[];
extern char PICOWOTA_APP_HEADER_END[];
extern char PICOWOTA_APP_IMAGE[];
extern char PICOWOTA_APP_IMAGE_END[];

#define IMAGE_HEADER_OFFSET (((unsigned)&PICOWOTA_APP_HEADER) - XIP_BASE)

#define BOOT_WRITE_ADDR_MIN ((unsigned)&PICOWOTA_BOOTLOADER_CYW43)
#define BOOT_WRITE_ADDR_MAX ((unsigned)&PICOWOTA_BOOTLOADER_CYW43_END)

#define WRITE_ADDR_MIN ((unsigned)&PICOWOTA_APP_IMAGE)
#define ERASE_ADDR_MIN ((unsigned)&PICOWOTA_APP_IMAGE)
#define FLASH_ADDR_MAX ((unsigned)&PICOWOTA_APP_IMAGE_END)

#define CMD_SYNC          (('S' << 0) | ('Y' << 8) | ('N' << 16) | ('C' << 24))
#define RSP_SYNC          (('W' << 0) | ('o' << 8) | ('T' << 16) | ('a' << 24))
#define CMD_INFO          (('I' << 0) | ('N' << 8) | ('F' << 16) | ('O' << 24))
#define CMD_INFO_BOOT     (('B' << 0) | ('T' << 8) | ('I' << 16) | ('F' << 24))

#define CMD_ERASE_WRITE       (('E' << 0) | ('R' << 8) | ('W' << 16) | ('R' << 24))
#define CMD_ERASE_WRITE_BOOT  (('B' << 0) | ('T' << 8) | ('E' << 16) | ('W' << 24))
#define CMD_READ   						(('R' << 0) | ('E' << 8) | ('A' << 16) | ('D' << 24))
#define CMD_CSUM   						(('C' << 0) | ('S' << 8) | ('U' << 16) | ('M' << 24))
#define CMD_CRC    						(('C' << 0) | ('R' << 8) | ('C' << 16) | ('C' << 24))
#define CMD_ERASE  						(('E' << 0) | ('R' << 8) | ('A' << 16) | ('S' << 24))
#define CMD_ERASE_BOOT  			(('B' << 0) | ('T' << 8) | ('E' << 16) | ('R' << 24))
#define CMD_WRITE  						(('W' << 0) | ('R' << 8) | ('I' << 16) | ('T' << 24))
#define CMD_SEAL   						(('S' << 0) | ('E' << 8) | ('A' << 16) | ('L' << 24))
#define CMD_GO     						(('G' << 0) | ('O' << 8) | ('G' << 16) | ('O' << 24))
#define CMD_REBOOT 						(('B' << 0) | ('O' << 8) | ('O' << 16) | ('T' << 24))

static uint32_t handle_sync(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	return RSP_SYNC;
}

const struct comm_command sync_cmd = {
	.opcode = CMD_SYNC,
	.nargs = 0,
	.resp_nargs = 0,
	.size = NULL,
	.handle = &handle_sync,
};

#if PICOWOTA_ENABLE_READ
static uint32_t size_read(uint32_t const* const args_in, uint32_t* const data_len_out, uint32_t* const resp_data_len_out)
{
	uint32_t size = args_in[1];
	if (size > STREAM_COMM_MAX_DATA_LEN) {
		return STREAM_COMM_RSP_ERR;
	}

	// TODO: Validate address

	*data_len_out = 0;
	*resp_data_len_out = size;

	return STREAM_COMM_RSP_OK;
}

static uint32_t handle_read(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	uint32_t addr = args_in[0];
	uint32_t size = args_in[1];

	memcpy(resp_data_out, (void *)addr, size);

	return STREAM_COMM_RSP_OK;
}

const struct comm_command read_cmd = {
	// READ addr len
	// OKOK [data]
	.opcode = CMD_READ,
	.nargs = 2,
	.resp_nargs = 0,
	.size = &size_read,
	.handle = &handle_read,
};
#endif

static uint32_t size_crc(uint32_t const* const args_in, uint32_t* const data_len_out, uint32_t* const resp_data_len_out)
{
	uint32_t addr = args_in[0];
	uint32_t size = args_in[1];

	if ((addr & 0x3) || (size & 0x3)) {
		// Must be aligned
		return STREAM_COMM_RSP_ERR;
	}

	// TODO: Validate address

	*data_len_out = 0;
	*resp_data_len_out = 0;

	return STREAM_COMM_RSP_OK;
}

// ptr must be 4-byte aligned and len must be a multiple of 4
static uint32_t calc_crc32(void const* const ptr, uint32_t const len)
{
	uint32_t dummy_dest, crc;

	int channel = dma_claim_unused_channel(true);
	dma_channel_config c = dma_channel_get_default_config(channel);
	channel_config_set_transfer_data_size(&c, DMA_SIZE_32);
	channel_config_set_read_increment(&c, true);
	channel_config_set_write_increment(&c, false);
	channel_config_set_sniff_enable(&c, true);

	// Seed the CRC calculation
	dma_hw->sniff_data = 0xffffffff;

	// Mode 1, then bit-reverse the result gives the same result as
	// golang's IEEE802.3 implementation
	dma_sniffer_enable(channel, 0x1, true);
	dma_hw->sniff_ctrl |= DMA_SNIFF_CTRL_OUT_REV_BITS;

	dma_channel_configure(channel, &c, &dummy_dest, ptr, len / 4, true);

	dma_channel_wait_for_finish_blocking(channel);

	// Read the result before resetting
	crc = dma_hw->sniff_data ^ 0xffffffff;

	dma_sniffer_disable();
	dma_channel_unclaim(channel);

	return crc;
}

static uint32_t handle_crc(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	uint32_t addr = args_in[0];
	uint32_t size = args_in[1];

	resp_args_out[0] = calc_crc32((void *)addr, size);

	return STREAM_COMM_RSP_OK;
}

struct comm_command crc_cmd = {
	// CRCC addr len
	// OKOK crc
	.opcode = CMD_CRC,
	.nargs = 2,
	.resp_nargs = 1,
	.size = &size_crc,
	.handle = &handle_crc,
};

static uint32_t size_erase_write_ex(uint32_t const write_min, uint32_t const write_max, uint32_t const* const args_in, uint32_t* const data_len_out, uint32_t* const resp_data_len_out)
{
	uint32_t addr = args_in[0];
	uint32_t size = args_in[1];

	if ((addr < write_min) || (write_max < (((uint64_t)addr) + size))) {
		// Outside flash
		DBG_PRINTF("write outside flash region; flash-region=[0x%08x, 0x%08x] write=[0x%08x, 0x%08x]\n",
			(unsigned)write_min, (unsigned)write_max, (unsigned)addr, (unsigned)(addr + size));
		return STREAM_COMM_RSP_ERR;
	}

	if ((addr & (FLASH_PAGE_SIZE - 1)) || (size & (FLASH_PAGE_SIZE -1))) {
		// Must be aligned
		DBG_PRINTF("write not aligned\n");
		return STREAM_COMM_RSP_ERR;
	}

	// TODO: Validate address

	*data_len_out = size;
	*resp_data_len_out = 0;

	return STREAM_COMM_RSP_OK;
}

static uint32_t handle_erase_write_ex(uint32_t const write_min, uint32_t const write_max, uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out, bool disable_reboot_if_changed)
{
	uint32_t const addr = args_in[0];
	uint32_t const size = args_in[1];
	uint32_t const detailed = args_in[2];

	if ((addr < write_min) || (write_max < (((uint64_t)addr) + size))) {
		// Outside flash
		DBG_PRINTF("erase outside flash region; flash-region=[0x%08x, 0x%08x] write=[0x%08x, 0x%08x]\n",
			(unsigned)write_min, (unsigned)write_max, (unsigned)addr, (unsigned)(addr + size));
		return STREAM_COMM_RSP_ERR;
	}

	if ((addr & (FLASH_SECTOR_SIZE - 1)) || (size & (FLASH_SECTOR_SIZE - 1))) {
		// Must be aligned
		DBG_PRINTF("erase not aligned\n");
		return STREAM_COMM_RSP_ERR;
	}

	uint32_t changed = 0;
	critical_section_enter_blocking(&critical_section);
	{
		if (detailed == 1) {
			for (uint32_t i = 0; i < size; ++i)
				changed += ((uint8_t*)addr)[i] != data_in[i];
		} else {
			changed = memcmp((void*)addr, data_in, size) != 0;
		}

		if (changed) {
			if (disable_reboot_if_changed && idle_reboot_enabled()) {
				DBG_PRINTF("changing bootloader - idle reboot suppressed\n");
				g_idle_timeout = at_the_end_of_time;
			}

			flash_range_erase(addr - XIP_BASE, size);
			flash_range_program(addr - XIP_BASE, data_in, size);
		} else {
			DBG_PRINTF("block [0x%08x, 0x%08x] identical - skipping...\n", (unsigned)addr, (unsigned)(addr + size));
		}
	}
	critical_section_exit(&critical_section);

	resp_args_out[0] = calc_crc32((void *)addr, size);
	resp_args_out[1] = changed;

	return STREAM_COMM_RSP_OK;
}

static uint32_t size_erase_write(uint32_t const* const args_in, uint32_t* const data_len_out, uint32_t* const resp_data_len_out)
{
	return size_erase_write_ex(WRITE_ADDR_MIN, FLASH_ADDR_MAX, args_in, data_len_out, resp_data_len_out);
}

static uint32_t handle_erase_write(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	return handle_erase_write_ex(WRITE_ADDR_MIN, FLASH_ADDR_MAX, args_in, data_in, resp_args_out, resp_data_out, false);
}

struct comm_command erase_write_cmd = {
	// ERWR addr len detailed-diff
	// OKOK crc changed
	.opcode = CMD_ERASE_WRITE,
	.nargs = 3,
	.resp_nargs = 2,
	.size = &size_erase_write,
	.handle = &handle_erase_write,
};


static uint32_t size_erase_write_boot(uint32_t const* const args_in, uint32_t* const data_len_out, uint32_t* const resp_data_len_out)
{
	return size_erase_write_ex(BOOT_WRITE_ADDR_MIN, BOOT_WRITE_ADDR_MAX, args_in, data_len_out, resp_data_len_out);
}

static uint32_t handle_erase_write_boot(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	return handle_erase_write_ex(BOOT_WRITE_ADDR_MIN, BOOT_WRITE_ADDR_MAX, args_in, data_in, resp_args_out, resp_data_out, true);
}

struct comm_command erase_write_boot_cmd = {
	// BTEW addr len detailed-diff
	// OKOK crc changed
	.opcode = CMD_ERASE_WRITE_BOOT,
	.nargs = 3,
	.resp_nargs = 2,
	.size = &size_erase_write_boot,
	.handle = &handle_erase_write_boot,
};

static uint32_t handle_erase_ex(uint32_t const write_min, uint32_t const write_max, uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out, bool disable_reboot_if_changed)
{
	uint32_t const addr = args_in[0];
	uint32_t const size = args_in[1];

	if ((addr < write_min) || (write_max < (((uint64_t)addr) + size))) {
		// Outside flash
		DBG_PRINTF("erase outside flash region; flash-region=[0x%08x, 0x%08x] write=[0x%08x, 0x%08x]\n",
			(unsigned)write_min, (unsigned)write_max, (unsigned)addr, (unsigned)(addr + size));
		return STREAM_COMM_RSP_ERR;
	}

	if ((addr & (FLASH_SECTOR_SIZE - 1)) || (size & (FLASH_SECTOR_SIZE - 1))) {
		// Must be aligned
		DBG_PRINTF("erase not aligned\n");
		return STREAM_COMM_RSP_ERR;
	}

	critical_section_enter_blocking(&critical_section);
	{
		if (disable_reboot_if_changed && idle_reboot_enabled()) {
			DBG_PRINTF("changing bootloader - idle reboot suppressed\n");
			g_idle_timeout = at_the_end_of_time;
		}
		flash_range_erase(addr - XIP_BASE, size);
	}
	critical_section_exit(&critical_section);

	return STREAM_COMM_RSP_OK;
}

static uint32_t handle_erase_boot(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	return handle_erase_ex(BOOT_WRITE_ADDR_MIN, BOOT_WRITE_ADDR_MAX, args_in, data_in, resp_args_out, resp_data_out, true);
}

struct comm_command erase_boot_cmd = {
	// BTER addr len
	// OKOK
	.opcode = CMD_ERASE_BOOT,
	.nargs = 2,
	.resp_nargs = 0,
	.size = NULL,
	.handle = &handle_erase_boot,
};

static uint32_t handle_erase(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	return handle_erase_ex(ERASE_ADDR_MIN, FLASH_ADDR_MAX, args_in, data_in, resp_args_out, resp_data_out, false);
}

struct comm_command erase_cmd = {
	// ERAS addr len
	// OKOK
	.opcode = CMD_ERASE,
	.nargs = 2,
	.resp_nargs = 0,
	.size = NULL,
	.handle = &handle_erase,
};

static uint32_t size_write(uint32_t const* const args_in, uint32_t* const data_len_out, uint32_t* const resp_data_len_out)
{
	uint32_t addr = args_in[0];
	uint32_t size = args_in[1];

	if ((addr < WRITE_ADDR_MIN) || (FLASH_ADDR_MAX < (((uint64_t)addr) + size))) {
		// Outside flash
		DBG_PRINTF("write outside flash region; flash-region=[0x%08x, 0x%08x] write=[0x%08x, 0x%08x]\n",
			(unsigned)WRITE_ADDR_MIN, (unsigned)FLASH_ADDR_MAX, (unsigned)addr, (unsigned)(addr + size));
		return STREAM_COMM_RSP_ERR;
	}

	if ((addr & (FLASH_PAGE_SIZE - 1)) || (size & (FLASH_PAGE_SIZE -1))) {
		// Must be aligned
		DBG_PRINTF("write not aligned\n");
		return STREAM_COMM_RSP_ERR;
	}

	if (size > STREAM_COMM_MAX_DATA_LEN) {
		DBG_PRINTF("write too big\n");
		return STREAM_COMM_RSP_ERR;
	}

	// TODO: Validate address

	*data_len_out = size;
	*resp_data_len_out = 0;

	return STREAM_COMM_RSP_OK;
}

static uint32_t handle_write(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	uint32_t addr = args_in[0];
	uint32_t size = args_in[1];

	critical_section_enter_blocking(&critical_section);
	flash_range_program(addr - XIP_BASE, data_in, size);
	critical_section_exit(&critical_section);

	resp_args_out[0] = calc_crc32((void *)addr, size);

	return STREAM_COMM_RSP_OK;
}

struct comm_command write_cmd = {
	// WRIT addr len [data]
	// OKOK crc
	.opcode = CMD_WRITE,
	.nargs = 2,
	.resp_nargs = 1,
	.size = &size_write,
	.handle = &handle_write,
};

struct image_header {
	uint32_t vtor;
	uint32_t size;
	uint32_t crc;
	uint8_t pad[FLASH_PAGE_SIZE - (3 * 4)];
};
static_assert(sizeof(struct image_header) == FLASH_PAGE_SIZE, "image_header must be FLASH_PAGE_SIZE bytes");

static bool image_header_ok(struct image_header const* const hdr)
{
	uint32_t *vtor = (uint32_t *)hdr->vtor;

	uint32_t calc = calc_crc32((void *)hdr->vtor, hdr->size);

	// CRC has to match
	if (calc != hdr->crc) {
		DBG_PRINTF("bad crc; given=%u; actual=%u\n", (unsigned)hdr->crc, (unsigned)calc);
		return false;
	}

	// Stack pointer needs to be in RAM
	if (vtor[0] < SRAM_BASE) {
		DBG_PRINTF("stack ptr 0x%08x < 0x%08x\n", (unsigned)vtor[0], (unsigned)SRAM_BASE);
		return false;
	}

	// Reset vector should be in the image, and thumb (bit 0 set)
	if (!(hdr->vtor <= vtor[1] && vtor[1] < hdr->vtor + hdr->size)) {
		DBG_PRINTF("reset vector not in img: vtor=0x%08u img=[0x%08u, 0x%08u]\n",
			(unsigned)vtor[1], (unsigned)hdr->vtor, (unsigned)(hdr->vtor + hdr->size));
		return false;
	}
	if (!(vtor[1] & 1)) {
		DBG_PRINTF("thumb bit not set\n");
		return false;
	}

	// Looks OK.
	return true;
}


static uint32_t handle_seal(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	struct image_header hdr = {
		.vtor = args_in[0],
		.size = args_in[1],
		.crc = args_in[2],
	};

	if ((hdr.vtor & 0xff) || (hdr.size & 0x3)) {
		// Must be aligned
		DBG_PRINTF("hdr not aligned\n");
		return STREAM_COMM_RSP_ERR;
	}

	if (!image_header_ok(&hdr)) {
		return STREAM_COMM_RSP_ERR;
	}

	critical_section_enter_blocking(&critical_section);
	static_assert(sizeof(hdr) <= FLASH_SECTOR_SIZE);
	flash_range_erase(IMAGE_HEADER_OFFSET, FLASH_SECTOR_SIZE);
	flash_range_program(IMAGE_HEADER_OFFSET, (const uint8_t *)&hdr, sizeof(hdr));
	critical_section_exit(&critical_section);

	struct image_header *check = (struct image_header *)PICOWOTA_APP_HEADER;
	if (memcmp(&hdr, check, sizeof(hdr))) {
		DBG_PRINTF("failed post-flash check\n");
		return STREAM_COMM_RSP_ERR;
	}

	return STREAM_COMM_RSP_OK;
}

struct comm_command seal_cmd = {
	// SEAL vtor len crc
	// OKOK
	.opcode = CMD_SEAL,
	.nargs = 3,
	.resp_nargs = 0,
	.size = NULL,
	.handle = &handle_seal,
};

static void disable_interrupts(void)
{
	SysTick->CTRL &= ~1;

	NVIC->ICER[0] = 0xFFFFFFFF;
	NVIC->ICPR[0] = 0xFFFFFFFF;
}

static void reset_peripherals(void)
{
    reset_block(~(
            RESETS_RESET_IO_QSPI_BITS |
            RESETS_RESET_PADS_QSPI_BITS |
            RESETS_RESET_SYSCFG_BITS |
            RESETS_RESET_PLL_SYS_BITS
    ));
}

static void jump_to_vtor(uint32_t vtor)
{
	// Derived from the Leaf Labs Cortex-M3 bootloader.
	// Copyright (c) 2010 LeafLabs LLC.
	// Modified 2021 Brian Starkey <stark3y@gmail.com>
	// Originally under The MIT License
	uint32_t reset_vector = *(volatile uint32_t *)(vtor + 0x04);

	SCB->VTOR = (volatile uint32_t)(vtor);

	asm volatile("msr msp, %0"::"g"
			(*(volatile uint32_t *)vtor));
	asm volatile("bx %0"::"r" (reset_vector));
}


static uint32_t handle_go(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	struct event ev = {
		.type = EVENT_TYPE_GO,
		.go = {
			.vtor = args_in[0],
		},
	};

	if (!queue_try_add(&event_queue, &ev)) {
		return STREAM_COMM_RSP_ERR;
	}

	return STREAM_COMM_RSP_OK;
}

struct comm_command go_cmd = {
	// GOGO vtor
	// NO RESPONSE
	.opcode = CMD_GO,
	.nargs = 1,
	.resp_nargs = 0,
	.size = NULL,
	.handle = &handle_go,
};

// populates the addr, size, erase-size, write-size, and chunk-size fields
static void handle_info_ex(uint32_t const addr_min, uint32_t const addr_max, uint32_t* const resp_args_out/*[5]*/)
{
	resp_args_out[0] = addr_min;
	resp_args_out[1] = addr_max - addr_min;
	resp_args_out[2] = FLASH_SECTOR_SIZE;
	resp_args_out[3] = FLASH_PAGE_SIZE;
	resp_args_out[4] = STREAM_COMM_MAX_DATA_LEN;
}

static uint32_t handle_info(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	handle_info_ex(WRITE_ADDR_MIN, FLASH_ADDR_MAX, resp_args_out);

	return STREAM_COMM_RSP_OK;
}

const struct comm_command info_cmd = {
	// INFO
	// OKOK flash_start flash_size erase_size write_size max_data_len
	.opcode = CMD_INFO,
	.nargs = 0,
	.resp_nargs = 5,
	.size = NULL,
	.handle = &handle_info,
};


static uint32_t handle_info_boot(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	resp_args_out[0] = RP2040_FAMILY_ID;
	handle_info_ex(BOOT_WRITE_ADDR_MIN, BOOT_WRITE_ADDR_MAX, resp_args_out + 1);

	return STREAM_COMM_RSP_OK;
}

const struct comm_command info_boot_cmd = {
	// BTIF
	// OKOK boot_start boot_size erase_size write_size max_data_len
	.opcode = CMD_INFO_BOOT,
	.nargs = 0,
	.resp_nargs = 6,
	.size = NULL,
	.handle = &handle_info_boot,
};

static uint32_t handle_reboot(uint32_t const* const args_in, uint8_t const* const data_in, uint32_t* const resp_args_out, uint8_t* const resp_data_out)
{
	struct event ev = {
		.type = EVENT_TYPE_REBOOT,
		.reboot = {
			.to_bootloader = !!args_in[0],
		},
	};

	if (!queue_try_add(&event_queue, &ev)) {
		DBG_PRINTF("failed to enqueue reboot\n");
		return STREAM_COMM_RSP_ERR;
	}

	return STREAM_COMM_RSP_OK;
}

struct comm_command reboot_cmd = {
	// BOOT to_bootloader
	// NO RESPONSE
	.opcode = CMD_REBOOT,
	.nargs = 1,
	.resp_nargs = 0,
	.size = NULL,
	.handle = &handle_reboot,
};

static bool should_stay_in_bootloader()
{
#ifdef PICOWOTA_OTA_PIN
	if (!gpio_get(PICOWOTA_OTA_PIN)) return true;
#endif

	bool wd_says_so = (watchdog_hw->scratch[5] == PICOWOTA_BOOTLOADER_ENTRY_MAGIC) &&
		(watchdog_hw->scratch[6] == ~PICOWOTA_BOOTLOADER_ENTRY_MAGIC);
	return wd_says_so;
}

#if PICOWOTA_TCP
static struct tcp_comm_ctx *g_tcp_server;
#endif

static void network_deinit()
{
#if PICOWOTA_BT_SPP
	bt_spp_comm_close();
#endif
#if PICOWOTA_TCP
	tcp_comm_server_close(g_tcp_server);
#endif
#if PICOWOTA_USB_CDC
	usb_cdc_comm_close();
#endif
#if PICOWOTA_WIFI_AP
	dhcp_server_deinit(&dhcp_server);
#endif
#if PICWOTA_CYW43
	cyw43_arch_deinit();
#endif
}

static void reboot_if_idle_timeout() {
	if (0 < stream_comm_active() && idle_reboot_enabled()) {
		g_idle_timeout = make_timeout_time_ms(PICOWOTA_IDLE_TIMEOUT_SEC * 1000);
		return;
	}

	// timeout hasn't happened yet
	if (to_us_since_boot(get_absolute_time()) < to_us_since_boot(g_idle_timeout)) return;

#ifdef PICOWOTA_OTA_PIN
	// suppress idle reboot when the bootloader pin is held low
	if (!gpio_get(PICOWOTA_OTA_PIN)) return;
#endif

	// Never reboot if we've an invalid image.
	struct image_header *hdr = (struct image_header *)PICOWOTA_APP_HEADER;
	if (!image_header_ok(hdr)) {
		// Image will never become valid w/o someone connecting and uploading a new
		// image. Set the timeout to never to avoid wasting time re-validating the
		// broken image.
		DBG_PRINTF("idle timeout - image invalid, reboot suppressed\n");
		g_idle_timeout = at_the_end_of_time;
		return;
	}

	DBG_PRINTF("idle timeout - rebooting\n");
	struct event ev = {
		.type = EVENT_TYPE_REBOOT,
		.reboot = { .to_bootloader = false },
	};
	if (!queue_try_add(&event_queue, &ev)) {
		DBG_PRINTF("failed to enqueue reboot\n");
	}
}

static void pump_events() {
	struct event ev;
	while (queue_try_remove(&event_queue, &ev)) {
		switch (ev.type) {
		case EVENT_TYPE_SERVER_DONE: {
#if PICOWOTA_TCP
			err_t err = tcp_comm_listen(g_tcp_server, TCP_PORT);
			if (err != ERR_OK) {
				DBG_PRINTF("Failed to start server: %d\n", err);
			}
#endif
		} break;
		case EVENT_TYPE_REBOOT:
			network_deinit();
			picowota_reboot(ev.reboot.to_bootloader);
			/* Should never get here */
			break;
		case EVENT_TYPE_GO:
			network_deinit();
			disable_interrupts();
			reset_peripherals();
			jump_to_vtor(ev.go.vtor);
			/* Should never get here */
			break;
		};
	}

#if PICOWOTA_USB_CDC
	tud_task();
	usb_cdc_update();
#endif

	uint64_t time_ms = time_us_64() / 1000;
	uint64_t time_blink = time_ms / 100;
	bool blinker = time_blink % 2 == 0;
	bool led_on = 0 < stream_comm_active() || blinker;

#if defined(PICO_DEFAULT_LED_PIN)
	gpio_put(PICO_DEFAULT_LED_PIN, led_on);
#elif defined(PICO_DEFAULT_WS2812_PIN)
	// FUTURE WORK: implement WS2812 LED
#elif defined(CYW43_WL_GPIO_LED_PIN)
	// HACK:  `cyw43_arch_gpio_put` w/o having the HCI powered on
	//        kills the timer task when it enters `cyw43_ensure_up`.
	//        Root cause unknown. This hack should be benign since
	//        Pico W is typically built w/ BT enabled.
	cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
#endif

	reboot_if_idle_timeout();
}

#if PICOWOTA_BLUETOOTH
static void bt_pump_events(btstack_timer_source_t* timer) {
	pump_events();
	btstack_run_loop_set_timer(timer, 5);
	btstack_run_loop_add_timer(timer);
}
#endif

int main()
{
#ifdef PICOWOTA_OTA_PIN
	gpio_init(PICOWOTA_OTA_PIN);
	gpio_pull_up(PICOWOTA_OTA_PIN);
	gpio_set_dir(PICOWOTA_OTA_PIN, 0);

	sleep_ms(10);
#endif

#if PICOWOTA_USB_CDC
	tusb_init();
#endif

	DBG_PRINTF_INIT();

	struct image_header *hdr = (struct image_header *)PICOWOTA_APP_HEADER;

	if (!should_stay_in_bootloader() && image_header_ok(hdr)) {
		disable_interrupts();
		reset_peripherals();
		jump_to_vtor(hdr->vtor);
	}

	queue_init(&event_queue, sizeof(struct event), EVENT_QUEUE_LENGTH);

#if PICWOTA_CYW43
	if (cyw43_arch_init()) {
		DBG_PRINTF("failed to initialise\n");
		return 1;
	}
#endif

	critical_section_init(&critical_section);

	const struct comm_command *cmds[] = {
		&erase_write_cmd,
		&erase_write_boot_cmd,
		&sync_cmd,
#if PICOWOTA_ENABLE_READ
		&read_cmd,
#endif
		&crc_cmd,
		&erase_cmd,
		&erase_boot_cmd,
		&write_cmd,
		&seal_cmd,
		&go_cmd,
		&info_cmd,
		&info_boot_cmd,
		&reboot_cmd,
	};

#if PICOWOTA_BT_SPP
	int bt_spp_err = bt_spp_comm_init(cmds, sizeof(cmds) / sizeof(cmds[0]), CMD_SYNC);
	if (bt_spp_err) {
		DBG_PRINTF("failed to init SPP err=%d\n", bt_spp_err);
	}
#endif

#if PICOWOTA_USB_CDC
	int usb_cdc_err = usb_cdc_comm_init(cmds, sizeof(cmds) / sizeof(cmds[0]), CMD_SYNC);
	if (usb_cdc_err) {
		DBG_PRINTF("failed to init USB CDC err=%d\n", usb_cdc_err);
	} else {
		DBG_PRINTF("USB CDC comm ready\n");
	}
#endif

#if PICOWOTA_WIFI
#if PICOWOTA_WIFI_AP
	cyw43_arch_enable_ap_mode(wifi_ssid, wifi_pass, CYW43_AUTH_WPA2_AES_PSK);
	DBG_PRINTF("Enabled the WiFi AP.\n");

	ip4_addr_t gw, mask;
	IP4_ADDR(&gw, 192, 168, 4, 1);
	IP4_ADDR(&mask, 255, 255, 255, 0);

	dhcp_server_t dhcp_server;
	dhcp_server_init(&dhcp_server, &gw, &mask);
	DBG_PRINTF("Started the DHCP server.\n");
#else
	cyw43_arch_enable_sta_mode();

	DBG_PRINTF("Connecting to WiFi...\n");
	while (cyw43_arch_wifi_connect_timeout_ms(wifi_ssid, wifi_pass, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
		DBG_PRINTF("failed to connect - retrying...\n");
		sleep_ms(500);
	}

	DBG_PRINTF("Connected.\n");
#endif
#endif

#if PICOWOTA_TCP
	g_tcp_server = tcp_comm_new(cmds, sizeof(cmds) / sizeof(cmds[0]), CMD_SYNC);
#endif

	struct event ev = {
		.type = EVENT_TYPE_SERVER_DONE,
	};

	queue_add_blocking(&event_queue, &ev);

	g_idle_timeout = make_timeout_time_ms(PICOWOTA_IDLE_TIMEOUT_SEC * 1000);

#if PICOWOTA_BLUETOOTH
	btstack_timer_source_t bt_pump_events_timer;
	bt_pump_events_timer.process = &bt_pump_events;
	bt_pump_events(&bt_pump_events_timer);
	btstack_run_loop_execute();
#else
	for ( ; ; ) {
		pump_events();
#if PICWOTA_CYW43
		cyw43_arch_poll();
#endif
		sleep_ms(5);
	}
#endif

	assert(false && "unreachable");
	return 0;
}
