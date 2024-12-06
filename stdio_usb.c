/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if PICOWOTA_USB_CDC

#include "stdio_usb.h"
#include "hardware/irq.h"
#include "pico/binary_info.h"
#include "pico/mutex.h"
#include "pico/stdio/driver.h"
#include "pico/time.h"
#include "tusb.h"

// these may not be set if the user is providing tud support (i.e. LIB_TINYUSB_DEVICE is 1 because
// the user linked in tinyusb_device) but they haven't selected CDC
#if !((CFG_TUD_ENABLED | TUSB_OPT_DEVICE_ENABLED) && CFG_TUD_CDC)
#error USB device expected
#endif

#if PICO_STDIO_USB_SUPPORT_CHARS_AVAILABLE_CALLBACK
#error Not implemented.
#endif

#define STDIO_ITF 0

static mutex_t stdio_usb_mutex;

static void stdio_usb_out_chars(const char* buf, int length) {
    if (!mutex_try_enter_block_until(&stdio_usb_mutex, make_timeout_time_ms(PICO_STDIO_DEADLOCK_TIMEOUT_MS)))
        return;

    static uint64_t last_avail_time;
    if (!stdio_usb_connected()) {
        // reset our timeout
        last_avail_time = 0;
        mutex_exit(&stdio_usb_mutex);
        return;
    }

    for (int i = 0; i < length;) {
        int n = length - i;
        uint32_t written = tud_cdc_n_write(STDIO_ITF, buf + i, (uint32_t)n);
        tud_task();
        tud_cdc_n_write_flush(STDIO_ITF);

        if (0 < written) {
            i += written;
            last_avail_time = time_us_64();
        } else {
            if (!stdio_usb_connected()) break;
            if (!tud_cdc_n_write_available(STDIO_ITF) &&
                    last_avail_time + PICO_STDIO_USB_STDOUT_TIMEOUT_US <= time_us_64())
                break;
        }
    }

    mutex_exit(&stdio_usb_mutex);
}

int stdio_usb_in_chars(char* buf, int length) {
    // note we perform this check outside the lock, to try and prevent possible deadlock conditions
    // with printf in IRQs (which we will escape through timeouts elsewhere, but that would be less graceful).
    //
    // these are just checks of state, so we can call them while not holding the lock.
    // they may be wrong, but only if we are in the middle of a tud_task call, in which case at worst
    // we will mistakenly think we have data available when we do not (we will check again), or
    // tud_task will complete running and we will check the right values the next time.
    //
    if (!stdio_usb_connected()) return PICO_ERROR_NO_DATA;
    if (!tud_cdc_n_available(STDIO_ITF)) return PICO_ERROR_NO_DATA;

    if (!mutex_try_enter_block_until(&stdio_usb_mutex, make_timeout_time_ms(PICO_STDIO_DEADLOCK_TIMEOUT_MS)))
        return PICO_ERROR_NO_DATA;  // would deadlock otherwise

    int rc = PICO_ERROR_NO_DATA;
    if (stdio_usb_connected() && tud_cdc_n_available(STDIO_ITF)) {
        uint32_t count = tud_cdc_n_read(STDIO_ITF, buf, (uint32_t)length);
        rc = count ? (int)count : PICO_ERROR_NO_DATA;
    } else {
        // because our mutex use may starve out the background task, run tud_task here (we own the mutex)
        tud_task();
    }
    mutex_exit(&stdio_usb_mutex);

    return rc;
}

stdio_driver_t stdio_usb = {
        .out_chars = stdio_usb_out_chars,
        .in_chars = stdio_usb_in_chars,
#if PICO_STDIO_ENABLE_CRLF_SUPPORT
        .crlf_enabled = PICO_STDIO_USB_DEFAULT_CRLF,
#endif

};

bool stdio_usb_init() {
#if !PICO_NO_BI_STDIO_USB
    bi_decl_if_func_used(bi_program_feature("USB stdin / stdout"));
#endif

    if (get_core_num() != alarm_pool_core_num(alarm_pool_get_default())) {
        // included an assertion here rather than just returning false, as this is likely
        // a coding bug, rather than anything else.
        assert(false);
        return false;
    }

    assert(tud_inited());  // we expect the caller to have initialized if they are using TinyUSB

    mutex_init(&stdio_usb_mutex);

    stdio_set_driver_enabled(&stdio_usb, true);

#if PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS
#if PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS > 0
    absolute_time_t until = make_timeout_time_ms(PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS);
#else
    absolute_time_t until = at_the_end_of_time;
#endif
    do {
        if (stdio_usb_connected()) {
#if PICO_STDIO_USB_POST_CONNECT_WAIT_DELAY_MS != 0
            sleep_ms(PICO_STDIO_USB_POST_CONNECT_WAIT_DELAY_MS);
#endif
            break;
        }
        sleep_ms(10);
    } while (!time_reached(until));
#endif

    return true;
}

bool stdio_usb_connected(void) {
#if PICO_STDIO_USB_CONNECTION_WITHOUT_DTR
    return tud_ready();
#else
    // this actually checks DTR
    return tud_cdc_n_connected(STDIO_ITF);
#endif
}

#endif
