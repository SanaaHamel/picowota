#if PICOWOTA_BLUETOOTH

#include "pico/btstack_flash_bank.h"

static_assert(PICOWOTA_FLASH_BANK_STORAGE_OFFSET == PICO_FLASH_BANK_STORAGE_OFFSET);
static_assert(PICOWOTA_FLASH_BANK_TOTAL_SIZE == PICO_FLASH_BANK_TOTAL_SIZE);

#endif