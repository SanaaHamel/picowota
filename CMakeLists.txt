# Derived from the Pico SDK, which carries the following
# LICENSE.txt:
# Copyright 2020 (c) 2020 Raspberry Pi (Trading) Ltd.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
# disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products
# derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.17)

include(pico_sdk_import.cmake)

project(picowota C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(NOT DEFINED PICO_BOARD)
  set(PICO_BOARD pico_w)
endif()

pico_sdk_init()

function(picowota_property name desc)
  define_property(
    TARGET PROPERTY "${name}" INHERITED
    BRIEF_DOCS "${desc}"
  )

  list(LENGTH ARGN argc)

  if(${argc} GREATER 1)
    message(FATAL_ERROR "too many extra arguments")
  elseif(${argc} EQUAL 1)
    list(GET ARGN 0 argn0)
    set_property(GLOBAL PROPERTY "${name}" "${argn0}")
  endif()
endfunction()

picowota_property(PICOWOTA_IDLE_TIMEOUT_SEC "Seconds to wait for comms before loading application." 60)
picowota_property(PICOWOTA_WIFI_SSID "WiFi SSID")
picowota_property(PICOWOTA_WIFI_PASS "WiFI password")
picowota_property(PICOWOTA_WIFI_AP "Host WiFi AP")
picowota_property(PICOWOTA_OTA_PIN "Bootloader trigger GPIO")
picowota_property(PICOWOTA_BT_SPP "Enable BT SPP comms" false)
picowota_property(PICOWOTA_TCP "Enable TCP comms" false)
picowota_property(PICOWOTA_USB_CDC "Enable USB CDC comms" false)
picowota_property(PICOWOTA_CYW43_SIZE "CYW43 firmware section size (KiB)" 240)
picowota_property(PICOWOTA_BOOTLOADER_SIZE "Bootloader firmware section size (KiB)" 120)
picowota_property(PICOWOTA_APP_STORE_SIZE "Application storage section size (KiB)" 0)
# FUTURE WORK: default to 8 KiB in all cases. ideally we'd want 0 if no BT.
picowota_property(PICOWOTA_BT_STORE_SIZE "btstack storage section size (KiB)" 8)

# Following properties are internal/derived
#   PICOWOTA_WIFI       := PICOWOTA_TCP is defined
#   PICOWOTA_BLUETOOTH  := PICOWOTA_BT_SPP is defined

# defines a new picowota build w/ the name `name` and a client library with `${name}_client`
function(add_picowota name)
  set(SRC_DIR "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")

  function(target_cl_options)
    target_compile_options(${ARGN})
    target_link_options(${ARGN})
  endfunction()

  function(target_compile_def_prop target mode prop)
    target_compile_definitions("${name}" "${mode}"
      $<$<NOT:$<STREQUAL:$<TARGET_PROPERTY:${prop}>,>>:${prop}=$<TARGET_PROPERTY:${prop}>>)
  endfunction()

  # Define client library

  add_library("${name}_client" INTERFACE)

  target_include_directories("${name}_client" INTERFACE
    "${SRC_DIR}/picowota_client/include"
  )

  target_sources("${name}_client" INTERFACE
    "${SRC_DIR}/picowota_client/reboot.c"
  )

  target_link_libraries("${name}_client" INTERFACE
    cmsis_core
    hardware_structs
  )

  # `picowota` will pick up `picowota_client`'s INTERFACE definitions
  target_compile_definitions("${name}_client" INTERFACE
    "PICO_FLASH_BANK_TOTAL_SIZE=($<TARGET_PROPERTY:${name},PICOWOTA_BT_STORE_SIZE> * 1024)"
    # FIXME: This really sucks. It makes assumptions about max flash size.
    "PICO_FLASH_BANK_STORAGE_OFFSET=(2048 * 1024 - PICO_FLASH_BANK_TOTAL_SIZE)"
  )


  file(GLOB SRC_FILES_C LIST_DIRECTORIES false "${SRC_DIR}/*.c")

  add_executable("${name}"
    ${SRC_FILES_C}
    "${SRC_DIR}/dhcpserver/dhcpserver.c"
  )

  target_include_directories("${name}" PRIVATE
    "${SRC_DIR}" # Needed so that lwip can find lwipopts.h
    "${SRC_DIR}/dhcpserver"
  )

  target_cl_options("${name}" PRIVATE "-Wall" "-Os" "-ffunction-sections" "-fdata-sections")
  target_link_options("${name}" PRIVATE "LINKER:--gc-sections")

  target_link_libraries(
    "${name}"
    "${name}_client"
    boot_uf2_headers
    cmsis_core
    hardware_dma
    hardware_flash
    hardware_resets
    hardware_structs
    pico_stdlib
    pico_sync
    pico_time
    pico_util
    $<$<BOOL:$<TARGET_PROPERTY:PICOWOTA_BT_SPP>>:pico_btstack_classic>
    $<$<BOOL:$<TARGET_PROPERTY:PICOWOTA_TCP>>:pico_cyw43_arch_lwip_poll>
    $<$<BOOL:$<TARGET_PROPERTY:PICOWOTA_USB_CDC>>:pico_unique_id tinyusb_device>
  )

  if("${PICO_BOARD}" STREQUAL "pico_w")
    target_link_libraries("${name}"
      # app might be using the bluetooth firmware even if we aren't
      pico_btstack_cyw43
      pico_cyw43_arch_poll
      pico_cyw43_driver
    )
  endif()

  target_compile_def_prop("${name}" PUBLIC PICOWOTA_OTA_PIN)

  target_compile_definitions("${name}" PUBLIC
    "PICOWOTA_IDLE_TIMEOUT_SEC=$<TARGET_PROPERTY:PICOWOTA_IDLE_TIMEOUT_SEC>"
    "PICOWOTA_BT_SPP=$<BOOL:$<TARGET_PROPERTY:PICOWOTA_BT_SPP>>"
    "PICOWOTA_TCP=$<BOOL:$<TARGET_PROPERTY:PICOWOTA_TCP>>"
    "PICOWOTA_USB_CDC=$<BOOL:$<TARGET_PROPERTY:PICOWOTA_USB_CDC>>"
    "PICOWOTA_WIFI_AP=$<BOOL:$<TARGET_PROPERTY:PICOWOTA_WIFI_AP>>"
    "PICOWOTA_WIFI_SSID=$<TARGET_PROPERTY:PICOWOTA_WIFI_SSID>"
    "PICOWOTA_WIFI_PASS=$<TARGET_PROPERTY:PICOWOTA_WIFI_PASS>"
    "CYW43_LWIP=$<BOOL:$<TARGET_PROPERTY:PICOWOTA_TCP>>"
  )

  picowota_set_linker_defs("${name}" "${name}")
  picowota_share_cyw43_firmware("${name}")

  pico_set_linker_script("${name}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/bootloader_shell.ld")
  pico_set_binary_type("${name}" copy_to_ram)
  pico_add_extra_outputs("${name}")
  pico_enable_stdio_uart("${name}" 1)
endfunction()

# CWY43 drivers are very large. Can't fit them in RAM.
# Good news is that we don't need it after the chip is init'd.
# So long as the flash writes happen after that, we're okay.
function(picowota_share_cyw43_firmware target)
  target_compile_definitions(
    "${target}" PUBLIC "CYW43_RESOURCE_ATTRIBUTE=__attribute__((aligned(4), section(\".cyw43_firmware\")))"
  )
endfunction()

function(picowota_set_linker_defs target picowota)
  function(target_link_opt_4k linker_name prop)
    target_link_options("${target}" PUBLIC
      "LINKER:--defsym=${linker_name}=$<TARGET_PROPERTY:${picowota},${prop}>k")
  endfunction()

  target_link_opt_4k("cyw43_len" "PICOWOTA_CYW43_SIZE")
  target_link_opt_4k("bootloader_len" "PICOWOTA_BOOTLOADER_SIZE")
  target_link_opt_4k("app_store_len" "PICOWOTA_APP_STORE_SIZE")
  target_link_opt_4k("bt_store_len" "PICOWOTA_BT_STORE_SIZE")
endfunction()

function(picowota_app_store_declare target picowota)
  target_compile_definitions("${target}" PUBLIC "PICOWOTA_APP_STORE_SIZE=($<TARGET_PROPERTY:${picowota},PICOWOTA_APP_STORE_SIZE> * 1024)")
endfunction()

function(picowota_build_no_bootloader_with_app_store target picowota)
  pico_set_linker_script("${target}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/memmap_default_with_app_store.ld")
  target_link_options("${target}" PUBLIC
    "LINKER:--defsym=app_store_len=$<TARGET_PROPERTY:${picowota},PICOWOTA_APP_STORE_SIZE>k"
    "LINKER:--defsym=bt_store_len=$<TARGET_PROPERTY:${picowota},PICOWOTA_BT_STORE_SIZE>k"
  )
  picowota_app_store_declare("${target}" "${picowota}")
endfunction()

function(picowota_build_standalone target picowota)
  picowota_share_cyw43_firmware("${target}")
  picowota_app_store_declare("${target}" "${picowota}")
  picowota_set_linker_defs("${target}" "${picowota}")
  pico_set_linker_script("${target}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/standalone.ld")
endfunction()

# Provide a helper to build a combined target
# The build process is roughly:
# 1. Build the bootloader, using a special linker script which leaves
# two sections to be filled in with the header (.app_hdr) and
# app binary (.app_bin)
# 2. Build the app binary, using a special linker script to set the load
# address properly and skip boot2.
# 3. Calculate the checksum of the app binary
# 4. Update the header and binary sections in the ELF from 1.
function(picowota_build_combined target picowota)
  set(wota_output_name $<IF:$<STREQUAL:$<TARGET_PROPERTY:${picowota},OUTPUT_NAME>,>,$<TARGET_PROPERTY:${picowota},NAME>,$<TARGET_PROPERTY:${picowota},OUTPUT_NAME>>)
  set(app_output_name  $<IF:$<STREQUAL:$<TARGET_PROPERTY:${target},OUTPUT_NAME>,>,$<TARGET_PROPERTY:${target},NAME>,$<TARGET_PROPERTY:${target},OUTPUT_NAME>>)
  set(app_bin_name    "${app_output_name}_without-cyw43-firmware-section.bin")
  set(app_bin         "$<TARGET_PROPERTY:${picowota},BINARY_DIR>/${app_bin_name}")
  set(app_hdr_bin     "$<TARGET_PROPERTY:${picowota},BINARY_DIR>/${app_output_name}_hdr.bin")
  set(combined        "${picowota}_${target}")
  set(combined_output "${picowota}_${app_output_name}")

  # need a custom bin, one w/o the shared firmware
  add_custom_command(
    TARGET "${target}"
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY}
      "--remove-section" ".cyw43_firmware"
      "--output-target" "binary" "$<TARGET_FILE:${target}>"
      "${app_bin}"
    VERBATIM
  )

  # The app must be built with the correct linker script (and a .bin)
  picowota_build_standalone("${target}" "${picowota}")

  add_custom_target("${target}_hdr" DEPENDS "${target}")

  # TODO: The hard-coded base address here is a bit nasty
  # default entry point is the beginning of the app image
  # i.e. bootloader + CYW43 + app header
  add_custom_command(
    TARGET  "${target}_hdr"
    DEPENDS "${app_bin}"
    COMMAND "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/gen_imghdr.py"
      --addr-base   0x10000000
      --boot-size   "$<TARGET_PROPERTY:${picowota},PICOWOTA_BOOTLOADER_SIZE>"
      --cyw43-size  "$<TARGET_PROPERTY:${picowota},PICOWOTA_CYW43_SIZE>"
      "${app_bin}"
      "${app_hdr_bin}"
  )

  add_custom_target("${combined}" ALL)
  add_dependencies("${combined}" "${picowota}" "${target}_hdr" "${target}")
  add_custom_command(
    TARGET  "${combined}"
    DEPENDS "${app_hdr_bin}" "${app_bin}"
    COMMAND ${CMAKE_OBJCOPY}
        --update-section ".app_hdr=${app_hdr_bin}"
        --update-section ".app_bin=${app_bin}"
        "$<TARGET_PROPERTY:${picowota},BINARY_DIR>/${wota_output_name}.elf"
        "${combined_output}.elf"
  )
  add_custom_command(
    TARGET "${combined}"
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -Obinary "${combined_output}.elf" "${combined_output}.bin"
  )

  if(NOT ELF2UF2_FOUND)
    set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${PICO_SDK_PATH}/tools")
    find_package(ELF2UF2)
  endif()

  if(ELF2UF2_FOUND)
    add_custom_command(
      TARGET "${combined}"
      POST_BUILD
      COMMAND ELF2UF2 "${combined_output}.elf" "${combined_output}.uf2"
    )
  endif()
endfunction()
