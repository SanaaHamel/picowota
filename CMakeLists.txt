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

cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(picowota C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(NOT DEFINED PICO_BOARD)
	set(PICO_BOARD pico_w)
endif()

pico_sdk_init()

add_executable(picowota
	main.c
	comm_bt_spp.c
	comm_stream.c
	comm_tcp.c
	dhcpserver/dhcpserver.c
)

function(target_cl_options option)
	target_compile_options(picowota PRIVATE ${option})
	target_link_options(picowota PRIVATE ${option})
endfunction()

target_cl_options("-Wall")
target_cl_options("-Os")
target_cl_options("-ffunction-sections")
target_cl_options("-fdata-sections")
target_link_options(picowota PRIVATE "LINKER:--gc-sections")

# CWY43 drivers are very large. Can't fit them in RAM.
# Good news is that we don't need it after the chip is init'd.
# So long as the flash writes happen after that, we're okay.
function(picowota_share_cyw43_firmware NAME)
	target_compile_definitions(${NAME} PUBLIC "CYW43_RESOURCE_ATTRIBUTE=__attribute__((aligned(4), section(\".cyw43_firmware\")))")
endfunction()

picowota_share_cyw43_firmware(picowota)
pico_set_binary_type(picowota copy_to_ram)
get_target_property(PICOWOTA_SRC_DIR picowota SOURCE_DIR)
pico_set_linker_script(picowota ${PICOWOTA_SRC_DIR}/bootloader_shell.ld)

pico_add_extra_outputs(picowota)

target_include_directories(picowota PRIVATE
	${CMAKE_CURRENT_LIST_DIR} # Needed so that lwip can find lwipopts.h
	${CMAKE_CURRENT_LIST_DIR}/dhcpserver)

# pico_enable_stdio_usb(picowota 1)
pico_enable_stdio_uart(picowota 1)

add_subdirectory(picowota_client)

target_link_libraries(picowota
	boot_uf2_headers
	cmsis_core
	hardware_dma
	hardware_flash
	hardware_resets
	hardware_structs
	pico_cyw43_arch_poll
	pico_stdlib
	pico_sync
	pico_time
	pico_util
	picowota_client
)

# causes the the bluetooth firmware to be linked in.
# required b/c the app might be using the bluetooth firmware even if we aren't
target_link_libraries(picowota pico_btstack_hci_transport_cyw43)

# Retrieves build variables from the environment if present
function(picowota_retrieve_variable name hidden)
	if(DEFINED ENV{${name}} AND(NOT ${name}))
		# HACK: `CACHE` so that it's visible in all scopes. same thing below.
		# FIXME: This is fucking awful, will interact badly with default values
		# changing and cached env vars, but I'm not being paid for this
		# so whatever works.
		set(${name} $ENV{${name}} CACHE INTERNAL "" FORCE)
		set(found_value true)

		if(hidden)
			set(log_value "hidden")
		else()
			set(log_value "'$ENV{${name}}'")
		endif()

		message("Using ${name} from environment (${log_value})")
	endif()

	set(argn ${ARGN})
	list(LENGTH argn argc)

	if(${argc} EQUAL 1)
		if(NOT DEFINED ${name} AND NOT DEFINED found_value)
			list(GET argn 0 argn0)

			# HACK: this `CACHE` is trash. see above.
			set(${name} ${argn0} CACHE INTERNAL "" FORCE)
		endif()
	elseif(${argc} GREATER 1)
		message(FATAL_ERROR "too many extra arguments")
	endif()
endfunction()

picowota_retrieve_variable(PICOWOTA_IDLE_TIMEOUT_SEC false 60)
picowota_retrieve_variable(PICOWOTA_WIFI_SSID false)
picowota_retrieve_variable(PICOWOTA_WIFI_PASS true)
picowota_retrieve_variable(PICOWOTA_WIFI_AP false)
picowota_retrieve_variable(PICOWOTA_OTA_PIN false)
picowota_retrieve_variable(PICOWOTA_BT_SPP false 0)
picowota_retrieve_variable(PICOWOTA_TCP false 1)
picowota_retrieve_variable(PICOWOTA_CYW43_SIZE false "240") # in KiB
picowota_retrieve_variable(PICOWOTA_BOOTLOADER_SIZE false "120") # in KiB
picowota_retrieve_variable(PICOWOTA_APP_STORE_SIZE false "0") # in KiB

# If any transport requires WiFi, add it here.
if(PICOWOTA_TCP)
	set(PICOWOTA_WIFI 1)
else()
	set(PICOWOTA_WIFI 0)
endif()

# If any transport requires Bluetooth classic add it here
if(PICOWOTA_BT_SPP)
	set(PICOWOTA_BLUETOOTH_CLASSIC 1)
else()
	set(PICOWOTA_BLUETOOTH_CLASSIC 0)
endif()

# If any transport requires Bluetooth classic add it here
set(PICOWOTA_BLUETOOTH_LE 0)

if(PICOWOTA_BLUETOOTH_CLASSIC OR PICOWOTA_BLUETOOTH_LE)
	set(PICOWOTA_BLUETOOTH 1)
else()
	set(PICOWOTA_BLUETOOTH 0)
endif()

if(NOT(0 LESS PICOWOTA_IDLE_TIMEOUT_SEC))
	message(FATAL_ERROR "`PICOWOTA_IDLE_TIMEOUT_SEC` must be > 0")
endif()

function(assert_4k_aligned NAME)
	math(EXPR remainder "${${NAME}} % 4")

	if(NOT(remainder EQUAL 0))
		message(FATAL_ERROR "`${NAME}` must be 4 KiB aligned")
	endif()
endfunction()

assert_4k_aligned("PICOWOTA_CYW43_SIZE")
assert_4k_aligned("PICOWOTA_BOOTLOADER_SIZE")
assert_4k_aligned("PICOWOTA_APP_STORE_SIZE")

target_compile_definitions(picowota PUBLIC PICOWOTA_BLUETOOTH=${PICOWOTA_BLUETOOTH})
target_compile_definitions(picowota PUBLIC PICOWOTA_BT_SPP=${PICOWOTA_BT_SPP})
target_compile_definitions(picowota PUBLIC PICOWOTA_IDLE_TIMEOUT_SEC=${PICOWOTA_IDLE_TIMEOUT_SEC})
target_compile_definitions(picowota PUBLIC PICOWOTA_TCP=${PICOWOTA_TCP})
target_compile_definitions(picowota PUBLIC PICOWOTA_WIFI=${PICOWOTA_WIFI})
target_compile_definitions(picowota PUBLIC CYW43_LWIP=${PICOWOTA_WIFI})

function(picowota_set_linker_defs NAME)
	target_link_options(${NAME} PUBLIC "LINKER:--defsym=cyw43_len=${PICOWOTA_CYW43_SIZE}k")
	target_link_options(${NAME} PUBLIC "LINKER:--defsym=bootloader_len=${PICOWOTA_BOOTLOADER_SIZE}k")
	target_link_options(${NAME} PUBLIC "LINKER:--defsym=app_store_len=${PICOWOTA_APP_STORE_SIZE}k")
endfunction()

picowota_set_linker_defs(picowota)

if(PICOWOTA_WIFI)
	if((NOT PICOWOTA_WIFI_SSID) OR(NOT PICOWOTA_WIFI_PASS))
		message(FATAL_ERROR
			"WiFi SSID/Pass not set, please set PICOWOTA_WIFI_SSID/PICOWOTA_WIFI_PASS."
		)
	endif()

	# TODO: This causes a full rebuild if they change, configure_file might
	# be better.
	target_compile_definitions(picowota PUBLIC PICOWOTA_WIFI_SSID=${PICOWOTA_WIFI_SSID})
	target_compile_definitions(picowota PUBLIC PICOWOTA_WIFI_PASS=${PICOWOTA_WIFI_PASS})

	target_link_libraries(picowota pico_cyw43_arch_lwip_poll)

	# Use the WiFi AP mode upon request
	if(PICOWOTA_WIFI_AP)
		target_compile_definitions(picowota PUBLIC PICOWOTA_WIFI_AP=1)
		message("Building in WiFi AP mode.")
	endif()
endif()

if(DEFINED PICOWOTA_OTA_PIN)
	target_compile_definitions(picowota PUBLIC PICOWOTA_OTA_PIN=${PICOWOTA_OTA_PIN})
endif()

if(PICOWOTA_BLUETOOTH_CLASSIC)
	target_link_libraries(picowota pico_btstack_cyw43 pico_btstack_classic)
endif()

if(PICOWOTA_BLUETOOTH_LE)
	target_link_libraries(picowota pico_btstack_cyw43 pico_btstack_le)
endif()

function(picowota_app_store_declare NAME)
	math(EXPR in_bytes "${PICOWOTA_APP_STORE_SIZE} * 1024" OUTPUT_FORMAT HEXADECIMAL)
	target_compile_definitions(${NAME} PUBLIC PICOWOTA_APP_STORE_SIZE=${in_bytes})
endfunction()

function(picowota_build_no_bootloader_with_app_store NAME)
	get_target_property(PICOWOTA_SRC_DIR picowota SOURCE_DIR)
	pico_set_linker_script(${NAME} ${PICOWOTA_SRC_DIR}/memmap_default_with_app_store.ld)
	target_link_options(${NAME} PUBLIC "LINKER:--defsym=app_store_len=${PICOWOTA_APP_STORE_SIZE}k")
	picowota_app_store_declare(${NAME})
endfunction()

# Provide a helper to build a standalone target
function(picowota_build_standalone NAME)
	picowota_app_store_declare(${NAME})
	picowota_share_cyw43_firmware(${NAME})
	get_target_property(PICOWOTA_SRC_DIR picowota SOURCE_DIR)
	pico_set_linker_script(${NAME} ${PICOWOTA_SRC_DIR}/standalone.ld)
	picowota_set_linker_defs(${NAME})
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
function(picowota_build_combined NAME)
	set(APP_BIN_NAME $<IF:$<BOOL:$<TARGET_PROPERTY:${NAME},OUTPUT_NAME>>,$<TARGET_PROPERTY:${NAME},OUTPUT_NAME>,$<TARGET_PROPERTY:${NAME},NAME>>_without-cyw43-firmware-section.bin)
	set(APP_BIN ${CMAKE_CURRENT_BINARY_DIR}/${APP_BIN_NAME})
	set(APP_HDR_BIN ${CMAKE_CURRENT_BINARY_DIR}/${NAME}_hdr.bin)
	set(COMBINED picowota_${NAME})
	get_target_property(PICOWOTA_SRC_DIR picowota SOURCE_DIR)
	get_target_property(PICOWOTA_BIN_DIR picowota BINARY_DIR)

	# need a custom bin, one w/o the shared firmware
	add_custom_command(TARGET ${NAME} POST_BUILD COMMAND ${CMAKE_OBJCOPY}
		"--remove-section" ".cyw43_firmware"
		"--output-target" "binary"
		$<TARGET_FILE:${NAME}>
		${APP_BIN}
		VERBATIM)

	# The app must be built with the correct linker script (and a .bin)
	picowota_build_standalone(${NAME})

	# TODO: The hard-coded address here is a bit nasty
	add_custom_target(${NAME}_hdr DEPENDS ${NAME})

	# default entry point is the beginning of the app image
	# i.e. bootloader + CYW43 + app header + app storage
	math(EXPR header_vtor "0x10000000 + (${PICOWOTA_BOOTLOADER_SIZE} + ${PICOWOTA_CYW43_SIZE} + 4) * 1024" OUTPUT_FORMAT HEXADECIMAL)
	message("${NAME} hdr vtor ${header_vtor}")
	add_custom_command(TARGET ${NAME}_hdr DEPENDS ${APP_BIN}
		COMMAND ${PICOWOTA_SRC_DIR}/gen_imghdr.py -a ${header_vtor} ${APP_BIN} ${APP_HDR_BIN}
	)

	add_custom_target(${COMBINED} ALL)
	add_dependencies(${COMBINED} picowota ${NAME}_hdr ${NAME})
	add_custom_command(TARGET ${COMBINED} DEPENDS ${APP_HDR_BIN} ${APP_BIN}
		COMMAND ${CMAKE_OBJCOPY}
		--update-section .app_hdr=${APP_HDR_BIN}
		--update-section .app_bin=${APP_BIN} ${PICOWOTA_BIN_DIR}/picowota.elf ${COMBINED}.elf
	)

	add_custom_command(TARGET ${COMBINED} POST_BUILD
		COMMAND ${CMAKE_OBJCOPY} -Obinary ${COMBINED}.elf ${COMBINED}.bin
	)

	if(NOT ELF2UF2_FOUND)
		set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PICO_SDK_PATH}/tools)
		find_package(ELF2UF2)
	endif()

	if(ELF2UF2_FOUND)
		add_custom_command(TARGET ${COMBINED} POST_BUILD
			COMMAND ELF2UF2 ${COMBINED}.elf ${COMBINED}.uf2
		)
	endif()
endfunction()
