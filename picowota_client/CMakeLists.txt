add_library(picowota_client INTERFACE)

target_include_directories(picowota_client INTERFACE
	${CMAKE_CURRENT_LIST_DIR}/include
)

target_sources(picowota_client INTERFACE
	${CMAKE_CURRENT_LIST_DIR}/reboot.c
)

target_link_libraries(picowota_client INTERFACE
	cmsis_core
	hardware_structs
)
