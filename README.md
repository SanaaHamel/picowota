# `picowota` - Raspberry Pi Pico W OTA bootloader

> `picowota`, kinda sounds like you're speaking [Belter](https://expanse.fandom.com/wiki/Belter)

WARNING: This project is intended for low security applications. There is no authentication, cryptographic verification, or downgrade protection.

This project implements a bootloader for the Raspberry Pi Pico W which allows
updating both the bootloader and the application over WiFi or BlueTooth Classic ("Over The Air").

This fork has significantly diverged from @usedbytes 's version.

The easiest way to use it is to include this repository as a submodule in the
application which you want to be able to update over WiFi.

There's an example project using picowota at https://github.com/usedbytes/picowota_blink

## New Features Compared (Rel. to @usedbytes 's original)

* updating bootloader
* updating over BlueTooth
* lazy updating
* shared CYW43 firmware (saves ~300kb)
* reboot on idle timeout

Shared firmware is enabled for all targets marked with
`picowota_build_standalone` or `picowota_build_combined`, but if the build is
more complex you can explicitly enable it by adding
`picowota_share_cyw43_firmware(nevermore-controller)` to `CMakeList.txt`.

Note: This sets `CYW43_RESOURCE_ATTRIBUTE`.

## Using in your project

First add `picowota` as a submodule to your project:
```
git submodule add https://github.com/usedbytes/picowota
git submodule update --init picowota
git commit -m "Add picowota submodule"
```

Then modifiy your project's CMakeLists.txt to include the `picowota` directory:

```
add_subdirectory(picowota)
```

You can either provide the following as environment variables, or set them
as CMake variables:

```
PICOWOTA_WIFI_SSID # The WiFi network SSID
PICOWOTA_WIFI_PASS # The WiFi network password
PICOWOTA_WIFI_AP # Optional; 0 = connect to the network, 1 = create it
PICOWOTA_OTA_PIN # Optional; if set, pulling this pin low at boot time will stay in OTA mode
PICOWOTA_TCP # Optional; allow upload over TCP. 0 = disabled; default = 1
PICOWOTA_BT_SPP # Optional; allow upload over Bluetooth SPP. 0 = disabled; default = 0
PICOWOTA_IDLE_TIMEOUT_SEC # Optional; how long to wait before reboot; default = 60
```

If TCP transport is enabled then `picowota` either connects to an existing WiFi
network (by default) or creates one, in both cases with the given SSID and
password.

Then, you can either build just your standalone app binary (suitable for
updating via `picowota` when it's already on the Pico), or a combined binary
which contains the bootloader and the app (suitable for flashing the first
time):

```
picowota_build_standalone(my_executable_name)
picowota_build_combined(my_executable_name)
```

Note: The combined target will also build the standalone binary.
Note: With bootloader updating you might as well just distribute the combined build.

To be able to update your app, you must provide a way to return to the
bootloader. If `PICOWOTA_OTA_PIN` is defined and that GPIO is pulled low at boot
time, then `picowota` will stay in bootloader mode, ready to receive new app code.

You can also return to the bootloader from your app code - for example when a
button is pressed, or in response to some network request. The
`picowota_reboot` library provides a `picowota_reboot(bool to_bootloader)`
function, which your app can call to get back in to the bootloader.

```
CMakeLists.txt:

target_link_libraries(my_executable_name picowota_reboot)

your_c_code.c:

#include "picowota/reboot.h"

...

{

	...

	if (should_reboot_to_bootloader) {
		picowota_reboot(true);
	}

	...

}
```

## Uploading code via `picowota`

Once you've got the `picowota` bootloader installed on your Pico, you can use
https://github.com/SanaaHamel/serial-flash-py tool to upload code to it.
(The original tool, https://github.com/usedbytes/serial-flash, will *not* work,
but serial-flash-py is backwards compatible.)

As long as the Pico is "in" the `picowota` bootloader (i.e. because there's no
valid app code uploaded yet, or your app called `picowota_reboot(true);`), you
can upload an app `.elf` or `.uf2` file which was built by `picowota_build_standalone()`:

If using the AP mode, the Pico's IP address will be (at the time of writing)
192.168.4.1/24, and the connected device's something in the same subnet.
Otherwise it depends on your network settings.

(Assuming your Pico's IP address is 192.168.1.123):
```
serial-flash tcp:192.168.1.123:4242 my_executable_name.elf
```

After uploading the code, if successful, the Pico will jump to the newly
uploaded app.

## How it works

This is derived from my Pico non-W bootloader, https://github.com/usedbytes/rp2040-serial-bootloader, which I wrote about in a blog post: https://blog.usedbytes.com/2021/12/pico-serial-bootloader/

The bootloader code attempts to avoid "bricking" by storing a CRC of the app
code which gets uploaded. If the CRC doesn't match, then the app won't get run
and the Pico will stay in `picowota` bootloader mode. This should make it fairly
robust against errors in transfers etc.

## Known issues

* No authentication
* No cryptographic verification of image (integrity *is* verified)
* No downgrade prevention
