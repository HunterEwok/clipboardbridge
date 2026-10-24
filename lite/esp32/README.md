# The lite member on the Arduino Nano ESP32

Firmware for the [Arduino Nano ESP32](https://docs.arduino.cc/hardware/nano-esp32/) (an
ESP32-S3), written in Rust on the same protocol core as `cbb-lite` (`lite/core`), with
the member TLS 1.3 on the chip itself (docs/roadmap.md, item 15).

This first step is a self-test only. It makes two keys and self-signed certificates with
the chip's true random number generator (fed by the ADC's noise), runs a pairing TLS 1.3
handshake between them in memory, passes a message and checks that both ends export the
same key. Wi-Fi, storage in flash, joining a group, syncing and typing over USB come next.
It is not yet run on a real board.

## Build

The ESP32-S3 is an Xtensa chip, which needs Espressif's Rust toolchain:
[espup](https://github.com/esp-rs/espup) installs it as `esp`, or take the 1.99.0.0
release of [esp-rs/rust-build](https://github.com/esp-rs/rust-build) as CI does. The
firmware links with `rust-lld`, so no GCC is needed.

```sh
cd lite/esp32
cargo +esp build --release
espflash flash --monitor target/xtensa-esp32s3-none-elf/release/cbb-esp32
```

[espflash](https://github.com/esp-rs/espflash) writes it over the board's USB-C port. The
log appears on the same port.

esp-hal and its crates come from a fixed commit of their git repository. Rust 1.99 no
longer keeps the order of `global_asm!` blocks, which breaks esp-hal 1.2.2's start-up code
for the S3 (it does not link). The fix (esp-hal #6497) is in that commit but not yet in a
release. Move back to crates.io once a release carries it.

## Test in QEMU

```sh
QEMU=path/to/qemu-system-xtensa ESPFLASH=path/to/espflash ./qemu-test.sh
```

The script builds with the `qemu` feature, writes a flash image and boots it in
[Espressif's QEMU](https://github.com/espressif/qemu) (machine `esp32s3`), then waits for
the self-test's result. That build skips esp-hal's init, because QEMU does not emulate the
clock calibration it waits for, and without init the chip's generator does not work. So
it uses a fixed pseudo-random sequence instead: its keys are not secret, and it says so
when it starts. Never flash the `qemu` build to a board.
