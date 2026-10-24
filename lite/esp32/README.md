# The lite member on the Arduino Nano ESP32

Firmware for the [Arduino Nano ESP32](https://docs.arduino.cc/hardware/nano-esp32/) (an
ESP32-S3), written in Rust on the same protocol core as the lite member on Linux (`lite/core`), with
the member TLS 1.3 on the chip itself (docs/roadmap.md, item 15).

So far the board keeps its settings in flash, joins the Wi-Fi network set on its console
and takes an address by DHCP, joins a group by the phone, and runs a self-test of the
protocol core: it makes two keys
and self-signed certificates with the chip's true random number generator (fed by the
ADC's noise), runs a pairing TLS 1.3 handshake between them in memory, passes a message
and checks that both ends export the same key. Syncing (which needs the time of day, from
SNTP) and typing over USB come next. It is not yet run on a real board.

## Build and flash

The ESP32-S3 is an Xtensa chip, which needs Espressif's Rust toolchain:
[espup](https://github.com/esp-rs/espup) installs it as `esp`, or take the 1.99.0.0
release of [esp-rs/rust-build](https://github.com/esp-rs/rust-build) as CI does. The
firmware links with `rust-lld`, so no GCC is needed.

```sh
cd lite/esp32
cargo +esp run --release
```

`cargo run` builds and hands the firmware to
[espflash](https://github.com/esp-rs/espflash), which writes it with the partition table
`partitions.csv` over the board's USB-C port and then opens the console. Without cargo:

```sh
espflash flash --monitor --chip esp32s3 --partition-table partitions.csv \
  target/xtensa-esp32s3-none-elf/release/cbb-esp32
```

The partition table matters: the settings live in its partition `cbb`. A board flashed
without it says so on the console and keeps the Wi-Fi network only until it restarts.

esp-hal and its crates come from a fixed commit of their git repository. Rust 1.99 no
longer keeps the order of `global_asm!` blocks, which breaks esp-hal 1.2.2's start-up code
for the S3 (it does not link). The fix (esp-hal #6497) is in that commit but not yet in a
release. Move back to crates.io once a release carries it.

## The console

The board's USB port is a serial port; type on it in espflash's monitor (`espflash
monitor`) or any serial terminal. The board echoes what is typed and shows stars for a
password.

```text
cbb> wifi
Wi-Fi network name: Home
Password (empty for an open network): ********
Saved. Joining Home.
cbb-esp32: joined Home
cbb-esp32: address 192.168.0.57/24
cbb> status
  firmware: cbb-esp32 0.1.0
  Wi-Fi network: Home
  network: joined Home, address 192.168.0.57/24
  error details: off
```

| Command | What it does |
| --- | --- |
| `status` | what the board knows and how its network is doing |
| `wifi` | sets the Wi-Fi network to join: asks for its name and password, saves them and joins it |
| `wifi forget` | leaves the Wi-Fi network and forgets it |
| `join [NAME]` | joins a group by the phone, under NAME (default: Nano ESP32): see below |
| `leave` | forgets the group; remove the board in the app too, so the group revokes it |
| `debug on`, `debug off` | shows the details of errors under their message, or not; saved in flash. Without it a debug build shows them and a release build does not |
| `selftest` | runs the TLS 1.3 self-test |

The board joins WPA2 networks (and WPA2/WPA3 mixed ones), or open ones with an empty password; it joins
again after the connection drops.

## Joining a group

Once the board has an address, type `join`. It prints a `clipboardbridge://join?...` link
with a new pairing code, its address and port 8764 and the fingerprint of its pairing
certificate; in the app, tap "Connect a new device" and paste it. The phone dials the
board, and the two run the pairing of docs/protocol.md over TLS 1.3 (`lite/embassy`, the
same exchange as the lite member's `cbb join`, with the core's `Joiner`). The phone proves the code
first; three wrong codes, or five minutes without a phone, end the attempt. The board
takes connections from private addresses only. It saves the identity the phone's Welcome
gives it, as a lite member without CA keys, and `status` shows the group.

The board announces itself as a Linux lite member: the pairing knows only Linux and macOS
as systems so far. A QR code drawn on the console, so the phone can scan the terminal, may
follow.

## Settings in flash

The partition `cbb` (64 KB) holds two slots. A save goes to the slot that does not hold the
newest copy, and each copy ends with its SHA-256, so a power cut while saving keeps the
last good copy (`cbb_core::store`, with its tests on the host).

The flash is not encrypted: whoever holds the board can read the Wi-Fi password and the
member's key from it. The ESP32-S3 could encrypt its flash, but that burns eFuses for
good, so it is not done yet. Removing the board from the group revokes its certificate,
as for any lost device.

## Test in QEMU

```sh
QEMU=path/to/qemu-system-xtensa ESPFLASH=path/to/espflash ./qemu-test.sh
```

The script builds with the `qemu` feature, writes a flash image with the partition table,
and `qemu-test.py` boots it in [Espressif's QEMU](https://github.com/espressif/qemu)
(machine `esp32s3`) three times, typing on the console over UART0: it checks that `join`
says the build has no network, sets a Wi-Fi network and debug mode, runs the self-test, checks that both are still there after a restart,
forgets the network and checks that it stays forgotten.

That build has no Wi-Fi (QEMU does not emulate the S3's radio) and skips esp-hal's init,
because QEMU does not emulate the clock calibration it waits for; without init the chip's
generator does not work, so it uses a fixed pseudo-random sequence instead: its keys are
not secret, and it says so when it starts. Never flash the `qemu` build to a board.

## Test the network code on Linux

The pairing lives in the crate [`lite/embassy`](../embassy), on embassy-net and nothing of
the chip. Its feature `host` builds `esp32-on-linux`, which runs the same code on Linux:
embassy-net over a TAP interface with a fixed address takes the place of the Wi-Fi and
DHCP, and `esp32-on-linux` joins a group by the phone as the board's `join` does. The Go test
`TestEmbassyJoiner` plays the phone and has a Go member admit it (CONTRIBUTING.md, "The
other parts", has the commands; CI's `lite` job runs it). Only the Wi-Fi driver and the
flash stay for a real board.
