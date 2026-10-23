# cbb-lite: the lite member

`cbb-lite` is a small clipboardbridge member in Rust for weak Linux devices: a Raspberry
Pi, a router, a small board. It speaks the member protocol of
[docs/protocol.md](../docs/protocol.md), but unlike `cbb` it

- never holds CA keys, so it never admits devices;
- dials the computers (found by mDNS, or named with `-peer`), and publishes itself in mDNS
  and listens on the member port, TCP 8764, so that phones, Macs and other lite members
  dial it: a phone syncs with it directly, with no computer on;
- never holds `clipboardbridge.local` or serves the shortcut, the Apple Shortcuts action an
  iPhone without the app uses (a phone with the app, iPhone or Android, needs neither);
- has no desktop clipboard of its own: other programs use `copy`, `paste` and `watch`.

Full members list it with role `lite`. Sync away from home, through the group's WireGuard
tunnel to the hub ("Sync away from home" in [docs/design.md](../docs/design.md)), is not
built into `cbb-lite` yet: for a device on another subnet, where mDNS does not reach, name a
computer there with `-peer`.

The protocol core is its own crate, [`core`](core) (`cbb_core`): certificates, records,
the hybrid clock, the sync engine, the frames and the joiner's side of the pairing, with
CPace in `core/src/third_party/cpace`. It does no I/O and needs no operating system
(no_std with alloc; RustCrypto for P-256, SHA-2 and HMAC), so a lite member on the ESP32
can use it as it is. On a microcontroller the firmware supplies the randomness, as
getrandom's custom backend (`__getrandom_v03_custom`), and the core's locks are spin
locks; with the `std` feature, as `cbb-lite` uses it, they are the standard library's.

With the `tls` feature the core has the TLS of members and pairing too (`core/src/tls`):
rustls through its unbuffered API, which needs no standard library, with a crypto
provider of RustCrypto code (TLS 1.3 only, ChaCha20-Poly1305 or AES-128-GCM, X25519,
ECDSA P-256), the certificate checks, a `Session` that does no I/O (the caller moves the
bytes) and the pairing's TLS exporter, which rustls offers only with std: the core takes
the exporter secret from the connection's key log and derives the exporter itself
(RFC 8446, section 7.5). `cbb-lite` runs on exactly this code, so the e2e test below
checks the TLS a microcontroller would use against Go members.
`cbb-lite` itself (`src`) adds the state files, the sockets, mDNS, the control socket and
the service.

## Build

With Rust 1.85 or later:

```sh
cd lite
cargo build --release          # target/release/cbb-lite
cargo test --workspace         # unit tests and the vectors in ../testdata/interop
```

The core alone, with its TLS, for a RISC-V microcontroller such as the ESP32-C6
(`rustup target add riscv32imac-unknown-none-elf`; `.cargo/config.toml` sets getrandom's
backend):

```sh
cargo build -p clipboardbridge-core --features tls --release --target riscv32imac-unknown-none-elf
```

For the ESP32-S3 (Xtensa) with Espressif's Rust toolchain (`espup install`, or the
`esp32` job in `.github/workflows/ci.yml`, which fetches the same toolchain directly):

```sh
cargo +esp build -Zbuild-std=core,alloc -p clipboardbridge-core --features tls --release \
  --target xtensa-esp32s3-none-elf
```

For a Raspberry Pi (64-bit Raspberry Pi OS or Debian) from an x86 Linux machine:

```sh
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

For a Raspberry Pi Zero, Zero W or Pi 1 (ARMv6, 32-bit Raspberry Pi OS): a static binary,
all Rust, with no cross toolchain (`.cargo/config.toml` holds the settings):

```sh
rustup target add arm-unknown-linux-musleabihf
cargo build --release --target arm-unknown-linux-musleabihf
```

CI builds both for every pull request: the `cbb-lite-linux-arm64` and `cbb-lite-linux-armv6`
artifacts of the `lite member (Rust)` job.

The e2e test runs the lite member among Go members: it joins through the phone's QR code,
gets no CA keys and syncs both ways.

```sh
cd .. && CBB_LITE=$PWD/lite/target/release/cbb-lite go test ./internal/service -run TestLiteMember -v
```

## Install

```sh
sudo install -m 0755 cbb-lite /usr/local/bin/
sudo install -m 0644 packaging/cbb-lite.sysusers /usr/lib/sysusers.d/cbb-lite.conf
sudo systemd-sysusers
sudo install -d -o cbb-lite -g cbb-lite -m 0700 /var/lib/cbb-lite
sudo install -m 0644 packaging/cbb-lite.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cbb-lite
```

The service waits until the device joins a group. Join as the service's user, so that it
can read its keys:

```sh
sudo -u cbb-lite cbb-lite join -name pi
```

It shows a QR code: in the clipboardbridge app (iPhone or Android) tap "Connect a new device"
(or, on an iPhone with the shortcut, run "clipboardbridge: add a computer") and scan it. The phone reaches the device on
TCP port 8764 (`-port` to change it), while it joins and afterwards to sync; open that port
from the home network if a firewall drops it. In a group without a phone, run `cbb pair` on a Linux member and
`sudo -u cbb-lite cbb-lite join -code <that member>:8764` here, then type the code.

Add yourself to the `cbb-lite` group to use the control socket without `sudo`:

```sh
sudo usermod -aG cbb-lite "$USER"   # then log in again
echo hello | cbb-lite copy          # -secret for a password: the group keeps it 60 s
cbb-lite paste
cbb-lite status
cbb-lite devices
cbb-lite watch                      # one line per text the group sends here
```

Without mDNS on the network, name the full members: edit the unit's `ExecStart` to
`/usr/local/bin/cbb-lite run -peer 192.168.0.10:8764 -peer ...`. `run -port` moves the
member port, `-no-listen` turns it off (the device then only dials the computers).

## ZX Spectrum Next

On the Accelerated ZX Spectrum Next, `cbb-lite` runs on the Raspberry Pi wired to the
Next's second UART (docs/design.md, roadmap item 14), and the Next's `.cbb` dot command
types `cbb-lite next ...` at NextPi's shell (`SUP>`) on that UART, as NextPi's own tools
do. These commands answer in frames a Z80 reads without a parser:

- Every line ends in CR (13). Every answer ends in one status line: `CBBOK`, or
  `CBBERR <message>` in printable ASCII (with the cause after it in debug mode). Lines that
  start with `CBB#` are notes to skip.
- Texts are in the Spectrum character set: printable ASCII, CR for a new line, the pound
  sign at 0x60 and the copyright sign at 0x7F. Every other character becomes `?` on the way
  to the Next (the backtick too); from the Next, block graphics, UDGs and BASIC tokens
  become `?` and CR LF is one new line. Cyrillic comes later.
- CRC-32 is IEEE 802.3, as zlib and PiTools' `.crc32` compute it, in 8 lowercase hex
  digits.

| Command | Answer |
| --- | --- |
| `cbb-lite next paste [-max bytes]` | `CBB1 <len> <crc32>`, then len bytes of the latest text (cut to bytes), then CR, then the status line. |
| `cbb-lite next copy <len> <crc32>` | `CBBGO` once the service answers; the Next then sends exactly len bytes, which `cbb-lite` reads with the terminal in raw mode (no echo, no CR to LF; it gives up after 10 s without a byte), checks the CRC-32 and sends to the group; then the status line. |
| `cbb-lite next join [-name name] [-port port] [-addr host[:port]]...` | `CBBQ <size>`, then size rows of the QR code for the phone app, each of (size + 3) / 4 hex digits with the leftmost module in the high bit of the first digit and a set bit dark; the Next draws it, the phone scans it, and after the pairing the status line (up to 5 minutes). A join payload makes a code of about 41 modules, which fits the 192 lines of the screen at 4 pixels per module. |

## Errors

Every error has a short message. `-debug` (before the command), `CBB_DEBUG=1`, or a debug
build adds the cause under it; `CBB_DEBUG=0` hides it in a debug build. The service logs
every error with its cause.
