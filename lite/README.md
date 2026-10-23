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

Full members list it with role `lite`. A device on another network than the phone (another
subnet, where mDNS does not reach) syncs through the internet, over a VPN between the
devices; see "Sync away from home" in [docs/design.md](../docs/design.md). Until then, name
a computer there with `-peer`.

The protocol core is its own crate, [`core`](core) (`cbb_core`): certificates, records,
the hybrid clock, the sync engine, the frames and the joiner's side of the pairing, with
CPace in `core/src/third_party/cpace`. It does no I/O and needs no operating system
(no_std with alloc; RustCrypto for P-256, SHA-2 and HMAC), so a lite member on the ESP32
can use it as it is. On a microcontroller the firmware supplies the randomness, as
getrandom's custom backend (`__getrandom_v03_custom`), and the core's locks are spin
locks; with the `std` feature, as `cbb-lite` uses it, they are the standard library's.
`cbb-lite` itself (`src`) adds the state files, TLS with rustls, mDNS, the control socket
and the service.

## Build

With Rust 1.85 or later:

```sh
cd lite
cargo build --release          # target/release/cbb-lite
cargo test --workspace         # unit tests and the vectors in ../testdata/interop
```

The core alone for a RISC-V microcontroller such as the ESP32-C6
(`rustup target add riscv32imac-unknown-none-elf`; `.cargo/config.toml` sets getrandom's
backend):

```sh
cargo build -p clipboardbridge-core --release --target riscv32imac-unknown-none-elf
```

For a Raspberry Pi (64-bit Raspberry Pi OS or Debian) from an x86 Linux machine:

```sh
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

For a Raspberry Pi Zero, Zero W or Pi 1 (ARMv6, 32-bit Raspberry Pi OS): a static binary,
with clang and llvm-ar (`apt install clang llvm`) and no cross toolchain (`.cargo/config.toml` holds the settings):

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

## Errors

Every error has a short message. `-debug` (before the command), `CBB_DEBUG=1`, or a debug
build adds the cause under it; `CBB_DEBUG=0` hides it in a debug build. The service logs
every error with its cause.
