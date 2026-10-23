# cbb-lite: the lite member

`cbb-lite` is a small clipboardbridge member in Rust for weak Linux devices: a Raspberry
Pi, a router, a small board. It speaks the member protocol of
[docs/protocol.md](../docs/protocol.md), but unlike `cbb` it

- never holds CA keys, so it never admits devices;
- only dials the full members (found by mDNS, or named with `-peer`), like a Mac;
- never holds `clipboardbridge.local` or serves the iPhone shortcut;
- has no desktop clipboard of its own: other programs use `copy`, `paste` and `watch`.

It needs at least one full member (`cbb` on a computer) to be on. Full members list it
with role `lite`.

The protocol core (`certs`, `records`, `clip`, `hlc`, `wire`, `pair` and CPace in
`src/third_party/cpace`) keeps away from the operating system where it can, for a later
port to the ESP32.

## Build

With Rust 1.85 or later:

```sh
cd lite
cargo build --release          # target/release/cbb-lite
cargo test                     # unit tests and the vectors in ../testdata/interop
```

For a Raspberry Pi (64-bit Raspberry Pi OS or Debian) from an x86 Linux machine:

```sh
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

For a Raspberry Pi Zero, Zero W or Pi 1 (ARMv6, 32-bit Raspberry Pi OS): a static binary,
with clang and llvm-ar and no cross toolchain (`.cargo/config.toml` holds the settings):

```sh
rustup target add arm-unknown-linux-musleabihf
cargo build --release --target arm-unknown-linux-musleabihf
```

CI builds both on every push: the `cbb-lite-linux-arm64` and `cbb-lite-linux-armv6`
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
sudo install -m 0644 packaging/cbb-lite.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cbb-lite
```

The service waits until the device joins a group. Join as the service's user, so that it
can read its keys:

```sh
sudo -u cbb-lite cbb-lite join -name pi
```

It shows a QR code: in the clipboardbridge app tap "Connect a new device" (or run the
shortcut "clipboardbridge: add a computer") and scan it. The phone reaches the device on
TCP port 8764 (`-port` to change it); open that port from the home network if a firewall
drops it. In a group without a phone, run `cbb pair` on a Linux member and
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
`/usr/local/bin/cbb-lite run -peer 192.168.0.10:8764 -peer ...`.

## Errors

Every error has a short message. `-debug` (before the command), `CBB_DEBUG=1`, or a debug
build adds the cause under it; `CBB_DEBUG=0` hides it in a debug build. The service logs
every error with its cause.
