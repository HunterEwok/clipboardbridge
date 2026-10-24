<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Roadmap

What comes next, the designs that are agreed but not built yet, and the questions to study
before anything is planned. How clipboardbridge works today is in [design.md](design.md),
with the reasons in its decision log; what works on real devices is the
[status table](../README.md#status).

## Order of work

The order may change.

1. **Done.** Repository scaffolding.
2. **Done.** Service core: sync engine, group and pairing, discovery, member connections, control
   socket, command line; Linux without a desktop and tmux.
3. **Done.** macOS: service as a LaunchDaemon and the pasteboard agent.
4. **Done.** Desktop connector: Wayland data-control, X11, GNOME through XWayland.
5. **Done.** iPhone: `/sync`, the pairing pages, the published shortcut.
6. **Done.** Simpler setup: QR codes, the generated shortcuts, the phone as the main device.
7. **Partly: the Linux and Windows installers, Homebrew and releases with checksums and attestations are done; the signed `.pkg` waits for an Apple developer account.** Installers: a one-line installer for Linux (with the firewall), Homebrew and a signed
   `.pkg` for macOS, signed releases.
8. **Built; CI on windows-latest, not yet run on a real PC.** Windows: the service as a Windows service and a clipboard connector through the Win32
   API.
9. **Built; tested in CI, not yet on a real phone or in a store.** Apps for iPhone and Android, which make the phone the group's root of trust (see "The phone apps" in [design.md](design.md#the-phone-apps)).
10. **Planned.** Console helper and auto-paste.
11. **Linux done; on the ESP32 the protocol core and its TLS build for the chip, the firmware is next.** A lite member in Rust for weak devices (routers, small boards): a member without CA
    keys that joins by QR code through the phone and syncs; it never admits devices, holds
    `clipboardbridge.local` or serves the iPhone shortcut. It dials the Linux members and
    listens for phones and Macs, so a phone and a lite member sync with no computer on. Only once the Go version is complete and its architecture settled, so it is
    written once. Before it: the protocol written down in `docs/protocol.md`, a `lite` role
    that full members treat like a Mac, test vectors in `testdata/`, and an e2e test with a
    Rust member among Go members. Done for Linux in `lite/` (`cbb-lite`, built for the
    Raspberry Pi, not yet run on one). The ESP32 comes next: the protocol core is its own
    crate, `lite/core`, without the standard library (no_std with alloc, RustCrypto in
    place of ring), with the member TLS in it (rustls without std and a RustCrypto
    provider; `cbb-lite` uses the same code), which CI builds for the ESP32-C6 (RISC-V)
    and the ESP32-S3 (Xtensa); the firmware and the networking on the chip follow.
12. **Partly: built between computers (`cbb away`, `cbb invite` for joining from afar, `cbb forward` for hubs behind carrier-grade NAT, and `cbb relay`, a blind relay of the user's own for groups without a hub); the rest is the order of work in [design.md](design.md#order-of-work).** Sync away from home and between subnets, through the group's own WireGuard tunnel in a
    star around a hub; see "Sync away from home" in [design.md](design.md#sync-away-from-home).
13. **Planned.** Computer keys in hardware; see "Device keys in hardware" below.
14. **Started: `cbb-lite next` and the `.cbb` dot command (`apps/zxnext`) are written, not yet
    run on a real Next; the NextPi set-up and the path through the ESP8266 are next.** The ZX
    Spectrum Next through its own Raspberry Pi. The Accelerated Next carries a
    Raspberry Pi Zero on its accelerator header, wired to the FPGA's second UART, with
    NextPi (a read-only DietPi) and a root shell (`SUP>`) on that UART. `cbb-lite` runs on
    this Pi as an ordinary lite member, installed on the NextPi card itself (its user
    partition and a start script), so NextPi's own tools keep working. It speaks the
    member protocol with TLS 1.3 like any other member and reaches the network in one of
    two ways, both built: the Pi's own Wi-Fi on a Zero W, which NextPi turns off and we
    turn back on; or, on a Zero without a radio, the Next's built-in ESP8266, which then
    only carries the Pi's TLS bytes: the Z80 copies them between the Pi's UART and the
    ESP's, and the ESP never sees anything but ciphertext. A dot command on the Next,
    `.cbb`, talks to `cbb-lite` over the internal UART the way NextPi's own tools do
    (`.pisend`): it copies a text to the group, pastes the latest one, and joins by
    drawing the QR code for the phone app on the Next's screen (`cbb-lite next`,
    lite/README.md). The UART is a trace on the
    Next's board and never leaves the case, so it carries the texts in the clear. The Pi
    converts between UTF-8 and the Spectrum character set: printable ASCII first, with
    every other character shown as `?`; Cyrillic follows later as an encoding of its own.
    No other device takes part: a Next without a Pi is future research (below), not a
    reason to lean on a computer in the group.
15. **Started: the firmware (`lite/esp32`) builds for the Nano ESP32, keeps its settings in
    flash, joins the Wi-Fi network set on its USB console, joins a group by the phone and
    passes its self-test (keys, certificates, a TLS 1.3 handshake on the chip) in QEMU;
    sync and the USB keyboard are next.** Arduino: the Arduino Nano ESP32 (an ESP32-S3) as a full lite member, on the same
    `lite/core` as the other ESP32 boards, with the member protocol and TLS 1.3 on the
    board itself. It ships as a ready firmware built from our Rust code, flashed over USB
    with one command; a library for writing one's own Arduino sketches on top of it may
    follow. Over its USB port it can act as a keyboard and type the group's latest text
    into any computer without clipboardbridge (Latin characters only: a USB keyboard
    cannot type most other scripts), and it can show texts on a display and send one with
    a button.
16. **Planned.** Full members, admins and the device's system: a Windows PC shown as
    Windows, the Mac a full member, CA keys only on the creator and the admins, and the
    upgrade of older groups; see "Full members, admins and the operating system" in
    [design.md](design.md#full-members-admins-and-the-operating-system).
17. **Planned, after TestFlight.** Removing the iPhone shortcut (the `shortcut` role), a
    legacy way, once the owner's Apple developer account puts the app on real iPhones
    through TestFlight: with it go the iPhone CA and its key on the admins, the shortcut
    endpoints and pages on the member port, the configuration profile and its plain-HTTP
    port, the tokens, and the rule for who holds `clipboardbridge.local`, which only the
    shortcut uses. The group then has one kind of trust, the member certificates, and no
    key that cannot be revoked by a record.
18. **Planned for 0.5.** Remote paste: an admin device sends a text to one member and has
    it pasted or typed where that member's focus is, with nothing pressed on the target;
    every admin may do it on every member (D-54), the iPhone only sends. See "Remote paste"
    in [design.md](design.md#remote-paste-planned-for-05). One pull request each:
    1. the signed `paste` command, its result and its forwarding, in Go and both phone
       kits with interop vectors; `cbb paste --on DEVICE`;
    2. Linux targets: X11, Wayland (virtual keyboard, uinput), tmux and the console helper
       (item 10);
    3. Windows and macOS targets;
    4. sending from the iPhone and Android apps, and the Android target;
    5. the `cbb-lite` target, then the Nano ESP32's keyboard.
19. **Planned for 0.5.** Sync modes: each device keeps its own clipboard by default and is
    switched to shared, receive only or send only by itself or by any admin (D-55). See
    "Sync modes" in [design.md](design.md#sync-modes-planned-for-05).

## Device keys in hardware

On the phones the member key and the root and admin keys live in the Secure Enclave or the
Android Keystore and cannot be exported. On computers the member key, the WireGuard key
and the CA keys sit in files readable only by the service, so whoever gets root on a
computer, or a copy of its disk, can copy them and act as that device until it is removed.
The plan:

- **Hardware where there is some.** Linux and Windows keep the member key (P-256) and the
  admin key in the TPM 2.0 (Linux through the kernel's TPM device, Windows through the
  Platform Crypto Provider), and a Mac in the Secure Enclave (Apple silicon or the T2
  chip), so the keys are used there and never leave it. WireGuard's X25519 is not offered
  by these chips; that key is kept sealed by the TPM or the Secure Enclave and opened only
  in the service's memory.
- **Without hardware** (many Raspberry Pis and older PCs, Intel Macs without the T2): the
  key stays in a file readable only by the service, on Linux sealed with `systemd-creds`
  (by the TPM when there is one, else by the machine's own key readable only by root), on
  an Intel Mac in the system keychain. This protects a copy of the file alone, such as a
  backup or a memory card read elsewhere, not a device whose root is taken; it is said
  plainly rather than hidden. At home that is how every computer works today; for sync
  away from home such a device needs the user's separate consent (see "Turning it on, step
  by step").
- `cbb status` and the devices list show where each device keeps its key (hardware or a
  file), so the user sees which devices are weaker.
- **Regular renewal**: the member key and the WireGuard key are replaced on a schedule
  (the certificate renewal and a new tunnel key through the tunnel), so a copied key stops
  working even when nobody noticed the theft.
- Removing a device stays the main answer to a stolen key in every case.
- **Attestation (planned, off by default).** A TPM can sign that a key was made inside it and
  cannot leave it, with a chain up to its maker's certificate (the endorsement key);
  Android's Key Attestation does the same with Google's root. The admin checks that chain
  when the device joins, and the device then carries a mark "key in hardware, proven". It
  is checked only offline, with the makers' roots shipped in `cbb` and the apps: a TPM
  whose endorsement certificate must be fetched from its maker's server (some Intel and AMD
  firmware TPMs) does not pass, and Apple offers no attestation that works without its
  servers or MDM, so Macs and iPhones are never marked. It is off by default and not used
  in the project's own setup; the user turns it on at the hub, which then lets only marked
  devices sync away from home. What it does not do: it does not stop malware on the device
  itself from using the key while it runs there, and it is no stronger than the chip.

## Future research (not planned)

Questions to study before anything is planned for them.

- **A ZX Spectrum Next without a Pi**, on its own hardware only: no other device in the
  network may do its part. Three paths, in the order to try them:
  (1) the Z80N is the member itself and the built-in ESP8266, with its stock AT firmware,
  only carries the TCP bytes, so the ESP never sees anything but ciphertext; TLS 1.3, the
  P-256 signatures and X25519 in Z80N assembly would take minutes per connection (one
  X25519 is estimated at 5-20 s), then the connection stays open and texts move at
  several KB/s; (2) our own firmware for the ESP-01, which then is the member and the
  Z80 only shows the text, with about 80 KB of RAM for TLS 1.3 and at the cost of the AT
  programs that need the stock firmware; (3) an ESP32 module in place of the ESP-01 in
  its socket, running `lite/core`, if such a module exists for that socket. To measure:
  the cost of P-256 on the Z80N and the RAM a TLS 1.3 member needs on the ESP8266.
- **No gateway and no plain tier.** A device too weak for the member protocol does not
  lean on another member over the network to do its part, neither through a gateway with
  a simpler encrypted protocol nor in the clear. Such a device joins through hardware of
  its own (the Next's Pi, an ESP32 on the board) or not at all. Arduino boards whose
  Wi-Fi chip runs its own TLS (Uno R4 WiFi, Nano 33 IoT, MKR WiFi 1010) cannot be lite
  members, because that TLS gives no access to the exporter the member protocol needs,
  so they are not supported; boards without a network are not either.
