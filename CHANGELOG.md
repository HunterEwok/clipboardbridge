# Changelog

All notable changes to clipboardbridge are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Sync away from home in the Android app: a switch in Settings makes the phone's WireGuard
  key, offers it to the group's hub on the next connection at home, and keeps the hub's
  answer. While the hub is not found on the home network, the phone reaches it through the
  tunnel in the app's own process, with the same member TLS as at home, trying the hub's
  addresses in turn; without the tunnel there is no connection. Off by default; turning it
  off forgets the key. Building the app now needs Go for the tunnel.
- The first firmware for the Arduino Nano ESP32 (`lite/esp32`, Rust on the ESP32-S3): a
  console on its USB port sets the Wi-Fi network up, the board joins it and takes an
  address by DHCP, joins a group by the phone (`join` prints the link to paste into the
  app, and the phone pairs with the board over TLS 1.3 as with `cbb-lite join`), and keeps
  its settings and identity in flash in two slots, so a power cut while saving keeps the
  last good copy (`cbb_core::store`); its `selftest` makes keys and
  certificates with the chip's true random number generator and runs a TLS 1.3 handshake
  of the protocol core on the chip. CI types on the console and runs the self-test in
  Espressif's QEMU. Pairing and syncing come next; not yet run on a real board.
- A forwarder for hubs that the computers cannot reach directly, for example behind
  carrier-grade NAT: `cbb forward` runs it on a server with a public address, and
  `cbb away hub -forwarder ADDRESS:PORT -forwarder-key KEY` registers the hub there with its
  member certificate and its WireGuard key. It holds no keys, passes each encrypted packet
  only to its own group's hub, routes by WireGuard's `mac1` so nothing on the wire tells
  groups apart, limits each group, and writes nothing about the groups, not even to its
  log. `cbb away` on the hub shows the registration.
- A blind relay for a group without a computer to be its hub: `cbb relay -group TAG` runs it
  on a server you run, and `cbb away relay ADDRESS:PORT -key KEY` on each computer meets the
  group's other computers there away from home. It holds none of the group's keys: each
  computer registers with its member certificate and gets its own WireGuard tunnel to the
  relay, which joins two computers' member connections end to end, so it sees who talks
  and when but cannot read the clipboard or pose as a device. It serves only the groups it
  is given and writes nothing about them. `cbb away` shows the link.
- `.cbb`, a dot command for the ZX Spectrum Next (`apps/zxnext`, C for z88dk): with
  `cbb-lite` on the Next's own Raspberry Pi it pastes the group's text to the screen or a
  file, sends a file or words, and joins by drawing the QR code for the phone app. Not yet
  run on a real Next.

### Fixed

- The desktop connectors (the Mac's and Windows's agent, `cbb desktop` on Linux) take the
  first texts soon after the device joins a group. While the service turned them down for
  being in no group, they waited up to 30 seconds between tries, and the texts that came
  meanwhile reached the clipboard late; now they ask again every 2 seconds, and log it once.
- Installing again on a Mac, as after `brew upgrade`, no longer fails now and then with
  "Bootstrap failed: 5: Input/output error": the installer waits for launchd to let the
  old service go before starting it.
- Stopping a tunnel for sync away from home while a packet comes in no longer races in
  WireGuard's network stack, which could crash the service: the peers stop first.

## [0.3.0] - 2026-10-24

### Changed

- A computer that joins at an address (`cbb join -code ADDRESS`, as through an SSH
  forward or a VPN of your own) now connects to the member that admitted it at that
  address and syncs at once, and so meets the hub to sync away from home, where before it
  synced only once it was on the home network.

- A Mac now takes connections on the member port and publishes itself on mDNS with
  `r=mac`, so phones, other Macs and lite members reach it with no Linux member on; it
  still dials the Linux and lite members itself, so a firewall that blocks incoming
  connections never cuts it off from them. `install.sh` lists the service in the macOS
  application firewall (`CBB_FIREWALL=no` leaves the firewall alone) and `uninstall.sh`
  takes it away. Linux members and `cbb-lite` no longer dial a Mac; update `cbb-lite`
  together with the Macs.

- The lite member's TLS is in its protocol core and needs no operating system, the first
  step to a lite member on the ESP32: rustls without the standard library, with a small
  crypto provider of RustCrypto code (TLS 1.3, ChaCha20-Poly1305 or AES-128-GCM, X25519,
  ECDSA P-256) in place of ring, a TLS session that does no I/O, and the pairing's TLS
  exporter derived from the connection's key log. `cbb-lite` on Linux uses it, so it no
  longer builds C code, and CI builds the core for the ESP32-C6 and the ESP32-S3.

- An event sent from a phone has `via` `phone` (the app, iPhone or Android, or the iPhone
  shortcut), where it had `iphone`; members still take `iphone`. The control socket takes
  and reports `phone` too. Names that belong to the shortcut, for an iPhone without the
  app, keep the word: the iPhone CA, the `iphone` token role, `to_iphone` and `from_iphone`.

- **clipbridge is now clipboardbridge, and its command is `cbb`.** Everything is renamed: the
  repository, the binary (`/usr/local/bin/cbb`), the service (`clipboardbridge.service`, on
  macOS `io.github.hunterewok.clipboardbridge`), the user and group, the directories, the
  environment variables (`CBB_PORT` and the others), and the protocol's names
  (`_clipboardbridge._tcp`, `clipboardbridge.local`, the ALPN protocols, the QR code
  scheme, the signature labels). It does not reach 0.2.0: the installers remove clipbridge,
  with its keys, its user and its firewall rules, and each device pairs again.

- Members accept a group CA with path length 1, the root that the phone app creates for its
  group, so that it can certify admin phones later (docs/protocol.md, sections 9 and 10).
- The phone app logs every error it shows, and a debug build (or the `ShowErrorDetails`
  default) puts the error itself under the message, to find out what failed.
- In the iOS simulator the app keeps its root and admin keys in the keychain, since the
  simulator cannot make a Secure Enclave key that needs Face ID.
- `cbb join` names the app's "Connect a new device" and prints the QR code's text
  as well, to paste into the app on a phone without a camera.
- The Linux installer opens clipboardbridge's ports from the home network on every run, not only
  from `get.sh`, so an update fixes a firewall turned on after the first install: in ufw as
  before, and now in firewalld too (a `clipboardbridge` service and rules for the home network);
  under a bare nftables or iptables setup that drops input it prints the commands.
  `CBB_FIREWALL=no` leaves the firewall alone. `cbb join` names the firewall
  when the phone cannot connect.
- clipboardbridge needs one TCP port, 8764: a listening `cbb join` waits on it (the
  computer is in no group yet), and the iPhone shortcut's HTTPS and the profile moved there
  from 8765 and 8766; the member port tells the connections apart by their first bytes.
  Installed shortcuts stop working: run `cbb pair -phone` and add the new one from
  its page.
- The Linux installer keeps track of the firewall rules it adds and removes them before
  adding new ones, so a changed port leaves nothing open; it never touches other rules.
- The phone app's Start screen says what to do in plain words: "Connect a new device" (a
  computer or another phone) and "I already use clipboardbridge on another phone". Its buttons
  and cards use Liquid Glass from iOS 26, with materials before.

### Added

- `cbb-lite next paste|copy|join` for the ZX Spectrum Next: on the Next's own Raspberry Pi,
  `cbb-lite` answers the Next's `.cbb` dot command over the internal UART in frames its
  Z80 reads (CR lines, the Spectrum character set, length and CRC-32, a QR code as hex
  rows for the phone to scan); see lite/README.md.
- Releases carry the lite member: `cbb-lite-linux-amd64.tar.gz`, `-arm64` and `-armv6`,
  static builds, each with the systemd unit and the licenses of the crates it is built from
  (`THIRD_PARTY_NOTICES`).

- Sync away from home for computers, off by default. `cbb away on` turns it on after a
  warning that the device keeps its keys in files; `cbb away hub address:port` makes an
  always-on computer the group's hub, which takes the others through the group's own
  WireGuard tunnel, in user space inside `cbb`, with member TLS inside it. A member uses the
  tunnel only when the hub is not on its network; `cbb away` and `cbb status` show the
  state and what went wrong (with the underlying error in a development build or with
  `CBB_DEBUG=1`); `cbb away off` forgets the keys.

- The first part of remote invitations: a pairing window can take an invitation's 128-bit
  secret in place of the six-digit code, live up to a day, and ask its admin to confirm the
  device (name, system, key fingerprint) before it admits it; an invited device never gets
  the CA keys.

- Remote invitations for computers: `cbb invite` on the group's hub writes an invitation
  file (`.cbbinvite`, valid for an hour, at most a day, for one device) and asks you to
  confirm the device that uses it; `cbb join -invite FILE` joins from any network through a
  one-time guest key that reaches only the hub's pairing, then syncs through the hub with
  its own tunnel key. The hub's peers now change without resetting the sessions of the
  clients that stay.

- Homebrew, on macOS and Linux (x86-64, ARM64):
  `brew install hunterewok/tap/clipboardbridge`. The formula installs the
  release archive as it is, so it needs no Apple signing, and the release workflow updates
  the tap after each release (`packaging/homebrew/formula.sh`, docs/maintaining.md). On a
  Mac, `install.sh --in-place` runs the service and the agent from Homebrew's binary, so a
  `brew upgrade` followed by the same command updates them.

- `packaging/macos/uninstall.sh` removes clipboardbridge from a Mac, keeping its keys unless
  `--purge`.

- **Windows 10 (1809 or later) and 11, x86-64 and ARM64.** The service runs as a Windows
  service under its own virtual account and listens like a Linux member; the agent
  (`cbbw.exe agent`, started with every sign-in) links the clipboard, skips and writes the
  marks that password managers and the clipboard history use, and turns CR LF into LF.
  `get.ps1` installs a release (`irm .../get.ps1 | iex` as administrator), `install.ps1`
  takes `-Port N` and `-NoFirewall` and allows TCP 8764 and mDNS from the local network in
  Windows Firewall, and Settings, Apps, Uninstall (`uninstall.ps1`, `-Purge` for the keys)
  removes it with exactly those rules. The installers name the step that failed and the
  system's message; `-Details` or `CBB_ERROR_DETAILS=1` adds the full error. The service
  logs to `ProgramData\clipboardbridge\logs`, the agent to
  `LocalAppData\clipboardbridge\agent.log`.
- **The lite member, `cbb-lite`, in Rust** (`lite/`): a small member for weak Linux devices
  (a Raspberry Pi, a router) that joins a phone group by QR code (or a computer group with
  the code from `cbb pair`) and never holds CA keys. It dials the computers, and publishes
  itself in mDNS (TXT `r=lite`) and listens on the member port, so that a phone syncs with it
  directly, with no computer on; Linux members leave it to dial them. `copy`, `paste`,
  `status`, `devices` and `watch` work as in `cbb`. Its errors
  show their details with `-debug` or `CBB_DEBUG=1`, and in a debug build. CI builds it for 64-bit
  Raspberry Pis and, statically, for the ARMv6 Pi Zero W. Its protocol core, `lite/core`,
  needs no operating system (no_std, RustCrypto), for a lite member on the ESP32 later.
- A joiner can say it is a lite member (`"role":"lite"` in its pairing Info): Go members
  send it no CA keys and list it with role `lite`.
- The Android app is started in `apps/android`: a Gradle build with the protocol core in
  Kotlin (`kit`, no Android dependencies) and a Compose app, built and tested in CI. The kit
  has CPace over X25519 (tested with the vectors of RFC 7748 and the CPace draft), the group's
  certificates, the member and pairing messages, the join QR code and the signed records; it
  reads the Go and Swift vectors in `testdata/interop`, and Go checks the records it signs.
  It also has the sync engine, the member node, pairing in both directions and the phone's
  group (making admins, renewals, removal, the takeover); Go checks its renewals, admin CAs
  and `root` records. An Android phone joins with `os` `android` and an admin phone admits it
  as a phone, and both kits record a lite member (`"role":"lite"` in its Info) with role `lite`.
  TLS 1.3 comes from Conscrypt (bundled in the app), with ALPN and the exporter: in CI, Go
  pairs with the Kotlin kit over plain TCP and over TLS, and syncs with it as a member.
  The app keeps its keys in the Android Keystore (StrongBox where the phone has it): the
  member key signs TLS in the background, and the root and admin keys sign only for five
  minutes after the fingerprint, the face or the screen lock.
  It finds the computers with NsdManager and keeps a connection to each (the kit's
  `MemberDialer`), and reads QR codes with CameraX and ZXing, without Google Play services.
  Its screens follow the iPhone app's: Start with the one-time "This phone is ready" note,
  joining another phone's group by showing a QR code, Home with the Send-or-fetch button and
  the computers' live dots, Devices (remove, make a computer an admin, take the group over
  from a lost root phone), Add a device (the camera or pasted text) and Settings; the four
  themes of `apps/design/tokens.json` (`tools/tokens` now writes Kotlin too) and Material
  You, in English and Russian. The app asks for the local network permission Android 17
  needs.
  While there is a group a foreground service keeps the connections, and what a computer
  copies lands on the phone's clipboard by itself. The phone's copies go with one tap: the
  Quick Settings tile "Send clipboard", the notification's Send button, Share and the
  selection menu, and a "cbb send" launcher entry for Quick Tap or a back-tap app; or with
  none, with the accessibility service "Send my copies by themselves", which notices a copy
  and takes the input focus for a moment to read the clipboard (Settings explains it and
  opens the system's page).
  The app has its icon, and a release carries `clipboardbridge-X.Y.Z.apk`, signed with the
  project's release key (docs/apps.md, "Releasing the Android app").

- A new app icon, a clipboard with a key: light, and dark in the system's dark mode
  (iOS 18 and later).
- The phone app's "Sync clipboard" action, in Shortcuts and Spotlight without setting
  anything up: Back Tap or the Action button sends or fetches by the Home button's rule
  without opening the app, and says what it did.
- `install.sh --port N` (and `get.sh --port N`) moves the member port from 8764; it is kept
  in `/etc/clipboardbridge/clipboardbridge.env` as `CBB_PORT` for later updates, and the
  installer says to allow it in other firewalls. The phone app needs no setting.
- `uninstall.sh`, installed to `/usr/local/share/clipboardbridge`, removes clipboardbridge and the
  firewall rules its installer added; `--purge` also deletes the device's keys.
- The phone app's language can be chosen in the app (System, English, Russian), in Settings
  and, when the system's language has no translation, on the Start screen; Settings, with
  the theme, opens from the Start screen too.
- At the first launch the phone app makes its own key and says once that the phone is
  ready and that the next step is to connect a device.
- Groundwork for a second admin phone: members accept a member certificate issued by an
  admin CA under the phone's root, keep that CA with their identity, send it in member
  handshakes and take it from a pairing Welcome; the phone app makes admin CAs, verifies
  such chains and reads and signs records through an admin CA (docs/protocol.md, section 10).
- The phone app asks for Face ID (or the passcode) before it signs with the group's key in
  the Secure Enclave, once per action: adding a computer, removing a device, renewing its
  own certificate. It renews the computers' certificates only while that check lasts.
- The phone app's icon, drawn by `tools/icon` from the design tokens.
- The phone kit lets a second phone join a phone group: it listens and shows a join QR code,
  an admin phone scans it, and the root makes the new phone an admin with an admin CA for
  the admin key it sent. Admin phones admit and renew through their admin CA, and removing
  an admin phone keeps the devices it admitted (docs/protocol.md, sections 6 and 10).
- The phone app joins another phone's group: "Join another phone's group" on the Start
  screen shows a QR code, the other phone scans it with +, and the new phone becomes an
  admin. The Devices screen marks the admin phones and lets only admins remove devices.
- Members accept `root` records, which hand a phone group to a new root when the root phone
  is lost: they trust the new root next to the earlier ones, keep it with their identity,
  take renewals from it and refuse anything the old root's key signs after the handover
  (docs/protocol.md, section 10).
- Any admin phone renews the certificates of the group's devices, also those another admin
  admitted, as after that admin was removed: the `cert` message carries the admin CA that
  issued the new certificate, and members take it as their new issuer (docs/protocol.md,
  section 10).
- The phone app removes a lost phone that made the group: on an admin phone, Remove on that
  phone takes the group over with a new key in the Secure Enclave, and the computers and the
  other phones follow it.
- A computer can be an admin of a phone group: it keeps an admin key and offers it to the
  root phone, which can certify it as an admin CA. An admin computer admits computers with
  `cbb pair`, removes devices with `cbb revoke` and renews certificates from
  its admin CA; it never removes the root phone (docs/protocol.md, section 10, "A computer
  as admin").
- The phone app makes a computer an admin: on the root phone, "Make it an admin" on a
  computer's row in Devices asks for Face ID, sends the computer its admin CA and lists it
  as an admin; a computer that missed it gets it when it connects again.

### Fixed

- The release archives now carry `THIRD_PARTY_NOTICES`, the licenses of the Go modules,
  the copied CPace code and Go itself that `cbb` is built from, as their licenses require.
- A `cbb away` request still running while the service stops no longer starts the hub or
  the tunnel again after the stop.
- `cbb-lite version` and its status show the release's version, taken from the tag; it
  said 0.1.0 whatever the release.
- Adding a device in the phone app no longer hangs when the computer does not answer: a
  connection gives up after 5 s and its TLS handshake after 10 s, the pairing after 30 s,
  IPv4 addresses come first, leaving the sheet cancels it, and the message names the
  computer's firewall as a likely cause.
- The phone app could not sign its TLS handshake with its own key (PRIVATE_KEY_OPERATION_FAILED):
  the keychain kept the key's public half under the same label, and the identity paired
  the certificate with it. Only the private key is stored now, and stale public keys are
  removed. When every address of a device fails, the app reports the most telling failure,
  such as a failed handshake, rather than the last timeout.

## [0.2.0] - 2026-10-21

### Added

- A quick start, [docs/quickstart.md](docs/quickstart.md): install with one command, make
  the group, add the iPhone and the other computers.
- The devices list: `clipbridge devices` shows every device of the group with its role, an
  admin mark and when this member last saw it; `clipbridge revoke <name or ID>` removes a
  Mac, a phone or an iPhone's shortcut from the group. Members keep signed device and
  revocation records, give them to each other, and refuse removed devices at once; a removed
  iPhone's token stops working. A Linux member records the devices it admits, and the
  members of an existing group when it meets them. Removing a Linux member is not supported
  yet. See section 10 of [docs/protocol.md](docs/protocol.md).

### Fixed

- `clipbridge pair` and the installers told the new computer to run `clipbridge join`, which
  now shows a QR code for the phone; for the code they show, it is `clipbridge join -code`.

## [0.1.1] - 2026-10-21

The first release. The tag v0.1.0 was made, but its release build failed on the macOS
archives, so it has no release.

### Added

- Repository scaffolding: license (AGPL-3.0-only), security policy, contributing rules,
  code of conduct, issue forms and repository settings.
- Design document: [docs/design.md](docs/design.md).
- The `clipbridge` command: `service` runs the service; `pair` and `join` admit a computer to
  the group with a six-digit code; `copy` and `paste` use the group's clipboard; `status`
  shows the group and the connected members.
- The service: the group's certificates, pairing, mDNS discovery (publishing on Linux,
  browsing on a Mac), member connections and the sync engine, and a local control socket.
- The connector package, which links a desktop clipboard to the service.
- Linux desktops: `clipbridge desktop` links the session's clipboard, through Wayland
  data-control or X11 (XWayland on GNOME), started by an XDG autostart entry.
- Linux packaging: a hardened systemd unit, the service user, a tmux configuration, an
  optional tmux start on the text console, and `packaging/linux/install.sh`.
- macOS: `clipbridge agent` links the pasteboard (secrets stay on the Mac and carry the
  concealed marker); the service runs as a LaunchDaemon and the agent as a LaunchAgent,
  installed by `packaging/macos/install.sh`.
- iPhone: `clipbridge pair -phone` on the member that holds `clipbridge.local` serves the
  profile with the iPhone CA and a pairing page that issues the shortcut's token; the
  shortcut's `/sync` sends the iPhone's text to the group or brings a recent copy back.
  `pair -phone` shows a QR code of a page that walks through the steps; the shortcut,
  generated from the code and signed on a Mac, asks for the six-digit code on its first run
  and keeps its token.
- The phone as the main device: `clipbridge pair -phone` on a Linux machine in no group
  creates the group, and `clipbridge join` listens and shows a QR code (a `clipbridge://join`
  URL with its code, addresses and certificate fingerprint) that the shortcut "clipbridge:
  add a computer" scans; the Linux member then dials the computer, so no announcement and
  no multicast are needed, and a device that does not know the code learns nothing from a
  try. `clipbridge join -code` keeps the code from `clipbridge pair`.
- Certificate renewal: a Linux member renews its own certificates and, with a new `cert`
  message, those of the members it is connected to, months before they expire.
- The member protocol accepts the roles `phone` (the phone apps) and `lite` (a lite member),
  which connect like a Mac.
- Releases from a version tag: archives for Linux and macOS, `SHA256SUMS` and build
  provenance attestations; `get.sh` installs the latest release on Linux in one command,
  checks it, and opens clipbridge's ports in ufw for the home network only. The member port
  is 8764 and a listening join 8767 when they are free.
- Linux members without the CA keys, for groups whose root will be the phone: a welcome
  without them makes such a member, which syncs but admits nobody and never holds
  `clipbridge.local`.
- The start of the phone app: `apps/ios/ClipbridgeKit`, a Swift package with CPace (checked
  against the draft's test vectors), the pairing frames and the join QR code, tested on
  Linux and macOS against vectors from the Go side in `testdata/interop/`.
- ClipbridgeKit admits a computer as the phone will: it dials, confirms the code first and
  issues the computer's certificate; a Go test runs it against the Go joiner.
- Protocol specification: [docs/protocol.md](docs/protocol.md); the plan for the phone apps:
  [docs/apps.md](docs/apps.md).
- CI: formatting, vet, staticcheck, govulncheck, actionlint and repository rules; tests on Linux and
  macOS; builds for Linux (x86-64, ARM64, ARMv7, ARMv6) and macOS (ARM64, x86-64).

### Fixed

- The release build packs the macOS archives with `packaging/macos`; CI now builds every
  release archive on each pull request with the same script, `packaging/archive.sh`.

[Unreleased]: https://github.com/HunterEwok/clipboardbridge/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/HunterEwok/clipboardbridge/releases/tag/v0.1.1
