# Changelog

All notable changes to clipbridge are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Members accept a group CA with path length 1, the root that the phone app creates for its
  group, so that it can certify admin phones later (docs/protocol.md, sections 9 and 10).
- The phone app logs every error it shows, and a debug build (or the `ShowErrorDetails`
  default) puts the error itself under the message, to find out what failed.
- In the iOS simulator the app keeps its root and admin keys in the keychain, since the
  simulator cannot make a Secure Enclave key that needs Face ID.
- `clipbridge join` names the app's "Connect a new device" and prints the QR code's text
  as well, to paste into the app on a phone without a camera.
- The Linux installer opens clipbridge's ports from the home network on every run, not only
  from `get.sh`, so an update fixes a firewall turned on after the first install: in ufw as
  before, and now in firewalld too (a `clipbridge` service and rules for the home network);
  under a bare nftables or iptables setup that drops input it prints the commands.
  `CLIPBRIDGE_FIREWALL=no` leaves the firewall alone. `clipbridge join` names the firewall
  when the phone cannot connect.
- clipbridge needs one TCP port, 8764: a listening `clipbridge join` waits on it (the
  computer is in no group yet), and the iPhone shortcut's HTTPS and the profile moved there
  from 8765 and 8766; the member port tells the connections apart by their first bytes.
  Installed shortcuts stop working: run `clipbridge pair -phone` and add the new one from
  its page.
- The Linux installer keeps track of the firewall rules it adds and removes them before
  adding new ones, so a changed port leaves nothing open; it never touches other rules.
- The phone app's Start screen says what to do in plain words: "Connect a new device" (a
  computer or another phone) and "I already use clipbridge on another phone". Its buttons
  and cards use Liquid Glass from iOS 26, with materials before.

### Added

- `install.sh --port N` (and `get.sh --port N`) moves the member port from 8764; it is kept
  in `/etc/clipbridge/clipbridge.env` as `CLIPBRIDGE_PORT` for later updates, and the
  installer says to allow it in other firewalls. The phone app needs no setting.
- `uninstall.sh`, installed to `/usr/local/share/clipbridge`, removes clipbridge and the
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
  `clipbridge pair`, removes devices with `clipbridge revoke` and renews certificates from
  its admin CA; it never removes the root phone (docs/protocol.md, section 10, "A computer
  as admin").
- The phone app makes a computer an admin: on the root phone, "Make it an admin" on a
  computer's row in Devices asks for Face ID, sends the computer its admin CA and lists it
  as an admin; a computer that missed it gets it when it connects again.

### Fixed

- Adding a device in the phone app no longer hangs when the computer does not answer: a
  connection gives up after 5 s and its TLS handshake after 10 s, the pairing after 30 s,
  IPv4 addresses come first, leaving the sheet cancels it, and the message names the
  computer's firewall as a likely cause.

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

[Unreleased]: https://github.com/HunterEwok/clipbridge/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/HunterEwok/clipbridge/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/HunterEwok/clipbridge/releases/tag/v0.1.1
