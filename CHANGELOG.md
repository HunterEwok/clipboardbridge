# Changelog

All notable changes to clipbridge are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Members accept a group CA with path length 1, the root that the phone app creates for its
  group, so that it can certify admin phones later (docs/protocol.md, sections 9 and 10).

### Added

- Groundwork for a second admin phone: members accept a member certificate issued by an
  admin CA under the phone's root, keep that CA with their identity, send it in member
  handshakes and take it from a pairing Welcome; the phone app makes admin CAs, verifies
  such chains and reads and signs records through an admin CA (docs/protocol.md, section 10).

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
