# Changelog

All notable changes to clipbridge are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Protocol specification: [docs/protocol.md](docs/protocol.md); the plan for the phone apps:
  [docs/apps.md](docs/apps.md).
- CI: formatting, vet, staticcheck, govulncheck, actionlint and repository rules; tests on Linux and
  macOS; builds for Linux (x86-64, ARM64, ARMv7, ARMv6) and macOS (ARM64, x86-64).
