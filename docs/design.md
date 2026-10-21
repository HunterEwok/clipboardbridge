# Design

Status: agreed design, before the first code. Decisions are listed in the
[decision log](#decision-log) at the end; questions that still need an experiment are under
[open questions](#open-questions).

## Goals

- One clipboard for the user's Apple devices and any number of Linux machines on one home
  network.
- Copy and paste with the normal means of each system, and at most one press on the iPhone.
- Linux with and without a desktop, from a Raspberry Pi Zero W to a workstation, without
  depending on a particular distribution or desktop.
- Encrypted and paired; no cloud, no accounts, no telemetry.

## Non-goals

- Sync over the internet. All devices are on one local network.
- Working around iOS. iOS lets an app read the clipboard only after a user action.
- Sync between Apple devices. Universal Clipboard already does it.
- Clipboard history.
- Images and files in the first version: text only.

## Devices and roles

| Device                  | Component                         | How it takes part                                              |
|-------------------------|-----------------------------------|----------------------------------------------------------------|
| Linux with a desktop    | service + desktop connector       | automatic, through the desktop clipboard                       |
| Linux without a desktop | service (+ console helper)        | its own clipboard: tmux, `clipbridge copy`/`paste`, console paste |
| Mac                     | agent                             | automatic                                                      |
| iPhone, iPad            | a shortcut                        | one press (Action button or Back Tap)                          |

Linux machines and Macs are equal **members** of a **group**. There is no central server, and
any member may be switched off at any time.

## Group and pairing

- **Group CA.** The first member creates a certificate authority for the group. Every member
  has its own key and a certificate signed by the group CA, and members talk to each other
  over mutual TLS. Linux members keep a copy of the CA key, so any of them can admit a new
  device.
- **Joining a computer.** `clipbridge pair` on a member opens a pairing window for five
  minutes. The new device connects, both screens show the same six digits, and the user
  confirms on both, as with Bluetooth. The digits are derived from the keys of both devices,
  so a device in the middle cannot pass the check. The new member then receives its
  certificate and the group state.
- **Joining an iPhone or iPad.** The iPhone opens the pairing address in Safari and types the
  six digits shown on the member. The page offers a configuration profile with the
  certificate the iPhone must trust (see [Security](#security)) and shows the iPhone's token
  with a Copy button. The shortcut sends the token with every request.
- **Devices and revocation.** `clipbridge devices` lists the members and iPhones;
  `clipbridge revoke <name>` removes one. The revocation spreads to every member.

## Discovery and the shared address

- Members advertise the service `_clipbridge._tcp` over mDNS (Bonjour) and find each other
  without configuration. clipbridge answers mDNS itself and does not need avahi-daemon.
- Members connect to each other directly. A home group is small, so every member keeps a
  connection to every other member.
- The iPhone uses one address for the whole group: **`clipbridge.local`**. The live member
  with the lowest device ID publishes this name, with a short record lifetime (10 seconds).
  A member that shuts down hands the name over at once; after a power cut the others notice
  the missing member and take the name over within about 10–20 seconds.
- Whichever member answers does not matter: all members hold the same state.

## Sync model

- A clipboard change on a member becomes an **event**: a random ID, the origin device, a
  timestamp, the text and its kind (normal or secret).
- Members forward every event to all members they are connected to. A member drops an event
  it has already seen, and ignores an event whose text equals its current text. The second
  rule also removes duplicates when two Macs report the same Universal Clipboard item.
- Events are ordered by a hybrid logical clock, so small clock differences between devices
  do not reorder copies. The latest event is the group's current text.
- **No echo.** A member that writes an event into its local clipboard remembers that it did,
  and does not report the resulting clipboard change as a new copy.
- **After a disconnect** (a Mac wakes up, a Linux machine is switched on) members compare
  what was copied during the gap. If only one side copied, its latest copy goes to the
  other side. If both sides copied, nothing is applied automatically, so nothing is
  overwritten.

## The iPhone button

The shortcut reads the iPhone clipboard and sends it to
`POST https://clipbridge.local:8765/sync`. The port is the project's own, so clipbridge does
not clash with a web server on the same machine. The member decides the direction:

1. A computer in the group copied something less than 45 seconds ago → the member returns
   that text, and the shortcut puts it on the iPhone clipboard. The user most likely pressed
   Ctrl+C or ⌘C a moment ago and picked up the phone.
2. Otherwise, if the iPhone text is new → it becomes a group event.
3. Otherwise, if the group has a newer copy from earlier → the member returns it.
4. Otherwise there is nothing to transfer.

The response is JSON: `direction`, `copy` (text for the iPhone clipboard, may be empty) and
`message`, which the shortcut shows as a notification ("Sent to …", "Received from …",
"Nothing new"). When the guess is wrong, the user copies again and presses again.

The shortcut is published as an iCloud link with import questions, so setting it up means
opening one link and pasting the address and the token.

## Linux components

clipbridge for Linux is one program that runs as up to three processes with different rights
and lifetimes. The installer enables what the device needs.

### 1. Service

- A system service that runs from boot, as its own unprivileged user, with or without a
  desktop.
- Network, group, discovery, the shared address, sync and the current text.
- Command line: `clipbridge copy` (standard input to the group), `clipbridge paste` (the
  current text to standard output), `clipbridge pair`, `devices`, `revoke`, `status`.
- tmux: copying in tmux copy mode goes to the group (`copy-command`), and a key binding
  pastes the current text into any program inside tmux. A login snippet starts tmux on the
  text console.

### 2. Desktop connector

- A user process started with any graphical session (XDG autostart, which nearly every
  desktop supports; a systemd user unit where needed). It links the desktop clipboard to the
  service over a local socket and stops when the session ends; the service keeps running.
- Clipboard access, chosen automatically:

  | Desktop                                                        | Access                                     |
  |----------------------------------------------------------------|--------------------------------------------|
  | any X11 desktop (XFCE, LXQt, MATE, Openbox, …)                 | X11 selections, change events from XFixes  |
  | Wayland with data-control: KDE, sway, Hyprland, labwc, Wayfire, COSMIC | the data-control protocol            |
  | GNOME (no data-control)                                        | X11 selections through XWayland            |
  | anything else                                                  | the `wl-clipboard` tools as a fallback     |

- A received text goes into both the clipboard and the primary selection, so Ctrl+V works in
  applications, and Shift+Insert and the middle mouse button work in terminals.
- **Auto-paste** (optional): after a text arrives from the iPhone, the connector presses
  Shift+Insert through a virtual keyboard (uinput). Not on the lock screen.

### 3. Console helper

- Optional, runs as root, because only root may inject input into a console.
- On a double press of Right Ctrl (configurable; a modifier alone types nothing, so
  programs do not notice) it injects the current text into the active virtual console as
  input. This works at the login prompt, in `sudo` and in any console program, with any
  characters, independent of the console keyboard layout.
- No network. It accepts requests only from the local service, over a Unix socket checked
  with peer credentials. It reads keyboards only to detect the trigger.

## macOS agent

- A LaunchAgent. It checks the pasteboard change counter every 0.5 seconds and reads the
  text only after a change.
- Skips items marked by password managers (`org.nspasteboard.ConcealedType`,
  `org.nspasteboard.TransientType`, `org.nspasteboard.AutoGeneratedType`).
- Finds members over Bonjour and trusts only the group CA, in its own configuration; the
  system keychain is not changed.
- macOS may ask once for permission to read the pasteboard.
- Later: a menu bar item with pause, status and devices.

## Passwords

- Automatic sync skips items marked as secret: the macOS types above, and on Linux the
  `x-kde-passwordManagerHint: secret` type set by KeePassXC and KDE.
- Explicit actions may carry a secret: the iPhone button, "send even if secret" on the Mac,
  and the console paste. Secret events are kept only in memory and expire after 60 seconds.

## Limits

- Text only, UTF-8, up to 1 MiB per item.

## Security

| Threat                                                         | Measure                                                                    |
|----------------------------------------------------------------|----------------------------------------------------------------------------|
| Someone on the home network reads the traffic                  | TLS everywhere                                                             |
| A device impersonates a member (for example, a host that answers `clipbridge.local` on another network) | mutual TLS with the group CA; a Mac sends nothing to a device without a group certificate |
| A device is lost or stolen                                     | `clipbridge revoke`                                                        |
| A member is compromised                                        | it can read the group clipboard, by design; it cannot read the iPhone's other HTTPS traffic, because the iPhone trusts only a certificate that cannot sign others; the Mac never changes its system trust |
| A bug in the network code                                      | memory-safe language; the service runs as an unprivileged user in a systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, restricted address families) |
| The root helper is abused                                      | no network; local socket with peer credentials; one function only          |
| Requests from outside the home network                         | the service accepts connections only from private and link-local addresses |
| A compromised dependency or build                              | few dependencies, `govulncheck`, actions pinned to commit SHAs, release builds in CI with checksums and build provenance |

## Build

- Go. Small C or Objective-C parts only where the platform requires them (the macOS
  pasteboard, possibly Wayland).
- Targets: `linux/amd64`, `linux/arm64`, `linux/arm` with ARMv7 and ARMv6, `darwin/arm64`
  and `darwin/amd64`.
- The Raspberry Pi Zero W (ARMv6) cannot run Ubuntu; it runs Raspberry Pi OS. clipbridge
  does not depend on distribution specifics.

## Roadmap

The order may change.

1. Repository scaffolding.
2. Service core: group, pairing, discovery, sync, command line; Linux without a desktop
   and tmux.
3. Desktop connector: X11 and GNOME through XWayland, then Wayland data-control.
4. macOS agent.
5. iPhone: `/sync`, the pairing page, the published shortcut.
6. Console helper and auto-paste.
7. Packages and signed releases.

## Open questions

- Does the Mac see a Universal Clipboard item from the iPhone (the change counter moves)
  without a paste on the Mac? If yes, the iPhone button is rarely needed while a Mac is
  near.
- Does iOS fully trust a self-signed certificate that is not a CA? If not, the iPhone gets a
  separate CA restricted with name constraints to `clipbridge.local`.
- Wayland data-control in pure Go, or a small C part?
- Images and files after the first version.

## Decision log

| ID  | Decision                                                                                   |
|-----|--------------------------------------------------------------------------------------------|
| D-1 | License: AGPL-3.0-only. Code contributions are not accepted, so no contributor agreement is needed. |
| D-2 | Language: Go, for reliable ARMv6 builds, TLS and networking in the standard library, and development speed. |
| D-3 | A group of equal members instead of a central server; any member may be off.              |
| D-4 | Encryption with the project's own TLS and pairing instead of an overlay VPN, which on iOS would conflict with other VPN apps. |
| D-5 | All devices are on one home network; no relay.                                             |
| D-6 | Mac and Linux sync automatically; the iPhone uses one button that picks the direction.     |
| D-7 | Console without a desktop: tmux for copy and paste, a root helper for console paste outside tmux. |
| D-8 | The repository is in English only.                                                         |
