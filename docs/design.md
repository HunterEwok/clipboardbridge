# Design

Status: agreed design; the code follows it stage by stage. Decisions are listed in the
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
| Mac                     | service + pasteboard agent        | automatic                                                      |
| iPhone, iPad            | a shortcut                        | one press (Action button or Back Tap)                          |

Linux machines and Macs are equal **members** of a **group**. There is no central server, and
any member may be switched off at any time.

## Identifiers and ports

- **Device ID**: 128 random bits as 32 lowercase hex characters. It fits in a DNS label and
  compares the same way everywhere.
- **Member port**: Linux members listen for mutual TLS on a port chosen at start and
  advertised in the mDNS SRV record. That listener never serves the iPhone. Macs only dial
  out.
- **iPhone port 8765**: HTTPS for the shortcut (`/sync`) and the pairing page (`/pair`),
  with no client certificate. Only Linux members open it.
- **Profile port 8766**: plain HTTP that serves only the iPhone CA's configuration profile,
  and only while a phone pairing window is open. The profile is public, and the user checks
  its fingerprint before trusting it.

## Group and pairing

- **Creating the group**: the first `clipbridge pair` on a Linux machine that is in no group
  creates it: the group CA and the iPhone CA. A Mac cannot start a group.
- **Group CA**: ECDSA P-256, valid 20 years, path length 0. Every member has its own P-256
  key and a certificate from the group CA, valid 2 years and renewed when less than 240 days
  remain. Its `NotBefore` is the CA's, and members check certificates with their own clock but
  never earlier than the CA's start, so a Raspberry Pi that boots with a clock years behind
  real time still accepts them; expired certificates are rejected. Linux members keep a copy
  of the CA key, so any of them can admit a new device. TLS 1.3 only, with the ALPN protocol
  `clipbridge/1`; a client checks that the server's certificate names the device it found in
  discovery.
- **iPhone CA**: ECDSA P-256, valid 20 years, path length 0, with critical name constraints
  that permit only the DNS name `clipbridge.local` and names below it (and URI and e-mail
  names under `clipbridge.invalid`) and exclude every IP address. Every Linux member holds its key and its
  own `clipbridge.local` server certificate from it, valid 397 days from a day before it was
  issued and renewed when less than 60 days remain, or at once if it starts in the future
  because it was issued while the clock was ahead, so whichever member holds the name can
  serve the iPhone.
- **End of a CA's life**: certificates end no later than their CA. A member certificate that
  already ends with its CA is not renewed again; replacing a CA after 20 years works like
  the replacement after a revocation.
- **Identity file**: each device keeps its device ID, its key, its certificates and, on a
  Linux member, the keys of both CAs in one file, `identity.json` in the service's state
  directory, readable only by the service. It is replaced in one step, so a crash leaves the
  old identity or the new one.
- **Joining a computer**: `clipbridge pair` on a Linux member (on a Mac, the command asks a
  connected Linux member) shows a six-digit code and opens a pairing window for five minutes
  (one attempt at a time, closed after a success or the third failed attempt; an attempt that
  has started may finish after the five minutes). On the new device the user runs
  `clipbridge join` and types the code. The new device connects to the member's port with
  the ALPN protocol `clipbridge-pair/1` and presents a self-signed certificate for the key
  it will keep. The two run the CPace password-authenticated key exchange
  (CPACE-X25519-SHA512) with the code, bound to the TLS session by an exporter and to both
  certificates, and confirm the key, the new device first. An attacker gets one guess per
  attempt and no offline attack; a relay between two TLS sessions fails. An attempt that
  reaches the exchange and does not succeed counts as a failure. The new member then
  receives, over the TLS session that CPace authenticated, a certificate for the key it
  presented, the group CA and the group state, and checks the member's certificate against
  that CA; a Linux member also receives the keys of both CAs and the token hashes and issues
  its own `clipbridge.local` certificate. Sending the certificate is the point of no return:
  the window then records the device and closes, and reports whether the device confirmed
  that it stored its identity. Errors travel as short codes, never as text, so a device that
  has not proved it knows the code cannot put words in front of the user. The five minutes
  count the time the machine sleeps.
- **Joining an iPhone or iPad**: `clipbridge pair --phone` asks the Linux member that holds
  `clipbridge.local` to open a phone pairing window, with the same limits as for a computer,
  and prints a six-digit code and the fingerprint of the iPhone CA. No secret travels before
  the iPhone trusts the CA:
  1. In Safari the user downloads the configuration profile with the iPhone CA from the
     profile port (plain HTTP, so no certificate warning is ever accepted for port 8765) and
     installs it.
  2. The user compares the fingerprint (at least 64 bits) under the profile's details with
     the printed one, and only then turns on full trust.
  3. The user opens `https://clipbridge.local:8765/pair`, which must load without a
     certificate warning (otherwise the user stops), and types the code there; the token for
     the shortcut comes back on that same connection.

  A relay on the home network cannot present a certificate from the verified CA, so it sees
  neither the code nor the token. The profile has a fixed identifier, so a new one replaces
  the old. Only a hash of each token is stored, and the hashes spread to every Linux member.
- **Devices and revocation**: `clipbridge devices` lists the members and iPhones;
  `clipbridge revoke <name>` removes one. Revocations are signed records that only grow and
  spread to every member. A revoked Linux member still holds the CA keys, so revoking it also
  replaces both CAs. The Linux member where `revoke` runs (on a Mac, a connected Linux
  member) creates a new group CA and a new iPhone CA, issues new certificates to the members
  connected at that moment, and revokes every iPhone token. Members drop the old CA as soon as
  they receive the new one. A member that was off at that moment still trusts the old CA, so
  it can still connect to the revoked member and to other members that were off, but not to
  the rest of the group. `revoke` lists those members, and the user pairs them again, or stops
  clipbridge on them, before they join the network again. The user also deletes the old
  clipbridge profile on every iPhone at once and pairs the iPhones again; until then the old
  profile still trusts the revoked member, so the button must not be used.

## Discovery and the shared address

- Linux members advertise `<device ID>._clipbridge._tcp.local` with SRV, TXT (device ID,
  protocol version, a short group fingerprint, so another group's members are ignored) and
  A/AAAA records under their own host label `cb-<device ID>.local`, never the system host
  name. Macs only browse.
- Linux members run clipbridge's own small mDNS responder, which shares UDP port 5353 with
  avahi-daemon or systemd-resolved. Macs use the system Bonjour service (dns_sd).
- Members connect to the addresses from discovery, never by resolving a `.local` name: a
  static Linux binary cannot resolve `.local` itself. Peers are authenticated by the group
  CA, not by name. A home group is small: Linux members connect to each other, every Mac
  connects to every Linux member, and Macs never connect to each other. A Mac is alone
  whenever no Linux member is reachable.
- The iPhone uses one address for the whole group: **`clipbridge.local`**, with a record
  lifetime of 10 seconds. The live Linux member with the lowest device ID holds it. Macs
  never hold it: they sleep and roam, and when no Linux member is up the iPhone and the Mac
  share through Universal Clipboard anyway.
- **Handover**: a holder that leaves sends goodbye packets for the name first and then tells
  its successor over the member connection; the successor announces at once without probing.
  After a power cut the others notice the missing member and take the name over within
  about 10–20 seconds.
- Only private IPv4, unique-local and link-local IPv6 addresses are published.

## Sync model

- A clipboard change on a member becomes an **event**: a random ID, the origin device, a
  hybrid timestamp, the age, the text, its kind (normal or secret) and how it arrived (a copy
  on the member, the iPhone button, or Universal Clipboard relayed by a Mac, which carries
  copies from an iPhone, an iPad or another Mac).
- Members forward every event the first time they see it to all members they are connected
  to, drop events they have seen, and exchange their current event whenever a connection
  starts. A newer event whose text the member's own clipboard already holds becomes the
  current event without a write; this also removes duplicates when two Macs report the same
  Universal Clipboard item. A Mac that receives the group's own text through Universal
  Clipboard does not turn it into a new event.
- **Member connections** carry frames of a 4-byte length and a JSON message. Each side first
  sends a hello with its role (Linux member or Mac) and its current event; events follow. A
  side that has sent nothing for 5 seconds sends a ping, and a connection that stays silent
  for 15 seconds is closed; a large frame gets more time, as if the link carried at least
  16 KiB a second. A member that stops sends what is queued and a goodbye, so the others
  notice at once. A new connection from a member replaces the old one. A peer that falls a
  whole queue (256 messages) behind is disconnected and gets the current event again in the
  next hello. An event that does not decode or is invalid is dropped, and a hello whose
  current event does not decode counts as one without; a connection that does not start
  with a hello is closed. When the member was away, it closes its connections and waits up
  to 2 seconds for them to end before the engine treats it as back; connections that start
  meanwhile wait too, so every hello after the absence counts.
- **Automatic reports and deliberate actions.** A clipboard watcher (a desktop connector or
  the Mac's pasteboard agent) reports changes; a report of the text the clipboard already
  held, for example offered again by a clipboard manager, makes no event. Deliberate actions
  (the iPhone button, `clipbridge copy`, tmux, "send even if secret" on a Mac) always make an
  event, and the text also goes to the member's own clipboard.
- Events are ordered by a hybrid logical clock, then by event ID. No timestamp is ever
  refused: members would disagree about where to draw the line, and the group could split. A
  clock far ahead moves every member's hybrid clock forward; events that depend on each other
  stay in order, but while the clocks are ahead of real time, copies made independently are
  ordered by the logical counter until real time catches up. Only timestamps past the year
  9999 are invalid, the same bound on every member. Each hello carries the sender's wall
  clock, and `clipbridge status` warns when a connected peer's clock differs by more than 5
  seconds. Before the hybrid clock passes the last mark it saved, the service saves a new
  mark 10 seconds ahead, so after a restart, even after a crash, it never issues a timestamp
  below one it issued before.
- **Age**: every event carries how long ago it was copied. The receiver turns it into a
  local time, so an old event that arrives late, for example after a reconnect, never looks
  recent. Local durations are measured on a clock that counts the time the machine slept and
  does not jump when the wall clock is set (`CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on
  macOS). Connections have heartbeats and are closed before the machine sleeps, and an event
  that waited in a queue is sent with that time added to its age. The hybrid clock is never
  used to measure durations.
- **Secrets** travel in a hello only as a mark without their text, so the group converges on
  them too; a member that knows a secret only by its mark has no current text until the full
  event reaches it. Each member remembers the texts of secrets of the last 12 hours (up to
  4096, as keyed hashes in memory only): sent, received, and skipped because a password
  manager marked them. When a clipboard watcher offers such a text again without its mark,
  for example a clipboard manager restoring it, it makes no event; a deliberate action makes
  it a secret event again.
- **Group state and each member's own clipboard are separate.** The group's current text is
  always the latest event, so all members converge whatever happens to the connections. What
  goes into a member's own clipboard is a local decision:
  - a live event (copied at most 60 seconds ago) that becomes the group's current event is
    written;
  - for 30 seconds after the member itself was away (the service started, the machine woke
    up or its network came back), an event that becomes the group's current event is written
    even when it is old, unless the member copied something before it was back in sync with
    the group (a connection up and a hello exchanged). The connections from before the
    absence are closed first;
  - nothing else is written: a group text the member already knew is not written again, and
    a member that only lost its peers, because they went away, keeps its clipboard.

  So a member that returns with an old copy does not overwrite the clipboards of the others,
  a member that wakes up gets the latest text, and a copy made while away is replaced only by
  a live copy made after it. Writes carry a sequence number, so they are applied in order. On a member
  without a desktop, the service keeps this own clipboard text itself, and `clipbridge paste`,
  tmux and the console helper use it.
- **No echo.** A member does not report a text it wrote into its clipboard as a new copy,
  even when the clipboard reports it up to 10 seconds late.

## The iPhone button

One shortcut, published as an iCloud link with an import question for the token. It reads
the iPhone clipboard and sends `POST https://clipbridge.local:8765/sync` with the JSON body
`{"v": 1, "text": "…"}` (optionally `"secret": true`, which makes a secret event) and the
header `Authorization: Bearer <token>`. The member that holds the name decides the direction:

1. A computer in the group copied something less than 45 seconds ago → the member returns
   that text, and the shortcut puts it on the iPhone clipboard. The user most likely pressed
   Ctrl+C or ⌘C a moment ago and picked up the phone. Text that came from the iPhone itself,
   directly or through Universal Clipboard, does not count as a computer's copy.
2. Otherwise, if the iPhone text is new, that is, neither the group's text nor the text of
   the member's own clipboard → it becomes a group event, and it also goes to the member's
   own clipboard (with auto-paste, if it is on).
3. Otherwise, if the member's own clipboard holds another text → the member returns it. The
   member's own clipboard, not the group state, follows the rules above, so a member that
   returned with an old copy never sends that copy to the iPhone.
4. Otherwise there is nothing to transfer.

The answer is always HTTP 200 with JSON, because the shortcut cannot read status codes:
`{"v": 1, "direction": "to_iphone" | "from_iphone" | "none" | "error", "copy": "…",
"expires_in": 0, "message": "…"}`. The shortcut writes `copy` with **Local Only** when
`direction` is `to_iphone` (with an expiry for a secret) and shows `message` as a
notification. Errors, such as a revoked token, come back as `direction: "error"` with a
human message; a secret never appears in `message`.

## Linux components

clipbridge for Linux is one program that runs as up to three processes with different rights
and lifetimes. The installer enables what the device needs.

### 1. Service

- A system service that runs from boot as its own system user `clipbridge`, with or without
  a desktop.
- Network, group, discovery, the shared address, sync and the current text.
- Local control socket `/run/clipbridge/control.sock`, mode 0660, group `clipbridge`: the
  kernel admits only root and members of that group. The installer adds the desktop or tmux
  user to the group. Frames are a small JSON header plus the raw text.
- Command line: `clipbridge copy` (standard input to the group), `clipbridge paste` (the
  member's own clipboard text to standard output), `clipbridge pair`, `join`, `devices`,
  `revoke`, `status`.
- tmux: copying in tmux copy mode goes to the group (`copy-command`), and a key binding
  pastes the member's own clipboard text into any program inside tmux. A login snippet starts tmux on the
  text console.

### 2. Desktop connector

- A user process started with any graphical session (XDG autostart, which nearly every
  desktop supports; a systemd user unit where needed). It links the desktop clipboard to the
  service over the control socket. When the display connection drops, it reconnects with a
  backoff, and exits only when the session is gone.
- Clipboard access, chosen automatically, in pure Go:

  | Desktop                                                                  | Access                                                    |
  |--------------------------------------------------------------------------|-----------------------------------------------------------|
  | Wayland with `ext-data-control-v1` or `wlr-data-control` (KDE, sway, Hyprland, labwc, Wayfire, COSMIC) | the data-control protocol |
  | X11 (XFCE, LXQt, MATE, Openbox, …)                                       | X11 selections, change events from XFixes                 |
  | GNOME and other Wayland desktops without data-control                    | X11 selections through XWayland (expected to work on GNOME, see the open questions; best effort elsewhere) |

- Only the regular clipboard is watched; mouse selections are not sent to the group. A
  received text goes into both the clipboard and the primary selection, so Ctrl+V works in
  applications, and Shift+Insert and the middle mouse button work in terminals.
- **Auto-paste** (optional): after the connector writes an event made by the iPhone button
  (via `iphone`), it presses Shift+Insert through a virtual keyboard (uinput). Never for
  Universal Clipboard items or other events, and not on the lock screen.

### 3. Console helper

- Optional, root with only `CAP_SYS_ADMIN`, because only that may inject input into a
  console. It runs with `clipbridge` as a supplementary group and connects to the control
  socket as a client; it listens on nothing.
- On a double press of Right Ctrl (configurable; a modifier alone types nothing, so
  programs do not notice) it injects the member's own clipboard text into the active virtual
  console with TIOCSTI on `/dev/tty0`. This works at the login prompt, in `sudo` and in any
  console program, with any characters, independent of the console keyboard layout.
- Only a single line is injected by default; multi-line text needs a second double press.
  Control characters, escape sequences and invalid UTF-8 are removed. This stops a local
  user from planting commands that would run in a root console.

## macOS

- **Service**: the same service as on Linux, as a LaunchDaemon under a hidden service account.
  macOS grants local network access to daemons without a prompt. It only dials out to Linux
  members, so the macOS firewall needs no exception.
- **Pasteboard agent**: a LaunchAgent in the user's session, linked to the service over a
  local socket. It checks the pasteboard change counter every 0.5 seconds on the main thread
  and reads the text only after a change.
- Skips items marked by password managers: `org.nspasteboard.ConcealedType`,
  `org.nspasteboard.TransientType`, `org.nspasteboard.AutoGeneratedType` and the older
  markers listed on nspasteboard.org.
- Items that arrive through Universal Clipboard are relayed to Linux, marked
  `universal-clipboard`; they do not count as a computer's copy for the iPhone button.
  Received secrets are written with `org.nspasteboard.ConcealedType` and for the current host
  only, so clipboard histories skip them and they do not travel over Universal Clipboard.
- Finds members with the system Bonjour service and trusts only the group CA, in its own
  configuration; the system keychain is not changed.
- Installing needs administrator rights once. Later: a menu bar item with pause, status and
  devices.

## Passwords

- Automatic sync skips items marked as secret: the macOS types above, and on Linux the
  presence of the `x-kde-passwordManagerHint` type, whatever its value.
- Received secrets are written with the same marks clipbridge reads: the
  `x-kde-passwordManagerHint` type on Linux and the macOS types above, so clipboard managers
  skip them.
- Some desktops and clipboard managers keep a copy of the last clipboard text and offer it
  again without the mark. The engine remembers secret texts, including the marked items it
  skipped, and such an offer makes no event (see the sync model).
- Explicit actions may carry a secret: "send even if secret" on the Mac and the console
  paste; the shortcut may mark a text as secret. Secret events are kept only in memory and
  expire 60 seconds after the copy, judged by the event's age. When a secret that a connector
  wrote expires, the connector gives up the clipboard, so the desktop does not keep it.
- Only root and members of the `clipbridge` group receive secrets through the control socket.

## Limits

- Text only, UTF-8, up to 1 MiB per item.

## Security

| Threat                                                         | Measure                                                                    |
|----------------------------------------------------------------|----------------------------------------------------------------------------|
| Someone on the home network reads the traffic                  | TLS 1.3 everywhere                                                         |
| Someone guesses or intercepts the pairing code of a computer   | CPace inside TLS: one online guess per attempt, at most three per pairing window, no offline attack |
| Someone attacks the pairing of an iPhone                       | the same attempt limits; the profile comes over a separate plain-HTTP port, so no certificate warning is ever accepted for the pairing page; the user compares the iPhone CA fingerprint before trusting it; the code and the token travel only over a connection that the trusted CA authenticates, so a relay sees neither |
| A device impersonates a member (for example, a host that answers `clipbridge.local` on another network) | mutual TLS with the group CA; members dial discovered addresses and check the peer's certificate; the iPhone accepts only a certificate from the iPhone CA, so an impostor gets neither the token nor the text |
| A device is lost or stolen                                     | `clipbridge revoke`; for a Linux member also a new group CA, a new iPhone CA and new tokens, the old profile deleted on every iPhone, and the members that were off paired again before they rejoin |
| A member is compromised                                        | it can read the group clipboard, by design. It cannot read the iPhone's other HTTPS traffic: the iPhone CA is restricted by name constraints to `clipbridge.local` and names below it, and excludes IP addresses and other name forms. The Mac never changes its system trust |
| A bug in the network code                                      | memory-safe language; the service runs as an unprivileged user in a systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateDevices`, no capabilities, restricted address families and system calls) |
| A local user abuses the console helper                         | the helper listens on nothing; the control socket admits only root and the `clipbridge` group; single-line injection by default with control characters removed |
| Requests from outside the home network                         | the service accepts connections only from private, unique-local and link-local addresses, checked in the program and by systemd |
| A compromised dependency or build                              | few dependencies, `govulncheck`, actions pinned to commit SHAs, release builds in CI with checksums and build provenance |

## Build

- Go, with `CGO_ENABLED=0` everywhere except on macOS, where the service's Bonjour binding
  (dns_sd) and the pasteboard agent use cgo with a small Objective-C file. From then on CI
  builds the macOS targets on macOS runners with cgo.
- Targets: `linux/amd64`, `linux/arm64`, `linux/arm` with ARMv7 and ARMv6, `darwin/arm64`
  and `darwin/amd64`.
- The Raspberry Pi Zero W (ARMv6) cannot run Ubuntu; it runs Raspberry Pi OS. clipbridge
  does not depend on distribution specifics. The systemd units use directives from systemd
  248 and later and are checked with `systemd-analyze verify`.
- Third-party code: `golang.org/x/net` and `golang.org/x/sys` (BSD-3-Clause), `jezek/xgb`
  (BSD-3-Clause), and the CPace implementation copied from `rsc.io/cmd/mote` v0.1.3
  (BSD-3-Clause) into `internal/third_party/cpace`. Release archives carry their notices.

## Roadmap

The order may change.

1. Repository scaffolding.
2. Service core: sync engine, group and pairing, discovery, member connections, control
   socket, command line; Linux without a desktop and tmux.
3. macOS: service as a LaunchDaemon and the pasteboard agent.
4. Desktop connector: Wayland data-control, X11, GNOME through XWayland.
5. iPhone: `/sync`, the pairing pages, the published shortcut.
6. Console helper and auto-paste.
7. Packages and signed releases.

## Open questions

These need experiments on real devices; CI cannot answer them.

- Does the Mac see a Universal Clipboard item from the iPhone (the change counter moves)
  without a paste on the Mac, and which types does the item carry?
- Does reading the pasteboard types trigger the macOS pasteboard privacy alert, and is the
  alert enforced by default on macOS 27.2 and later?
- On iOS 18, 26 and 27: does Shortcuts trust the name-constrained iPhone CA and reach
  `clipbridge.local` (Local Network prompt, first-run prompts, behaviour from the Lock
  Screen), and how fast does it notice a handover of the name?
- On GNOME with on-demand XWayland: do copies in native Wayland apps reach the connector
  promptly, and do its writes become the Wayland selection without focus?
- Console injection at an agetty login prompt, in `sudo` and in vim on Ubuntu and Raspberry Pi
  OS; latency and CPU of the double-tap trigger on a Pi Zero W.
- Images and files after the first version.

## Decision log

| ID   | Decision                                                                                   |
|------|--------------------------------------------------------------------------------------------|
| D-1  | License: AGPL-3.0-only. Code contributions are not accepted, so no contributor agreement is needed. |
| D-2  | Language: Go, for reliable ARMv6 builds, TLS and networking in the standard library, and development speed. |
| D-3  | A group of equal members instead of a central server; any member may be off.              |
| D-4  | Encryption with the project's own TLS and pairing instead of an overlay VPN, which on iOS would conflict with other VPN apps. |
| D-5  | All devices are on one home network; no relay.                                             |
| D-6  | Mac and Linux sync automatically; the iPhone uses one button that picks the direction.     |
| D-7  | Console without a desktop: tmux for copy and paste, a root helper for console paste outside tmux. |
| D-8  | The repository is in English only.                                                         |
| D-9  | Pairing a computer: code entry with CPace inside TLS 1.3 instead of comparing digits, which a man in the middle can grind. |
| D-10 | The iPhone trusts a separate CA restricted by name constraints; the token is shown only after that trust is in place. |
| D-11 | Members talk on their own advertised port; port 8765 serves only the iPhone.               |
| D-12 | Own mDNS responder on Linux, system Bonjour on macOS: no Go library publishes a separate name with its own lifetime, probes without renaming and sends goodbyes. |
| D-13 | Only Linux members hold `clipbridge.local`; Macs only dial out.                            |
| D-14 | The hybrid clock never refuses a timestamp and warns about skew measured per connection; events carry their age for the 45-second rule and secret expiry, and local durations count sleep. |
| D-15 | macOS runs the service as a LaunchDaemon plus a pasteboard LaunchAgent, which avoids the Local Network prompt; installing needs administrator rights. |
| D-16 | Desktop clipboard in pure Go: Wayland data-control (both protocol variants) and X11 through `jezek/xgb`; no `wl-clipboard`. |
| D-17 | Console paste injects a single line by default, with control characters removed.         |
| D-18 | Secrets reach only root and the `clipbridge` group; the control socket enforces it through file permissions. |
| D-19 | The group state is last-writer-wins; the protection of copies made during a disconnect applies only to writing the local clipboard (live window 60 s, rejoin window 30 s). The first version kept that rule in the group state, and a review showed that the group could then split for good. |
| D-20 | The rejoin window opens only on a local sign that the member itself was away (start, wake, network back), not when it merely lost its peers. |
| D-21 | Each member keeps its own clipboard text apart from the group state; `clipbridge paste`, tmux, the console helper and the iPhone button use it. |
| D-22 | A secret travels in a hello as a mark without its text, so the group converges on secrets too. |
| D-23 | Revoking a Linux member replaces both CAs, because it holds their keys; members that were off still trust the old CA until they pair again, and iPhones delete the old profile. |
| D-24 | Local durations use a clock that counts sleep and ignores wall-clock steps (package `uptime`). |
| D-25 | The hybrid clock saves a mark 10 seconds ahead before passing the last one, so it never goes back after a crash. |
| D-26 | iPhone pairing: the profile over a separate plain-HTTP port and the fingerprint check first, then the code on a page that the trusted CA authenticates. |
| D-27 | The engine remembers secrets for 12 hours; a watcher offering one again without its mark makes no event, a deliberate action makes it a secret again. |
| D-28 | Two ways in: watchers report changes (no event when nothing really changed), deliberate actions always send and also write the member's own clipboard. |
| D-29 | Certificates are checked with the local clock, but never earlier than the group CA's start: a clock that is behind does not break the group, an expired certificate is still rejected. |
| D-30 | Pairing runs inside TLS with self-signed certificates on the new device's side and channel binding (an exporter and both certificates) instead of a separate encryption layer: CPace authenticates the TLS session, and everything after it travels in that session. |
