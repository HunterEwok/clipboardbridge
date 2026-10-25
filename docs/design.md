# Design

Status: agreed design; the code follows it stage by stage. This document describes how
Clipboard Bridge works and why; what comes next, the plans not built yet and the research are
in [roadmap.md](roadmap.md), and the wire format is in [protocol.md](protocol.md). Decisions
are listed in the [decision log](#decision-log) at the end; questions that still need an
experiment are under [open questions](#open-questions).

## Goals

- One clipboard for the user's phones (iPhone and Android), Macs, Windows PCs and any number
  of Linux machines on one home network, and away from home through the group's own
  encrypted tunnel (built for computers; the phones follow).
- Copy and paste with the normal means of each system, and at most one press on the iPhone.
- Linux with and without a desktop, from a Raspberry Pi Zero W to a workstation, without
  depending on a particular distribution or desktop.
- Encrypted and paired; no cloud, no accounts, no telemetry.

## Non-goals

- Sync through anyone else's servers or services. Away from home, devices reach the group
  only through its own tunnel (see "Sync away from home").
- Working around iOS. iOS lets an app read the clipboard only after a user action.
- Sync between Apple devices. Universal Clipboard already does it.
- Clipboard history.

## Devices and roles

| Device                  | Component                         | How it takes part                                              |
|-------------------------|-----------------------------------|----------------------------------------------------------------|
| Linux with a desktop    | service + desktop connector       | automatic, through the desktop clipboard                       |
| Linux without a desktop | service (+ console helper, planned) | its own clipboard: tmux, `cbb copy`/`paste`                  |
| Mac                     | service + pasteboard agent        | automatic                                                      |
| Windows                 | service + clipboard agent         | automatic                                                      |
| iPhone, iPad            | the app, or a shortcut            | the app: one tap or the Action button; the shortcut: one press |
| Android phone           | the app                           | receives by itself; sends by itself (accessibility service) or with one tap |
| Small Linux device      | the lite member, `cbb`            | `cbb copy`/`paste`/`watch`; no desktop clipboard               |

Linux machines, Windows PCs, Macs and lite members are equal **members** of a **group**, and
so is a phone with the app. There is no central server, and any member may be switched off
at any time. In a group made by a phone app, the phones are its admins (see "The phone
apps" below).

## Identifiers and ports

- **Device ID**: 128 random bits as 32 lowercase hex characters. It fits in a DNS label and
  compares the same way everywhere.
- **Member port**: Clipboard Bridge's one port, TCP 8764 unless the installer was given another,
  advertised in the mDNS SRV record. Every computer and lite member listens there for mutual
  TLS (Macs since D-46); phones only dial. The first bytes of a connection pick what it gets (docs/protocol.md, section 3):
  - members and the phone app, with the member ALPN protocol and mutual TLS;
  - pairing, with its own ALPN protocol;
  - the shortcut's HTTPS (`/sync` and the pairing page `/pair`), with no client
    certificate, for any other ALPN protocol;
  - plain HTTP that serves only the iPhone CA's configuration profile, and only while a
    phone pairing window is open. The profile is public, and the user checks its
    fingerprint before trusting it.

  A computer that joins by QR code listens there too, since it is in no group yet. One port
  is one rule in a firewall, and changing it is one setting.

## Group and pairing

- **The shortcut only syncs.** With the shortcut (no app), `cbb new` on the first Linux
  machine creates the group and `cbb pair -phone` pairs the phone; every further computer
  joins with `cbb pair` on the root or an admin, which shows a six-digit code to type on the
  new computer. The shortcut's token gives only `/sync`: a copied or stolen token can sync
  the clipboard until it is revoked, but cannot add a device. `cbb pair -phone -new-token`
  revokes every shortcut's token and pairs the iPhone again; `cbb revoke` removes one. With
  the phone app, the phone admits computers by their QR code (section 6 of the protocol,
  "The joiner listens").
- **Creating the group**: the first `cbb pair` or `cbb pair -phone` on a Linux
  machine that is in no group creates it: the group CA and the iPhone CA. A Mac cannot start
  a group.
- **Group CA**: ECDSA P-256, valid 20 years, path length 0. Every member has its own P-256
  key and a certificate from the group CA, valid 2 years and renewed when less than 240 days
  remain. Its `NotBefore` is the CA's, and members check certificates with their own clock but
  never earlier than the CA's start, so a Raspberry Pi that boots with a clock years behind
  real time still accepts them; expired certificates are rejected. Linux members keep a copy
  of the CA key, so any of them can admit a new device. TLS 1.3 only, with the ALPN protocol
  `clipboardbridge/1`; a client checks that the server's certificate names the device it found in
  discovery.
- **iPhone CA**: ECDSA P-256, valid 20 years, path length 0, with critical name constraints
  that permit only the DNS name `clipboardbridge.local` and names below it (and URI and e-mail
  names under `clipboardbridge.invalid`) and exclude every IP address. Every Linux member holds its key and its
  own `clipboardbridge.local` server certificate from it, valid 397 days from a day before it was
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
- **Joining a computer from a Linux member**: `cbb pair` on a Linux member (on a Mac,
  the command asks a connected Linux member) shows a six-digit code and opens a pairing
  window for five minutes (one attempt at a time, closed after a success or the third failed
  attempt; an attempt that has started may finish after the five minutes). On the new device
  the user runs `cbb pair -code` and types the code (it is read from the terminal or standard input, never
  from the command line, where other users of the machine could read it). The new device
  connects to the member's port with
  the ALPN protocol `clipboardbridge-pair/1` and presents a self-signed certificate for the key
  it will keep. The two run the CPace password-authenticated key exchange
  (CPACE-X25519-SHA512) with the code, bound to the TLS session by an exporter and to both
  certificates, and confirm the key, the new device first. An attacker gets one guess per
  attempt and no offline attack; a relay between two TLS sessions fails. An attempt that
  reaches the exchange and does not succeed counts as a failure. The new member then
  receives, over the TLS session that CPace authenticated, a certificate for the key it
  presented, the group CA and the group state, and checks the member's certificate against
  that CA; a Linux member also receives the keys of both CAs and the token hashes and issues
  its own `clipboardbridge.local` certificate. Sending the certificate is the point of no return:
  the window then records the device and closes, and reports whether the device confirmed
  that it stored its identity. Errors travel as short codes, never as text, so a device that
  has not proved it knows the code cannot put words in front of the user. The five minutes
  count the time the machine sleeps.
- **Joining an iPhone or iPad**: `cbb pair -phone` asks the Linux member that holds
  `clipboardbridge.local` to open a phone pairing window, with the same limits as for a computer,
  and prints a QR code of the profile page, the first 64 bits of the iPhone CA's
  fingerprint and a six-digit code. The user only scans, compares and types digits. No
  secret travels before the iPhone trusts the CA:
  1. The camera opens the profile page (plain HTTP, so no certificate warning is
     ever accepted for HTTPS), which walks through the steps; the user installs the
     configuration profile with the iPhone CA.
  2. The user compares the fingerprint's first 64 bits under the profile's details with the
     printed ones, and only then turns on full trust.
  3. The user adds the shortcut from the same page and runs it. On its first run it asks for
     the code and posts it to `https://clipboardbridge.local:8764/pair`, which only works once the
     CA is trusted; the token comes back on that connection, and the shortcut keeps it in
     iCloud Drive (Shortcuts/clipboardbridge/token.txt). Told later that its token is unknown, it
     deletes it, so the next run pairs again. The same page also takes the code in Safari
     and shows the token, for a shortcut built by hand.

  The shortcut is a property list generated from the code (`tools/shortcut`) and signed on
  a Mac with `shortcuts sign`, since iOS imports only signed shortcuts; the build embeds the
  signed file. The profile cannot be signed so that iOS shows it as verified: it carries
  the group's own CA, made on the member, and only a key that Apple's roots vouch for would
  do, which a release cannot ship. The fingerprint comparison is what protects it.

  A relay on the home network cannot present a certificate from the verified CA, so it sees
  neither the code nor the token. The profile has a fixed identifier, so a new one replaces
  the old. Only a hash of each token is stored, and the hashes spread to every Linux member.
- **Devices and revocation**: `cbb status` lists the members and iPhones;
  `cbb revoke <name>` removes one. Revocations are signed records that only grow and
  spread to every member. A revoked Linux member still holds the CA keys, so revoking it also
  replaces both CAs. The Linux member where `revoke` runs (on a Mac, a connected Linux
  member) creates a new group CA and a new iPhone CA, issues new certificates to the members
  connected at that moment, and revokes every iPhone token. Members drop the old CA as soon as
  they receive the new one. A member that was off at that moment still trusts the old CA, so
  it can still connect to the revoked member and to other members that were off, but not to
  the rest of the group. `revoke` lists those members, and the user pairs them again, or stops
  Clipboard Bridge on them, before they join the network again. The user also deletes the old
  Clipboard Bridge profile on every iPhone at once and pairs the iPhones again; until then the old
  profile still trusts the revoked member, so the button must not be used. The records and
  the list are described in "Admin phones, the devices list and revocation" below.

## Discovery and the shared address

- Linux members advertise `<device ID>._clipboardbridge._tcp.local` with SRV, TXT (the protocol
  version `v=1`; the group tag `g=`, a short fingerprint of the group CA, so the members of
  another group, or of a replaced CA, are ignored; and `p=1` while a pairing window is open)
  and A/AAAA records under their own host label `cb-<device ID>.local`, never the system
  host name. Macs only browse.
- Linux members run Clipboard Bridge's own small mDNS responder, which shares UDP port 5353 with
  avahi-daemon or systemd-resolved; a CI job checks that avahi browses and resolves it. It
  answers each query with the addresses of the interface the query arrived on, and with an
  NSEC record when the name has no address of the asked type, so a resolver does not wait
  for it. Records that name a host (SRV, A, AAAA) live 120 seconds, PTR and TXT 75 minutes.
  The member announces its records twice at start and after every change, and sends
  goodbyes, without the cache-flush bit, for addresses that go away and for everything when
  it stops. A record is multicast at most once a second on an interface, and
  a legacy unicast resolver gets a few answers a second at most. Packets are read record by
  record, so a record Clipboard Bridge cannot read, such as an Apple device's instance name with a
  dot in it, costs only itself. It browses at growing intervals, listing the members it
  knows as known answers, and asks again for the records of the members it found at 80,
  85, 90 and 95 percent of their lifetime, so they do not expire while the members are
  there. A received record lives no longer than Clipboard Bridge's own records of its type, and
  only names in the form of device IDs count as members. Names are not probed: device IDs
  are random, and the election, not a probe, decides who holds `clipboardbridge.local`. Macs
  publish and browse with the same code, as full members; a test on macOS showed that it shares port 5353 with
  mDNSResponder and that the system's `dns-sd` sees what it publishes, so no Bonjour
  binding is needed.
- Members connect to the addresses from discovery, never by resolving a `.local` name: a
  static Linux binary cannot resolve `.local` itself. Peers are authenticated by the group
  CA, not by name. A home group is small: of two full members (Linux, Windows or Mac) the
  one with the lower device ID dials, and the other dials as well when no connection has
  come up within 30 seconds, so a firewall that keeps the first out does not keep them
  apart; full members dial the lite members, and phones dial every member. With no Linux
  member on, the Macs, the lite members and the phones still sync among themselves.
- The iPhone uses one address for the whole group: **`clipboardbridge.local`**, with a record
  lifetime of 10 seconds. Among the live full members, a machine that does not sleep holds
  it first and a laptop only when no other is on, then the lowest device ID; the service
  guesses which it is from a battery, `cbb holder` overrides the guess, and the TXT key `h`
  tells the others (D-53, "Full members, admins and the operating system").
- **Handover**: a holder that leaves sends goodbye packets for the name first and then closes
  its member connections with a goodbye; the member that is now the lowest sees that at
  once and announces the name. After a power cut the others notice the missing member when
  its connection falls silent and take the name over within about 15–20 seconds.
- Only private IPv4, unique-local and link-local IPv6 addresses are published.
- **Known networks** (D-63). A full member publishes itself, and takes connections on the
  member port, only on networks where it met its group: where it created or joined the
  group (not by a remote invitation), opened a pairing window, or had a member connection
  come up. Elsewhere, in a café or a hotel, it only browses, so that its host label and the
  group tag do not follow a laptop around and its port answers nobody there. A network is
  told by the IPv4 networks of the interface (its IPv6 networks when it has none, since ISPs
  change IPv6 prefixes) and the link-layer address of its default gateway, read from the
  system's ARP table (`internal/netid`), so the same `192.168.1.0/24` behind a café's router
  is another network. Just after a link comes up, before the gateway's address is in the
  table, the addresses alone count. `networks.json` in the state directory keeps a random key
  and, for at most 64 networks, an HMAC of each under that key, which says nothing about
  them. A member that is updated to a version with the list and has none yet takes the
  networks it is on as known, as it is most likely at home then. In a network it does not
  know it still finds the members that publish themselves, and once a connection to one
  comes up there the network is known. `cbb status` names the interfaces where it keeps
  quiet; `sudo cbb network` takes the current networks as known, for a home with a new
  router where every member keeps quiet. A pairing window takes connections on any network
  while it is open. The lite member publishes itself everywhere: it runs on boards that stay
  at home.

## Sync model

- A clipboard change on a member becomes an **event**: a random ID, the origin device, a
  hybrid timestamp, the age, the text, its kind (normal or secret) and how it arrived (a copy
  on the member, sent from a phone (the app or the iPhone shortcut's button), or Universal
  Clipboard relayed by a Mac, which carries
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
  (sending from a phone, `cbb copy`, tmux, "send even if secret" on a Mac) always make an
  event, and the text also goes to the member's own clipboard.
- Events are ordered by a hybrid logical clock, then by event ID. No timestamp is ever
  refused: members would disagree about where to draw the line, and the group could split. A
  clock far ahead moves every member's hybrid clock forward; events that depend on each other
  stay in order, but while the clocks are ahead of real time, copies made independently are
  ordered by the logical counter until real time catches up. Only timestamps past the year
  9999 are invalid, the same bound on every member. Each hello carries the sender's wall
  clock, and `cbb status` warns when a connected peer's clock differs by more than 5
  seconds. Before the hybrid clock passes the last mark it saved, the service saves a new
  mark 10 seconds ahead, so after a restart, even after a crash, it never issues a timestamp
  below one it issued before.
- **Age**: every event carries how long ago it was copied. The receiver turns it into a
  local time, so an old event that arrives late, for example after a reconnect, never looks
  recent. Local durations are measured on a clock that counts the time the machine slept and
  does not jump when the wall clock is set (`CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on
  macOS). Connections have heartbeats; the ones from before a sleep are closed when the
  machine wakes (a sleeping holder of `clipboardbridge.local` is replaced after the 15-second
  silence timeout, as it sends no goodbye), and an event
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
  - for 30 seconds after the member itself was away (the service started or the machine woke
    up), an event that becomes the group's current event is written
    even when it is old, unless the member copied something before it was back in sync with
    the group (a connection up and a hello exchanged). The connections from before the
    absence are closed first. A hello that arrived before the member noticed it had slept is
    written too, when the member is back in sync. A network that drops without a sleep does
    not open the window: such a member gets the group's text only while it is live;
  - nothing else is written: a group text the member already knew is not written again, and
    a member that only lost its peers, because they went away, keeps its clipboard.

  So a member that returns with an old copy does not overwrite the clipboards of the others,
  a member that wakes up gets the latest text, and a copy made while away is replaced only by
  a live copy made after it. Writes carry a sequence number, so they are applied in order. On a member
  without a desktop, the service keeps this own clipboard text itself, and `cbb paste`,
  tmux and the console helper use it.
- **No echo.** A member does not report a text it wrote into its clipboard as a new copy,
  even when the clipboard reports it up to 10 seconds late.

## The iPhone button

The button is for an iPhone without the app; a phone with the app, iPhone or Android, is a
member and sends from the app instead (see "The phone apps" below). One
shortcut, published as an iCloud link with an import question for the token. It reads
the iPhone clipboard and sends `POST https://clipboardbridge.local:8764/sync` with the JSON body
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

Clipboard Bridge for Linux is one program that runs as up to three processes with different rights
and lifetimes. The installer enables what the device needs.

### 1. Service

- A system service that runs from boot as its own system user `clipboardbridge`, with or without
  a desktop.
- Network, group, discovery, the shared address, sync and the current text. It keeps the
  identity and the clock mark in its state directory (`/var/lib/clipboardbridge`) and listens on
  a member port chosen at start. Of two Linux members, the one with the lower device ID
  dials the other, so they make one connection; a member keeps dialing a member it finds,
  waiting up to 30 seconds between attempts, at the addresses and port that discovery last
  saw. It notices that the machine slept when the clock that counts sleep moves further than
  the one that does not, and then rejoins. At most 32 connections to the member port may be
  in their TLS handshake or a pairing attempt at once; errors such as running out of file
  descriptors only pause the accept loops. On stop it sends the mDNS goodbyes first, then
  the member goodbyes.
- Local control socket `/run/clipboardbridge/control.sock`, mode 0660, group `clipboardbridge`: the
  kernel admits only root and members of that group. It is made in a private directory and
  moved into place, so it is never reachable with a wider mode. The installer adds the desktop or tmux
  user to the group. That group is for the clipboard only: everything that changes the group
  goes to the admin socket `admin.sock` next to it, mode 0600 (on Windows a directory that
  only the system and administrators enter), so only root reaches it (D-62). A program that
  runs as a user of the group, a browser exploit for example, cannot admit a device of its
  own, remove one, or turn on sync away from home. Each message is a JSON header on one line followed by the raw text.
  Commands send one request and read the answers; a desktop connector keeps its connection
  open to receive writes and report copies. Its watch request carries what the clipboard
  holds; a write that no connector got, such as the group's text at boot, goes to the next
  one that connects, if it is still the member's own text.
- Command line: `cbb copy` (standard input to the group), `cbb paste` (the
  member's own clipboard text to standard output), `cbb new`, `cbb pair`,
  `revoke`, `status` (which lists the group's devices too). `cbb new` creates a group; `cbb pair` joins one on a device in no group and admits a device on the root or an admin.
  `cbb pair` finds the member with an open pairing window by its TXT record, or uses
  the address that `pair` prints, for networks where multicast does not pass. It talks to
  one member only, tries that member's addresses (IPv4 first, link-local last) until one
  answers, and stops after the first attempt in which the other side could check the code,
  so a device that only pretends to pair gets one guess at most. When more than one device
  announces a window, it asks for the address. Hanging up cancels it, and it gives up after
  two minutes, or, while it shows its QR code for the phone, after the five minutes it waits
  for the window.
- tmux: copying in tmux copy mode goes to the group (`copy-command`), and a key binding
  pastes the member's own clipboard text into any program inside tmux. The binding runs
  `cbb paste -terminal`, so that a text from another device cannot drive the terminal or the
  shell: no control characters (an escape could end bracketed paste and run the rest), only
  the first line, no final line feed, and never a secret. A login snippet starts tmux on the
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
- **Auto-paste** (optional): after the connector writes an event sent from a phone (via
  `phone`), it presses Shift+Insert through a virtual keyboard (uinput). Never for
  Universal Clipboard items or other events, and not on the lock screen.

### 3. Console helper (planned)

Not built yet (roadmap item 10); the design:

- Optional, root with only `CAP_SYS_ADMIN`, because only that may inject input into a
  console. It runs with `clipboardbridge` as a supplementary group and connects to the control
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
  macOS grants local network access to daemons without a prompt. It listens on UDP 5353
  for mDNS (D-32), and dials and takes connections like the other full members, from the
  home network only. It may hold `clipboardbridge.local`, a laptop only as a fallback
  (D-53); it does not admit devices yet (step 4 of "Full members, admins and the operating
  system"). `install.sh` lists the
  service in the application firewall (`socketfilterfw --add` and `--unblockapp`), and
  `uninstall.sh` takes it away; `CBB_FIREWALL=no` leaves the firewall alone.
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
- Finds the members with Clipboard Bridge's own mDNS code, publishing itself as a full member,
  and trusts only the group CA, in its own configuration; the system keychain is not changed.
- Installing needs administrator rights once. Later: a menu bar item with pause, status and
  devices.

## Windows

- **Service**: the same service as on Linux, as a Windows service (`cbb.exe service`) under
  the virtual account `NT SERVICE\clipboardbridge`, with only `SeChangeNotifyPrivilege`, and
  restarted by the service manager when it fails. It listens like a Linux member and speaks
  with the `linux` role, since roles describe what a member does on the network. Its data is
  in `ProgramData\clipboardbridge` (`state`, `logs`, `run`), owned by administrators with an
  access list for the system, administrators and the service only; the port is `CBB_PORT` in
  the service's environment.
- **Control socket**: an AF_UNIX socket, `ProgramData\clipboardbridge\run\control.sock`.
  Windows lets a client connect only with write access to the socket file, which inherits the
  protected access list the service gives `run` before it listens: the system,
  administrators, the service, the local `clipboardbridge` group, and each member of the group
  by its own SID as the service finds them at start, so a user just added connects without
  signing in again.
- **Clipboard agent**: `cbbw.exe agent`, the same program linked without a console window,
  started at every sign-in from the `Run` key of the machine, once per session (a named
  mutex). It polls the clipboard sequence number every 0.5 seconds, like the Mac, and opens
  the clipboard only after a change, from one thread with a message-only window. It reads
  `CF_UNICODETEXT`; text ends at the first NUL, and CR LF becomes LF (and back when it
  writes).
- **Secrets**: an item with `ExcludeClipboardContentFromMonitorProcessing` or
  `Clipboard Viewer Ignore`, or with `CanIncludeInClipboardHistory` set to 0, is a secret.
  Received secrets are written with all of these and `CanUploadToCloudClipboard` set to 0, so
  the clipboard history, the cloud clipboard and other monitors skip them.
- **mDNS**: the service shares UDP 5353 with the DNS Client service through `SO_REUSEADDR`.
  Windows gives no packet information through `golang.org/x/net`, so a packet's interface is
  the one whose network holds its source address, or the zone of a link-local source, and a
  multicast goes out on the interface set on the socket.
- **Installer**: `install.ps1` (or `get.ps1`, which checks a release against
  `SHA256SUMS`) needs an administrator once. It allows TCP 8764 and UDP 5353 for `cbb.exe`
  from the local subnet in Windows Firewall, in rules of the group `clipboardbridge` that
  it and `uninstall.ps1` remove, and registers the uninstaller in Settings, Apps.
- Logs: `ProgramData\clipboardbridge\logs\service.log` and
  `LocalAppData\clipboardbridge\agent.log`, each moved to `.1` at 1 MiB.

## Passwords

- Automatic sync skips items marked as secret: the macOS and Windows formats above, and on
  Linux the presence of the `x-kde-passwordManagerHint` type, whatever its value.
- Received secrets are written with the same marks Clipboard Bridge reads: the
  `x-kde-passwordManagerHint` type on Linux and the macOS types above, so clipboard managers
  skip them.
- Some desktops and clipboard managers keep a copy of the last clipboard text and offer it
  again without the mark. The engine remembers secret texts, including the marked items it
  skipped, and such an offer makes no event (see the sync model).
- Explicit actions may carry a secret: "send even if secret" on the Mac and the console
  paste; the shortcut may mark a text as secret. Secret events are kept only in memory and
  expire 60 seconds after the copy, judged by the event's age. When a secret that a connector
  wrote expires, the connector gives up the clipboard, so the desktop does not keep it.
- Secrets stay out of swap where the system allows it: on Linux the service's unit sets
  `MemorySwapMax=0`, and macOS encrypts its swap. Windows does not encrypt its page file by
  default, so there a secret in the service's memory may reach it (not solved yet). The desktop's
  own clipboard, which holds a received secret until it expires, is outside the service.
- Only root and members of the `clipboardbridge` group receive secrets through the control socket.

## Limits

- Text: UTF-8, up to 1 MiB per item.
- Images and files (planned for 0.6): up to 100 MiB per copy at home and 25 MiB away from
  home by default, set on each device up to 1 GiB (see "Images and files").

## Images and files (planned for 0.6)

Images, files and folders travel wherever the platform lets a program read and write them,
with the same protection as text; formatted text (HTML next to the plain text) comes last
and is optional (D-56). Today's event carries its whole text and sits in every hello and
queue, so large content cannot simply go inside it.

### Where

| Device | Images | Files and folders | HTML |
|---|---|---|---|
| Linux, Wayland (data-control) | `image/png`, `image/jpeg` | `text/uri-list`, `x-special/gnome-copied-files`, KDE's types | `text/html` |
| Linux, X11 and GNOME through XWayland | the same targets, large ones in INCR pieces | the same | the same |
| Linux without a desktop | `cbb copy FILE...`, `cbb paste -o DIR` | the same | no |
| Windows | `CF_DIBV5` and the registered `PNG` format | `CF_HDROP` with the paths of the received copies; virtual files (Outlook attachments, ZIP contents) later | `HTML Format` |
| Mac | `public.png`, `public.jpeg`, `public.tiff` (sent as PNG) | `public.file-url` items | `public.html` |
| iPhone app | on the button, as text; HEIC is sent as JPEG | files copied in Files and other apps (named after their type when iOS gives no name); a share extension later | yes |
| Android app | reads a `content://` image with the clipboard, writes one through its FileProvider | Android file managers have no system copy, so files come through the share sheet; received files are offered in the notification ("Open", "Save to Downloads") | yes |
| iPhone shortcut, the lite member, ESP32, ZX Next | no | no | no |

Text-only devices take the event, so the group converges, but never fetch its content and
keep their last text; a copy that carries text next to its image (a browser copies both)
gives them that text. Secrets and remote paste stay text only. Cut in a file manager counts
as copy: nothing is ever deleted on the source.

Images travel as PNG (screenshots) or JPEG (photos, which would grow about five times as
PNG); the sender converts HEIC and TIFF, and a receiver converts JPEG to PNG when an
application asks for PNG. A copied folder keeps its tree, up to 10 000 entries.

### Manifest and chunks

- A `media` event carries a **manifest** instead of the bytes: for each part its type (or
  name and path inside a copied folder), size and SHA-256, the total size and an optional
  plain-text alternative. It is small, so it travels in events and hellos like a text, and
  the sync model applies unchanged; duplicates (two Macs reporting one Universal Clipboard
  image) are recognised by hash.
- A member that wants the content sends `get` (hash, offset, length) to a connected member
  that has it, preferably the origin, and receives binary `chunk` frames of 256 KiB (not
  base64 in JSON, which costs a third more). It asks for at most 4 MiB at a time, more as
  chunks arrive, and continues from the last offset after a reconnect.
- Events, hellos, pings and records go first; chunks go only while the event queue is empty
  and do not count against the 256-message queue limit, so text keeps flowing during a large
  transfer.
- Content is addressed by its hash, so any member that has it serves it, and a member asked
  for a part it lacks fetches it and passes the chunks on as they arrive. Away from home that
  is the hub serving its clients, which never talk to each other.
- A receiver fetches in the background once the event is the group's current live event and
  fits its limit, and writes its clipboard only when every part has arrived and matches its
  hash, so a paste never gives half a file; a newer copy stops the fetch. Progress shows in
  `cbb status` and the apps' notification.
- Images and files follow the device's sync mode ("Sync modes", D-55) like text: a device
  fetches only in a mode that takes the group's copies into its clipboard, and offers its
  own only in a mode that sends them.
- Android on the home Wi-Fi fetches images by itself; files, and anything away from home,
  wait for a tap on the notification. The iPhone fetches on its button.

### Storage

The service keeps fetched content as files in a cache in its state directory, readable only
by the service, so a Pi Zero never holds a large copy in memory; files the clipboard points
at live in a folder per copy readable only by the user. The cache keeps the current copy,
deletes older ones 10 minutes after they are replaced and everything on restart, within
twice the device's limit. The apps keep it in their sandbox. Nothing is kept as history.

Received names are cleaned (no path separators, `..`, control characters or reserved Windows
names, at most 255 bytes); links inside folders are neither followed nor created; nothing is
made executable; on Mac and Windows received files carry the system's mark of a download
(quarantine, Mark of the Web).

### Size limit

| Setting | Default | Range |
|---|---|---|
| Largest copy a device sends or fetches at home (`cbb config max-copy`, the apps' settings) | 100 MiB | 1 MiB to 1 GiB |
| The same away from home (`max-copy-away`) | 25 MiB | 1 MiB to the home limit |
| Text | 1 MiB | fixed |

The receiver's limit decides (D-57): a sender offers any copy within its own limit, each
receiver fetches only what fits its own and says once that a copy was too large ("A 300 MB
copy from Mac is over this device's limit of 100 MB"). The hub's away limit caps its whole
star. The limit protects the memory and disks of small devices, mobile data, the hub and the
forwarder's 2 MiB a second per group; beyond 1 GiB Clipboard Bridge is the wrong tool.

### Security

The rules of "Sync away from home" hold unchanged (D-58): at home chunks travel inside the
member connection's mutual TLS 1.3, away from home only inside the group's WireGuard tunnel
with member TLS inside it, so the forwarder and the blind relay see neither content nor
headers nor inner addresses. Only group members hold the plaintext, and every part is
checked against the SHA-256 of a manifest that came over an authenticated connection, so a
member serving from its cache cannot change it. What stays visible: the network between a
client and the hub sees that roughly so many megabytes went; chunks are padded to 256 KiB,
and cover traffic cannot hide a large transfer.

### Order of work

1. The `media` event, the content cache, `get` and `chunk`, priorities and limits in Go;
   interop vectors for the Swift and Kotlin kits and the lite core (which learns to ignore
   content); `cbb copy FILE` and `cbb paste -o DIR` without a desktop.
2. Images in the desktop connectors: Wayland, X11, Mac, Windows.
3. Files and folders in the desktop connectors.
4. The phone apps: images, then files and the share targets.
5. Away from home: the away limit, the hub serving its clients, the bench's tests.
6. HTML, optional.

## Security

| Threat                                                         | Measure                                                                    |
|----------------------------------------------------------------|----------------------------------------------------------------------------|
| Someone on the home network reads the traffic                  | TLS 1.3 everywhere                                                         |
| Someone guesses or intercepts the pairing code of a computer   | CPace inside TLS: one online guess per attempt, at most three per pairing window, no offline attack; the joining device spends the code on one attempt, and never takes it from the command line |
| Someone attacks the pairing of an iPhone                       | the same attempt limits; the profile comes over a separate plain-HTTP port, so no certificate warning is ever accepted for the pairing page; the user compares the iPhone CA fingerprint with the one in the terminal (never with the plain-HTTP page) before trusting it; the code and the token travel only over a connection that the trusted CA authenticates, so a relay sees neither |
| A device impersonates a member (for example, a host that answers `clipboardbridge.local` on another network) | mutual TLS with the group CA; members dial discovered addresses and check the peer's certificate; the iPhone accepts only a certificate from the iPhone CA, so an impostor gets neither the token nor the text |
| A device is lost or stolen                                     | `cbb revoke`; for a Linux member also a new group CA, a new iPhone CA and new tokens, the old profile deleted on every iPhone, and the members that were off paired again before they rejoin. With the apps: "Remove" on another admin phone; a lost root phone hands the root to the remaining admin without pairing anything again |
| A member is compromised                                        | it can read the group clipboard, by design. It cannot read the iPhone's other HTTPS traffic: the iPhone CA is restricted by name constraints to `clipboardbridge.local` and names below it, and excludes IP addresses and other name forms. The Mac never changes its system trust |
| A bug in the network code                                      | memory-safe language; the service runs as an unprivileged user in a systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateDevices`, no capabilities, restricted address families and system calls) |
| A local user abuses the console helper                         | the helper listens on nothing; the control socket admits only root and the `clipboardbridge` group; single-line injection by default with control characters removed |
| Requests from outside the home network                         | the service accepts connections only from private, unique-local and link-local addresses, checked in the program and by systemd; away from home only through the group's WireGuard tunnel, whose port drops every packet without a key from the group's records |
| Someone copies a computer's keys                               | the identity and tunnel files are readable only by the service; whoever copies them can act as that device until it is removed, so removing it makes every member and the hub refuse it at once. Planned: keys in hardware where the computer has it, file keys shown as such, and regular renewal ([roadmap.md](roadmap.md#device-keys-in-hardware)) |
| Someone on the internet reads or traces the traffic (planned)  | the member TLS inside the group's own WireGuard tunnel, a preshared key per client, padded frames; clients talk only to the hub; the project's forwarder holds no keys and passes each packet only to its own group's hub |
| An admin orders a paste on a member (planned, 0.6)            | off until the target's user turns it on, Enter and root consoles separately; any admin turns it off everywhere; only admins send; the command is signed and expires in 30 seconds, and the target checks the signature, the revocations and a replay cache; control characters removed; a notification and a log on the target; a rate limit; a phone signs only behind Face ID or the fingerprint; a stolen admin computer is frozen by any other admin and removed by the root or an admin phone (see "Who may remove an admin") |
| A compromised dependency or build                              | few dependencies, `govulncheck`, actions pinned to commit SHAs, release builds in CI with checksums and build provenance |

## Build

- Go, with `CGO_ENABLED=0` everywhere except for the Mac's pasteboard agent (the Windows
  clipboard needs no cgo), which uses cgo
  with a small Objective-C file. From then on CI builds the macOS targets on macOS runners
  with cgo.
- Targets: `linux/amd64`, `linux/arm64`, `linux/arm` with ARMv7 and ARMv6, `darwin/arm64`,
  `darwin/amd64`, `windows/amd64` and `windows/arm64` (`cbb.exe`, and `cbbw.exe` linked with
  `-H windowsgui` for the agent).
- The Raspberry Pi Zero W (ARMv6) cannot run Ubuntu; it runs Raspberry Pi OS. Clipboard Bridge
  does not depend on distribution specifics. The systemd units use directives from systemd
  248 and later and are checked with `systemd-analyze verify`.
- Third-party code: `golang.org/x/net`, `golang.org/x/sys`, `golang.org/x/crypto` and
  `golang.org/x/time` (BSD-3-Clause), `jezek/xgb` (BSD-3-Clause), `rsc.io/qr`
  (BSD-3-Clause), `amnezia-vpn/amneziawg-go` (MIT, a fork of wireguard-go) with gVisor's netstack (Apache-2.0)
  and `google/btree` (Apache-2.0) for the tunnel, and the CPace implementation copied from
  `rsc.io/cmd/mote` v0.1.3 (BSD-3-Clause) into `internal/third_party/cpace`. The lite
  member uses RustCrypto and rustls (MIT or Apache-2.0).

## Sync away from home

Away from home, and between subnets that mDNS does not reach (for example a Pi on
192.168.20.x and the rest of the group on 192.168.0.x), members reach each other through the
group's own WireGuard tunnel in a star around one member, the hub. Built so far: the tunnel
itself (`internal/tunnel`: the hub and the Go client, with tests that clients cannot reach
each other), the exchange of its keys among Go members, and `cbb global`, which turns it on
with the consent below and makes a computer the hub; Go members sync through it when the
hub is not on their network; a computer with a remote invitation joins from afar (`cbb
invite` on the hub); a hub that clients cannot reach directly registers with a forwarder
(`cbb forward`, routing by `mac1`). The phones and the rest of the order of work below are
not built yet.

### Turning it on, step by step

Every widening of what the group exposes is the user's own choice, made in turn:

1. **The home network only**, the default. A new group, and every device that joins it,
   syncs at home and has no tunnel key; nothing listens or connects beyond the home network.
2. **Sync away from home**, turned on by the user: on the hub, which the user chooses (`cbb`
   on that computer, or the root phone asking it), and then on each device that should sync
   away from home (`cbb` on a computer, a switch in the app). Only then does the device make
   its tunnel key and offer it to the hub. The screen that turns it on says what changes: the
   hub's port is reachable from the internet, only through WireGuard with the group's keys.
   Until then the service reaches only the home network (loopback, private IPv4,
   link-local, multicast, unique-local IPv6), and only the home network reaches its member
   port. Every computer enforces it in the program: the member port drops other addresses,
   and the service's own connections are refused outside the home network
   (`internal/netguard`). With sync away from home on, the service may reach beyond the home
   network only the group's own servers, from the group's settings: its hub, forwarder and
   relay, self-hosted or not, and nothing else on the internet (D-61). A client's WireGuard
   socket sends only there too. Linux and Windows add a second line of defence outside the
   program: on Linux the systemd unit (`IPAddressDeny`/`IPAddressAllow`), on Windows the
   outbound block rule `clipboardbridge-home-only` of Windows Firewall for the service and
   inbound rules for the local subnet. `cbb global on`, `hub`, `relay` and `cbb pair
   -invite`, with `sudo` or as administrator, add exactly the group's servers to that limit
   (a drop-in with their addresses, or the rule without them), `cbb global off` takes them
   away, and `cbb global allow` follows the servers when the hub's addresses change, which
   the client learns without root: `cbb global` and `cbb status` say when the system's limit
   lags behind. One exception: a hub reached at its own address answers its clients wherever
   they are, but only those that prove the group's keys. Windows opens only the hub's UDP port
   for that; systemd cannot allow one port only, so on Linux such a hub's unit allows every
   address and the program's limit holds alone. A Mac has the program's limit only, since
   macOS limits a single program's network only through a Network Extension of a signed app;
   the Mac app will add it (item 22 of [roadmap.md](roadmap.md)).
3. **A device whose keys sit in a file**: a computer without a TPM or a Secure Enclave (see
   "Device keys in hardware") can turn sync away from home on only after a second, separate
   consent. It explains that whoever copies the files (root on that device, its disk or
   memory card, an unencrypted backup) can act as the device from anywhere until it is
   removed, and gives the measures: encrypt the disk (LUKS, BitLocker, FileVault), keep the
   state directory out of unencrypted backups, keep the device's keys renewed more often
   (the default for such devices is shorter), and remove the device at once when it is lost
   or its root may be taken. `cbb status` and the devices list show such a device with a
   mark, and the hub can be set to refuse them.
4. **Remote invitations**, possible only once sync away from home is on at the hub.

Each step can be turned off again, which forgets its keys. The documentation and the apps
explain each step where it is turned on, in the same words.

### Rules

These take precedence over convenience:

1. The safety of clipboard data outside the home network comes first. A feature that cannot
   keep the data fully protected is not built.
2. No third-party services: no Tailscale or other overlay network, no hosted relay, no cloud,
   no push service. WireGuard of our own, inside our own programs.
3. A star. Over the internet a client talks only to the hub, never to another client, and the
   hub decides what reaches whom.
4. On the internet, data exists only inside the tunnel, with the member protocol's mutual TLS
   inside it: nobody but the group's devices reads the contents, the inner headers or the
   inner addresses.
5. The tunnel serves Clipboard Bridge only and cannot be used as a general VPN.
6. Where WireGuard is blocked, the user can switch on VLESS.
7. Groups are fully isolated from each other on the project's forwarder and cannot affect
   each other, even from one network.

What no design hides, and the documentation says so: the network between a client and the
hub (or the forwarder) sees that encrypted packets go to that address, when, and roughly how
many. VLESS with REALITY makes them look like an ordinary HTTPS connection to a well-known
site. Where a network admits only listed addresses (allow-lists), no protocol helps.

### The hub

- One member of the group, a computer of the user's at home, is the hub. It need not stay
  on: while it is off, nothing syncs away from home, and the devices at home still sync
  among themselves. The user chooses: a computer that is always on, one that is turned on
  when sync away from home is needed (for example to copy codes from afar for an hour), or
  no hub and sync at home only. `cbb global hub` and the documentation say so. The hub is a Linux member, normally, or a Windows PC. Both accept connections already. A Mac only
  dials today and becomes able to be the hub once it gets a listening mode, the next piece
  of work. Phones and lite members are clients: a phone is not always on
  and cannot accept connections in the background, and a lite member has no room for it. A
  group with no computer has its phone as the hub while the app is open (planned for 0.5,
  below).
- Why sync over the internet needs a computer of the user's: the hub must be on and
  reachable all the time, it must be at home so that the devices hand it their keys there
  (below), and it is a full member that reads the texts, so it must be the user's own
  device. Any other meeting point is someone else's server, which learns at least which
  devices talk and when; the user's own hub lets nothing out but encrypted packets. A group
  without such a computer syncs at home only, unless the user runs a blind relay of their
  own (below).
- Changing the hub means making another device the hub, for example when the old one
  breaks. The new hub starts with no keys and learns each device's key when that device next
  meets it at home; a device that stays away meanwhile cannot reach it until it comes home.
  A new address, provider or forwarder is not a change of hub: the hub keeps its key and
  tells its clients the new address.
- The hub runs WireGuard in user space inside `cbb` (amneziawg-go, a fork of wireguard-go that
  speaks plain WireGuard until the group switches obfuscation on, with its in-process network
  stack, gVisor netstack), as do the Go clients. The operating system sees only encrypted UDP
  on one port: there is no `wg0` interface, no route, no IP forwarding and no firewall rule
  to get wrong.
- Behind the tunnel the hub's stack has one open port, the member protocol's. There is no
  internet, no home network and no other client behind it, so the tunnel cannot carry
  anything else.
- Each client has exactly one tunnel address, a unique-local IPv6 address derived from its
  device ID, and the hub drops packets from any other source address (WireGuard's cryptokey
  routing). A client's tunnel admits only the hub's address. Nothing forwards packets between
  peers; the hub passes clipboard events at the member protocol level, as every member
  already forwards events to its peers.
- Inside the tunnel the member protocol runs unchanged, with mutual TLS 1.3 and the group's
  certificates: a valid WireGuard key alone gets no further than the TLS handshake.
- Each client has its own WireGuard preshared key, random and handed over at home, so that
  traffic recorded today stays protected against a future quantum computer (WireGuard alone
  is not post-quantum secure).
- Fail closed: away from home a member talks to the group only through the tunnel. If the
  tunnel cannot be built, nothing is sent, and the app or `cbb status` says why, with the
  real cause in debug builds.

### The phone as the hub while its app is open (planned for 0.5)

Everyone in a group has a phone; not everyone has a computer. A group made on a phone with
TVs, set-top boxes, other phones or lite members and no computer has nothing to be its hub,
and without a lite member nothing in it accepts connections even at home: phones never do,
and the Android app on a TV is a phone app. So the phone takes on the hub's work as far as it
can: while its app is open, it is the hub. Decided on 2026-10-25 (D-64).

- **What the user gets.** A group made on a phone has that phone as its hub from the start;
  sync away from home is still turned on by the user, step by step as above. While the app
  is in the foreground the group syncs, at home and from afar; when the app goes to the
  background, the hub stops. The app says so where sync away from home is turned on and on
  Home ("Sync away from home works while this app is open"). Some users want exactly this,
  so it is a choice the user may keep, not a fault the app keeps pointing out.
- **At home** the open app accepts member connections on the home network, as its
  `TLSListener` already does for a joining phone, and publishes itself by mDNS while it is
  open. The devices that only dial (phones, TVs, and lite members dialing out) find it and
  connect, so a group of phones and TVs syncs at home too.
- **From afar** nobody reaches the phone directly (carrier-grade NAT on mobile networks, an
  address that changes, iOS closing sockets in the background), so it registers with the
  forwarder over an outgoing connection, as a hub behind carrier-grade NAT does, and keeps
  the registration and its hellos while the app is open. The forwarder finds a hub by its
  key, not its address, so a phone that moves from Wi-Fi to a mobile network stays the same
  hub. The hub's WireGuard runs in the app's process, in `mobile/cbbtun`, beside the client
  side.
- **The clients come quickly.** A phone hub is there for minutes at a time, so its clients
  keep trying it every few seconds while their own app or service runs, instead of backing
  off to 30 s and more; a handshake initiation to the forwarder costs one small packet, and
  the forwarder drops it while the hub is not registered. The interval is to be measured
  (phone batteries, the forwarder's load); the forwarder's per-group limits apply as to any
  group.
- **Keys.** The hub's WireGuard key lives in the phone's keychain or Keystore for this device
  only (Curve25519 does not fit the Secure Enclave), and the clients hand their keys to it in
  their hellos at home, as with any hub. The phone's root or admin key signs only after
  Face ID, so the hub registers with the forwarder by its member key instead, which signs
  without the user: the group's records show the forwarder that this member key is the
  root's or an admin's (docs/protocol.md, section 13). Asking for Face ID on every
  registration (each time the app opens or the network changes) would make the phone hub
  useless. Stealing the member key would let someone displace the registration, which a
  root or admin computer's key in a file allows too, and nothing more: the clients take
  only the hub key of the offer they met at home. A device far away joins with a remote invitation
  made on the phone, which is then both the admin who confirms the device and the hub that
  serves the guest tunnel, so no invitation has to be handed over.
- **Android** may keep the hub running in its foreground service while the app is in the
  background, if the user turns it on and accepts the battery cost; iOS gives an app no way
  to do that.
- **Moving the hub to a computer.** When a computer that can be the hub joins (Linux,
  Windows, a Mac with its listening mode), above all one that is always on (no battery, as
  the holder setting judges), the app suggests making it the hub, once, with the reason in
  plain words: sync away from home then works with the app closed. The user may keep the
  phone as the hub; the app then does not ask again, and Settings keeps the choice. When the
  user agrees, the phone, still the hub, passes the new hub its clients' tunnel keys and
  preshared keys inside member TLS and tells its connected clients the new hub's offer
  through the tunnel, so devices far away (a parent's TV in another city) move without
  coming home. The new hub admits each key only for a device whose certificate is valid in
  the group's records.
- **Losing the phone.** When the root phone that is the hub is lost, the admin phone that
  takes the group over (`PhoneGroup.takeOver`) becomes its hub too. Clients at home learn
  the new hub there; a client far away cannot learn it from a lost phone and joins again
  with a new remote invitation. That is one more reason for a second phone as an admin,
  which the app already suggests.
- **What it does not change.** The rules above hold: a star around the hub, the member TLS
  inside the tunnel, the project's forwarder only passing packets. The hub reads the texts,
  as every hub does; the root phone is the group's most trusted device, so that adds no
  exposure.

#### Groups without a working hub

| Situation | Today | Planned |
|---|---|---|
| Phones only, or phones and Android TVs or other Android devices | nothing syncs, at home or away: all of them only dial | a phone with its app open is the hub; the others sync while they run (Android in its foreground service, an iPhone with its app open) |
| A phone and lite members | syncs at home, where lite members listen; not away from home | the same at home; from afar, the phone with its app open is the hub |
| The whole group away together (a trip, a hotel Wi-Fi that isolates its clients, mobile data) | nothing syncs unless the hub at home is reached | the phone hub, through the forwarder |
| A computer is the hub but is off, broken or offline | nothing syncs away from home | several hubs with a priority (below): the next hub that is on, such as the phone with its app open, serves |
| The hub's home has no public address and the project's forwarder is not reached | nothing syncs away from home | the same; a forwarder or relay of the user's own (`cbb forward`, `cbb relay`) |
| A network blocks WireGuard | AmneziaWG, then VLESS | AmneziaWG for the phone hub as for any hub; VLESS for the phone hub's own registration is to be checked |
| The root phone that is the hub is lost | | an admin phone takes over and is the hub; devices far away are invited again |

- **Built so far:** the hub's side in `mobile/cbbtun` (`StartHub`, `Register`): the clients'
  tunnels, the member port that leads to the kit's member listener on the loopback address,
  and the registration with the forwarder by the member key, with the forwarder's check of
  it; in both kits the member listener (`MemberListener`) and the hub's answer to a hello's
  tunnel key (`PhoneHub`, by the rules of a computer's hub). The apps, the clients' short
  retries, remote invitations on the phone and moving the hub come next (roadmap item 30).

### Reaching the hub

- A client tries the hub's addresses in order: its public IPv6 address directly, then a
  public IPv4 address (a forwarded port), then the project's forwarder. A client needs only
  outgoing connections and opens nothing.
- The hub needs one inbound UDP port for direct access. The hub checks from outside, through
  the forwarder, whether it is reachable; if not, the app asks the user to add a firewall
  rule on the router (with a short guide) or, with the user's consent, opens it through the
  router's PCP or UPnP.
- A client's own address changes need nothing: WireGuard follows a client to its new address
  with its next authenticated packet. When the hub's address changes (a new IPv6 prefix), the
  hub tells its connected clients through the tunnel and updates its registration on the
  forwarder; a client that was offline comes in through the forwarder, learns the new
  address inside the tunnel and moves to the direct path. No DNS name is needed.
- Pings over the tunnel are less frequent than the home network's 5 s (WireGuard's
  persistent keepalive of 25 s keeps NAT mappings open), to spare phone batteries; the exact
  interval is to be measured.

### The forwarder

For homes behind carrier-grade NAT, and for clients without IPv6, the project runs a
forwarder on its own server for all users. It holds no keys and only passes encrypted
WireGuard packets between a group's clients and that group's hub. The forwarder is built
(`cbb forward`, `cbb global hub -forwarder`; the wire format is in
[protocol.md](protocol.md), section 13), with routing by `mac1`; the computed port below is
not. The project's own forwarder does not run yet: it needs a server, and until then a
user can run `cbb forward` on a server of their own.

- **One port for all groups, routed by `mac1`.** Every WireGuard handshake initiation
  carries `mac1`, a MAC keyed with the responder's public key. The forwarder knows each hub's
  public key from its registration, so it finds the group by checking `mac1` against the
  registered keys; it still holds no key that decrypts anything. Nothing is added to the
  packets, and `mac1` looks random to anyone who does not know the hub's public key, so the
  network cannot tell groups apart. Data packets then carry the receiver index the hub chose
  in the handshake, which the forwarder maps to the group together with the client's address.
  The check costs one BLAKE2s per registered group per handshake (a client's handshake comes
  every two minutes while it is active), tens of milliseconds for 100 000 groups; beyond that,
  groups are spread over several servers. AmneziaWG's header protection hides `mac1`, so an
  obfuscated hub gives the forwarder its group's settings when it registers ("Blocked
  networks"); the forwarder then tries them only on handshakes of the size that group's
  have, and on the packets of addresses that already have a session with it. In VLESS mode
  the forwarder lets in only the VLESS user IDs of registered groups and routes what comes
  inside the same way.
- **Fallback: a port computed by the group.** If `mac1` routing does not hold up, the hub and
  its clients compute the group's port themselves, from a secret of the group and the current
  hour, as an authenticator app computes its codes; there is no request that names the group.
  The hub claims the port for the coming hours over its registration connection and tells its
  clients inside the tunnel which one it holds. When two groups' ports collide, the forwarder
  gives the port to one and the other takes the next of its two or three candidates; a client
  that was offline sends its handshake to all of them at once, and only its own hub answers.
  A handshake that reaches another group's port is dropped by the forwarder, whose `mac1` check
  does not match, and would be dropped by that hub anyway, since it does not know the client's
  key. The port changes every hour, so it links a group's devices only for that hour; on IPv6
  the computed value picks an address of the server's /64 instead, so collisions do not come up.
  A fixed port per group was rejected: it would link a group's devices for good, and so would a
  visible group tag in the packets or a request that asks the forwarder for a port.
- Clients behind one shared address are told apart by address and port, as the hub's own
  WireGuard does. A packet is passed only to its own group's hub; there is no shared path
  between groups.
- **Registration.** The hub keeps one connection out to the forwarder and registers its
  WireGuard public key by proving its membership (its member key with the chain to the group
  CA) and that it is the root or an admin (a signature by the root's or its admin CA's key).
  It also sends the group's authority records, so the forwarder refuses an admin or device that
  the group removed or froze. A member that is no admin, or a removed one, cannot take the hub's
  place. The forwarder knows a group only by its tag, the hash of the CA certificate, and stores
  nothing on disk: its state is the open connections and, while a group is registered, its
  records.
- **No interference.** Limits per group: packets and bytes per second, at most 16 clients,
  memory. A group that reaches a limit is slowed down alone. Limits per source: registrations
  per address and per network (/24, /64), and a share of the budget for checking handshakes
  against the groups per network, so a few hosts can neither fill the forwarder nor starve the
  others.
- **Nothing to gain.** Whoever takes the forwarder over sees the same encrypted packets as
  the network and can at most stop forwarding.
- It learns the group tag, the hub's WireGuard public key, the addresses of the hub and its
  clients, and the timing and sizes of packets: any forwarder has to know which hub a client's
  packets go to. From the registration it also learns the hub's member certificate (its
  device ID, its validity and its admin CA if it has one), the group's root certificates,
  the group's obfuscation settings and, with VLESS, the group's VLESS user ID; and from the
  number of clients that send packets, roughly how many devices are away from home. It does
  not learn the texts, the devices' names, or which client address is which device. This
  metadata is accepted by design (owner decision, 2026-10-24): it reveals that a group
  exists and how busy it is, never what it syncs, and hiding it would need certificate-less
  registration or a chain of relays. It writes nothing to disk, logs included; what it knows lives in memory while the
  connections last. The clients' addresses cannot be hidden from it, since they are where its
  answers go; a chain of relays in the manner of Tor would hide them at a cost in speed and
  complexity that the project does not take on.
- **Optional, off by default:** the hub can change its WireGuard key on a schedule, for
  example weekly, handing the new key to its clients inside the tunnel, so that the forwarder
  cannot link a group's traffic from one period to the next. The project's own forwarder does
  not rely on it.
- The forwarder is `cbb` in a mode that holds no keys. A hub never runs on a rented server:
  that would put the decrypted clipboard on someone else's hardware.

### Keys and pairing

- Each device creates its own WireGuard key pair when sync away from home is turned on
  there, not before; the private key never leaves it and never appears in a QR code.
- A device gets the hub's public key and addresses, the forwarder's address and port, and
  its preshared key inside the member TLS, at home, when it joins or later on request; its
  public key reaches the hub the same way, in its hello. The hub admits a key only from a
  member connection, for the device ID and certificate chain of that connection, so the
  member certificate binds the key and no extra signed record is needed (one would ask the
  root phone for Face ID for every device and add nothing the certificate does not prove).
  The wire format is in [protocol.md](protocol.md), section 11.
- Removing a device (the revocation records) makes the hub drop its key at once. A new
  preshared key can be issued through the tunnel at any time.
- A device joins with the six-digit code only where no stranger can try it: on the home
  network, or through a path the user already controls (see "Joining from another
  network"). The code is short, so the open internet never reaches that pairing: there
  anyone could try it, and before it joins a device has neither a certificate nor a
  tunnel. The usual order is: the device joins at home, meets the hub at home and hands it
  its key, and from then on syncs from anywhere. Keys and preshared keys can be renewed
  later through the tunnel, since the member TLS runs inside it.

### Joining from another network

Three ways admit a device that is not on the home network. The first two work today for
the pairing itself; the third is planned.

- **Through SSH.** When the new computer can log in to a Linux member that admits devices,
  it forwards a local port to the member port, `ssh -N -L 18764:localhost:8764 user@member`;
  the user runs `cbb pair` on the member (in another SSH session) and
  `cbb pair -code 127.0.0.1:18764` on the new computer. The member sees a connection from
  itself (loopback), which it accepts, and the usual pairing (CPace with the code inside
  TLS) runs inside SSH. A remote desktop (RDP, VNC) gives a screen, not a network path; it
  still needs the SSH forward or a VPN.
- **Through a VPN of the user's own** that gives both devices private addresses (RFC 1918
  IPv4 or IPv6 unique-local), such as a WireGuard the user runs: the member port accepts
  private addresses, so `cbb pair -code <member's VPN address>:8764` works. Addresses
  outside those ranges, such as the 100.64.0.0/10 of carrier-grade NAT that some overlay
  VPNs use, are refused like any address of the internet. On Linux the installer's
  firewall rules allow the private networks the machine had when it ran, so after setting
  up the VPN the installer is run again. Only a VPN the user runs fits the rules above: the
  member port is then open to every peer of that VPN.
- In both ways the device joins, but members find each other by mDNS, which crosses
  neither SSH nor a VPN, so it would meet the hub only at home. So after a join by address
  the new member keeps dialing that address as a member while the SSH forward or the VPN
  is up and discovery does not find the member: it syncs at once, and a device that joined
  through the hub hands it its tunnel key as soon as sync away from home is on there, and
  syncs away from home from then on. It stops once it holds the hub's offer; the address is
  not kept across a restart of the service.
- **Remote invitation**, for a device that shares no network and no SSH with the
  group. An admin makes it: the root or an admin phone, a Linux member that admits devices
  or an admin computer (`cbb invite`). Built so far for computers, made on the hub itself
  when the hub can admit devices: `cbb invite` there, `cbb pair -invite FILE` on the new
  computer (docs/protocol.md, section 12). Handing an invitation made on another admin to
  the hub, and the phones' part, are still planned. It is never typed: it comes only as a QR code or as
  a file to open (`.cbbinvite`), and holds the group's tag, the hub's WireGuard public key
  and addresses (and the forwarder's), a one-time WireGuard key pair with its preshared key
  for a guest tunnel, a 128-bit one-time secret and the time it expires. It serves one
  device once, for at most a day (an hour by default), and the admin can cancel it.
  - The admin hands the invitation to the hub inside member TLS before it is used. The hub
    adds the guest key as a peer that reaches only the pairing service inside the tunnel,
    never the members' sync, and drops it after one use, at expiry, or after three failed
    attempts. A packet without that key gets no answer, as for any unknown WireGuard key.
  - The new device opens the guest tunnel and pairs with the hub with CPace on the secret,
    the same exchange as at home. The hub then shows the admin who made the invitation the
    device's name, system and key fingerprint; nothing is admitted until the admin
    confirms (Face ID on a phone, a question in the terminal for `cbb invite`), and the
    admin signs its certificate as for any other device. In a phone group whose hub holds
    no CA keys the request goes to the admin phone through the hub, inside member TLS, at
    home or through the phone's own tunnel.
  - With its certificate the device offers its own tunnel key in its first hello through
    the guest tunnel; the hub admits it, drops the guest peer, and the device reconnects
    with its own key as an ordinary client.
  - Why it is safe over the internet: without the guest key nobody reaches the hub at all;
    the 128-bit secret makes guessing hopeless and CPace allows no offline attack; the
    guest reaches nothing but the pairing; and the admin's confirmation names the device,
    so an invitation stolen and used first is seen and refused. The invitation is a secret
    until it is used, so the user passes it only through a channel they trust; the app says
    so when it shows it.

### Groups that sync at home only

At home no hub is needed: the members sync directly over the home network, with the phone as
the root and any computers and lite members. Some member has to accept connections: a Linux
member, a Windows PC, a Mac or a lite member; only phones never do. So any group with a
computer or a lite member besides its phones syncs at home.

### Blind relay (self-hosted only)

For a user with no computer that could be the hub, a blind relay can stand in as the meeting
point. It is a `cbb` mode on a server the user runs: it holds none of the group's keys, ends
the clients' WireGuard tunnels, and joins the member TLS of two clients of one group end to
end, so it reads nothing. It is still a star: clients reach only the relay, and the relay
decides which two connections to join. What it learns, and what the user's own hub would
not let out: which devices of the group talk, when, and how much. Both devices must be
online at once, since it stores nothing. It is built as an option for those who run it
themselves and is never switched on in the project's own forwarder, which collects nothing
about who talks to whom.

- `cbb relay -group TAG` runs it on the user's server, for the groups whose tags it is
  given and no other. Each device turns it on with `cbb global relay ADDRESS -key KEY`, in
  place of a hub; the key is the pin of the relay's own key, as with the forwarder.
- A device registers with its member certificate and proves it holds its WireGuard key, as
  a hub does with the forwarder. The relay then gives it a tunnel, a preshared key and a
  tunnel address of the relay's choosing, and drops it when the registration ends.
- Inside the tunnels the relay listens on one port. Each device keeps a connection there
  for notes: which of its group's devices are on the relay, and calls. The device with the
  lower ID dials the other through the relay; the relay calls the other, joins the two
  connections once it answers, and copies the bytes. Member TLS then runs end to end
  between the two devices, and the answering device checks that the certificate is the
  caller's, so the relay cannot pose as a device.
- The relay sees which devices of a group are online, which of them talk, when and how
  much; it cannot read the clipboard or pose as a device. A device still revoked by the
  group's records can register, since the relay does not read the records, but the other
  devices' member TLS refuses it, so it learns only who is online.
- The wire format is in docs/protocol.md, section 14.

### Blocked networks

1. **AmneziaWG**, a fork of wireguard-go that randomises message headers, adds junk and
   imitation packets before the handshake and pads messages. Same keys and code; the user
   switches it on per group, on the hub (`cbb global hub -obfuscate`). `cbb` and the phones'
   tunnel run on amneziawg-go always; without settings it is plain WireGuard on the wire.
   - The hub makes the group's settings once, at random, and keeps them while obfuscation
     stays on: 3 to 8 junk packets of 40 to 600 bytes before each handshake, 16 to 64 random
     bytes in front of each handshake message and 16 to 32 in front of each data message,
     each message type drawn from its own random range instead of WireGuard's 1 to 4, and a
     header protection key that encrypts the rest of each header (the session indices
     among it) with the padding in front as its nonce. Nothing on the wire then starts or
     sizes like WireGuard, and no field stays the same from packet to packet, so no
     constant of the group fingerprints it either.
   - The settings travel like the rest of the hub's offer: inside member TLS at home
     (docs/protocol.md, section 11), and in a remote invitation. They hide what the packets
     are, not what they carry; the security is WireGuard's and the member TLS's with or
     without them, so they are not a secret the design relies on. A client that has not met
     the hub since obfuscation was switched on or off cannot reach it away from home until
     it has.
   - The forwarder routes by WireGuard's own headers and `mac1`, which the header
     protection hides, so an obfuscated hub gives the forwarder the group's settings when it
     registers, over the registration's TLS. The forwarder takes the protection off a copy
     of each packet to read the type, the indices and `mac1`, and passes the packet on as
     it came. The settings give it nothing it did not have with plain WireGuard: the same
     headers, never a key that decrypts anything. The hub's hellos to the forwarder are
     masked with a key the forwarder gives every hub, so they show no constant either.
   - The phones keep the settings with the hub's offer and start their tunnel with them
     (`mobile/cbbtun` takes them as JSON). The lite member's Rust WireGuard does not speak
     AmneziaWG, so in an obfuscated group it reaches the hub at home only.
2. **WireGuard inside VLESS with REALITY**, between a client and the forwarder, with
   Xray-core (MPL-2.0) as a Go module in `cbb`, and in the phones' Go tunnel
   (`mobile/cbbtun`) rather than libXray, so that one framework carries both; VLESS carries
   the UDP packets itself. The forwarder then has one path for everything, the hub does not
   change, and traffic is always inside our own tunnel. VLESS adds no security of its own and
   the design does not rely on it: the boundary stays the member TLS, then WireGuard.
   - The forwarder's operator switches it on with a well-known site to borrow (`cbb forward
     -vless-site www.example.com`): the forwarder listens on TCP 443, and whoever is not a
     client gets that site's own TLS and pages, by REALITY. Its REALITY key stays in its key
     file.
   - The hub's user switches it on per group (`cbb global hub -forwarder ... -vless`). The hub
     makes the group's VLESS user ID, the forwarder lets that ID in while the hub is
     registered and tells the hub its REALITY key, short ID and site, and the hub gives all
     of it to its clients with its offer, inside the member TLS at home.
   - Then VLESS is the clients' only way to the hub: a client that tried plain WireGuard
     first would show it to the network it wants to hide it from. The hub sends no offer
     until it has the forwarder's settings.
   - The forwarder passes whatever comes over VLESS to its own UDP port and routes it as it
     routes every packet, by `mac1` and the indices, so VLESS cannot be used to reach
     anything else; with AmneziaWG on as well, both apply.

sing-box is not used (GPL).

### Members

| Member                         | Tunnel                                                                                        | Role                     |
|--------------------------------|-----------------------------------------------------------------------------------------------|--------------------------|
| Go service (Linux, macOS, Windows) | amneziawg-go with netstack in `cbb`; Xray-core as a Go module                             | hub, forwarder, relay or client |
| iPhone app                     | in the app process, no Network Extension, one Go framework for WireGuard and Xray             | client, while the app is open |
| Android app                    | in the app process, in the foreground service the app already has; no `VpnService`            | client                   |
| the lite member on Linux       | GotaTun's WireGuard (from Mullvad) with smoltcp's TCP, in its process; plain WireGuard only    | client                   |
| the lite member on the ESP32   | none: the home network only, until a mature WireGuard exists for it                           | home only                |

- On phones the tunnel is ordinary UDP traffic of the app. It does not take the phone's
  single VPN slot, the user's own VPN keeps working, and the app is not a VPN app (Apple's
  guideline 5.4 and Google Play's VpnService rules concern apps that create a device VPN).
- The Swift kit (Network.framework) and the Kotlin kit (Conscrypt) keep their TLS code: the
  app opens a port on the loopback address that leads into the tunnel, and the kit dials it.
  Another app that connects to that port reaches only the hub's member TLS.
- The lite member does the same: GotaTun's WireGuard over a UDP socket and smoltcp's TCP run
  in one thread of `cbb`, behind a port on the loopback address that its member TLS dials, so
  no TUN device, no root and no capability is needed. GotaTun takes its AEAD from ring, whose
  C and assembly would need a C cross compiler for each target; the lite member gives it a
  stand-in with ring's API on RustCrypto's ChaCha20-Poly1305 (`lite/ring-shim`), the
  implementation its TLS uses too, so it stays all Rust and links with rust-lld. GotaTun
  speaks plain WireGuard, not AmneziaWG, so a lite member refuses an obfuscated hub or one
  reached over VLESS and stays at home; its traffic is plain WireGuard to the network.
- No push notifications: they go through Apple's and Google's servers. A phone gets the
  current text when the app opens, as at home.

### Traffic analysis

Frames over the tunnel are padded to a few fixed sizes, so that the length of a text does not
show; the wire format goes into `docs/protocol.md` with the code.

Cover traffic is an option, off by default: a client and the hub send padded empty frames on a
timer, so that neither the network nor the forwarder sees when a text is copied. It costs
traffic and, on a phone, battery, so the user turns it on per device.

### Direct links between clients (later)

Through the forwarder the star is mandatory. Two clients of one group that can reach each
other directly, for example both with IPv6, may later get a direct link: a WireGuard tunnel
with keys from the group's records and member TLS inside, as with the hub, so it is as safe.
It needs each client to accept connections from the internet (phones on mobile networks
mostly cannot) and the hub to hand out the addresses, so it comes after the star works and
only adds to it.

### Rejected

- Overlay networks (Tailscale, Headscale, ZeroTier): third-party services.
- A public relay that routes by the TLS server name: the name shows on the network, and it is
  a server between the user's devices.
- Hole punching: needs a coordinating server and fails on part of the networks.
- A system WireGuard on phones (the WireGuard app, or a Network Extension): takes the VPN
  slot, the app cannot tell whether it is up, and on iOS needs an organisation developer
  account.
- Push notifications and events stored for members that are off: someone else's server.

### Cost

- With a public address at home: nothing; the hub is a member the user already has.
- The forwarder: a small virtual server serves thousands of groups, since clipboard texts are
  small; traffic is the texts and the keepalives.
- On the devices: one UDP socket and an in-process network stack, a few megabytes of memory.

### Order of work

1. WireGuard in `cbb` (done) and the key exchange (done).
2. A listening mode for Macs, so that a Mac can be the hub and phone-and-Mac groups connect
   at home (done).
3. The service: turning sync away from home on and off (the hub, each device, the consent
   for keys in a file), hub mode, dialing through the tunnel, failing closed, `cbb status`
   and the member dial after a join by address (done).
4. Remote invitations in `cbb` (`cbb invite`, the guest tunnel, the admin's confirmation):
   done for computers, made on the hub; handing them over from another admin to the hub
   follows.
5. The forwarder: `cbb forward` and the hub's registration, routing by `mac1` (done); the
   computed port as a fallback if AmneziaWG needs it; the project's own server.
6. The blind relay, self-hosted only (done for computers).
7. The phones: the in-app tunnel in both kits and apps, interop tests against the Go hub,
   making and opening remote invitations. Done: the tunnel, `mobile/cbbtun`, bound by
   gomobile into an AAR and an xcframework; the tunnel offer in both kits; both apps'
   switch, which keeps the hub's offer and reaches the hub through the tunnel while it is not
   found at home. The invitations follow.
8. Blocked networks: AmneziaWG, then VLESS with REALITY. Done: `cbb` and the phones' tunnel
   run on amneziawg-go; obfuscation per group between computers (`cbb global hub
   -obfuscate`), in the hub's offer and in invitations, on both phones, and through the
   forwarder; VLESS between computers (`cbb forward -vless-site`, `cbb global hub -vless`)
   and on both phones.
9. The lite member on Linux (done: `cbb global on`, GotaTun and smoltcp in `cbb`, plain
   WireGuard only, so a group whose hub hides its tunnel keeps it at home); the ESP32 when
   WireGuard on it is mature.

## Device keys in hardware

Today a computer keeps its member key, its WireGuard key and any CA keys in files readable
only by the service. The plan to keep them in the TPM or the Secure Enclave, to show where
each device keeps its keys and to renew them on a schedule is in
[roadmap.md](roadmap.md#device-keys-in-hardware) (D-44, D-47).

## The phone apps

The shortcut can neither hold a key, sign, run CPace nor accept connections, so in a group
that a computer created the group CA lives on the Linux members and the phone only
authorizes with its token. The phone apps can do all four, and in a group that an app
creates the phone is the root of the group (D-33 to D-36; the wire side is section 9 of
[protocol.md](protocol.md)):

- The app creates the group CA in the Secure Enclave (iPhone) or StrongBox/Keystore
  (Android): a P-256 key that cannot be exported. Only the admin phones issue member
  certificates; a computer holds CA keys only when the root phone makes it an admin, so a
  stolen computer cannot add devices.
- The first computer joins the phone, not the other way round: `cbb pair` shows a QR code
  with its addresses, its certificate fingerprint and a fresh code, and listens; the app
  scans it, dials the computer, checks the fingerprint and runs CPace with that code, with
  the phone in the admitting role, then issues its certificate. No profile for the user to
  check: the app trusts its own group's CA.
- Every computer is then a member without CA keys; Linux members still publish, hold
  `clipboardbridge.local` and serve the shortcut for phones without the app. A lite member
  (Rust) takes part the same way.
- Certificate renewal (every two years) and revocation need an admin phone. Losing one is
  covered by a second admin phone, which is an equal admin with a key of its own; see
  "Admin phones, the devices list and revocation" below.
- The app syncs while it is open and through its "Sync clipboard" action (Back Tap or the
  Action button on the iPhone); on Android a foreground service receives by itself, and an
  accessibility service or one tap sends ([apps.md](apps.md)). Background sync stays
  impossible on iOS.
- The mode with the CA on the Linux members and the phone's token as the authority stays for
  users without the app, and `cbb pair` / `join -code` for groups without a phone.

## Admin phones, the devices list and revocation

A user may have several phones, for example an iPhone and an Android phone. All of them join
the one group, and any of them can be an **admin**: it admits devices, renews certificates
and revokes devices, so losing one phone loses nothing. Every app shows the whole group, and
an admin removes a device in two taps. The wire format is in section 10 of
[protocol.md](protocol.md).

**Keys and certificates.** No key ever leaves the Secure Enclave or StrongBox where it was
made, so two phones cannot share one CA key. Instead:

- The first phone's app creates the **group root CA**, as section 9 of the protocol says,
  but with path length 1, so it can certify one level of CAs below it.
- Every admin phone, the first one included, has an **admin CA** of its own: a key in its
  Secure Enclave or StrongBox, certified by the root as a CA with path length 0. Admin keys
  sign only when the user confirms with Face ID, Touch ID, the fingerprint or the passcode,
  so a locked phone in a thief's hand signs nothing.
- Each phone also has a separate member key and certificate, as every member has, for its
  everyday connections; that key needs no confirmation.
- A member certificate comes from whichever admin admitted the device. Members present
  their certificate with the admin CA's certificate in the TLS handshake and check peers
  against the group root, so a certificate from any admin is valid everywhere.
- Making a second phone an admin: the second phone joins as every device does (it scans the
  first phone's QR code in "Add a device"), then the first phone offers "Make it an admin";
  the second phone sends the public key of its new admin key, and the first phone signs its
  admin CA certificate with the root key. From then on both are equal, with one exception:
  only the root key can make further admins. If the root phone is lost, the remaining admin
  **becomes the root** (below).

**The devices list.** Every admission produces a signed **device record**: the device ID,
its name, its role (Linux, Mac, phone, lite), the hash of its key, whether it is an admin,
who admitted it and when. Revocations are signed **revocation records**. Both kinds form one
set that only grows: every member keeps the set and gives it to every peer it meets, so all
members, and every app, show the same list. Merging two sets is their union, and what the
list says follows from the set alone, never from the order in which records arrived, so the
group always converges. The list is small (a few hundred bytes per device) and spreads with
the member protocol; nothing else stores it.

Every app and the command line show it:

- The phone apps: a **Devices** screen (see [apps.md](apps.md)) with every device, its role,
  an admin mark, whether it is online now and when this phone last saw it; on an admin phone
  each row has "Remove".
- The command line on Linux and the Mac: `cbb status` prints the same list;
  `cbb revoke <name or ID>` removes a device; it runs where the device is an admin (a
  Linux member in a group that a computer created, or a computer the root phone made an
  admin; elsewhere the command says so).
- The Windows connector and later apps show the same list from the same records.

**Revoking a device.** An admin signs a revocation record naming the device's keys: its
member key and, for an admin phone, its admin key. The record spreads to every member that
is on, and each refuses the revoked keys at once: running connections with that device are
closed, and new handshakes fail. A revoked admin key also voids every certificate it issued,
except those the record lists as kept: when an admin revokes another admin, its app lists
the devices that the revoked one admitted and keeps them, so they stay in the group, and
renews their certificates from its own admin CA as they connect. A device the thief admits
afterwards is not on the list and is refused. A member that was off gets the record from the
first member it meets.

**Losing a phone.** On the remaining admin phone: Devices, the lost phone, "Remove". That
revokes both of the lost phone's keys and keeps every device it had admitted. If the lost
phone held the root key, the remaining phone also **becomes the root**: it creates a new
root CA, certifies its own admin CA under it, and signs a root record that hands the group
over from the old root to the new one; members that receive the record verify it with the
trust they have, then trust the new root alone, and the remaining admin renews their
certificates from it. Members that were off follow when they come back, as with any record,
so no device has to be paired again. A thief who knows the lost phone's passcode can act as
an admin until the phone is removed; when two admins revoke each other, both lose admin
rights (the rule depends only on the set of records), and the user starts the group anew from
the phone in hand.

**A computer as admin.** The root phone can also make a computer of its group an admin, for
a user who would rather admit and remove devices from a terminal. Every computer of a phone
group keeps an admin key next to its identity and offers its public key in the member
protocol; "Make it an admin" on the root phone certifies it as an admin CA and sends that to
the computer. From then on the computer admits computers with `cbb pair`, removes
devices with `cbb revoke` and renews certificates, as an admin phone does; it makes no
admins and never removes the root phone. Its key is a file, so a thief with the computer can
act as an admin until another admin removes it; that is the price of the convenience, and
why it is a choice, not the default.

**Groups that a computer created** keep working as today (the CA keys on the Linux members):
the device records and revocation records exist there too, signed with the group CA key, so
`cbb status` shows the group and `cbb revoke` removes a Mac or an iPhone's
token without replacing anything. Revoking a Linux member there still replaces both CAs, as
"Devices and revocation" above says, because it holds the CA keys. "Full members, admins and
the operating system" below changes this: such groups get a root and admins as a phone group
has, and any device but the root is removed by a record.

**Order of work.** The Go side first, since it needs no phone: the records, their exchange
in the member protocol, refusing revoked keys, the devices list and `cbb revoke`
in groups a computer created, and members that verify certificates through an admin CA. Then
the apps: the root and admin CAs, the Devices screen, making an admin, and the root record.

## Full members, admins and the operating system

Decided on 2026-10-24 (D-50 to D-53) and built in the steps at the end of this section. It
replaces what "Group and pairing", "Discovery and the shared address", "macOS" and
"Windows" say about Linux members holding the CA keys, the `linux` and `mac` roles and the
Mac only dialing; those parts describe the code until the steps are done. No device of
an earlier version needs to keep working with the new one: every device is updated first.

**The operating system is not the role.** Until now the role in hellos and device records
named a system (`linux`, `mac`), and a Windows PC took part as `linux`, so the group could
not tell the two apart, and it got the CA keys because the pairing gave them to every
`linux` joiner. From now on each device states its operating system in `os`, in the pairing
Info, in its hello and in its device record: `linux`, `windows`, `macos`, `ios`,
`android`, or `none` for firmware without one (the ESP32); `macos` takes the place of the
pairing Info's `darwin`. The `os` is shown, never trusted for anything else. The **role** says only what a device does in the group:

| Role     | Devices                                     | What it does                                                    |
|----------|---------------------------------------------|-----------------------------------------------------------------|
| `full`   | a computer with the service: Linux, Windows, macOS | listens on the member port, dials the other full members and the lite members, may hold `clipboardbridge.local`, may create a group and be an admin |
| `lite`   | the lite member (`lite/`)                   | dials the full members, listens for phones; never holds keys     |
| `phone`  | a phone with the app                        | dials every member, never listens for members                   |
| `shortcut` | an iPhone without the app: a shortcut's token, not a member (legacy, below) | uses the endpoints of the member that holds `clipboardbridge.local` |

The `linux` and `mac` roles are gone: everything that set the Mac apart was a choice, not a
limit of macOS, and the Mac is a full member like the others. The `iphone` role is now
`shortcut`. Records of an earlier group that say `linux` or `mac` are read as `full`, and
`iphone` as `shortcut`. A phone with the app, an iPhone or an Android phone, has its own
key and member certificate and the role `phone`. `cbb status` and the Devices screens of the
apps show each device's system (Linux, Windows, macOS, iOS, Android, or "device" for
firmware) and mark the root and the admins. A device's record takes its `os` from the
pairing Info; when a device's hello states another `os` than its record, an admin that
meets it signs a new record, which is how the Windows PCs that joined as `linux` get their
name back.

**Who dials whom.** Between two full members the one with the lower device ID dials; if it
has not connected within 30 seconds, the other dials as well, and of two connections
between the same pair the one the lower ID dialed stays. Full members dial the lite
members; phones dial everyone. The installers open the member port in the system's
firewall on all three systems, as they do today.

**Who holds `clipboardbridge.local`.** Only a full member that can serve the shortcut, that
is one that holds the iPhone CA key (the root and the admins of a group a computer created).
Among those that are on, a device that does not sleep comes first and a laptop only when no
other is on; then the lowest device ID, as today. This is a preference, not a requirement:
no device has to stay on, and whichever of them is on holds the name. The service guesses which it is from
whether the machine has a battery, and a setting overrides the guess (always first, only as
a fallback, or never). The TXT record tells the others the member's priority. Whether the
Mac's own mDNS code can hold the name next to mDNSResponder is an open question until it is
tried on a Mac.

**Keys: the creator and the admins.** Any full member can create a group, a Mac included.
Every new group gets a root CA with path length 1, as a group a phone creates has, and the
creating computer holds its key and is the group's **root**. Every other full member gets
only its member certificate: no CA key reaches it by joining. Each full member keeps an
admin key next to its identity and offers it in its hello, as a computer of a phone group
does today ("A computer as admin" above); the root makes a member an **admin** on request,
with `cbb admin <name>` on the root computer or "Make it an admin" on a root phone, by
certifying that key as an admin CA. An admin admits devices, renews certificates, signs
records and removes devices; only the root makes admins. In a group a computer created an
admin also receives the iPhone CA key with its admin CA, so the shortcut and the pairing of
an iPhone without the app work while any admin is on. A group a phone created stays as it
is: the phone is the root and the group has no iPhone CA. Lite members never hold keys and
are never admins.

**Removing a device.** Every device except the root is removed with a revocation record, as
in a phone group, without a new group:

- a member that is no admin: its member key is revoked, and that is all;
- an admin: its member key and its admin key are revoked, and the devices it admitted are
  kept. Only the root or an admin phone removes an admin; another admin computer freezes it
  ("Who may remove an admin" below). In a group a computer created, it also held the iPhone CA key, so the admin that
  removes it replaces the iPhone CA as well: a new key, new `clipboardbridge.local`
  certificates for the admins, and every token revoked; iPhones that use the shortcut
  delete the old profile and pair again. The group's root stays;
- the root computer: another admin takes the group over with a `root` record, as an admin
  phone does when the root phone is lost (`cbb takeover <name>`), and then removes it. This
  is open to admin computers in a group whose root is a computer; in a phone group they
  still never take over. A group whose root is gone and has no other admin must be made
  anew, so `cbb pair` suggests making a second admin.

**Upgrading a group a computer created.** A group made before this change has a group CA
with path length 0, and every Linux and Windows member holds the keys of both CAs. It is
upgraded once with `cbb upgrade` on one of them, after every member runs the new version,
and that member becomes the root:

1. It creates a new root CA with path length 1 and signs, with the old group CA key, a
   `root` record that names it. The group keeps its tag, so no device pairs again.
2. Under the new root it revokes the old group CA key and keeps every listed device's key,
   so nothing the old key signs from then on counts. A `root` record that a group CA with
   path length 0 signed itself still counts when every record that revokes that key was
   signed under the root it names: a leftover copy of the old key can then break the group
   by signing a rival handover, but never take it over.
3. It replaces the iPhone CA as above, since every member held its key; iPhones that use
   the shortcut pair again.
4. It signs a new device record for every device, with role `full` or `lite` and the `os`
   its hello states, and renews certificates from the new root as members connect.
5. Each member that gets the records deletes its copies of the old CA keys and says so in
   its hello. Until a member has said so, `cbb status` marks it as still holding the old
   keys, and `cbb revoke` refuses to remove it. Members that were off follow when they
   come back.

**The shortcut is a legacy way.** An iPhone without the app joins through a shortcut and a
token (section "The iPhone button"), never with a key of its own. It stays for now, since
the app does not yet run on a real iPhone, but it is not developed further, and every user
is expected to use the app. Everything it needs comes with it: the iPhone CA, its key on the
admins, and the rule for who holds `clipboardbridge.local`. It is removed with all of these
once the app runs on real iPhones through TestFlight (roadmap.md, item 17): the group is
then simpler, with one kind of trust, and every key in it can be revoked by a record.

**Order of work**, one pull request each:

1. This decision.
2. The `os` beside the role: `os` in the pairing Info (`windows` allowed), the hello and
   device records; the roles `full`, `lite`, `phone` and `shortcut` in Go, the lite member and both
   phone kits; `cbb status` (which takes in `cbb devices`) and the Devices screens show
   the system and the root and admin marks; an admin re-signs a record whose `os` is
   wrong.
3. The Mac as a full member: the dialing rule above, listening like the others, holding
   `clipboardbridge.local` by priority, with the battery guess and its setting; `cbb global hub`
   says that nothing syncs away from home while the hub is off.
4. New groups made by a computer with a root of path length 1: the CA keys on the creator
   only, the admin key on every full member, `cbb admin`, the iPhone CA key for admins,
   removing any device but the root by record, and replacing the iPhone CA when an admin
   goes. A Mac can create a group and be an admin from here on.
5. Taking over from a lost root computer (`cbb takeover`).
6. `cbb upgrade` for groups made before.

## Who may remove an admin

Decided on 2026-10-24 (D-60). An admin computer keeps its admin key in a file, so it is the
admin a thief gets most easily: with the laptop, or with a copy of the file. The root and
the admin phones keep theirs in the Secure Enclave or the Keystore, behind Face ID or the
fingerprint. So the question is what an admin computer may do to another admin.

**The rule.** The root and the admin phones remove any admin (`cbb revoke` on the root, Remove
in the apps). An admin computer removes ordinary devices only; it never removes the root or
another admin, and hands the group over only from a lost root computer (below). Instead, **any admin freezes another admin
computer** (`cbb freeze <name>`): from then on the frozen admin is no admin, nothing it signs
counts beyond the records it signed before, its connections are refused, and it cannot
paste. The root or an admin phone then decides: Unfreeze in the apps (`cbb unfreeze` on a
root computer) makes it an admin again, Remove takes it out for good. Nobody freezes the
root or an admin phone. How the records say it is in protocol section 10, rule 4.

**Taking over from a lost root computer.** In a group whose root is a computer, the root key
sits in a file just as an admin computer's key does, so a stolen admin computer is no
weaker than the root; and if the root is lost and only admin computers are left, the group
has no other way on. So there, and only there, an admin computer may hand the group over
(`cbb takeover`), and the records limit it: the takeover counts only while the old root's
own records leave that admin standing. If the old root is still there, it removes the
admin and the takeover stops counting, so a thief cannot take a group from a root that is
still in use. A frozen admin computer does not take over until the old root thaws it. In a phone's group an admin computer never takes over.

**Why freezing, and not one of the two simpler rules.**

- *Only the root and the admin phones act, and admin computers do nothing to admins.* This
  keeps a thief with an admin computer from touching the root or the other admins, but it
  leaves the thief an admin until the owner reaches the root or an admin phone: a window in
  which it admits devices of its own, removes ordinary devices and pastes where remote
  paste is on. The root is often a computer at home, and many groups have no second admin
  phone, so that window can be long.
- *Any admin removes any other admin.* This closes the window from any admin device, but it
  hands the thief the same power first: a stolen admin computer removes every other admin
  before the owner notices, the group keeps no admin but the thief and the root, and if the
  root is a computer the thief may be the last admin standing. A removal cannot be undone,
  so the group is made anew.
- *Freezing* takes the good half of each. Any admin, a computer included, stops a stolen admin
  at once, as the owner asked ("revoke everything of a stolen admin quickly on any admin
  device"). The worst a thief does with it is freeze honest admin computers, and a freeze is
  undone with one tap on the root or an admin phone, which loses nothing: what the frozen
  admin did before stays. The irreversible step, removal, stays with the keys that are
  hardest to steal.

**What it costs.** A new record type in every implementation (Go, the lite member, both phone
kits), and a short time in which a thief can keep honest admin computers frozen until the
owner reaches the root or an admin phone. Two admins that freeze each other both stay
frozen: a freeze counts whoever signed it, so the rule does not depend on which freeze came
first, which no member can tell. A freeze lists the frozen admin's records that stay, so
records of that admin that reached nobody before the freeze are lost with it; they were
signed after the theft at the earliest, or can be signed again after an unfreeze.

**Rejected.** A time limit after which a freeze lapses (a thief would wait it out), and votes
among admins (a home group has one or two admins, so a vote decides nothing).

## Sync modes (planned for 0.5)

Today every copy on any member goes to the clipboard of every other member within a second,
so a copy on one computer replaces what was just copied on another. Each device gets a
**sync mode** instead, and a new device starts in its own:

| Mode | Its copies go to the group | The group's copies reach its clipboard |
|---|---|---|
| **Own** (the default) | no | no; the group's text is still at hand on request (`cbb paste`, the app's button) |
| **Shared** | yes | yes (what every member does today) |
| **Receive only** | no | yes; for a Pi or a kiosk that only shows what comes |
| **Send only** | yes | no; for a work computer whose clipboard nobody else should change |

- The mode decides only what moves between the clipboard and the group. The member stays
  connected in every mode, so an admin can change its mode from afar, revocations reach it
  at once, and remote paste works on it. Sync away from home is turned on apart from the
  mode (D-45).
- A device changes its own mode (`cbb mode`, the apps' settings). An admin changes the mode
  of any member with a `mode` command, signed and checked like a `paste` command (see
  "Remote paste"); the member keeps the mode across restarts and reports it in its hello,
  so the devices list shows it.
- Deliberate actions (`cbb copy`, sending from a phone, a paste ordered by an admin) work
  in every mode.
- Built so far: the mode on the computers (`cbb mode`, the file `mode` in the service's state
  directory, the hello's `mode` and the devices list), with own for a device that makes or
  joins a group and shared for one that joined before 0.5, which has no mode file; the
  admin's signed `mode` command (`cbb mode -on DEVICE`, docs/protocol.md section 15), sent
  directly to a connected member, and in the phone kits the hello's `mode`, the commands and
  their results; the Mac app and the tray app set this computer's mode and, on an admin,
  another computer's, and an admin phone sets a computer's from its page. Still to come in
  0.5: the phones' and the lite member's own modes; they share until then, and refuse a
  `mode` command.

## Remote paste (planned for 0.6)

An admin device sends a text to one chosen member and has it pasted where that member's
focus is: a window, a terminal, a text console. Nobody touches the target. It is meant for
devices without a keyboard (a Raspberry Pi on a TV, a kiosk, a console login) and, through
the Nano ESP32's USB keyboard, for a computer that runs no Clipboard Bridge at all. For
running commands on a headless Pi, SSH stays the better tool; remote paste reaches what SSH
does not, the screen's own session.

### Who may paste where

A device in a group trusts its admins: they already admit it, renew its certificate and
remove it. Still, typing into a device is more than syncing a clipboard, so **remote paste
is off on every device until its own user turns it on there** (`cbb paste-receive on`, a
switch in the apps; D-59). Once it is on, every admin may paste on it with no further
consent. The admins are the root and admin phones, the admin computers of a phone group,
and in a group a computer created the root computer and the admins it made. Members that
are not admins never send. Besides the switch, the target's user sets up only the
permissions the operating system demands once (below); without them the system refuses the
input, and the sender is told so.

- **Enter and root consoles are off by default** even when remote paste is on: the `enter`
  flag is refused, and so are the Linux text console helper and a tmux session of root,
  until the device's user turns each on there (`cbb paste-receive on -enter`,
  `-console`). So a paste can at most put text in front of the user, not run it.
- **Any admin turns it off on any member** with a signed command, like the sync mode
  (D-55), when an admin device is lost: it takes effect at once, needs no consent, and only
  the device's own user turns it on again.
- **A stolen admin is cut off quickly.** Any other admin, a computer included, freezes it
  with one action (`cbb freeze`, "Who may remove an admin" above): from then on nothing it
  signs counts on any member, pastes included. The root or an admin phone then removes it
  (`cbb revoke`, Devices in the apps), which revokes its member and admin keys together.
  Any admin can also turn remote paste off on every member at once (`cbb paste-receive off
  --all`).

### How the text gets in

Two methods: **paste** (write the text to the target's clipboard, then press the paste
keys) and **type** (send each character as a key). Paste comes first: it does not depend
on the keyboard layout, it is fast, and a terminal with bracketed paste does not run a
pasted newline before the user sees it. The `enter` flag presses Enter afterwards.

| Target | Method | Limits |
|---|---|---|
| Linux, X11 | the desktop connector: clipboard and primary, then Shift+Insert through XTEST; typing through XTEST with a temporary keysym mapping | a screen locker that grabs the keyboard refuses it |
| Linux, Wayland with `zwp_virtual_keyboard_v1` (sway, Hyprland, labwc) | the clipboard through data-control, the keys through the virtual keyboard (any Unicode through its own keymap) | the compositor must offer the protocol |
| Linux, Wayland on GNOME and KDE | a uinput virtual keyboard, as auto-paste does, pressing Shift+Insert after the clipboard write | needs access to `/dev/uinput`, given by the installer through a udev rule for the connector's group; keys only, so typing follows the layout and paste does not |
| Linux text console | the console helper: TIOCSTI on the active virtual console, as root with only `CAP_SYS_ADMIN` (since Linux 6.2 TIOCSTI is otherwise refused, `dev.tty.legacy_tiocsti`); bytes, so any UTF-8 the console font shows | text consoles only |
| Linux, tmux | `tmux send-keys -l` into the active pane of the tmux session the login snippet starts | no root needed |
| Windows | the clipboard agent in the user's session (the service in session 0 cannot inject): clipboard and Ctrl+V, or `SendInput` with `KEYEVENTF_UNICODE` | UIPI keeps it out of elevated windows unless the agent runs with `uiAccess`, which needs a signed binary in Program Files; never on the secure desktop (UAC, the lock screen) |
| macOS | the pasteboard agent: pasteboard and Cmd+V through `CGEventPost`, or `CGEventKeyboardSetUnicodeString` | the Accessibility permission, granted once in System Settings; an ad hoc signed agent loses it on each update, so it waits for the signed `.pkg` to be practical; Secure Event Input (password fields, Terminal's Secure Keyboard Entry) and the lock screen refuse it |
| Android | the app's accessibility service: the clipboard, then `ACTION_PASTE` on the focused input node (or `ACTION_SET_TEXT`) | views without an editable node (some terminals and games); not on the lock screen |
| iPhone, iPad | not possible: iOS lets no app put text into another app | sender only |
| the lite member on Linux | the console helper or tmux, as on Linux | as Linux |
| Nano ESP32 | its USB keyboard (roadmap item 15) types into the computer it is plugged into | Latin characters only |
| ZX Spectrum Next | none: `.cbb` runs only when started | |

Senders: the iPhone and Android apps (a "Paste on…" action with the devices list) and admin
computers (`cbb paste --on DEVICE`, from standard input or the clipboard; later the Mac
menu bar item and a tray item on Linux and Windows).

### The command

A `paste` command is signed like a record (protocol section 10) and never stored. Its
body carries `v`, `type` (`paste`), `group`, `by`, `to` (the target's device ID), `id` (128
random bits), `time_ms`, `expires_ms` (at most 30 seconds later), `mode` (`paste` or
`type`), `enter`, `kind` (`text` or `secret`) and `text`, inside the signed body.

- The sender sends it on its connection to the target, or, without one, to the members
  that have one; a member passes a command it has not seen (by `id`) only towards `to`,
  unchanged. The text is not a group event and is not synced.
- The target checks that the signature verifies to a root on the path and the signer is an
  admin whose keys are not revoked, that `group` and `to` are its own, that `expires_ms` is
  in the future and `time_ms` at most 60 seconds ahead of its clock, and that `id` is not
  in its replay cache (kept until expiry). A target whose clock is not set (a Pi without a
  clock before NTP) refuses with that reason.
- It answers with a result that goes back the same way: `pasted`, `refused` with a reason,
  or `failed` with the underlying error, which the sender shows in debug mode.

The signature, not the connection, says who sent it, so a member that forwards a command,
such as the hub, cannot forge or change it.

### Safeguards that need no consent

- Control characters other than newline and tab, escape sequences and invalid UTF-8 are
  removed. At most 4 KiB when typing and 1 MiB when pasting.
- A phone signs with its key in the Secure Enclave or the Android Keystore, behind Face ID
  or the fingerprint, one prompt for a few minutes of pastes.
- The target shows a notification ("Pasted from iPhone", with the sender's name; the ESP32 blinks its LED)
  and keeps a log of the last 100 pastes: sender, time, length and result, never the text.
- At most one paste a second and 30 a minute from one sender.
- A `secret` paste is never logged, and the clipboard is cleared after it.
- Away from home only inside the group's tunnel, under the rules of "Sync away from home".

**A stolen admin device.** A phone cannot paste without its owner's face or finger. An
admin computer keeps its admin key in a file, so a thief with it can paste text on the
members whose users turned remote paste on, but presses Enter and reaches root consoles
only where those were turned on too, and only until another admin freezes it or turns
remote paste off, or the root or an admin phone removes it; removal reaches every member through the
records, and from then on its commands fail the signature check. Keys in hardware ("Device keys in hardware" in [roadmap.md](roadmap.md#device-keys-in-hardware))
narrow this to a thief who also has the computer running.

## Open questions

These need experiments on real devices; CI cannot answer them. Each says what is known and
which case of the test bench ([testbench.md](testbench.md)) answers it.

- Does the Mac see a Universal Clipboard item from the iPhone (the change counter moves)
  without a paste on the Mac, and which types does the item carry? The agent relies on
  both. Needs an iPhone signed in to the Mac's Apple account, not the app (bench case P15).
- Does reading the pasteboard types trigger the macOS pasteboard privacy alert, and is the
  alert enforced by default on macOS 27.2 and later? The bench's Mac runs 27.0, where the
  alert can be turned on by hand; the default waits for 27.2 (P23).
- On GNOME with on-demand XWayland: do copies in native Wayland apps reach the connector
  promptly, and do its writes become the Wayland selection without focus? The bench's
  GNOME session on the Steam Deck syncs through XWayland, but its own clipboard tool is an
  X11 client too, so native Wayland apps and a session where XWayland has not started yet
  remain to be tried (P24).
- Does the macOS application firewall filter the mDNS answers that reach the service's own
  socket on UDP 5353 (it is not mDNSResponder)? The installer already lists the service in
  the firewall; what remains is the mode "Block all incoming connections", which lets only
  the system's services through and ignores that list (P26).
- Can the Mac's own mDNS code hold `clipboardbridge.local` next to mDNSResponder (D-53)? The
  code lets a Mac hold the name since step 3 of "Full members, admins and the operating
  system"; whether the others resolve it is untried (P25).
- When the console helper is built (roadmap item 10): console injection at an agetty login
  prompt, in `sudo` and in vim on Ubuntu and Raspberry Pi OS; latency and CPU of the
  double-tap trigger on a Pi Zero W.
- When images and files are built (roadmap item 20): which applications on each system
  paste images and file lists that another program wrote (Android keyboards and apps,
  Windows Explorer with `CF_HDROP` from the agent, iOS apps)?
- Only while the shortcut lasts (it goes after TestFlight, roadmap item 17): on iOS 18, 26
  and 27, does Shortcuts trust the name-constrained iPhone CA and reach
  `clipboardbridge.local` (Local Network prompt, first-run prompts, behaviour from the Lock
  Screen), how fast does it notice a handover of the name, and does it reach a Mac that
  holds the name?

## Decision log

| ID   | Decision                                                                                   |
|------|--------------------------------------------------------------------------------------------|
| D-1  | License: AGPL-3.0-only. Code contributions are not accepted, so no contributor agreement is needed. |
| D-2  | Language: Go, for reliable ARMv6 builds, TLS and networking in the standard library, and development speed. |
| D-3  | A group of equal members instead of a central server; any member may be off.              |
| D-4  | Encryption with the project's own TLS and pairing instead of an overlay VPN, which on iOS would conflict with other VPN apps. |
| D-5  | At home, members find each other on one network; away from home they reach the hub through the group's own tunnel (D-38). |
| D-6  | Mac and Linux sync automatically; the iPhone uses one button that picks the direction.     |
| D-7  | Console without a desktop: tmux for copy and paste, a root helper for console paste outside tmux. |
| D-8  | The repository is in English only, apart from the apps' translations (String Catalogs, Android `values-<language>`). |
| D-9  | Pairing a computer: code entry with CPace inside TLS 1.3 instead of comparing digits, which a man in the middle can grind. |
| D-10 | The iPhone trusts a separate CA restricted by name constraints; the token is shown only after that trust is in place. |
| D-11 | One advertised port serves members, pairing and the iPhone, told apart by the first bytes. |
| D-12 | Own mDNS responder on Linux: no Go library publishes a separate name with its own lifetime, answers per interface and sends goodbyes. |
| D-13 | (Replaced by D-53.) Only Linux members hold `clipboardbridge.local`; Macs never hold it (since D-46 they listen too). |
| D-14 | The hybrid clock never refuses a timestamp and warns about skew measured per connection; events carry their age for the 45-second rule and secret expiry, and local durations count sleep. |
| D-15 | macOS runs the service as a LaunchDaemon plus a pasteboard LaunchAgent, which avoids the Local Network prompt; installing needs administrator rights. |
| D-16 | Desktop clipboard in pure Go: Wayland data-control (both protocol variants) and X11 through `jezek/xgb`; no `wl-clipboard`. |
| D-17 | Console paste injects a single line by default, with control characters removed.         |
| D-18 | Secrets reach only root and the `clipboardbridge` group; the control socket enforces it through file permissions. |
| D-19 | The group state is last-writer-wins; the protection of copies made during a disconnect applies only to writing the local clipboard (live window 60 s, rejoin window 30 s). The first version kept that rule in the group state, and a review showed that the group could then split for good. |
| D-20 | The rejoin window opens only on a local sign that the member itself was away (start, wake), not when it merely lost its peers. A network that drops without a sleep is not noticed yet. |
| D-21 | Each member keeps its own clipboard text apart from the group state; `cbb paste`, tmux, the console helper and the iPhone button use it. |
| D-22 | A secret travels in a hello as a mark without its text, so the group converges on secrets too. |
| D-23 | (Replaced by D-51.) Revoking a Linux member replaces both CAs, because it holds their keys; members that were off still trust the old CA until they pair again, and iPhones delete the old profile. |
| D-24 | Local durations use a clock that counts sleep and ignores wall-clock steps (package `uptime`). |
| D-25 | The hybrid clock saves a mark 10 seconds ahead before passing the last one, so it never goes back after a crash. |
| D-26 | iPhone pairing: the profile over a separate plain-HTTP port and the fingerprint check first, then the code on a page that the trusted CA authenticates. |
| D-27 | The engine remembers secrets for 12 hours; a watcher offering one again without its mark makes no event, a deliberate action makes it a secret again. |
| D-28 | Two ways in: watchers report changes (no event when nothing really changed), deliberate actions always send and also write the member's own clipboard. |
| D-29 | Certificates are checked with the local clock, but never earlier than the group CA's start: a clock that is behind does not break the group, an expired certificate is still rejected. |
| D-30 | Pairing runs inside TLS with self-signed certificates on the new device's side and channel binding (an exporter and both certificates) instead of a separate encryption layer: CPace authenticates the TLS session, and everything after it travels in that session. |
| D-31 | The mDNS responder does not probe its names: device IDs are random, `clipboardbridge.local` is never renamed, and the group's election decides who holds it; two holders for a moment are harmless, since any Linux member can serve the iPhone. |
| D-32 | The Mac browses with Clipboard Bridge's own mDNS code instead of the Bonjour API: it shares port 5353 with mDNSResponder, and the service needs no cgo. The cost is a socket of its own on UDP 5353, which the macOS firewall may treat differently (see Open questions). D-12 still holds for Linux. |
| D-33 | Several equal admin phones: a root CA with path length 1 certifies an admin CA per phone, each key in its own Secure Enclave or StrongBox, instead of one CA key copied between phones or backed up to a cloud. Only the root makes admins; a remaining admin becomes the root with a signed root record. |
| D-34 | The devices list and revocations are signed records in a set that only grows and spreads through the member protocol; what it says depends on the set alone, so the group converges. Two admins that revoke each other both lose admin rights. |
| D-35 | Revoking an admin keeps the devices it admitted, listed in the record, so losing a phone never means pairing the computers again. |
| D-36 | A computer can be an admin of a phone group, with an admin key in a file that the root phone certifies on request, never by default: admitting from a terminal is worth a key outside a Secure Enclave only to a user who asks for it. |
| D-37 | Windows runs the service as a Windows service plus a clipboard agent in each session, as on the Mac, since a service cannot reach a session's clipboard; the control socket stays an AF_UNIX socket, guarded by the access list of its directory, so the protocol and the client code are the same everywhere. |
| D-38 | Away from home: a star of WireGuard tunnels to a hub, a member at home, with WireGuard in user space inside `cbb` and the apps and the member TLS inside; no third-party services; a feature that cannot keep the data fully protected is not built. |
| D-39 | Homes behind carrier-grade NAT use a forwarder run by the project that holds no keys and routes each packet to its own group's hub only (by WireGuard's `mac1`, so nothing on the wire tells groups apart; if that fails, by a port the group computes from its secret and the hour, never by a fixed port or a request naming the group), with limits per group. On disk it keeps only each group's roots, removals and freezes (so a removed device cannot register as its hub again), never a device's name. The hub registers with its member certificate; changing the hub's WireGuard key on a schedule and cover traffic are options, off by default. |
| D-40 | Blocked networks: AmneziaWG first, then WireGuard inside VLESS with REALITY to the forwarder, so that traffic always stays inside the group's tunnel. |
| D-41 | Phones keep the tunnel inside the app, without a system VPN or push notifications, so the VPN slot stays free and no one else's server is involved. |
| D-42 | The ESP32 stays on the home network until a mature WireGuard exists for it. |
| D-43 | A device away from the group joins by SSH, by the user's own VPN, or by a remote invitation: a QR code or a file, never typed, with a one-time guest WireGuard key that reaches only the pairing and a 128-bit secret, and admitted only after the admin confirms the device. The six-digit code never faces the open internet. |
| D-44 | Computers keep their keys in the TPM or the Secure Enclave where they have one, and otherwise in a file sealed as far as the system allows, shown as such in `cbb status`; keys are renewed on a schedule. |
| D-45 | A group starts on the home network only; sync away from home is turned on by the user, at the hub and on each device, and a device whose keys sit in a file needs a separate consent that explains the risk and the measures against it. |
| D-46 | (Replaced by D-50.) Macs listen on the member port and publish themselves with `r=mac`, so phones, other Macs and lite members reach them without a Linux member; a Mac still dials the Linux and lite members, which never dial it, so its firewall cannot cut it off from them. |
| D-47 | Key attestation (TPM, Android) is built as an option, off by default and not used in the project's own setup; it is checked only offline, so no maker's or Apple's server is involved. |
| D-48 | The ZX Spectrum Next joins through its own Raspberry Pi, which runs the lite member; no device outside the Next takes part, and a Next without a Pi is future research on its own hardware only. |
| D-49 | No gateway or plain tier: a device too weak for the member protocol joins through hardware of its own or not at all; on Arduino only ESP32 boards (the Nano ESP32 first) are supported, as full lite members. |
| D-50 | A device's operating system (`os`) is stated apart from its role, so a Windows PC is shown as Windows; the roles are `full` (every computer with the service, the Mac included), `lite`, `phone` and `iphone`, and the `linux` and `mac` roles are dropped. |
| D-51 | In a group a computer creates, only the creating computer (the root) and the members it makes admins hold CA keys, through the admin CAs of D-33 under a root with path length 1; any device but the root is removed by a record without a new group, and a lost root is taken over by an admin. |
| D-52 | Groups made before D-51 are upgraded in place with a `root` record signed by the old group CA key and a revocation of that key; a leftover copy of the old key can break such a group but never take it over. |
| D-53 | `clipboardbridge.local` is held only by a member with the iPhone CA key, machines that do not sleep first and laptops as a fallback, guessed from a battery and set by a setting. |
| D-54 | Every admin may paste a text on any member that turned remote paste on (D-59), the target pressing nothing per paste, since a member already trusts its admins; the command is signed by the admin and checked by the target, and the iPhone is a sender only, because iOS allows no input into other apps. |
| D-55 | Each device has a sync mode, own (the default), shared, receive only or send only, which decides only what moves between its clipboard and the group; it stays connected in every mode, changes its own mode, and any admin changes the mode of any member with a signed command. |
| D-56 | Images, files and folders sync wherever the platform allows, with formatted text (HTML) last and optional; lite members, the iPhone shortcut, secrets and remote paste stay text only. |
| D-57 | Large content travels outside the event: the event carries a manifest with SHA-256 hashes, the bytes are fetched in chunks at lower priority than events from any member that has them, and the clipboard is written only when everything has arrived and matches; each device sets its own limit (100 MiB at home, 25 MiB away from home by default, at most 1 GiB), and the receiver's limit decides. |
| D-58 | Images and files have the protection of text: member TLS at home, and away from home only the group's tunnel with member TLS inside it; no further layer is needed, since only group members ever hold the plaintext. |
| D-59 | Remote paste is opt-in on each device, turned on by its own user; Enter and root consoles are off by default and turned on separately; any admin turns remote paste off on any member with a signed command, and the root or an admin phone removes a stolen admin with one action (refines D-54). |
| D-60 | Only the root and the admin phones remove an admin; any admin, a computer included, freezes another admin computer, which then counts for nothing until the root or an admin phone unfreezes or removes it; nobody freezes the root or an admin phone. Freezing stops a stolen admin at once from any admin device, while the irreversible removal stays with the keys hardest to steal. |
| D-61 | With sync away from home on, a computer's service reaches beyond the home network only its group's own servers (hub, forwarder, relay, from the group's settings), in the program on every system and in the system's limit on Linux and Windows, which `cbb global` with root or an administrator keeps in step; a hub reached at its own address answers authenticated clients anywhere, which on Linux only the program can confine to its UDP port. |
| D-62 | The control socket takes only the clipboard and the status; what changes the group (pairing, removing, renaming, admins, takeover, freeze, sync away from home, the holder setting) takes the admin socket, which only root or an administrator reaches, so membership in the `clipboardbridge` group no longer gives a program the group's keys to use. |
| D-63 | A full member publishes itself by mDNS and takes connections on the member port only on networks where it met its group (by the interface's networks and its gateway's link-layer address); elsewhere it only browses, so a laptop in a café is not tracked by its host label and group tag. |
| D-64 | A group made on a phone has the phone as its hub while the app is open: at home it accepts member connections, from afar it registers with the forwarder over an outgoing connection, and its clients retry often; the app suggests once moving the hub to a computer that is always on, the old hub passing its clients' keys to the new one, and the user may keep the phone as the hub. Everyone has a phone, not everyone a computer, so the phone does what it can until a better device takes over. |
