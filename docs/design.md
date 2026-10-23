# Design

Status: agreed design; the code follows it stage by stage. Decisions are listed in the
[decision log](#decision-log) at the end; questions that still need an experiment are under
[open questions](#open-questions).

## Goals

- One clipboard for the user's Apple devices and any number of Linux machines on one home
  network, and away from home through the group's own encrypted tunnel (planned).
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
- Images and files in the first version: text only.

## Devices and roles

| Device                  | Component                         | How it takes part                                              |
|-------------------------|-----------------------------------|----------------------------------------------------------------|
| Linux with a desktop    | service + desktop connector       | automatic, through the desktop clipboard                       |
| Linux without a desktop | service (+ console helper)        | its own clipboard: tmux, `cbb copy`/`paste`, console paste |
| Mac                     | service + pasteboard agent        | automatic                                                      |
| Windows                 | service + clipboard agent         | automatic                                                      |
| iPhone, iPad            | a shortcut                        | one press (Action button or Back Tap)                          |

Linux machines, Windows PCs and Macs are equal **members** of a **group**. There is no central server, and
any member may be switched off at any time.

## Identifiers and ports

- **Device ID**: 128 random bits as 32 lowercase hex characters. It fits in a DNS label and
  compares the same way everywhere.
- **Member port**: clipboardbridge's one port, TCP 8764 unless the installer was given another,
  advertised in the mDNS SRV record. Linux members listen there for mutual TLS; Macs only
  dial out. The first bytes of a connection pick what it gets (docs/protocol.md, section 3):
  - members and the phone app, with the member ALPN protocol and mutual TLS;
  - pairing, with its own ALPN protocol;
  - the shortcut's HTTPS (`/sync`, `/admit` and the pairing page `/pair`), with no client
    certificate, for any other ALPN protocol;
  - plain HTTP that serves only the iPhone CA's configuration profile, and only while a
    phone pairing window is open. The profile is public, and the user checks its
    fingerprint before trusting it.

  A computer that joins by QR code listens there too, since it is in no group yet. One port
  is one rule in a firewall, and changing it is one setting.

## Group and pairing

- **The phone is the main device.** The usual way to build a group starts from the phone:
  `cbb pair -phone` on the first Linux machine creates the group and pairs the
  phone; every further computer runs `cbb join`, which shows a QR code with a fresh
  code, and the phone's second shortcut ("clipboardbridge: add a computer") scans it and posts
  the code to `/admit` on `clipboardbridge.local` with its token. The member there opens a
  pairing window with exactly that code, and the computer, which browses for a window for
  up to five minutes, joins through the same CPace exchange as below. The keys of the group
  stay on the Linux members, which must be on; the phone's token is the authority to add a
  computer, so a stolen token lets its holder add a computer (and a Linux one gets the CA
  keys). Each admission is logged. Admitting from a Linux member with `cbb pair` and
  `cbb join -code` stays for groups without a phone.
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
  the user runs `cbb join -code` and types the code (it is read from the terminal or standard input, never
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
- **Devices and revocation**: `cbb devices` lists the members and iPhones;
  `cbb revoke <name>` removes one. Revocations are signed records that only grow and
  spread to every member. A revoked Linux member still holds the CA keys, so revoking it also
  replaces both CAs. The Linux member where `revoke` runs (on a Mac, a connected Linux
  member) creates a new group CA and a new iPhone CA, issues new certificates to the members
  connected at that moment, and revokes every iPhone token. Members drop the old CA as soon as
  they receive the new one. A member that was off at that moment still trusts the old CA, so
  it can still connect to the revoked member and to other members that were off, but not to
  the rest of the group. `revoke` lists those members, and the user pairs them again, or stops
  clipboardbridge on them, before they join the network again. The user also deletes the old
  clipboardbridge profile on every iPhone at once and pairs the iPhones again; until then the old
  profile still trusts the revoked member, so the button must not be used. The records and
  the list are described in "Admin phones, the devices list and revocation (planned)" below.

## Discovery and the shared address

- Linux members advertise `<device ID>._clipboardbridge._tcp.local` with SRV, TXT (the protocol
  version `v=1`; the group tag `g=`, a short fingerprint of the group CA, so the members of
  another group, or of a replaced CA, are ignored; and `p=1` while a pairing window is open)
  and A/AAAA records under their own host label `cb-<device ID>.local`, never the system
  host name. Macs only browse.
- Linux members run clipboardbridge's own small mDNS responder, which shares UDP port 5353 with
  avahi-daemon or systemd-resolved; a CI job checks that avahi browses and resolves it. It
  answers each query with the addresses of the interface the query arrived on, and with an
  NSEC record when the name has no address of the asked type, so a resolver does not wait
  for it. Records that name a host (SRV, A, AAAA) live 120 seconds, PTR and TXT 75 minutes.
  The member announces its records twice at start and after every change, and sends
  goodbyes, without the cache-flush bit, for addresses that go away and for everything when
  it stops. A record is multicast at most once a second on an interface, and
  a legacy unicast resolver gets a few answers a second at most. Packets are read record by
  record, so a record clipboardbridge cannot read, such as an Apple device's instance name with a
  dot in it, costs only itself. It browses at growing intervals, listing the members it
  knows as known answers, and asks again for the records of the members it found at 80,
  85, 90 and 95 percent of their lifetime, so they do not expire while the members are
  there. A received record lives no longer than clipboardbridge's own records of its type, and
  only names in the form of device IDs count as members. Names are not probed: device IDs
  are random, and the election, not a probe, decides who holds `clipboardbridge.local`. Macs
  browse with the same code without publishing; a test on macOS showed that it shares port
  5353 with mDNSResponder and that the system's `dns-sd` sees what it publishes, so no
  Bonjour binding is needed.
- Members connect to the addresses from discovery, never by resolving a `.local` name: a
  static Linux binary cannot resolve `.local` itself. Peers are authenticated by the group
  CA, not by name. A home group is small: Linux members connect to each other, every Mac
  connects to every Linux member, and Macs never connect to each other. A Mac is alone
  whenever no Linux member is reachable.
- The iPhone uses one address for the whole group: **`clipboardbridge.local`**, with a record
  lifetime of 10 seconds. The live Linux member with the lowest device ID holds it. Macs
  never hold it: they sleep and roam, and when no Linux member is up the iPhone and the Mac
  share through Universal Clipboard anyway.
- **Handover**: a holder that leaves sends goodbye packets for the name first and then closes
  its member connections with a goodbye; the member that is now the lowest sees that at
  once and announces the name. After a power cut the others notice the missing member when
  its connection falls silent and take the name over within about 15–20 seconds.
- Only private IPv4, unique-local and link-local IPv6 addresses are published.

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
member and sends from the app instead (see "Target architecture with the phone apps" below). One
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

clipboardbridge for Linux is one program that runs as up to three processes with different rights
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
  user to the group. Each message is a JSON header on one line followed by the raw text.
  Commands send one request and read the answers; a desktop connector keeps its connection
  open to receive writes and report copies. Its watch request carries what the clipboard
  holds; a write that no connector got, such as the group's text at boot, goes to the next
  one that connects, if it is still the member's own text.
- Command line: `cbb copy` (standard input to the group), `cbb paste` (the
  member's own clipboard text to standard output), `cbb pair`, `join`, `devices`,
  `revoke`, `status`. `cbb pair` on a Linux machine in no group creates the group.
  `cbb join` finds the member with an open pairing window by its TXT record, or uses
  the address that `pair` prints, for networks where multicast does not pass. It talks to
  one member only, tries that member's addresses (IPv4 first, link-local last) until one
  answers, and stops after the first attempt in which the other side could check the code,
  so a device that only pretends to pair gets one guess at most. When more than one device
  announces a window, it asks for the address. Hanging up cancels it, and it gives up after
  two minutes, or, while it shows its QR code for the phone, after the five minutes it waits
  for the window.
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
- **Auto-paste** (optional): after the connector writes an event sent from a phone (via
  `phone`), it presses Shift+Insert through a virtual keyboard (uinput). Never for
  Universal Clipboard items or other events, and not on the lock screen.

### 3. Console helper

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
  for mDNS (D-32) and dials out to Linux members; it accepts no connections.
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
- Finds Linux members with clipboardbridge's own mDNS code, browsing without publishing, and
  trusts only the group CA, in its own configuration; the system keychain is not changed.
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
- Received secrets are written with the same marks clipboardbridge reads: the
  `x-kde-passwordManagerHint` type on Linux and the macOS types above, so clipboard managers
  skip them.
- Some desktops and clipboard managers keep a copy of the last clipboard text and offer it
  again without the mark. The engine remembers secret texts, including the marked items it
  skipped, and such an offer makes no event (see the sync model).
- Explicit actions may carry a secret: "send even if secret" on the Mac and the console
  paste; the shortcut may mark a text as secret. Secret events are kept only in memory and
  expire 60 seconds after the copy, judged by the event's age. When a secret that a connector
  wrote expires, the connector gives up the clipboard, so the desktop does not keep it.
- Only root and members of the `clipboardbridge` group receive secrets through the control socket.

## Limits

- Text only, UTF-8, up to 1 MiB per item.

## Security

| Threat                                                         | Measure                                                                    |
|----------------------------------------------------------------|----------------------------------------------------------------------------|
| Someone on the home network reads the traffic                  | TLS 1.3 everywhere                                                         |
| Someone guesses or intercepts the pairing code of a computer   | CPace inside TLS: one online guess per attempt, at most three per pairing window, no offline attack; the joining device spends the code on one attempt, and never takes it from the command line |
| Someone attacks the pairing of an iPhone                       | the same attempt limits; the profile comes over a separate plain-HTTP port, so no certificate warning is ever accepted for the pairing page; the user compares the iPhone CA fingerprint before trusting it; the code and the token travel only over a connection that the trusted CA authenticates, so a relay sees neither |
| A device impersonates a member (for example, a host that answers `clipboardbridge.local` on another network) | mutual TLS with the group CA; members dial discovered addresses and check the peer's certificate; the iPhone accepts only a certificate from the iPhone CA, so an impostor gets neither the token nor the text |
| A device is lost or stolen                                     | `cbb revoke`; for a Linux member also a new group CA, a new iPhone CA and new tokens, the old profile deleted on every iPhone, and the members that were off paired again before they rejoin. With the apps: "Remove" on another admin phone; a lost root phone hands the root to the remaining admin without pairing anything again |
| A member is compromised                                        | it can read the group clipboard, by design. It cannot read the iPhone's other HTTPS traffic: the iPhone CA is restricted by name constraints to `clipboardbridge.local` and names below it, and excludes IP addresses and other name forms. The Mac never changes its system trust |
| A bug in the network code                                      | memory-safe language; the service runs as an unprivileged user in a systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateDevices`, no capabilities, restricted address families and system calls) |
| A local user abuses the console helper                         | the helper listens on nothing; the control socket admits only root and the `clipboardbridge` group; single-line injection by default with control characters removed |
| Requests from outside the home network                         | the service accepts connections only from private, unique-local and link-local addresses, checked in the program and by systemd; away from home (planned) only through the group's WireGuard tunnel, whose port drops every packet without a key from the group's records |
| Someone on the internet reads or traces the traffic (planned)  | the member TLS inside the group's own WireGuard tunnel, a preshared key per client, padded frames; clients talk only to the hub; the project's forwarder holds no keys and passes each packet only to its own group's hub |
| A compromised dependency or build                              | few dependencies, `govulncheck`, actions pinned to commit SHAs, release builds in CI with checksums and build provenance |

## Build

- Go, with `CGO_ENABLED=0` everywhere except for the Mac's pasteboard agent (the Windows
  clipboard needs no cgo), which uses cgo
  with a small Objective-C file. From then on CI builds the macOS targets on macOS runners
  with cgo.
- Targets: `linux/amd64`, `linux/arm64`, `linux/arm` with ARMv7 and ARMv6, `darwin/arm64`,
  `darwin/amd64`, `windows/amd64` and `windows/arm64` (`cbb.exe`, and `cbbw.exe` linked with
  `-H windowsgui` for the agent).
- The Raspberry Pi Zero W (ARMv6) cannot run Ubuntu; it runs Raspberry Pi OS. clipboardbridge
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
6. Simpler setup: QR codes, the generated shortcuts, the phone as the main device.
7. Installers: a one-line installer for Linux (with the firewall), Homebrew and a signed
   `.pkg` for macOS, signed releases.
8. Windows: the service as a Windows service and a clipboard connector through the Win32
   API.
9. Apps for iPhone and Android, which make the phone the group's root of trust (see "Target
   architecture with the phone apps" below).
10. Console helper and auto-paste.
11. A lite member in Rust for weak devices (routers, small boards): a member without CA
    keys that joins by QR code through the phone and syncs; it never admits devices, holds
    `clipboardbridge.local` or serves the iPhone shortcut. It dials the Linux members and
    listens for phones and Macs, so a phone and a lite member sync with no computer on. Only once the Go version is complete and its architecture settled, so it is
    written once. Before it: the protocol written down in `docs/protocol.md`, a `lite` role
    that full members treat like a Mac, test vectors in `testdata/`, and an e2e test with a
    Rust member among Go members. Done for Linux in `lite/` (`cbb-lite`, built for the
    Raspberry Pi, not yet run on one). The ESP32 comes next: the protocol core is its own
    crate, `lite/core`, without the standard library (no_std with alloc, RustCrypto in
    place of ring), which CI builds for RISC-V; TLS and the networking on the chip follow.
12. Sync away from home and between subnets, through the group's own WireGuard tunnel in a
    star around a hub; see "Sync away from home (planned)" below.

### Future research (not planned)

Questions to study before anything is planned for them.

- **Very small and retro computers through a gateway**, for example the ZX Spectrum Next
  (Z80 at 28 MHz, Wi-Fi through an ESP8266 driven by AT commands, programs in C with z88dk).
  TLS 1.3 with P-256 is out of reach there, so a Linux member acts as a gateway with a
  simpler protocol: pairing with the six-digit code derives a key shared by the gateway and
  the device, and every text travels encrypted and authenticated with ChaCha20-Poly1305
  over plain TCP. The gateway turns those messages into ordinary events. The same protocol
  would serve any device too weak for the member protocol. To study: the cost of the
  key derivation and the cipher on a Z80, the AT command TCP mode of the ESP8266, and how
  the gateway names such devices in the devices list.
- **A plain tier below the gateway protocol**, for devices that cannot even run
  ChaCha20-Poly1305: texts in the clear over the home network, which is better than typing
  them by hand. Only by an explicit choice on the gateway, per device, after a warning that
  says plainly that anyone on the network can read and change what that device sends and
  receives and that the user takes this risk. Such a device carries a warning mark in the
  devices list, never receives secrets (items a password manager marked), and can be
  limited to receiving only, or to sending only. A middle step to study: a key from the
  pairing code used only to authenticate (a MAC, cheap even on a Z80), so that nobody else
  can inject texts, while they still travel unencrypted.
- **Arduino and other microcontrollers** with the same gateway protocol: AVR boards with a
  Wi-Fi or Ethernet module, for example to show or type the clipboard. Boards built on the
  ESP32 may manage TLS 1.3 with P-256 themselves and could become lite members instead; to
  be measured.

## Sync away from home (planned)

Away from home, and between subnets that mDNS does not reach (for example a Pi on
192.168.20.x and the rest of the group on 192.168.0.x), members reach each other through the
group's own WireGuard tunnel in a star around one member, the hub. Nothing here is built yet.

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
5. The tunnel serves clipboardbridge only and cannot be used as a general VPN.
6. Where WireGuard is blocked, the user can switch on VLESS.
7. Groups are fully isolated from each other on the project's forwarder and cannot affect
   each other, even from one network.

What no design hides, and the documentation says so: the network between a client and the
hub (or the forwarder) sees that encrypted packets go to that address, when, and roughly how
many. VLESS with REALITY makes them look like an ordinary HTTPS connection to a well-known
site. Where a network admits only listed addresses (allow-lists), no protocol helps.

### The hub

- One member of the group, normally the always-on Linux member at home, is the hub. Any Go
  member can be one; phones and lite members are clients.
- The hub runs WireGuard in user space inside `cbb` (wireguard-go with its in-process network
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
WireGuard packets between a group's clients and that group's hub.

- **One port for all groups, routed by `mac1`.** Every WireGuard handshake initiation
  carries `mac1`, a MAC keyed with the responder's public key. The forwarder knows each hub's
  public key from its registration, so it finds the group by checking `mac1` against the
  registered keys; it still holds no key that decrypts anything. Nothing is added to the
  packets, and `mac1` looks random to anyone who does not know the hub's public key, so the
  network cannot tell groups apart. Data packets then carry the receiver index the hub chose
  in the handshake, which the forwarder maps to the group together with the client's address.
  The check costs one BLAKE2s per registered group per handshake (a client's handshake comes
  every two minutes while it is active), tens of milliseconds for 100 000 groups; beyond that,
  groups are spread over several servers. Whether AmneziaWG keeps `mac1` usable for this is to
  be checked; in VLESS mode the group is known from its VLESS user ID inside REALITY's TLS.
- **Fallback: an endpoint per group.** If `mac1` routing does not hold up, each group gets its
  own address on the server's IPv6 /64, or its own port on IPv4 (about 60 000 per address).
  A visible group tag in the packets was rejected: it would link a group's devices.
- Clients behind one shared address are told apart by address and port, as the hub's own
  WireGuard does. A packet is passed only to its own group's hub; there is no shared path
  between groups.
- **Registration.** The hub keeps one connection out to the forwarder and registers its
  WireGuard public key by proving its membership (its member key with the chain to the group
  CA); nobody else can take its place. The forwarder knows a group only by its tag, the hash of the CA
  certificate, and stores nothing on disk: its state is the open connections.
- **No interference.** Limits per group: packets and bytes per second, at most 16 clients,
  memory. A group that reaches a limit is slowed down alone.
- **Nothing to gain.** Whoever takes the forwarder over sees the same encrypted packets as
  the network and can at most stop forwarding.
- It learns the group tag, the addresses of the hub and its clients, and the timing and
  sizes of packets; logs keep no addresses beyond what abuse handling needs, and only for
  days.
- The forwarder is `cbb` in a mode that holds no keys. A hub never runs on a rented server:
  that would put the decrypted clipboard on someone else's hardware.

### Keys and pairing

- Each device creates its own WireGuard key pair; the private key never leaves it and never
  appears in a QR code.
- A device gets the hub's public key and addresses, the forwarder's address and port, and
  its preshared key inside the member TLS, at home, when it joins or later on request; its
  public key reaches the hub the same way. The phone, as the root, signs a record that binds
  the device's WireGuard key to its device ID, and the hub admits only keys in such records.
  Joining a group from the internet is not possible.
- Removing a device (the revocation records) makes the hub drop its key at once. A new
  preshared key can be issued through the tunnel at any time.

### Blocked networks

1. **AmneziaWG**, a fork of wireguard-go that randomises message headers, adds junk and
   imitation packets before the handshake and pads messages. Same keys and code; the user
   switches it on per group.
2. **WireGuard inside VLESS with REALITY**, between a client and the forwarder, with
   Xray-core (MPL-2.0) in `cbb` and libXray (MIT) in the apps; VLESS carries the UDP packets
   itself. The forwarder then has one path for everything, the hub does not change, and
   traffic is always inside our own tunnel. VLESS adds no security of its own and the design
   does not rely on it: the boundary stays the member TLS, then WireGuard.

sing-box is not used (GPL).

### Members

| Member                         | Tunnel                                                                                        | Role                     |
|--------------------------------|-----------------------------------------------------------------------------------------------|--------------------------|
| Go service (Linux, macOS, Windows) | wireguard-go with netstack in `cbb`; AmneziaWG and Xray-core as Go modules               | hub, forwarder or client |
| iPhone app                     | in the app process, no Network Extension, one Go framework for WireGuard and Xray             | client, while the app is open |
| Android app                    | in the app process, in the foreground service the app already has; no `VpnService`            | client                   |
| `cbb-lite` on Linux            | a Rust userspace WireGuard (GotaTun, from Mullvad) with a small TCP stack                     | client                   |
| `cbb-lite` on the ESP32        | none: the home network only, until a mature WireGuard exists for it                           | home only                |

- On phones the tunnel is ordinary UDP traffic of the app. It does not take the phone's
  single VPN slot, the user's own VPN keeps working, and the app is not a VPN app (Apple's
  guideline 5.4 and Google Play's VpnService rules concern apps that create a device VPN).
- The Swift kit (Network.framework) and the Kotlin kit (Conscrypt) keep their TLS code: the
  app opens a port on the loopback address that leads into the tunnel, and the kit dials it.
  Another app that connects to that port reaches only the hub's member TLS.
- No push notifications: they go through Apple's and Google's servers. A phone gets the
  current text when the app opens, as at home.

### Traffic analysis

Frames over the tunnel are padded to a few fixed sizes, so that the length of a text does not
show; the wire format goes into `docs/protocol.md` with the code.

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

1. The hub and the Go client: WireGuard in `cbb`, the key records and pairing, tests with
   several clients that prove they cannot reach each other.
2. The forwarder.
3. The phones: the in-app tunnel in both kits and apps, interop tests against the Go hub.
4. Blocked networks: AmneziaWG, then VLESS with REALITY.
5. `cbb-lite` on Linux; the ESP32 when WireGuard on it is mature.

## Target architecture with the phone apps

The shortcut can neither hold a key, sign, run CPace nor accept connections, so today the
group CA lives on the Linux members and the phone only authorizes with its token. A phone
app can do all four, and then the phone becomes the root of the group:

- The app creates the group CA in the Secure Enclave (iPhone) or StrongBox/Keystore
  (Android): a P-256 key that cannot be exported. Only the phone issues member
  certificates; no computer holds CA keys, so a stolen computer cannot add devices.
- The first computer joins the phone, not the other way round: `cbb join` shows a
  QR code with its addresses, its certificate fingerprint and a fresh code, and listens
  (already so today, for the shortcut); the app scans it, dials the computer, checks the
  fingerprint and runs CPace with that code, with the phone in the admitting role, then
  issues its certificate. No profile for the user to check: the app trusts its own group's
  CA.
- Every computer is then a member without CA keys, as a Mac is today; Linux members still
  publish, hold `clipboardbridge.local` and serve the app and the shortcut. A lite member (Rust)
  fits the same role.
- Certificate renewal (every two years) and revocation need an admin phone. Losing one is
  covered by a second admin phone, which is an equal admin with a key of its own; see
  "Admin phones, the devices list and revocation (planned)" below.
- The app syncs while it is open and through a share extension, a widget or an Android
  quick-settings tile; background sync stays impossible on iOS.
- The current mode, with the CA on the Linux members and the phone's token as the authority,
  stays for users without the app, and `cbb pair` / `join -code` for groups without a
  phone.

The protocol in `docs/protocol.md` and the lite member are designed for this target, so
neither is written twice.

## Admin phones, the devices list and revocation (planned)

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
- The command line on Linux and the Mac: `cbb devices` prints the same list;
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
`cbb devices` shows the group and `cbb revoke` removes a Mac or an iPhone's
token without replacing anything. Revoking a Linux member there still replaces both CAs, as
"Devices and revocation" above says, because it holds the CA keys.

**Order of work.** The Go side first, since it needs no phone: the records, their exchange
in the member protocol, refusing revoked keys, `cbb devices` and `cbb revoke`
in groups a computer created, and members that verify certificates through an admin CA. Then
the apps: the root and admin CAs, the Devices screen, making an admin, and the root record.

## Open questions

These need experiments on real devices; CI cannot answer them.

- Does the Mac see a Universal Clipboard item from the iPhone (the change counter moves)
  without a paste on the Mac, and which types does the item carry?
- Does reading the pasteboard types trigger the macOS pasteboard privacy alert, and is the
  alert enforced by default on macOS 27.2 and later?
- On iOS 18, 26 and 27: does Shortcuts trust the name-constrained iPhone CA and reach
  `clipboardbridge.local` (Local Network prompt, first-run prompts, behaviour from the Lock
  Screen), and how fast does it notice a handover of the name?
- On GNOME with on-demand XWayland: do copies in native Wayland apps reach the connector
  promptly, and do its writes become the Wayland selection without focus?
- Console injection at an agetty login prompt, in `sudo` and in vim on Ubuntu and Raspberry Pi
  OS; latency and CPU of the double-tap trigger on a Pi Zero W.
- Does the macOS application firewall, set to block incoming connections, filter the mDNS
  answers that reach the service's own socket on UDP 5353 (it is not mDNSResponder)? If so,
  the installer must add an exception for the service.
- Images and files after the first version.

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
| D-13 | Only Linux members hold `clipboardbridge.local`; Macs only dial out.                            |
| D-14 | The hybrid clock never refuses a timestamp and warns about skew measured per connection; events carry their age for the 45-second rule and secret expiry, and local durations count sleep. |
| D-15 | macOS runs the service as a LaunchDaemon plus a pasteboard LaunchAgent, which avoids the Local Network prompt; installing needs administrator rights. |
| D-16 | Desktop clipboard in pure Go: Wayland data-control (both protocol variants) and X11 through `jezek/xgb`; no `wl-clipboard`. |
| D-17 | Console paste injects a single line by default, with control characters removed.         |
| D-18 | Secrets reach only root and the `clipboardbridge` group; the control socket enforces it through file permissions. |
| D-19 | The group state is last-writer-wins; the protection of copies made during a disconnect applies only to writing the local clipboard (live window 60 s, rejoin window 30 s). The first version kept that rule in the group state, and a review showed that the group could then split for good. |
| D-20 | The rejoin window opens only on a local sign that the member itself was away (start, wake), not when it merely lost its peers. A network that drops without a sleep is not noticed yet. |
| D-21 | Each member keeps its own clipboard text apart from the group state; `cbb paste`, tmux, the console helper and the iPhone button use it. |
| D-22 | A secret travels in a hello as a mark without its text, so the group converges on secrets too. |
| D-23 | Revoking a Linux member replaces both CAs, because it holds their keys; members that were off still trust the old CA until they pair again, and iPhones delete the old profile. |
| D-24 | Local durations use a clock that counts sleep and ignores wall-clock steps (package `uptime`). |
| D-25 | The hybrid clock saves a mark 10 seconds ahead before passing the last one, so it never goes back after a crash. |
| D-26 | iPhone pairing: the profile over a separate plain-HTTP port and the fingerprint check first, then the code on a page that the trusted CA authenticates. |
| D-27 | The engine remembers secrets for 12 hours; a watcher offering one again without its mark makes no event, a deliberate action makes it a secret again. |
| D-28 | Two ways in: watchers report changes (no event when nothing really changed), deliberate actions always send and also write the member's own clipboard. |
| D-29 | Certificates are checked with the local clock, but never earlier than the group CA's start: a clock that is behind does not break the group, an expired certificate is still rejected. |
| D-30 | Pairing runs inside TLS with self-signed certificates on the new device's side and channel binding (an exporter and both certificates) instead of a separate encryption layer: CPace authenticates the TLS session, and everything after it travels in that session. |
| D-31 | The mDNS responder does not probe its names: device IDs are random, `clipboardbridge.local` is never renamed, and the group's election decides who holds it; two holders for a moment are harmless, since any Linux member can serve the iPhone. |
| D-32 | The Mac browses with clipboardbridge's own mDNS code instead of the Bonjour API: it shares port 5353 with mDNSResponder, and the service needs no cgo. The cost is a socket of its own on UDP 5353, which the macOS firewall may treat differently (see Open questions). D-12 still holds for Linux. |
| D-33 | Several equal admin phones: a root CA with path length 1 certifies an admin CA per phone, each key in its own Secure Enclave or StrongBox, instead of one CA key copied between phones or backed up to a cloud. Only the root makes admins; a remaining admin becomes the root with a signed root record. |
| D-34 | The devices list and revocations are signed records in a set that only grows and spreads through the member protocol; what it says depends on the set alone, so the group converges. Two admins that revoke each other both lose admin rights. |
| D-35 | Revoking an admin keeps the devices it admitted, listed in the record, so losing a phone never means pairing the computers again. |
| D-36 | A computer can be an admin of a phone group, with an admin key in a file that the root phone certifies on request, never by default: admitting from a terminal is worth a key outside a Secure Enclave only to a user who asks for it. |
| D-37 | Windows runs the service as a Windows service plus a clipboard agent in each session, as on the Mac, since a service cannot reach a session's clipboard; the control socket stays an AF_UNIX socket, guarded by the access list of its directory, so the protocol and the client code are the same everywhere. |
| D-38 | Away from home: a star of WireGuard tunnels to a hub, a member at home, with WireGuard in user space inside `cbb` and the apps and the member TLS inside; no third-party services; a feature that cannot keep the data fully protected is not built. |
| D-39 | Homes behind carrier-grade NAT use a forwarder run by the project that holds no keys and routes each packet to its own group's hub only (by WireGuard's `mac1`, so nothing on the wire tells groups apart), with limits per group. |
| D-40 | Blocked networks: AmneziaWG first, then WireGuard inside VLESS with REALITY to the forwarder, so that traffic always stays inside the group's tunnel. |
| D-41 | Phones keep the tunnel inside the app, without a system VPN or push notifications, so the VPN slot stays free and no one else's server is involved. |
| D-42 | The ESP32 stays on the home network until a mature WireGuard exists for it. |
