# Changelog

All notable changes to clipboardbridge are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Docker: an image of the full service for a NAS or a home server, built from scratch with
  only `cbb` in it, for amd64, arm64 and armv7; it runs as its own user without
  capabilities, on a read-only root file system, with its state in one volume. Compose files
  run it as an always-on member at home or as a forwarder or relay on a server
  (packaging/docker). Each release publishes it as `ghcr.io/hunterewok/clipboardbridge` with a
  build provenance attestation and gives its digest in the release notes.
- Sync modes on the computers: `cbb mode own|shared|receive|send` sets what moves between a
  computer's clipboard and the group. A computer that makes or joins a group from now on
  keeps its own clipboard (own): its copies stay on it and the group's do not come, while
  `cbb copy` and the phones still send to the group and `cbb paste` prints the group's
  text. Computers that joined before keep sharing. `cbb status` shows the mode, and each
  computer's hello reports it for the devices list.
- An admin sets the sync mode of another computer with `cbb mode -on DEVICE MODE`: a
  command signed by the admin's key, which the computer checks against the group's records,
  takes once and only within 30 s (docs/protocol.md, section 15). The phone kits read the
  mode in the hellos and send such commands.
- The apps show each connected computer's sync mode. The Mac app and the tray app set this
  computer's mode in Settings and, on an admin, another computer's from its details; an
  admin iPhone or Android phone sets a computer's mode from its page, after Face ID or the
  fingerprint, and says if the computer refused.
- The phone's side of the phone as the hub (D-64), not yet in the apps: `mobile/cbbtun`
  runs the group's hub in the app's process (`StartHub`), leads the clients' connections to
  the kit's member listener and registers with the forwarder (`Register`). A phone hub
  registers with its member key, without Face ID, when the group's records make that key
  the root's or an admin's; the forwarder now takes such a registration
  (docs/protocol.md, section 13). Both phone kits listen for member connections
  (`MemberListener`) and, as the hub, admit a client by the tunnel key its hello offers and
  answer with the offer (`PhoneHub`).

### Changed

- The documentation for users is rewritten in plain words, under `docs/guide` and
  `docs/reference`: the quick start begins with the phone app as the group's root and then
  suggests making an always-on computer an admin and the hub; "How it works" draws every
  way the devices connect (at home, through the hub, through a forwarder, a blind relay,
  networks that block VPNs), in SVG pictures of one style with a light and a dark theme,
  drawn by `tools/diagrams`; new pages cover installing, sync away from home, AmneziaWG and
  VLESS, the devices, ports and files, and running one's own forwarder or relay. Text for
  readers says Clipboard Bridge; commands, paths and packages keep `clipboardbridge` and
  `cbb`.

### Fixed

- Security: a forwarder keeps a group's authority records after the group's registration
  ends, and writes the roots, removals and freezes among them (never a device's name) to
  `groups` next to its key (`cbb forward -records`), so an admin the group removed can no
  longer register as its hub with the records from before while the group's own hub is
  away or after the forwarder restarted.
- Privacy: the authority records a hub shows its forwarder, and a device its relay, no
  longer carry the records of devices the root admitted directly, with their names and
  systems; only the root's own device and the devices it made admins (their demotions
  included) are named.
- Security: the lite member on Linux takes crypto-bigint 0.7.6 and ctutils 0.4.5, whose
  arithmetic and comparisons no longer branch on secrets on some compilers and CPUs
  (RUSTSEC-2026-0387, RUSTSEC-2026-0385); the Nano ESP32 firmware had them already. CI now
  checks the lite member's crates, the Android apps' libraries and the tray app's Go module
  against the OSV advisories on every change.
- Android: a certificate with a length field near 2 GiB no longer slips past the DER
  reader's bounds check and throws an unexpected error instead of being refused. Both phone
  kits now test their certificate checks with thousands of randomly damaged certificates.
- iPhone kit: a key whose algorithm identifiers are damaged is refused, as Go and the
  Android kit refuse it; swift-crypto on Linux read the key's point without checking them.

## [0.4.1] - 2026-10-25

### Fixed

- Releases carry `winget-manifest.zip`: the release workflow writes it before it
  publishes the release, since an immutable release takes no files afterwards (0.4.0 went
  out without it).
- The release notes name the Wear OS app's APK, `clipboardbridge-wear-X.Y.Z.apk`, in the
  install steps and the file table.

## [0.4.0] - 2026-10-25

### Added

- Wear OS: an app that shows the group's devices and their live dots, the latest events and
  the switch for sync away from home, through the paired Android phone (the Wearable Data
  Layer of Google Play services); each release carries its signed APK.
- Linux and Windows: a tray app over the cbb service (Wails), the twin of the Mac app: the
  devices as tiles, a list or orbits, a device's details, send and fetch, sync away from
  home, and the group's changes after the administrator's password (pkexec, UAC).
- Mac: an app (SwiftUI) over the cbb service, a window and a menu bar item in the Glass
  design: the devices as tiles, a list or orbits, a device's details beside them, send and
  fetch, sync away from home, and renaming, removing, freezing and making admins after the
  administrator's password.
- Android: notifications of the group's events, as on the iPhone, each with a switch in
  Settings; the background service hears of them at once.
- Android: the Glass design of the iPhone app: ten colours and a Dark, Light or System theme
  (Material You stays a choice), one page with every device as tiles or a list, a device's
  own page with its type, system and version, Clipboard Bridge version, MAC address and
  role, and on tablets and foldables the orbits with the details beside them. The app's
  name on the home screen is CBB.
- iPhone: notifications of the group's events (a device joined or was removed, became an
  admin, was frozen or unfrozen, the group was taken over, the hub does not answer away from
  home), each with a switch in Settings.
- Apple Watch: an app that shows the group's devices and their live dots, the latest events
  and the switch for sync away from home, through the paired iPhone.
- iPad: the app runs on the iPad as a phone of the group. Its Home shows the devices on orbits
  around it (or as tiles or a list), with a device's details in a pane beside them; the
  same layout serves the inner screen of a foldable iPhone, whose strip at the right edge
  takes the toolbar in landscape.
- iPhone: a Live Activity in the Dynamic Island while a device is added and while the phone
  syncs away from home, and the result of a sync for a moment; it never shows what was
  copied.
- A member's hello says what its device is (docs/protocol.md, section 4, "Device"): its form
  (laptop, desktop, phone, tablet, board, console, server and others), its system's version,
  its own version and, on computers and boards, the MAC address of its network card. The
  iPhone app shows them on a device's page and picks its icon by the form; `cbb devices`'s
  socket answer carries them too.
- The Android and iPhone apps keep the home network addresses from the QR code of each
  computer they add, and dial a computer there while mDNS does not find it, so a member in
  another subnet (an IoT VLAN, for example) syncs with the phone too.
- winget: each release writes the manifest of `HunterEwok.clipboardbridge`, and `cbb install`
  installs the service from the copy that winget unpacked. The release signs the Windows
  programs with Authenticode when its secrets hold a certificate.
- ZX Spectrum Next: `.cbb text -s` and `.cbb copy -s` send a secret, through the lite
  member's `cbb next copy -secret`.
- iPhone: Share → Clipboard Bridge sends a text or a link to the computers at once (a share
  extension), and a Control Center control and a home-screen widget "Sync clipboard".
  Android: the home-screen widget "Send clipboard".
- Rename a device: `cbb rename NAME NEW-NAME` on an admin computer, and Rename in the Devices
  list of an admin phone (both apps). An admin signs a new device record with the name.
- Both apps: seven taps on the version in Settings show the switch "Show error details",
  without `adb` or Xcode.
- `cbb status` warns when members at home could not connect to this computer and sync only
  because it dials them back: a firewall here drops the member port.
- `cbb global hub` at the hub's own address lists the firewall rule for its UDP port and asks
  before it opens it (ufw, firewalld, Windows Firewall; the commands for the others);
  `-firewall yes` opens it without asking, `-firewall no` prints the commands. The port
  closes again when the device stops being a hub reached at its own address.
- `--home-cgnat on` for the installers (`-HomeCgnat on` on Windows, `CBB_HOME_CGNAT=1`)
  counts 100.64.0.0/10 as the home network for a home network on the carrier-grade NAT
  range: in the service, the firewall rules, the systemd unit's address limit and the
  Windows outbound rule. By default that range stays outside the home network.

- The Mac installer takes `--port N` like the Linux one, kept in
  `/etc/clipboardbridge/clipboardbridge.env`, and `get.sh` passes it on a Mac too.
- `CBB_ERROR_DETAILS=1` for the Linux and macOS installers, uninstallers and `get.sh`: they
  show every command as it runs. Without it a failure says it failed, with its exit status.
- [docs/parity.md](docs/parity.md): what each computer, phone and lite device can do, the
  gaps between devices of one class and the plan to close them.
- Sync away from home on the lite member: `cbb global on` (with the warning about keys in
  files) offers its tunnel key to the group's hub at home and keeps the hub's offer; away from
  home, or on another subnet, it reaches the hub through the group's WireGuard tunnel, with
  GotaTun's WireGuard and smoltcp's TCP in `cbb`, no TUN device and no root. Plain WireGuard
  only: a hub that hides its tunnel (`-obfuscate`, `-vless`) keeps a lite member at home.
- VLESS with REALITY for networks that block WireGuard and AmneziaWG alike: `cbb forward
  -vless-site www.example.com` also takes VLESS on TCP 443, borrowing that site's TLS, and
  `cbb global hub -forwarder ... -vless` has the hub's clients reach the forwarder only that
  way, inside what looks like HTTPS to the site. The group's WireGuard and member TLS go
  inside it unchanged. Xray-core runs in `cbb` and in the phones' tunnel (`mobile/cbbtun`),
  so both apps take the way over VLESS from the hub's offer too.
- `cbb upgrade`, once on a Linux or Windows member of a group made before this version,
  gives the group a root, that member: the old CA keys are revoked and the other members
  delete their copies when they hear of it, so every device but the root can then be
  removed by a record. No device pairs again; the iPhone CA is replaced, so iPhones that
  use the shortcut pair again. `cbb status` marks the computers that may still hold the old
  keys until they connect.
- `cbb takeover NAME` on an admin computer takes the group over from its lost root
  computer, as an admin phone does in a phone's group: the admin becomes the root, the
  lost root is removed, every other device stays, and the iPhone CA is replaced, so iPhones
  that use the shortcut pair again. After admitting a device, `cbb pair` on a root without
  another admin suggests making one.
- Obfuscation for networks that block WireGuard: `cbb global hub -obfuscate` makes the group's
  tunnel speak AmneziaWG, with junk packets before each handshake, random padding, random
  message types and encrypted headers, so nothing on the wire looks like WireGuard. The hub
  makes the group's settings and gives them to its clients with its offer at home and in
  remote invitations; both phone apps use them too. An obfuscated hub can use a forwarder:
  it gives the forwarder the group's settings when it registers. Not yet on the lite member.
- Sync away from home in the iPhone app, as in the Android app: a switch in Settings, the
  key and the hub's offer in the keychain (this device only), and the same in-process
  tunnel while the app runs. Building the app now needs Go for `Cbbtun.xcframework`.
- Sync away from home in the Android app: a switch in Settings makes the phone's WireGuard
  key, offers it to the group's hub on the next connection at home, and keeps the hub's
  answer. While the hub is not found on the home network, the phone reaches it through the
  tunnel in the app's own process, with the same member TLS as at home, trying the hub's
  addresses in turn; without the tunnel there is no connection. Off by default; turning it
  off forgets the key. Building the app now needs Go for the tunnel.
- The first firmware for the Arduino Nano ESP32 (`lite/esp32`, Rust on the ESP32-S3): a
  console on its USB port sets the Wi-Fi network up, the board joins it and takes an
  address by DHCP, joins a group by the phone (`join` prints the link to paste into the
  app, and the phone pairs with the board over TLS 1.3 as with the lite member's `cbb join`), and keeps
  its settings and identity in flash in two slots, so a power cut while saving keeps the
  last good copy (`cbb_core::store`); its `selftest` makes keys and
  certificates with the chip's true random number generator and runs a TLS 1.3 handshake
  of the protocol core on the chip. CI types on the console and runs the self-test in
  Espressif's QEMU. Syncing comes next; not yet run on a real board.
- The Nano ESP32's network code on Linux: the pairing moved to the crate `lite/embassy`,
  which the firmware and the program `esp32-on-linux` share; `esp32-on-linux` runs it on
  embassy-net over a TAP interface instead of the chip's Wi-Fi, and CI's
  `TestEmbassyJoiner` has a Go member admit it by the phone, as the board joins.
- A forwarder for hubs that the computers cannot reach directly, for example behind
  carrier-grade NAT: `cbb forward` runs it on a server with a public address, and
  `cbb global hub -forwarder ADDRESS:PORT -forwarder-key KEY` registers the hub there with its
  member certificate and its WireGuard key. It holds no keys, passes each encrypted packet
  only to its own group's hub, routes by WireGuard's `mac1` so nothing on the wire tells
  groups apart, limits each group, and writes nothing about the groups, not even to its
  log. `cbb global` on the hub shows the registration.
- A blind relay for a group without a computer to be its hub: `cbb relay -group TAG` runs it
  on a server you run, and `cbb global relay ADDRESS:PORT -key KEY` on each computer meets the
  group's other computers there away from home. It holds none of the group's keys: each
  computer registers with its member certificate and gets its own WireGuard tunnel to the
  relay, which joins two computers' member connections end to end, so it sees who talks
  and when but cannot read the clipboard or pose as a device. It serves only the groups it
  is given and writes nothing about them. `cbb global` shows the link.
- `.cbb`, a dot command for the ZX Spectrum Next (`apps/zxnext`, C for z88dk): with
  the lite member on the Next's own Raspberry Pi it pastes the group's text to the screen or a
  file, sends a file or words, and joins by drawing the QR code for the phone app. Not yet
  run on a real Next.
- iPhone: a new look, "Glass", in ten colours (Terminal, Midnight, Amber, Ocean, Teal,
  Coral, Rose, Lime, Graphite, Ruby), each dark and light. Home shows every device of the
  group as tiles or a list with its icon, system and live dot; a device opens its own page
  with a summary and its actions. The earlier theme carries over.

### Changed

- With `cbb global on`, a computer's service no longer reaches the whole internet: only the
  home network and its group's own hub, forwarder and relay. The program refuses everything
  else on every system, a client's WireGuard socket sends only to its hub, and on Linux and
  Windows the systemd drop-in and the outbound Windows Firewall rule list exactly those
  addresses. `cbb global hub` and `cbb global relay` now run with `sudo` or as administrator
  on those systems, and the new `cbb global allow` follows the hub's addresses when they
  change; `cbb global` and `cbb status` say when it is needed. A hub reached at its own
  address answers its clients anywhere on its UDP port only (on Linux by the program alone).
- The installers no longer open firewall ports without asking. They find the firewall
  (ufw, firewalld, nftables or iptables on Linux, the macOS application firewall, Windows
  Firewall), list each rule clipboardbridge needs with its protocol, port, source and
  purpose, and ask `Add these rules now? [y/N]`. Yes adds them and keeps them current on
  every update; No, the default and the answer when there is no terminal, adds none and
  prints the exact commands. The answer is kept for updates. `--express` (`-Express`,
  `CBB_FIREWALL=express`) adds them without asking and reports what it added;
  `--no-firewall` now also works on a Mac and prints the commands too.
- The lite member and the ESP32 firmware use x25519-dalek 3 (on curve25519-dalek 5) and
  base64 0.23. Dependabot updates the firmware's lock file in the same pull request as the
  lite member's, so the firmware's locked build keeps passing.
- The lite member's stand-in for ring (`lite/ring-shim`) uses chacha20poly1305 0.11, the
  version its TLS uses. smoltcp stays at 0.13, the version embassy-net 0.9 builds on: two
  copies of smoltcp share the `managed` crate's features and do not build together, so
  Dependabot leaves its minor versions alone until embassy-net moves.
- The lite member dials no address outside the home network: `-peer` names a member at
  home, and away from home the device reaches the group only through the tunnel.
- The lite member's command is `cbb`, as on a full member, with the same paths, user and
  service (`/usr/local/bin/cbb`, `/var/lib/clipboardbridge`, `clipboardbridge.service`);
  `cbb version` says which member a device runs, and the commands of a full member answer
  that this is the lite member. Its archive (`cbb-lite-linux-*`) carries the same Linux
  `install.sh` and `uninstall.sh` as a full member's, and `get.sh --lite` installs it.
  The installer moves an install from before the rename to the new names, keeping the
  device in its group, and refuses to put one kind of member over the other.
- `cbb away` is now `cbb global`, with the same subcommands (`on`, `off`, `hub`, `relay`):
  it turns on sync over the internet, beyond the home network.
- A computer that creates a group is now its root, as a phone is in its own group: only it
  and the admins it makes hold CA keys, and the computers that join get only their
  certificates, the Mac, Linux and Windows alike. `cbb admin NAME` on the root makes a
  connected computer an admin, which then admits and removes devices and serves the iPhone
  shortcut with the group's iPhone CA. Any device but the root is removed with
  `cbb revoke` and the group stays; removing an admin replaces the iPhone CA, so the
  iPhones that use the shortcut pair again. A Mac can create a group and be an admin.
  Groups made before keep working as they were until `cbb upgrade`.
- `cbb new` creates a group on a computer, and `cbb pair` does the rest by the device's
  state: in no group it joins one (it shows a QR code for the phone and also takes a
  typed code, `cbb pair -code` reads one from standard input), in a group it admits a
  device. `cbb join` is gone, and `cbb pair` no longer creates a group by itself.
- One `get.sh` installs on Linux and on a Mac: it picks the archive for the system and the
  architecture, checks it against `SHA256SUMS` and runs that system's `install.sh`. On a
  Mac, `install.sh` keeps `uninstall.sh` in `/usr/local/share/clipboardbridge`, as on Linux,
  so every platform has the same three: get, install and uninstall.
- `cbb desktop` is gone: `cbb agent` links the clipboard on every desktop, the Mac's, the
  Windows one and a Linux desktop's (Wayland or X11), and the Linux autostart entry runs it.
- The tunnel for sync away from home now runs on amneziawg-go, the AmneziaWG fork of
  wireguard-go, in `cbb` and in the phones' tunnel. Until a group switches obfuscation on
  it speaks plain WireGuard, the same on the wire as before.
- A hub's hellos to its forwarder are masked, so that they look like random bytes of a
  random length; a forwarder and a hub of this version are needed together.

### Fixed

- Security: a new device trusts only the roots that the group's records lead to. The Welcome
  carries the records of that path, and every member (Go, both phone kits, the lite member)
  refuses a certificate whose chain no root on the path signed, so an admin can no longer
  slip a root of its own into a device it admits and keep access after the group's root
  removes it. The roots a member trusts follow the records by content, not by count.
- Security: an admin can no longer fill the record set to block its own removal. A record
  signed under a root that can never be known (one a computer's admin names in a phone's
  group) is dropped, every signer (admin CAs and roots' own keys alike) is limited to 1024
  records, signatures are checked before the limits, and a full set still takes 1024 more
  records from the own key of a root on the path.
- Security: a device can no longer join twice under one device ID and leave a second key
  behind that removing it misses. The admitting member refuses an ID that the records or a
  connected member already have (new pairing error `taken`), the devices list shows a device
  while any of its keys stands, `cbb revoke`, `cbb takeover` and the apps' Remove revoke
  every key of the device, and a peer counts as the root only with the root's own key.
- Security: the lite member takes a tunnel offer only from the group's root or an admin, by
  its records and the key of its certificate, rather than from any member whose hello says
  `full`. It keeps the first hub until sync away from home is turned off and on again, and
  ignores an offer that does not decode instead of dropping the hub. The phone apps check
  the hub's key the same way.
- Security: the phone apps check each computer's certificate chain against the group's
  records when it connects, and close the connection as soon as new records remove it. A
  removed device is now dropped by its key, not only because its ID left the list.
- Security: a member refuses an event more than 7 days ahead of its clock (Go, the lite
  member and both phone kits), so a device with a wrong date or a removed member can no
  longer hold the group's clocks at the year 9999 and keep every later copy from winning. A
  clock that reads before 2026 refuses nothing, for boards that have not set their time.
- Security: an mDNS announcement of the hub on a foreign network no longer turns off sync
  away from home (Go, the lite member and both apps). A member found by discovery counts as
  on this network for 30 s; after that only a connection to it keeps the tunnel and the
  relay closed.
- Security: the iPhone shortcut's pairing page no longer shows the profile's fingerprint,
  which comes over plain HTTP and could be changed on the way; it sends the user to the
  terminal of `cbb pair -phone`, which now spells out where to compare it.
- Security: a device on the home network can no longer hold a pairing window busy. The
  joiner's first message must come within 10 s (a slow board computes its CPace message
  first), and after 5 attempts from one address that ended before they counted, the window
  answers it `busy`.
- Security (Android): other apps can no longer fetch the group's latest copy by opening the
  app's send activity. The tile, the widget and the notification open one that is not
  exported; Share, the selection menu and "cbb send" open another that asks first unless the
  home screen or the system opened it. "Always allow" now holds for one app only ("Always
  for this app"), and Settings lists those apps; the old switch for every app is gone.
- Security (Android): a secret is cleared from the clipboard after its minute while the
  app is in the background too, unless the app learned of a change since.
- Security: `get.sh` and `get.ps1` check the archive's build provenance attestation with
  `gh attestation verify` when the GitHub CLI is there and signed in, since `SHA256SUMS`
  comes from the same release; `CBB_ATTESTATION=require` refuses to install without it.
- Security: a computer publishes itself by mDNS and takes connections on the member port only
  on networks where it met its group (created or joined it, opened a pairing window, or
  connected to a member there), told by their addresses and the gateway's link-layer
  address. In a café or a hotel it only looks for the members, so its host label and group
  tag no longer follow a laptop around. `cbb status` says where it keeps quiet, and
  `sudo cbb network` takes the current network as known, as at home after a new router. An
  updated computer takes the networks it is on at the update as known.
- Security: only the group's root or an admin can register the group on a forwarder. The hub
  signs the registration with its root or admin CA key, and sends the group's authority
  records with it. The forwarder and the relay keep those records in memory and refuse a hub
  or device that the records remove or freeze, so a removed device can no longer push the
  real hub out or hold a relay slot.
- Security: a forwarder takes at most 16 registrations from one address and 64 from one
  network (/24 or /64), and gives each network a sixteenth of the budget for checking
  handshakes against the groups, so a few hosts can no longer fill it or use up the budget.
- Security: membership in the `clipboardbridge` group gives the clipboard only. The service
  takes what changes the group (`new`, `pair`, `invite`, `revoke`, `rename`, `admin`,
  `takeover`, `upgrade`, `freeze`, `unfreeze`, the holder setting, `global` on, off and hub)
  only on a new admin socket next to the control socket, which only root reaches (on Windows
  administrators): run those commands with `sudo`, or from a terminal opened as
  administrator. The lite member does the same for `cbb global on|off`.
- Security: tmux's paste key no longer types control characters, a second line or a secret
  into the terminal. It runs the new `cbb paste -terminal` (full and lite member), which drops
  the control characters of C0 but tab and line feed, DEL and those of C1, keeps only the
  first line unless `-lines`, leaves out the last line feed, and refuses a secret unless
  `-secret`.
- An update without a terminal over an installation from before the firewall question no
  longer removes the firewall rules it had added: rules that are there without a kept answer
  count as an earlier Yes (Linux, macOS, Windows), and with no terminal and no answer nothing
  is added or removed. `cbb global` returns only once a service it restarted answers again.
- An update no longer leaves an earlier version's limit in place: the Linux drop-in that let a
  member with `cbb global on` reach every address, or a Windows outbound rule written for
  other servers. The installers run `cbb global allow` once the service answers, and
  `cbb status` names such a limit instead of "the home network only". `cbb global on` says
  when the group's servers are not known yet and `sudo cbb global allow` is needed once
  they are. A second `cbb pair` says how to close the window that is still open.
- The phones' one button no longer puts the computers' older text over a clipboard it could
  not read (paste not allowed, or not text): it leaves the clipboard as it is and says so,
  with the details in debug builds.
- The phones' one button waits up to 5 seconds for a computer to connect before it says none
  is: back from the background, the dropped connections take a moment to come back.
- A used remote invitation no longer reaches the hub: its guest tunnel goes as soon as the new
  device's member connection through it ends after the hub answered its tunnel key (at most
  2 minutes after the admission, as before), and the hub refuses a second pairing through it.
- On Linux the service's memory, which holds secrets, never goes to swap (`MemorySwapMax=0`).
- When a device away from home gets no answer through the tunnel, `cbb global` says that the hub
  or the forwarder on the way may be down, not only the hub.
- Security: on Android, a text from Share or the selection menu is sent only after the user
  allows it, with "Allow" or "Always allow"; any app can hand over a text, so without a
  question an app could send whatever it liked to the computers. Settings turns the question
  back on.

- Security: on a Mac with Homebrew, the service, which holds the group's keys, no longer runs
  the binary under Homebrew's prefix, which the user and their programs may replace.
  `install.sh --in-place` copies it to `/Library/Application Support/clipboardbridge/bin`,
  where only root can change it; the agent and `cbb` in PATH still run Homebrew's. Running
  `install.sh` again after `brew upgrade` refreshes the copy, as before.

- Security: any admin, a computer included, can freeze another admin computer, as one that
  was stolen: `cbb freeze <name>`. From then on nothing the frozen admin signs counts beyond
  what it did before, its connections are refused, and it is no admin until the root or an
  admin phone unfreezes it ("Unfreeze" in Devices, `cbb unfreeze` on a root computer) or
  removes it. Nobody freezes the root or an admin phone. Every member (Go, the phone apps,
  the lite member) follows the new `freeze` and `thaw` records; docs/design.md, "Who may
  remove an admin", says why freezing was chosen.

- Security: an admin computer, whose admin key sits in a file, can remove ordinary devices
  but no longer the root or another admin, and cannot hand a phone's group to a new root;
  only the root and admin phones can. `cbb takeover` from a lost root computer still works,
  but counts only while the old root's own records leave that admin standing: a root that
  is still in use undoes it by removing the admin, and a frozen admin does not take over. Nothing an admin signs after it was removed counts,
  and each admin signs at most 1024 records. Every member (Go, the phone apps, the lite
  member) enforces this from the records alone (docs/protocol.md, section 10).

- Security: the iPhone shortcut's token only syncs. `POST /admit` and the shortcut
  "clipboardbridge: add a computer" are gone, so a copied token can no longer add a computer
  (which on Linux got the group's keys); computers join through the phone apps or
  `cbb pair`. `cbb pair -phone -new-token` revokes every shortcut's token and pairs the
  iPhone with a new one.

- Security: only the group's root or an admin can be the hub for sync away from home. A
  member, phone or computer, ignores tunnel offers from any other device, and once it keeps
  a hub's offer it ignores other hubs until sync away from home is turned off and on again,
  so a member cannot point the others' tunnels at itself.

- Security: the lite member makes its control socket in a private directory and narrows it there
  before moving it into place, so nobody can connect in the moment before its mode is set,
  whatever the umask. Dependabot also watches the lite member's crates and the Android
  app's Gradle dependencies.

- Security: handshakes to unknown groups cost the forwarder at most a fixed number of group
  checks a second (`Limits.ScanRate`), whatever their source addresses, so a flood of forged
  handshakes cannot hold up the other groups.

- Security: a member's certificate is checked against the issuer that actually signed it.
  Before, the revocation check and the admin check looked at the second certificate a peer
  presented, so extra certificates in a chain could get a removed admin's devices back in
  and make an ordinary member count as an admin. Fixed in Go, the phone kits and the lite
  member; the member protocol now passes on only the chain the handshake verified.

- A hub on a host without IPv6 could listen on a random UDP port instead of its own and
  then hear no client: wireguard-go's socket reported port 0 there, and the device's next
  rebind, which its own "up" event can cause while it starts, took any free port.

- A data race in the tunnel's WireGuard timers when a peer stops, as when a hub closes: a
  timer that fired at that moment cleared its state outside its lock. clipboardbridge now
  builds with a copy of amneziawg-go that clears it under the lock
  (`internal/third_party/amneziawg-go`).
- Sync away from home works on Linux: the service's unit lets it reach only the home network,
  so a hub could not register with its forwarder and a computer away from home could not reach
  its hub. `sudo cbb global on` (and `sudo cbb pair -invite`) now add a systemd drop-in that lets
  the service reach the internet, and `sudo cbb global off` removes it; until then `cbb global`
  says what is missing.
- Every computer keeps the service on the home network until sync away from home is on: the
  service refuses its own connections outside the home network (`internal/netguard`), as the
  member port already refused connections from there. On Windows the installer adds an
  outbound block rule of Windows Firewall for the service (`clipboardbridge-home-only`) as
  well, which `cbb global on` and `cbb pair -invite`, run as administrator, lift, and `cbb global
  off` puts back, as `sudo` does on Linux. A Mac gets the system's own limit with the Mac
  app's Network Extension later (docs/roadmap.md).
- `cbb global hub -forwarder` and `cbb global relay` take a server's name as well as its address.
- A device whose group file is damaged says so: the service keeps running without its group,
  `cbb status` and every other command explain what is wrong and how to recover (with the
  underlying error in a debug build or with `CBB_DEBUG=1`), and nothing writes over the file.
  Before, the service only restarted every few seconds and `cbb status` said it was not running.
- The service's log no longer says `<nil>` for a member connection that closed in order.
- A removed device learns that it was removed: the member that revokes it sends it the
  revocation before it closes the connection, and `cbb status` on the removed device says so.
  Until now the device never got the record and still showed its group's devices.
- The desktop connectors (the Mac's and Windows's agent, `cbb desktop` on Linux) take the
  first texts soon after the device joins a group. While the service turned them down for
  being in no group, they waited up to 30 seconds between tries, and the texts that came
  meanwhile reached the clipboard late; now they ask again every 2 seconds, and log it once.
- Installing again on Windows no longer fails now and then with "cbbw.exe is being used by
  another process": the installer waits for the old agent to exit, and tries the copy again
  while an agent the last install started is still starting.
- Installing again on a Mac, as after `brew upgrade`, no longer fails now and then with
  "Bootstrap failed: 5: Input/output error": the installer waits for launchd to let the
  old service go before starting it.
- Stopping a tunnel for sync away from home while a packet comes in no longer races in
  WireGuard's network stack, which could crash the service: the peers stop first.

## [0.3.0] - 2026-10-24

### Changed

- The Mac is a full member like the Linux and Windows computers (docs/design.md, D-51): it
  no longer publishes `r=mac`, and of two computers the one with the lower device ID dials;
  when it has not connected for 30 seconds, the other dials too, and of two connections the
  one the lower ID dialed stays. `cbb-lite` dials the Macs as it dials every computer. A Mac
  still does not admit devices.
- Which computer holds `clipboardbridge.local` (D-53): one without a battery comes first and a
  laptop only when no other is on, then the lowest device ID; the computers publish their
  priority in the TXT key `h`. `cbb holder auto|first|fallback|never` changes the guess, and
  `cbb status` says how this computer takes part.
- `cbb away hub` and the quick start say that the hub need not stay on: while it is off,
  nothing syncs away from home, and at home the devices sync without it.
- A device's system is separate from its role (docs/design.md, D-50): device records and
  hellos carry `os` (`linux`, `windows`, `macos`, `ios`, `android`, `none`), and the roles
  are `full`, `phone`, `lite` and `shortcut`. A Windows PC now shows as Windows, not Linux;
  an admin re-signs the record of a full member whose hello names another system. Records
  with the old roles `linux` and `mac` read as `full`, `iphone` as `shortcut`. Not
  compatible with 0.3 members: update every device of a group together.
- `cbb devices` is folded into `cbb status`, which shows this device's system and role and
  then the group's devices with their systems, roles and admins; `cbb-lite devices` the same.
  The apps' Devices screens show each device's system.
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

- A quick start, [docs/guide/quickstart.md](docs/guide/quickstart.md): install with one command, make
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

[Unreleased]: https://github.com/HunterEwok/clipboardbridge/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/HunterEwok/clipboardbridge/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/HunterEwok/clipboardbridge/releases/tag/v0.1.1
