<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Roadmap

What comes next, the designs that are agreed but not built yet, and the questions to study
before anything is planned. How Clipboard Bridge works today is in [design.md](design.md),
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
    `clipboardbridge.local` or serves the iPhone shortcut. It dials the computers and
    listens for phones, so a phone and a lite member sync with no computer on. Only once the Go version is complete and its architecture settled, so it is
    written once. Before it: the protocol written down in `docs/protocol.md`, a `lite` role
    that full members treat like a Mac, test vectors in `testdata/`, and an e2e test with a
    Rust member among Go members. Done for Linux in `lite/` (its command is `cbb` too, built for the
    Raspberry Pi, not yet run on one). The ESP32 comes next: the protocol core is its own
    crate, `lite/core`, without the standard library (no_std with alloc, RustCrypto in
    place of ring), with the member TLS in it (rustls without std and a RustCrypto
    provider; the lite member on Linux uses the same code), which CI builds for the ESP32-C6 (RISC-V)
    and the ESP32-S3 (Xtensa); the firmware and the networking on the chip follow.
12. **Partly: built between computers (`cbb global`, `cbb invite` for joining from afar, `cbb forward` for hubs behind carrier-grade NAT, and `cbb relay`, a blind relay of the user's own for groups without a hub); the rest is the order of work in [design.md](design.md#order-of-work).** Sync away from home and between subnets, through the group's own WireGuard tunnel in a
    star around a hub; see "Sync away from home" in [design.md](design.md#sync-away-from-home). The lite member on Linux
    takes part as a client, with plain WireGuard (`cbb global on` there).
13. **Planned.** Computer keys in hardware; see "Device keys in hardware" below.
14. **Started: `cbb next` on the lite member and the `.cbb` dot command (`apps/zxnext`) are written, not yet
    run on a real Next; the NextPi set-up and the path through the ESP8266 are next.** The ZX
    Spectrum Next through its own Raspberry Pi. The Accelerated Next carries a
    Raspberry Pi Zero on its accelerator header, wired to the FPGA's second UART, with
    NextPi (a read-only DietPi) and a root shell (`SUP>`) on that UART. The lite member runs on
    this Pi as an ordinary lite member, installed on the NextPi card itself (its user
    partition and a start script), so NextPi's own tools keep working. It speaks the
    member protocol with TLS 1.3 like any other member and reaches the network in one of
    two ways, both built: the Pi's own Wi-Fi on a Zero W, which NextPi turns off and we
    turn back on; or, on a Zero without a radio, the Next's built-in ESP8266, which then
    only carries the Pi's TLS bytes: the Z80 copies them between the Pi's UART and the
    ESP's, and the ESP never sees anything but ciphertext. A dot command on the Next,
    `.cbb`, talks to the lite member over the internal UART the way NextPi's own tools do
    (`.pisend`): it copies a text to the group, pastes the latest one, and joins by
    drawing the QR code for the phone app on the Next's screen (`cbb next`,
    lite/README.md). The UART is a trace on the
    Next's board and never leaves the case, so it carries the texts in the clear. The Pi
    converts between UTF-8 and the Spectrum character set: printable ASCII first, with
    every other character shown as `?`; Cyrillic follows later as an encoding of its own.
    No other device takes part: a Next without a Pi is future research (below), not a
    reason to lean on a computer in the group.
15. **Started: the firmware (`lite/esp32`) builds for the Nano ESP32, keeps its settings in
    flash, joins the Wi-Fi network set on its USB console, joins a group by the phone and
    passes its self-test (keys, certificates, a TLS 1.3 handshake on the chip) in QEMU;
    its network code (`lite/embassy`) also runs on Linux over a TAP interface, where CI
    has a Go member admit it by the phone; sync and the USB keyboard are next.** Arduino: the Arduino Nano ESP32 (an ESP32-S3) as a full lite member, on the same
    `lite/core` as the other ESP32 boards, with the member protocol and TLS 1.3 on the
    board itself. It ships as a ready firmware built from our Rust code, flashed over USB
    with one command; a library for writing one's own Arduino sketches on top of it may
    follow. Over its USB port it can act as a keyboard and type the group's latest text
    into any computer without Clipboard Bridge (Latin characters only: a USB keyboard
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
18. **Planned for 0.6.** Remote paste: an admin device sends a text to one member and has
    it pasted or typed where that member's focus is, with nothing pressed on the target;
    every admin may do it on every member whose user turned it on, Enter and root consoles
    separately (D-54, D-59), the iPhone only sends. See "Remote paste"
    in [design.md](design.md#remote-paste-planned-for-06). One pull request each:
    1. the signed `paste` command, its result and its forwarding, in Go and both phone
       kits with interop vectors; `cbb paste --on DEVICE`;
    2. Linux targets: X11, Wayland (virtual keyboard, uinput), tmux and the console helper
       (item 10);
    3. Windows and macOS targets;
    4. sending from the iPhone and Android apps, and the Android target;
    5. the lite member's target, then the Nano ESP32's keyboard.
19. **Planned for 0.5.** Sync modes: each device keeps its own clipboard by default and is
    switched to shared, receive only or send only by itself or by any admin (D-55). See
    "Sync modes" in [design.md](design.md#sync-modes-planned-for-05). **Built on the
    computers (`cbb mode`) with the admin's signed `mode` command (`cbb mode -on`) and in
    the phone kits and apps (an admin sets a computer's mode; the Mac and tray apps set their
    own); the phones' and the lite member's own modes are next.**
20. **Planned for 0.6.** Images, files and folders, with formatted text last and optional
    (D-56 to D-58): the event carries a manifest with SHA-256 hashes, the bytes are fetched
    in chunks at lower priority than events, and each device has its own limit (100 MiB at
    home, 25 MiB away from home, at most 1 GiB). See "Images and files" in
    [design.md](design.md#images-and-files-planned-for-06). One pull request each:
    1. the `media` event, the content cache, `get` and `chunk`, the limits, interop vectors;
       `cbb copy FILE` and `cbb paste -o DIR`;
    2. images in the desktop connectors (Wayland, X11, Mac, Windows);
    3. files and folders in the desktop connectors;
    4. the phone apps: images, then files and the share targets;
    5. away from home: the away limit and the hub serving its clients, on the bench;
    6. HTML, optional.
21. **Planned for 0.6.** OpenWrt routers: the full service on a router as an always-on
    member and the natural hub, the lite member for small routers. See "OpenWrt routers" below.
22. **Planned, when the Apple developer account is there.** A Mac app, signed with Developer ID
    and notarized, that carries the service and a Network Extension (a content filter): the
    system then keeps the service on the home network until sync away from home is on, and
    lets only the home network reach its port, as the systemd unit does on Linux and Windows
    Firewall on Windows. Until then the Mac has the service's own limit only
    (`internal/netguard`, and the member port's check of the address), which every computer
    has as well; macOS has no per-program limit without such an app (the application firewall
    allows or blocks a program, and pf is shared by the whole system), so this is the one
    difference between the computers, and it goes away with the app. The app's window and menu bar
    item over the installed service are there already (`apps/macos`, [apps.md](apps.md#the-mac-app));
    the signed app that carries the service waits for the account.
23. **Built: the image, its compose files and its publishing with each release; a container as the hub on the bench is next.** Docker: an image with the full service for a NAS or a home server, as an
    always-on member, the hub for sync away from home, a `cbb forward` forwarder or a
    `cbb relay` on a VPS. See "Docker" below.
24. **Planned for 0.6.** FreeBSD: the full service on FreeBSD (servers, desktops, and OPNsense or
    pfSense gateways as the hub). See "FreeBSD" below.
25. **Planned for 0.6, after remote paste (item 18).** Devices that are hard to type into: TVs,
    set-top boxes, game consoles, VR headsets, car head units, boot and login screens, so
    that a text copied on any device of the group lands in a field there without typing it
    with a remote. See "Devices that are hard to type into" below.
26. **Partly: the notifications and both watch apps are done; the watch's admin key and its emergency actions are planned for 0.6.** Watches: the Apple Watch, and Wear OS after it, show the group's
    events, turn sync away from home on and off, and act at once on a stolen device with an
    admin key of their own. The root stays on the phone. See "Watches" below.
27. **Planned for 0.6, after remote paste (item 18).** Quick actions: one button in the apps,
    on the watch or in `cbb` runs an action on a member, such as reboot or lock the screen,
    from a few presets and the user's own, always defined on the member itself. See "Quick
    actions" below.
28. **Planned for 0.5.** A blind relay for every group that needs a hub and has none, or
    does not want to run one: the project's relay at `cbb.tools`, and one of the user's own
    that is easy to set up. This changes the principle of "Blind relay (self-hosted only)"
    in [design.md](design.md#blind-relay-self-hosted-only); the pull request that builds it
    rewrites that section. It needs: groups that register with the project's relay by
    themselves, with limits per group (finding 3 of the security audit); the relay in both
    phone apps, beside the hub; a choice the user makes, after the apps and `cbb global
    relay` say what the relay learns (which devices talk, when and how much, and their
    addresses; never the clipboard); and the guide to running one's own forwarder or relay,
    with the plain, AmneziaWG and VLESS ways for networks and countries that block VPNs
    ([running your own servers](reference/self-hosting.md)).
29. **Proposed for 0.6.** Secure updates: every program updates itself, or is told to,
    from a release signed with the project's own key, downloaded from cbb.tools or GitHub,
    never to an older or unsigned version, and automatically where the user allows it. See
    "Secure updates" below.
30. **Planned for 0.5; steps 1 to 4 are built.** The phone as the hub while its app is open: a
    group made on a phone with no computer (phones, TVs, lite members) syncs at home and from
    afar while the app is open, through the project's forwarder; once a computer that is
    always on joins, the app suggests moving the hub there, and the user may keep it on the
    phone. See "The phone as the hub" below.
31. **Planned for 0.6.** Key levels: the user picks who may be the group's root, an admin
    or a hub: only devices whose hardware key is proven by attestation, devices with a key in
    hardware (the default), or, after a warning, devices with a key in a file too. See "Key
    levels" below and the guide "Keys and attestation", which comes with it.
32. **Planned for 0.6.** What the forwarder and the relay learn, cut to what they need: short
    credentials made for them (the hubs' credential, the members' credential) in place of
    the group's records, so they see no device ID, name, system, role or dates. See "What
    the servers learn" below, with the research of what is left to hide (the addresses
    and online times, stable pseudonyms, the group tag, the count of devices).
33. **To research in 0.6.** The iPhone as a hub in the background: the hub run as a
    Network Extension (a packet tunnel provider), which iOS does not suspend while the
    tunnel is on. See "Research: the iPhone hub in a Network Extension" below.

## OpenWrt routers

Planned for 0.6.

A router has no desktop and no clipboard of its own, so on a router Clipboard Bridge is
infrastructure, not a place to copy and paste:

- **The hub for sync away from home.** The router is always on and is the device with the
  public address, so it needs no port forwarding: it opens the hub's UDP port on its own
  WAN. Today the hub is a computer that must stay on.
- **An always-on member at home.** Phones and lite members sync through it when no
  computer is on, and it holds `clipboardbridge.local` (it is never on battery).
- **A member on every subnet.** A router sits on the home network and the IoT subnet at
  once, so a device on the IoT subnet syncs with the router directly, and the router passes
  its events on as every member does. No rule from the IoT subnet into the home network is
  needed, only one that lets the IoT subnet reach the router's member port.
- **Not a place for remote paste or CA keys.** It has no screen to paste on. It should
  join as an ordinary full member, never as the creator or an admin: CA keys do not belong
  on a box that faces the internet.

### Full or lite

| | `cbb` (Go, full member) | the lite member's `cbb` (Rust) |
|---|---|---|
| Size of the binary | about 25 MB stripped (6.4 MB compressed with xz) for arm64; armv7, mips and mipsle the same order | 1.7 MB for arm64 (static musl) |
| Routers it fits | 128 MB of flash or more, or eMMC (for example the Banana Pi BPI-R4); 256 MB of RAM or more | almost any OpenWrt router, 16 MB of flash and 64 MB of RAM |
| Hub | yes | no: lite members are clients only |
| Away from home | yes, as hub or client, with obfuscation and VLESS | as a client, with plain WireGuard (GotaTun); never AmneziaWG |
| Builds | Go cross-compiles statically for every OpenWrt CPU: aarch64, armv7, mips and mipsle (softfloat), x86-64; arm64 and armv7 are in every release already | aarch64, armv7, x86-64 with stable Rust; mips and mipsle are Tier 3 in Rust (nightly and `-Zbuild-std`) |

Recommendation: the full service first, aimed at routers with room for it, because the hub
is what a router adds that nothing else does; the lite member afterwards for small routers, as
packaging around what exists.

### What OpenWrt needs that other Linux does not

- **No systemd.** A procd init script (`/etc/init.d/clipboardbridge`) runs the service as
  its own user with respawn, and a UCI file (`/etc/config/clipboardbridge`) holds the
  settings: interfaces, port, hub.
- **`/var` is in RAM.** The state goes to `/etc/clipboardbridge`, which survives reboots,
  and a file in `/lib/upgrade/keep.d` keeps it across `sysupgrade`. The service writes it
  rarely (the identity, the records, the clock mark), so the flash does not wear.
- **The firewall is fw4 (nftables), driven by UCI.** The installer adds named rules
  (`clipboardbridge ...`): the member port and mDNS from the zones the user names (the
  `lan` zone already accepts input; an IoT zone usually does not), and the hub's UDP port
  from `wan` only while the router is the hub. It remembers what it added and removes
  exactly that, as on other Linux.
- **mDNS only on the inside.** Today `cbb` announces on every interface. On a router that
  would send the group's names and device IDs onto the provider's network, so the service
  gets a list of interfaces for mDNS and the member port, by default the devices of the
  `lan` zone. Avahi, already installed on many routers, keeps working: `cbb` shares port
  5353 with it as it does on desktop Linux.
- **Time.** Many routers have no clock that runs while they are off, and certificates need
  the right time, so the init script starts the service after NTP has set the clock.
- **Packages.** OpenWrt 25.12 installs `.apk` packages (apk 3); 24.10 and older use
  `.ipk` (opkg). The first step installs with a script, as `get.sh` does elsewhere;
  packages built with the OpenWrt SDK in CI come after.
- **The router's own WireGuard or AmneziaWG** stays separate: `cbb` runs its tunnel in its
  own process (amneziawg-go with netstack) on a port of its own and adds no interface or
  route.

The security rules of sync away from home do not change: the router is the user's own
device, the tunnel is the group's own WireGuard, member TLS runs inside it, and nothing but
the hub's UDP port faces the internet.

### Steps

One pull request each, smaller ones together:

1. The service on a router: a list of interfaces for mDNS and the member port, and release
   builds for mips and mipsle (softfloat).
2. `packaging/openwrt`: the procd script, the UCI file, install and uninstall through
   `get.sh` (it recognises OpenWrt by `/etc/openwrt_release`), the fw4 rules, the state in
   `/etc/clipboardbridge`, the wait for NTP; a CI job that runs the installer in an
   OpenWrt root file system.
3. The router as the hub: `cbb global hub` opens its UDP port on `wan` and `cbb global off`
   closes it; the bench gets the router as a device under test with cases for it in
   [testbench.md](testbench.md).
4. `.apk` and `.ipk` packages from the OpenWrt SDK in CI, attached to each release.
5. The lite member on OpenWrt: its procd script and installer path, builds for armv7 and, with
   nightly Rust, mips and mipsle.

Later, if wanted: a LuCI page with the status and the QR code for joining.

## Docker

Planned for 0.5; steps 1 and 2 are done ([packaging/docker](../packaging/docker/README.md)).

An image with the full service, for the machines that are always on but have no desktop: a
NAS (Synology, QNAP, TrueNAS, Unraid), a home server, a VPS. Like a router, the container is
infrastructure, not a place to copy and paste:

- **An always-on member and the hub.** At home it keeps the group's events while no
  computer is on and holds `clipboardbridge.local`; with `cbb global hub` it is the hub for
  sync away from home.
- **A forwarder or a relay on a VPS.** `cbb forward` and `cbb relay` hold no group keys, so
  a container on a rented server is the natural way to run them.
- **Never the creator or an admin.** It joins as an ordinary full member; CA keys stay on
  the devices the user holds.

What the image needs:

- **One small image for every CPU.** `cbb` is static and carries its own certificate roots,
  so the image is the binary and nothing else (`FROM scratch`), for linux/amd64, linux/arm64 and linux/arm/v7, published
  to the GitHub Container Registry with each release and carrying the same build
  attestations as the release archives. The documentation pins it by digest.
- **No privileges.** The tunnel runs in the process (WireGuard on gVisor netstack), so the
  container needs no `NET_ADMIN`, no `/dev/net/tun` and no `--privileged`. It runs as its
  own user with a read-only root file system; the state is one volume
  (`/var/lib/clipboardbridge`).
- **Host networking at home.** mDNS and the member port must be on the home network, so a
  member at home runs with `network_mode: host`; behind Docker's bridge the other devices
  would not find it. A forwarder or a relay on a VPS publishes its ports instead (UDP 8764,
  TCP 443 for VLESS).
- **The host's firewall stays the host's.** The container cannot change it, so `cbb` answers
  the firewall question with No (see the firewall consent in [design.md](design.md)): it
  prints the exact rules for the host and says in `cbb status` whether a home member could
  reach it. Its own limit (`internal/netguard`) works inside the container as everywhere.
- **Joining without a screen.** `docker exec -it clipboardbridge cbb join` shows the QR code
  in the terminal, as on any server.

Steps, one pull request each, smaller ones together:

1. Done. `packaging/docker`: the Dockerfile, a compose file for a home member and one for a
   forwarder or relay, and a CI job that builds the image and has two containers join a
   group and sync.
2. Done. The release workflow publishes the multi-arch image with its attestations; README and
   the installer pages say how to run it on the common NAS systems.
3. The bench gets a container as the hub, with cases for it in [testbench.md](testbench.md).

## FreeBSD

Planned for 0.6.

FreeBSD runs servers, some desktops, and the gateways OPNsense and pfSense. Go builds `cbb`
for it already (`GOOS=freebsd`, amd64 and arm64, no cgo); what is missing is what the
service needs from the system:

- **The service.** An rc.d script that runs `cbb` as its own user through daemon(8), with
  the state in `/var/db/clipboardbridge`; `get.sh` recognises FreeBSD and installs it, and
  a port and `pkg` package follow.
- **The control socket.** Its check of the connecting user takes the peer's credentials
  with `getpeereid`/`LOCAL_PEERCRED` on FreeBSD, where Linux uses `SO_PEERCRED`.
- **The firewall.** FreeBSD has pf and ipfw; `cbb` detects which one is active and asks as on
  the other systems (the same consent prompt, the same rules: the member port and mDNS from
  the home subnets only, the hub's UDP port while it is the hub). On OPNsense and pfSense
  the rules belong in the gateway's own configuration, which rewrites pf, so there `cbb`
  prints them for the web interface; a plugin may follow.
- **The desktop.** FreeBSD desktops run X11 and Wayland, so the Linux desktop connector
  (`internal/desktop`) is built for FreeBSD too and tested there.
- **A gateway as the hub.** OPNsense and pfSense are what OpenWrt is on other routers: always
  on, with the public address. They reuse the OpenWrt work: mDNS and the member port only on
  the inside interfaces, the hub's port on the WAN only while it is the hub, no CA keys.

The protection is the same as on Linux: the service's own limit to the home network until
sync away from home is on, member TLS, and the tunnel away from home.

Steps:

1. Release builds for freebsd-amd64 and freebsd-arm64, the control socket's check, and a CI
   job that runs the Go tests in a FreeBSD virtual machine.
2. The rc.d script, `get.sh`, the pf and ipfw rules with the consent prompt.
3. The desktop connector on FreeBSD.
4. OPNsense and pfSense as the hub, after the OpenWrt steps; the port in the ports tree.

## Devices that are hard to type into

Planned for 0.6, after remote paste (item 18).

The aim: a text copied on any device of the group lands in a field of a device where typing
it is slow or impossible with what is in the user's hands, usually a TV remote or a gamepad.
Logins, Wi-Fi passwords, links, search queries and codes are the common cases. There are
four ways, from the one that needs least to the one that reaches most.

### 1. Our app on the device

Many such devices run Android, so the Android app reaches them with little more than a
layout for a remote:

- **Android TV, Google TV, Fire TV** and the Android set-top boxes and projectors: a TV
  variant of the Android app, with a launcher banner, a screen driven by the D-pad and no
  need for a touch screen. The TV shows the QR code and the phone scans it, so joining
  types nothing on the TV. Fire TV takes the signed APK of each release or the Amazon
  Appstore.
- **Android car head units, Android e-readers (Onyx Boox), Chromebooks** take the Android
  app as it is.
- **Meta Quest** (Horizon OS is Android) takes the APK; whether its accessibility service
  may put text into other apps is to be checked on a headset.

The app receives as it does on a phone, in its foreground service; a TV is receive only by
default (sync modes, item 19). The text goes into the field that has the focus through the
accessibility service (`ACTION_SET_TEXT`, or `ACTION_PASTE` after setting the clipboard),
on remote paste from any admin, so nothing is pressed on the TV. This is the Android target
of item 18, step 4.

### 2. The device's own remote, from a member

Most TVs can be driven over the home network by the maker's remote app on a phone, and those
apps can type into the field on screen. A member does the same: it pairs once with the TV as
its remote and, on remote paste, sends the text into the field. Nothing is installed on the
TV.

| Device | Protocol | Pairing | On the network |
|---|---|---|---|
| Android TV, Google TV | Android TV Remote v2, as in the Google TV app | a code shown on the TV | TLS |
| Apple TV | the Companion protocol of the Apple TV Remote, with its keyboard | a PIN shown on the TV | encrypted |
| Samsung (Tizen) | the TV's remote WebSocket API, port 8002 | allowed once on the TV | TLS |
| LG (webOS) | SSAP over WebSocket, port 3001 | allowed once on the TV | TLS |
| Roku | External Control Protocol, a key press per character | none | plain HTTP |

Apple TV is the main reason for this way: an iPhone already types on it with its own
keyboard, but Android, Linux and Windows have no way to, and a tvOS app cannot type into
other apps.

The rules:

- **The TV is a target, not a member.** It holds no key, gets no events and never joins the
  group; it belongs to the member that pairs with it, is shown under that member in the
  device list, and is addressed by remote paste (`cbb paste --on living-room-tv`) like the
  member's own screen. The member keeps the TV's pairing keys in its state.
- **Only on the home network.** The last hop leaves the group's encryption and is protected
  by the TV's own protocol, so a member reaches a TV only on its home network (the address
  checked as `internal/netguard` does) and never through the tunnel. Away from home, the
  text reaches the member through the tunnel and member TLS as always; only the member's
  last step to the TV is local.
- **Roku is off until the user turns it on** for that Roku, after being told that the text
  then crosses the home network in the clear.
- **The protocols are not all documented** (only Roku's is, and Samsung's in part), so
  firmware updates may change them; each one is ours in Go, with no third-party service
  and no maker's cloud, and a failure says which TV and protocol failed (the debug details
  as everywhere).
- **Who can be the remote.** Every computer, the routers and the Docker image (they are
  always on), and the Android app; the iPhone app too, where iOS lets it use the local
  network. The same remotes on Linux, Mac and Windows, and on both phones.

### 3. A phone or a computer as a Bluetooth keyboard

A device of the group that has Bluetooth can pair with the TV, console or tablet as a
Bluetooth keyboard and type what remote paste sends it, so no extra hardware is needed. The
paired device is a target of that member, as a TV is in way 2.

| Member | Bluetooth keyboard | Why |
|---|---|---|
| Android | yes, Android 9 and later | the HID Device profile (`BluetoothHidDevice`); a few makers leave it out, which the app detects and says |
| Linux | yes | BlueZ registers a keyboard profile; the service needs the Bluetooth adapter's permission, asked for at install |
| iPhone, iPad | no | iOS does not let an app act as a keyboard: the HID service is the system's own |
| Mac, Windows | no | neither has a public interface for the keyboard side of Bluetooth HID |

So in a group with an Android phone or a Linux computer near the TV, the iPhone sends the
text and that device types it. Bluetooth keyboards on Android and Linux are the one
difference within the phones and within the computers, and it is the operating system's:
iOS, macOS and Windows allow it to no app. Groups without such a device use the Nano ESP32
(way 4). The text crosses the air as a Bluetooth keyboard's does, with the link's own
encryption after pairing, a short hop next to the device; Enter and secrets follow the
same rule as the Nano ESP32 below.

### 4. The Nano ESP32 as a keyboard

For devices with no app and no protocol, and for groups with no Android phone or Linux
computer near them, the Nano ESP32 (item 15) plugs in or pairs as a keyboard and types what
remote paste sends it:

- **USB keyboard** (item 15): PlayStation 5, Xbox, Nintendo Switch in the fields that take a
  keyboard, TVs and set-top boxes with a USB port, KVM switches, BIOS and UEFI setup, boot
  loaders, servers without a network.
- **Bluetooth LE keyboard** (the ESP32-S3 has Bluetooth LE): Apple TV, Samsung and LG TVs,
  iPads, consoles that take a Bluetooth keyboard. The board keeps its pairings in flash.
- **Serial console:** its UART on the console header of a router, a switch or a server, or a
  USB serial adapter, typed as a terminal.

A keyboard sends key codes and the device's layout decides the characters, so the board
types Latin with a US layout first; other layouts are a setting per target, and Cyrillic
works where the target has a Russian layout to switch to. Login, disk encryption (LUKS,
BitLocker) and password screens are typed only on an explicit remote paste, with Enter a
separate permission (D-59), never on sync.

### Other devices

- **SteamOS in Game Mode** has no clipboard the desktop connector can use; remote paste
  types there through uinput (item 18, step 2).
- **iPad**: the iPhone app on iPad, built as a universal app.
- **Keenetic and other routers with Entware**: after OpenWrt, the same service with
  Entware's init scripts.
- **WSL and Termux** need nothing of their own: the Windows service and the Android app
  cover them.
- **Not reachable**: Kindle e-readers take neither apps nor keyboards; watches have apps of
  their own (item 26) but nothing worth typing into.

### Steps

One pull request each, smaller ones together:

1. The TV variant of the Android app, with the accessibility target of item 18, step 4.
2. Remotes in Go: Android TV Remote v2 and the Apple TV Companion protocol first, then
   Samsung and LG, Roku last; `cbb remote add` pairs a TV, and the apps add theirs.
3. The Bluetooth keyboard on Android and Linux.
4. The Nano ESP32's Bluetooth LE keyboard, after its USB keyboard (item 15), the layouts,
   and the serial console.
5. The iPad build of the iPhone app.

## Watches

Steps 1 and 2 done in 0.4; the rest planned for 0.6. Decided on 2026-10-24: a watch is never
the group's root, but it carries notifications, a switch for sync away from home and the
emergency actions, with an admin key of its own.

### Why not the root

The Apple Watch has a Secure Enclave and CryptoKit makes P-256 keys in it, so it could hold
the root key. But watchOS gives an ordinary app no sockets: no TCP or TLS to the members, no
Bonjour, no listening, only `URLSession` and WatchConnectivity to its paired iPhone (Apple's
TN3135; low-level networking is for audio streaming apps only). A watch therefore always
works through its iPhone and cannot be a member. A root key on the watch with the iPhone as
the carrier would keep the root safe from a compromised phone, but the root signs rarely and
the iPhone's key already sits in the Secure Enclave behind Face ID, so the group stays as it is.

### What the watch does

1. **Notifications.** The phone app notifies of the group's events, and iOS and Wear OS show
   them on the watch: a device added or removed, an admin made, frozen or unfrozen, the group
   taken over, a certificate close to expiry that did not renew, the hub unreachable while
   away from home, a remote paste received or refused. Each is a setting.
2. **Sync away from home.** A switch on the watch turns the phone's own away mode on and off,
   as the app's switch does (`AwayFromHome`, `cbbtun`).
3. **Emergency actions** with the watch's own admin key: freeze an admin computer, remove an
   ordinary device, turn remote paste off on a member, turn sync away from home **off** on a
   member. The watch shows what it signs and asks for a tap; the phone only carries the
   record into the group.

### The watch's admin key

A key in the watch's Secure Enclave (on Wear OS, the watch's Keystore), which the root
certifies as an admin CA once, as it does an admin phone. The watch's device record has its
own role, `watch`. A watch on the wrist stays unlocked without asking for Face ID or a
fingerprint at each signature, so it signs the emergency actions above and nothing else: it
freezes admin computers (D-60) and removes ordinary devices, but never removes an admin,
makes one, admits devices, renews certificates or takes the group over. Any admin can freeze
a watch like an admin computer; removing one takes the root or an admin phone.
Every receiver checks these limits, in Go, Rust, Swift and Kotlin, with interop vectors.

Turning sync away from home on stays a decision on each device (D-45); a signed command only
turns it off, as any admin turns remote paste off (D-59).

### Delivery

On Android the foreground service receives the events by itself, so the watch hears of them
at once. On the iPhone the app has no background sync and learns of events only when it
syncs, so a notification may come late. To make it prompt, the hub could wake the phone with
an Apple push whose content is encrypted to the phone's key and decrypted only on the phone
(a Notification Service Extension); Apple would see that a push was sent, and when, but
nothing in it. Whether to use Apple's push service at all is the owner's decision, made
before step 3; without it, iPhone notifications come with the next sync.

### Steps

One pull request each, smaller ones together:

1. Notifications for the group's events in both phone apps, with a setting each. Done on
   both phones (docs/apps.md, Notifications).
2. The watch apps (watchOS, then Wear OS): the events and the away switch. Done on both
   (docs/apps.md, Apple Watch and Wear OS).
3. The `watch` role and its admin key: the records' rules and limits in Go, Rust, Swift and
   Kotlin, the interop vectors, certifying a watch from the root phone; the signed command
   that turns sync away from home off on a member.
4. Emergency actions on the watch, and the quick actions of item 27.
5. If the owner agrees, prompt iPhone notifications through an encrypted Apple push.

Not yet verified on a real watch: the Secure Enclave key on the watch, WatchConnectivity
waking the phone app in the background long enough to send a record, the Data Layer
starting the Android app's listener for the Wear OS switch, and the delay of notifications.

## Quick actions

Planned for 0.6, after remote paste (item 18), whose signed commands and opt-in it reuses.

One button runs an action on a member: in the phone apps, on the watch (item 26), or with
`cbb run <device> <action>`. Running commands on another machine is the most dangerous thing
the group could do, so the rule is that **the network never carries a command**: every
action is defined on the member that runs it, and the button sends only its name.

### Presets and the user's own

- **Presets**: lock the screen, sleep, reboot, shut down, cancel a pending shutdown, restart
  the service. Each is off until the device's own user turns it on, as with remote paste
  (D-59).
- **The user's own**: added on the device itself, with a name and a command line,
  `cbb action add <name> -- <command>` or in the settings of the Mac and Windows apps. The
  command takes no arguments from the network, so nothing a sender writes reaches a shell.
  It runs as the desktop user; an action that needs root, like reboot, gets exactly that
  right when it is added (a sudoers or polkit rule on Linux, the matching rights on a Mac and
  on Windows), after a prompt that lists what it grants, as the firewall prompt does.
- The member lists its actions in its hello, so the apps and the watch show them as buttons.
  A preset may ask for a second tap (reboot, shut down).

### Checks on the member

The command is signed by the sender's admin key and checked by the member, as a remote paste
is: the action exists and is on, the signer is an admin that is neither removed nor frozen,
the signer's kind is allowed for that action (each action lists the kinds that may run it:
the root, admin phones, watches, admin computers; all admins by default), and the command is
fresh and not a replay. The member answers with the exit status only; it sends output back
only for an action whose user allowed that. Any admin turns quick actions off on any member
with a signed command, and the member logs every action it runs and who asked.

### Where

Linux, Mac and Windows run actions; lite members run the presets reboot and restart the
service (the ESP32 restarts); the phones send only, since iOS runs nothing for another
device and Android would need more rights than the app should hold.

### Steps

1. Actions on the computers: the presets, `cbb action`, the rights prompt, the signed
   command and its checks in Go, with interop vectors for Rust, Swift and Kotlin.
2. The buttons in the phone apps and `cbb run`.
3. The presets on the lite member.
4. The buttons on the watch (item 26, step 4).

## The phone as the hub

Planned for 0.5; steps 1 to 4 are done. The design, and the other cases of a group without a
working hub, are in [design.md](design.md#the-phone-as-the-hub-while-its-app-is-open-planned-for-05) (D-64).

Everyone has a phone; not everyone has a computer. A group made on a phone gets a hub at once,
the phone itself, which works while its app is open; a computer that is always on is the
better hub, so the app suggests it when there is one, and the user decides.

### Steps

1. Done: the hub's side in `mobile/cbbtun` (`StartHub`, `Register`): the clients' tunnels,
   the member port leading to the kit's member listener, and the registration with the
   forwarder and its hellos by the phone's member key, which the forwarder takes when the
   group's records make that key the root's or an admin's (docs/protocol.md, section 13);
   tested with the Go client through a forwarder.
2. Done: the listening member in both kits (`MemberListener`, on the loopback address for
   the tunnel or on every address for the home network) and the hub's part of the member
   protocol (`PhoneHub`, MemberNode's `hub`): it admits a client by the tunnel key its hello
   offers, by the rules of a computer's hub, and answers with its offer; tested over member
   TLS in the Kotlin kit and over a pipe in the Swift kit.
3. Done: the phone hub in both apps: on by default in a group made on a phone, `StartHub`
   with the member listener's port, `Register` with the forwarder set in Settings and the
   group's authority records, its status on Home and in Settings, publishing of the member
   port (`r=phone`) on the home networks the phone remembers, and on Android the option to
   keep it running in the foreground service. Still to do on the bench: a computer and the
   lite member through the forwarder to a phone.
4. Done: clients for a hub that comes and goes: a hub whose device record says `phone` is
   tried at least every 5 s instead of up to 30 s, in `cbb`, the lite member and both apps.
   Still to measure on real phones: the battery cost and the forwarder's load.
5. Remote invitations made and served on the phone (step 7 of the order of work in
   [design.md](design.md#order-of-work)), so that a device far away, such as a parent's TV,
   joins.
6. Moving the hub: the suggestion when a computer that is always on joins, the old hub
   passing its clients' keys to the new one and its offer to the clients; and the hub moving
   with an admin phone's takeover.
7. Several hubs with a priority (D-65, in the plan for 0.5): the hubs' list in the group,
   the clients keeping every hub's offer, the hubs passing each other the clients' keys,
   the lower hub yielding to the higher one, and tests of switching both ways.

Not yet verified on real devices: how long iOS keeps the forwarder registration and the
tunnel up while the app is open and the screen locks, the battery cost of the clients'
retries, and the Android foreground service as a hub across battery savers.

### Research: the iPhone hub in a Network Extension

To research in 0.6, no release chosen. Today the iPhone is the hub only while its app is open; iOS
suspends the app soon after it leaves the screen. Android can keep the hub running in the
foreground service, at a battery cost. The one way known for the iPhone is to run the hub as
a Network Extension, a packet tunnel provider, a separate process that iOS keeps running
while the tunnel is on. What the hub needs fits it on paper: an outgoing registration with
the forwarder, WireGuard for the clients (the WireGuard app runs wireguard-go the same way),
and member connections; it needs no clipboard. Questions to answer before any work:

1. Whether it works: whether the extension may run cbbtun's hub (WireGuard, gVisor's
   netstack, the registration) and the kit's member node within its memory limit (about
   50 MB), reach the member key in the keychain (a shared access group) and the group's
   state (an App Group), and route nothing of the phone's own traffic (only the tunnel's
   prefix, or none). Also whether it may listen on the home network and publish itself by
   Bonjour, or serves only through the forwarder.
2. iOS allows one VPN at a time: a user who keeps another VPN on, common where a VPN is needed
   to reach the internet, cannot run both. Check what happens when the other one starts, and
   say it in the app.
3. Apple's rules: the App Review Guidelines (section 5.4) allow VPN apps only through
   NEVPNManager and, as we read them, only from developers enrolled as an organization, with
   a clear account of what data the app sees; background use must be for the stated purpose
   (2.5.4). Check the current text, whether the owner's developer account qualifies, and
   whether review accepts a tunnel that carries only the group's own sync.
4. The cost: the battery with the extension always on, measured on a real iPhone, against the
   hub moving to a computer that is always on (step 6 above).

The answers decide whether this becomes a step of the plan, an option the user turns on, or
is dropped in favour of a computer or a second hub (D-65).

## Secure updates

Proposed for 0.6. Today a release has `SHA256SUMS` and GitHub's build provenance attestation:
`get.sh` checks the sums, which come from the same place as the archives, and checks the
attestation only with `gh` and `CBB_ATTESTATION=require`. Nothing updates by itself, and
nothing pins who may sign a release. The aim is that a program updates only to a release the
project signed, from whichever server, and that a server, the network or a stolen GitHub
token cannot slip in another build or an older one.

### The signed manifest

- Each release gets `release.json`: the version, the date, an expiry date, the channel
  (stable or beta), the lowest version that may update to it directly, and the SHA-256 and
  size of every file. It is signed with the project's **release key**. The signature uses
  Ed25519, or P-256 if the key is kept in the Secure Enclave of the owner's Mac.
- The programs pin the release key's public half. `release.json` may name the next key,
  signed by the current one, so the key can be changed without a manual reinstall. A lost
  key needs a release installed by hand, and the documentation says so.
- **The key never sits in CI.** The release workflow builds the files and their sums and
  stops. The owner signs `release.json` on the Mac (`tools/release-sign`, one command after
  the tag), and the workflow publishes it. A stolen GitHub token can then publish files but
  not a manifest that any program accepts. The build attestation stays as a second,
  independent check.
- The check refuses a manifest whose signature fails, one whose expiry date has passed (so a
  mirror cannot freeze a device on an old release), a version lower than the installed one
  (rollback), and a file whose SHA-256 differs.

### Where updates come from

- `https://cbb.tools/releases/` mirrors each release: the same files and the same signed
  manifest, copied by the release workflow. Programs try cbb.tools first and GitHub second;
  a setting names another mirror or turns the check off. Since the signature is checked, the
  mirror is not trusted.
- An update check tells the server the device's address, its system and its version. It is
  at most once a day, sends no group data and works with sync away from home off. The
  documentation says so, and the check can be turned off.
- The service's egress limit (D-61) allows only the group's servers, so the service never
  downloads updates itself. `cbb update` runs as its own short-lived process, from a timer
  (systemd, launchd, a Windows scheduled task) or by hand, with only the update servers
  allowed.

### Per platform

- **Linux, macOS and Windows from `get.sh`/`get.ps1`:** `cbb update` (`-check` only reports)
  downloads the archive, checks the manifest and the sums, swaps the binaries atomically,
  restarts the service and the agent, and puts the previous binaries back if the new service
  does not report healthy within a minute. Off by default: the installers ask "update
  automatically?" as they ask about the firewall, and `cbb update -auto on|off` changes it
  later.
- **Homebrew, winget, Docker and distribution packages:** these update through their own
  tool. `cbb update` sees how it was installed and prints the command (`brew upgrade`,
  `winget upgrade`, `docker compose pull`) instead of replacing files. The release workflow
  already publishes the formula and the winget manifest from the same sums.
- **Windows:** the files are also Authenticode-signed when the certificate is in the
  secrets, and `cbb update` checks that signature too when the installed copy has one.
- **The tray app** checks with the service and shows "update available" with a button that
  runs `cbb update` through UAC or pkexec, like its other admin actions.
- **The Mac app:** Sparkle with its EdDSA signature, once the app is signed and notarized
  (waits for the Apple developer account), with the same manifest feeding the appcast.
- **The lite member on Linux:** `cbb update` the same way, for its own archive.
- **The Nano ESP32:** OTA into the second app partition, checked against the manifest and
  the release key in the firmware, with a fallback to the old partition if the new one does
  not boot. Later, with the firmware's sync (item 15).
- **Android, sideloaded APK:** the app checks the manifest, downloads the APK, checks its
  SHA-256 and that its signing certificate matches the installed app's, and hands it to
  `PackageInstaller`. On Android 12 and later an app that installed itself can update
  without asking each time (`setRequireUserAction`), and the user turns that on in settings.
  Installed from a store, the app leaves updates to the store.
- **iPhone and the watches:** only the App Store and TestFlight update them; the app shows
  that a newer version exists.

### In the group

- Each device's hello already carries its version. `cbb status` and the apps mark devices that
  run an older version than the newest one any member has seen.
- Later: an admin asks a member to update with a signed command, like `mode` (protocol
  section 15). The member still installs only a signed release and only if its own user
  allowed automatic updates.

### Steps

1. The manifest, the release key and `tools/release-sign`; the release workflow publishes
   the manifest and mirrors to cbb.tools; `get.sh` and `get.ps1` check the manifest.
2. `cbb update` and `-check` on Linux, macOS and Windows: download, check, swap, restart and
   roll back; detection of Homebrew, winget, Docker and packages; tests with a tampered
   file, a bad signature, an expired manifest and an older version.
3. Automatic updates: the installers' question, the timers, `cbb update -auto`.
4. The tray app and `cbb status`.
5. The Android app's own update for the sideloaded APK.
6. The lite member, then OTA on the Nano ESP32.
7. Sparkle in the Mac app, after the Apple account.
8. On the bench: an update from the previous release on every device (L9), a refused
   downgrade and a refused unsigned build.

## Key levels

Planned for 0.6 (D-66). The owner's rule: the root, the admins and the hub hold keys in
hardware. A key in hardware cannot be copied, even from a device that is broken into; it
can only be misused on that device while the attacker holds it. A key in a file can be
copied once and used anywhere, for as long as nobody removes the device.

The user picks one of three levels for the group, at its root:

1. **Proven hardware only.** A device may be the root, an admin or a hub only when
   attestation proves its key is in hardware: Android's Key Attestation, a TPM with its
   maker's certificate, the iPhone through App Attest. This asks outside servers, and the
   guide says which: Apple's for each iPhone that makes a key, Google's public list of
   revoked attestation keys, and for some TPMs their maker's server. The public lists are
   mirrored on cbb.tools, signed like the releases (item 29), so the devices ask only us;
   the per-device requests (Apple, the TPM makers) cannot be mirrored. This level is the
   one exception to D-47, and only for a group whose user chose it.
2. **Hardware (the default).** The device's own word that its key is in hardware: the
   phones, a Mac's Secure Enclave, a TPM without its maker's certificate. Nothing about the
   device leaves the group, which is why it is the default (D-47).
3. **Files allowed.** A device whose key is in a file may also be an admin or the hub, each
   time after the user allows it, with a warning that the key can be copied and must be
   watched. A group of computers only, while they have no TPM or Secure Enclave support
   (D-44), works only at this level.

- A device that shows signs of being broken into (a jailbreak or root, an unlocked
  bootloader, a Keystore in software, which attestation reports) counts as a key in a file,
  and the devices list marks it.
- Groups made before 0.6 keep working; one whose root or admins hold keys in files shows a
  warning and suggests moving the root to a phone.
- The guide "Keys and attestation" (docs/guide) says all of this plainly.

## What the servers learn

Planned for 0.6 (D-67). A forwarder and a relay now see the group's authority records,
which name the root's and the admins' devices with their names, systems and dates, and the
removals with who made them and when. Signed records cannot be cut, so the servers get
credentials made for them instead, signed with the group's keys:

- **The hubs' credential**, signed by the root (the several hubs' table, D-65): the group
  tag, a version, an expiry, and the hubs' member key hashes with their priority. The
  forwarder keeps only the newest version of each group and refuses older ones; a hub
  removed is left out of the next version. The hub's TLS to the forwarder presents a
  certificate without its device ID.
- **The members' credential**, for a relay: the group tag, a version, an expiry and the
  members' key hashes, signed by the root or an admin the hubs' credential lists. Tunnel
  addresses on a relay come from a key the group keeps, not from the device ID, so the
  relay sees pseudonyms only.
- Roots after a takeover: the chain from the old root to the new, without the device that
  took over.
- What stays: the group tag and root certificate, key hashes (stable pseudonyms), how many
  hubs or members there are, addresses, timing and sizes.
- Face ID is asked only when the credentials change (a device admitted or removed, a hub
  set) and once per expiry. Inside the group cbb keeps using the full records.

### Research for 0.6: what is left to hide

To research in 0.6, with the credentials above and the several hubs (D-65). Even with them,
the servers see something. From the most to the least revealing:

1. the addresses of the hub and its clients, the times they are online, and the volume;
2. a stable pseudonym per device (its key hash);
3. the group tag;
4. how many devices there are;
5. when the root changes (a takeover);
6. the root certificate.

Proposals to study:

- **No logs on cbb.tools**: the forwarder and the relay we run keep no logs and no
  addresses on disk; say so in the docs, and check it on the test bench.
- **The address**: document that a system VPN hides the user's address from cbb.tools;
  maybe a setting to reach cbb.tools through a proxy or a VPN of the user's choice.
- **The hub's online times**: optionally keep the hub registered all the time, so its
  hours are not seen. On Android in the foreground service, at a battery cost; on the
  iPhone only as a Network Extension (item 33, "Research: the iPhone hub in a Network
  Extension").
- **Rotating pseudonyms**: new device pseudonyms and a new group tag with each renewal of
  the credentials (about every 30 days), derived from a group secret the servers do not
  know. Today the forwarder sees the hub's member key, which never changes, so this needs
  a separate short-lived key for the servers, signed by the root.
- **Padding**: the credentials' lists padded to 4, 8 or 16 entries, so the count of
  devices shows only roughly.

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
