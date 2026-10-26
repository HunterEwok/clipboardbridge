<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The hardware test bench

The plan for testing Clipboard Bridge on real devices before each release, starting with 0.4,
and how the bench that runs it is built. The bench lives in `tools/bench` (being built, see
"Order of work" at the end); this document is its specification. CI and its jobs are in
[maintaining.md](maintaining.md#ci).

## 1. Goal

Before 0.4 is released, an automated bench of the maintainer's real devices runs every case that
matters to users and reports pass or fail with logs, with no person copying text by hand.
The same bench then runs before every later release.

CI already covers a lot in containers and on hosted runners (unit tests with `-race`, the
Docker e2e of three members, Wayland and X11 under headless compositors, the Windows
installer on windows-latest, the cross tests between Go, Swift and Kotlin, the lite member among
Go members). The bench covers what CI cannot:

- real hardware and real operating systems: ARMv6 Pi Zero W, Pi 4, Steam Deck, an Apple
  Silicon Mac, Windows 11 on ARM, an Android phone;
- the real desktop clipboards in a signed-in session (GNOME on the Deck, the macOS
  pasteboard, the Win32 clipboard), not only the service's own store;
- a real home network: Wi-Fi, mDNS on the router, two subnets, firewalls the installers
  configure;
- the real internet path: the hub's WireGuard tunnel from outside the home, the relay
  server (forwarder), NAT, IPv4 and IPv6;
- long runs, reboots, sleep, network loss and upgrades from the previous release.

## 2. Scope

In scope for 0.4:

| Area | What is tested |
|---|---|
| Install, update, remove | `get.sh`/`install.sh`/`uninstall.sh` on Linux and macOS (and Homebrew on macOS), `get.ps1`/`install.ps1`/`uninstall.ps1` on Windows, `get.sh --lite` for the lite member, which moves an old `cbb-lite` install to `cbb`; update from 0.3.x; firewall rules added and removed; `--purge` |
| Group and pairing | `cbb pair` / `cbb pair -code` (with and without an address), `cbb join -code` on the lite member, joining by QR from the Android app, wrong code, expired code, revoke, renewal, admin computers |
| Sync on the home network | every sender to every receiver, every content class (section 6), ordering and conflicts, `copy -secret` and its 60 s expiry, the holder of `clipboardbridge.local` and its handover |
| Between subnets | the main LAN and the IoT subnet (Pi Zero W): mDNS does not cross, so `-peer` / addresses and, later, the tunnel |
| Sync away from home | `cbb global hub`, `cbb global on/off`, `cbb invite` / `cbb pair -invite`, a device on another network (mobile data), reconnect, roaming |
| The relay server (forwarder) | `cbb forward` on the relay, the hub registered with `cbb global hub -forwarder ADDR:PORT -forwarder-key KEY`: registration by certificate chain, routing by `mac1`, per-group limits, the computed hourly fallback port (once built), isolation of groups, nothing written to disk or logged |
| Failure cases | section 8 |
| Security | section 9 (top priority for everything off the home network) |
| Debug/release error details | each tested error shows the user message; with `CBB_DEBUG=1` the underlying error too; the log always has it |

Out of scope for 0.4: the iPhone app and the shortcut (paused until the Apple developer
account; the Swift kit stays covered by CI), the ESP32 firmware, the ZX Spectrum Next and
the Arduino, app store and TestFlight builds, performance beyond the limits in section 10.

## 3. Devices under test

| Name | Hardware / OS | Network | Role on the bench |
|---|---|---|---|
| `pi4` | Raspberry Pi 4, Debian arm64, headless | home network | **the bench controller** (section 11); not a device under test, but the host of `nas` |
| `nas` | the Docker image on `pi4` (`linux/arm64`), from `packaging/docker/compose.home.yaml` | home network (the host's) | an ordinary member in a container, as on a NAS or a home server (P35); never the root or an admin, since the CA keys stay off a container; no desktop clipboard |
| `rpi0w` | Pi Zero W, Raspberry Pi OS armv6l, Wi-Fi only, no keyboard | a second subnet (IoT) | the lite member; cross-subnet case; must never lose Wi-Fi from a test |
| `deck` | Steam Deck, Ubuntu, GNOME (Wayland), ufw | LAN, or the router's away network | the Linux member: the root in layout A, the hub, the real desktop clipboard (through XWayland, as `cbb agent` uses it on GNOME); also the away device (plugged in, sleep off) |
| `mac` | MacBook, Apple Silicon | LAN | macOS member and agent; host of the Windows VM |
| `win` | Windows 11 ARM in VMware Fusion on the Mac | LAN, bridged | Windows service and `cbbw.exe` agent, `windows/arm64` build; reverted to a clean snapshot before each run |
| `phone` | Android emulator on the Mac (arm64 image); no real phone | the emulator's own NAT | Android app: root of a phone group, sync; limited, see below |
| `vps` | a VPS, Linux, public address | internet | a headless Linux member away from home: no NAT, public IPv4/IPv6; also covers `cbb copy`/`paste` without a desktop |
| `relay` | a VPS, Ubuntu, public IPv4 and IPv6 | internet | the project's production forwarder (`cbb forward`); packet capture point; never a group member |

The emulator sits behind its own NAT: it reaches LAN addresses but sees no mDNS from the
home network and takes no incoming connections without port forwarding, and its camera
scans a QR code only from an injected image. The bench tests what works there (the app,
pairing with an injected QR image, sync with members it dials by address); what needs a
real phone (mDNS discovery, the foreground service on a real battery saver, the
accessibility overlay) stays in the README's status table as "not yet" until there is one.

Two group layouts are tested, because both exist for users:

- **A. A computer's group**: `deck` runs `cbb new` and is the root; the others join by
  code; `deck` makes `win` an admin (`cbb admin win`).
- **B. A phone's group** (needs `phone`): the Android app is the root; computers and
  `rpi0w` join by its QR code; `mac` becomes an admin.

## 4. Network environments

| ID | Environment | How the bench makes it |
|---|---|---|
| N1 | One LAN, mDNS works | the home network as it is |
| N2 | Two subnets (LAN + IoT) | the existing IoT subnet; the bench switches the OpenWrt firewall rules between them (open, LAN to IoT only, closed) |
| N3 | Away: one device on a different network | a separate network on the OpenWrt router (its own VLAN, Wi-Fi name and subnet, internet only, no route to the LAN or IoT); the bench moves `deck` there and back. The second VPS (`vps`) is an away computer with a public address and no NAT |
| N4 | Away through the relay | as N3, with the hub reachable only through the forwarder |
| N5 | Bad network | `tc netem` on the Linux devices: latency, loss, reordering, bandwidth limit; always with an automatic revert timer |
| N6 | Network gone | firewall rules that drop the member port or the tunnel port for a time, with an automatic revert; no Wi-Fi switching on `rpi0w` |
| N7 | IPv6 only / IPv4 only for the tunnel | address family chosen per run on the hub's `cbb global hub` addresses |

## 5. Test design

Every test case has an ID, a short statement of what must hold, its preconditions, the
devices and environment it runs on, and how the result is observed. Test cases are kept as
data (one YAML file per area) so the matrix is generated, not typed: `sync` cases are
expanded over sender x receiver x content class x environment.

The observation is always end to end, at the user's clipboard where one exists:

| Device | Put text in | Read text out |
|---|---|---|
| `vps` (headless) | `cbb copy` | `cbb paste` |
| `rpi0w` | `cbb copy` | `cbb watch -0` |
| `deck` | `xclip` on the GNOME session's XWayland | `xclip -o` on the same display |
| `mac` | `pbcopy` as the signed-in user | `pbpaste` |
| `win` | `Set-Clipboard` inside the signed-in session (a small bench helper started at sign-in; an SSH session cannot reach the desktop clipboard) | `Get-Clipboard` through the same helper |
| `phone` | the app's UI through UI Automator over `adb` (bench only; users never need `adb`) | the app's UI / the system clipboard as the app sees it |

Every case is written out step by step, with its preconditions and how to tell pass from
fail, in [testbench-cases.md](testbench-cases.md).

Each run writes a unique marker into every text (run ID, case ID, sender, time) so a stale
clipboard can never pass a test.

## 6. Test matrix: sync on the home network (N1)

Senders and receivers on the home network: `rpi0w`, `deck`, `mac`, `win`, `phone`; `vps` joins them in the away cases. Every ordered pair
that the protocol allows (20 pairs) runs the content classes:

| Class | Content |
|---|---|
| C1 | short ASCII |
| C2 | Cyrillic, emoji, combining marks, right-to-left text |
| C3 | multi-line with CRLF and LF, tabs, trailing spaces (line endings must arrive as sent; a Windows clipboard holds CR LF and a Windows member sends LF, see design.md, Windows) |
| C4 | empty text and whitespace only |
| C5 | the size limit exactly, and one byte over it (must be refused with a clear message) |
| C6 | `copy -secret`: arrives, is gone 60 s after the copy, never written to disk |
| C7 | ten copies in one second from one sender: the last one wins everywhere |
| C8 | two senders at the same moment: every device ends on the same text (HLC order) |

Expected: the text arrives byte for byte at every other member within 2 s on N1 (p95) and
the same text is on every device at the end.

## 7. Group, pairing and life-cycle cases

- Pair each kind of device into layout A; then layout B with the phone.
- Join with a wrong code (refused, the attempt counter works), with an expired code, twice
  with the same code.
- Revoke a device: it stops receiving within one sync round, cannot rejoin with its old
  keys, and its certificate is refused by every member including `rpi0w`.
- Renewal: certificates near expiry are renewed (the bench sets the clock forward on a
  disposable device, or uses a short test lifetime build).
- Admin: `mac` made an admin in layout B pairs and revokes; in layout A `win`, made an admin
  by `deck`, pairs a device, serves the shortcut while `deck` is off, and when `deck` removes
  it, `deck` replaces the iPhone CA and the shortcut iPhones pair again.
- Takeover in layout A: with `deck` off, `win` runs `cbb takeover deck`; `win` is the root,
  every other device stays and syncs, the shortcut iPhones pair again, `win` makes another
  admin, and `deck` is refused when it comes back.
- Removing a member that is no admin in layout A (a Linux one, a Windows one, the Mac): the
  group stays, nobody pairs again.
- The holder of `clipboardbridge.local` goes away; another member takes it over.
- Upgrade: every device on 0.3.x, then updated one by one to the 0.4 candidate; mixed
  versions keep syncing during the upgrade; state and keys survive. Then `cbb upgrade` on
  `deck` with `win` off: `deck` is the root, the others delete the old keys, `cbb status`
  marks `win` until it is back, `cbb revoke win` is refused until then, and nobody pairs
  again except the shortcut iPhones.
- Uninstall: no service, no firewall rule, no leftover files (except keys without
  `--purge`).

### Features and platforms

Every other way Clipboard Bridge works, so no path ships untested:

| ID | Case | Expected |
|---|---|---|
| P1 | Password managers: a copy marked secret by the app (macOS concealed type, Windows "exclude from history and cloud", the Wayland password hint) | travels as a secret (C6 rules) or not at all, as designed; never as plain text |
| P2 | Rich text from a browser and an office app; an image or a file copied | the plain text arrives; non-text content is ignored without an error |
| P3 | Clipboard history (Windows Win+V, the GNOME clipboard) and copy echo | a received text is not sent back; no ping-pong between two members |
| P4 | The Mac as a full member: the lite member and the emulator reach the Mac with no other computer on; the Mac and a Linux member connect whichever has the lower device ID, also with the Mac's application firewall on | sync works; one connection between each pair |
| P5 | The lite member's options: `-peer`, `-no-mdns`, `-no-listen`, `watch` | each works as `docs/reference/cli.md` says |
| P6 | Another port (`--port`, `CBB_PORT`) on every installer, and back to 8764 | members find each other; the old firewall rule is gone |
| P7 | Homebrew on the Mac, `install.sh --in-place`, `uninstall.sh` before `brew uninstall` | the agent runs Homebrew's binary, the service a root-owned copy of it; nothing is left |
| P8 | Text console: `install.sh --console` (tmux) on a Linux member | copy and paste work in tmux |
| P9 | The Windows service before sign-in, the agent after it; fast user switching on Windows and the Mac | the clipboard of the signed-in user only; no text reaches another user's session |
| P10 | A phone group (layout B in the emulator): QR join of a computer and of `rpi0w`, "Make it an admin" for the Mac, renewal | as on a real phone, within the emulator's limits (section 3) |
| P11 | Sync away from home: `cbb invite` from the hub, `cbb pair -invite`, `cbb global on/off`, a hub with only IPv6 or behind CGNAT | joins and syncs; `cbb global` explains what is missing |
| P12 | A blind relay for a group without a hub: `cbb relay -open` beside the forwarder, `cbb global relay` on two members | members meet through it; it sees only TLS between members |
| P13 | `cbb status` (with the devices list), `cbb revoke` by name and by ID, `cbb version` on every platform | the output matches the state |
| P14 | Downgrade from the 0.4 candidate to 0.3.x on each platform | the older version starts on the newer state or refuses with a clear message; no keys are lost |
| P15 | macOS: the Local Network permission refused and granted, Gatekeeper on the downloaded binary, the application firewall, Universal Clipboard from an iPhone or iPad signed in to the same Apple account | each state is explained by `cbb status`; Universal Clipboard text syncs once, without an echo; the report records whether the item arrived before a paste on the Mac and which types it carried |
| P16 | Windows: locked screen, sign-out and sign-in, SmartScreen on the installer, `get.ps1` installing the arm64 build on ARM | the service keeps syncing; the agent comes back after sign-in; the right architecture |
| P17 | Steam Deck: sleep and wake, Game Mode, the lock screen | reconnects within 30 s of wake; Game Mode and the lock screen are recorded as they behave |
| P18 | mDNS on the router: the avahi reflector on and off between the home network and the IoT subnet | with it off the lite member is reached by address, with it on by mDNS; both work |
| P19 | IPv6 on the home network: AAAA records, link-local and global addresses, an IPv6-only member | members find and reach each other over IPv6 |
| P20 | A network that blocks UDP (a hotel or an office) for an away device | as designed for the transports that exist (WireGuard over UDP fails with a clear message; the TCP transport when it exists) |
| P21 | Invitations: the admin answers `no`; `-for 24h` and one second past it; the hub off when the invitation is used | refused with a clear message each time; nothing is left on the hub |
| P22 | `cbb global off` then `on` on a client and on the hub; a forwarder restart | keys are forgotten and made again; hubs register again by themselves |
| P23 | macOS pasteboard privacy: the alert for pasting from other apps turned on by hand, then on macOS 27.2 with its defaults | the report records whether the agent's reading of the types asks the user; text keeps syncing |
| P24 | GNOME on the Steam Deck: a copy in a native Wayland app (GNOME Text Editor); a received text pasted into it without clicking any window; the same right after sign-in, before any X11 app has started XWayland | the copy arrives within the usual latency; the paste gives the received text |
| P25 | The Mac holds `clipboardbridge.local`: the other full members off or set to `cbb holder never` | `cbb status` on the Mac shows it holds the name; `avahi-resolve` on `deck` and `Resolve-DnsName` on `win` resolve it to the Mac |
| P26 | The Mac's application firewall set to "Block all incoming connections" | the Mac still finds the members and reaches them; whether they find and reach it is recorded |
| P27 | The phone apps' Glass design: each of the ten colours in dark, light and system; tiles, list and orbits; a device's page; an iPad and a foldable's inner screen | every device shows its icon, system and live dot; the details match `cbb status`; a phone's MAC address reads "hidden by the system" |
| P28 | The group's events on both phones: a device added, removed, made an admin, frozen and unfrozen, a takeover, the hub off while away; each switch off in turn | one notification per event, in its words, none for a switch that is off; nothing shows the clipboard |
| P29 | The Apple Watch with its iPhone: the devices, the away switch, the latest events; the phone out of reach | the watch follows the phone; the switch turns the phone's away mode; out of reach it says so |
| P30 | The Dynamic Island: adding a device, the phone away from home, a sync | the timer while adding, the shield while away, the result for a moment; never the copied text |
| P31 | The Mac app: the window and the menu bar item, send and fetch, each layout, rename, remove, freeze, unfreeze, make an admin and sync away from home after the password, the prompt cancelled, the service stopped, error details on and off | each action does what the same `cbb` command does; a cancelled prompt changes nothing and says nothing; a stopped service is explained, with the error underneath when details are on |
| P32 | The tray app on the Linux members (GNOME, KDE, the Steam Deck) and on Windows: the tray item and the window, send and fetch, each layout, the group's changes after pkexec or UAC, the prompt dismissed, the service stopped, error details on and off, Russian | as P31; the tray item shows on each desktop (GNOME needs the AppIndicator extension) |
| P33 | The Wear OS app with its Android phone: the devices, the away switch, the latest events; the phone out of reach; a phone without Google Play services | as P29; without Play services the phone app works as before |
| P34 | Sync modes: own, receive, send and shared on `deck` with `win`, then on the lite member, the container and the Mac; a restart; `cbb paste` in own; an admin's `cbb mode -on` | each mode lets through only what design.md says; the mode survives the restart and the others list it; in own `cbb paste` prints the group's text |
| P35 | A member in a container (`nas`): it joins the hub's group; its settings; its process killed, a restart and a new container from the same volume; then, by the owner's explicit choice, an admin with its keys in a file and the hub for `vps` | it runs unprivileged as compose.home.yaml sets it; the group, the mode and sync survive each restart; as the hub `vps` syncs through its tunnel with no `NET_ADMIN` |
| P36 | Several hubs: the root and an admin computer each with a hub set up, an away device; the root's hub stopped and started again | the admin serves while the root is gone and gives way when it is back; the away device follows both ways with no invitation and loses no copy |
| P37 | Moving the hub with `cbb global move`: to the lite member and to the container (refused), to an admin computer | the new hub serves with the old one's forwarder; the old one becomes its client; the away device follows without coming home |
| P38 | The open relay's limits: registrations from one address, a busy group, groups leaving | over a limit refused with a clear message; one busy group does not slow the others; a group is forgotten when its last device leaves |

Known limits of this bench: it has no Intel Mac (`darwin/amd64`), no x86-64 Windows
(`windows/amd64`) and no ARMv7 Linux; those builds are covered only by CI. The ARM64 Linux
build runs on the bench only in the container on the Pi 4 (`nas`). It has no real Android phone and no iPhone app
(section 3).


## 8. Failure cases

| ID | Case | Expected |
|---|---|---|
| F1 | Kill the service (`SIGKILL`) on each device | restarts by its service manager; catches up on the latest text |
| F2 | Reboot `deck`, `win`, `mac`; power cycle `rpi0w` (a manual step: the bench pauses and asks the maintainer to pull the plug) | comes back, rejoins without a person |
| F3 | Mac sleeps and wakes; the VM pauses and resumes | reconnects within 30 s of wake |
| F4 | 30% loss, 300 ms latency, reordering (N5) | texts arrive, no duplicates, no crash |
| F5 | Member port blocked for 5 minutes (N6) | texts copied meanwhile arrive after the block ends (latest wins) |
| F6 | Hub down while devices are away | away devices report it in `cbb global` and `cbb status`; nothing is sent another way |
| F7 | Relay down or unreachable | fallback port tried as designed; then a clear error; never a cleartext path |
| F8 | Clock skew of hours on one device | certificates still accepted within the protocol's margin; HLC order holds |
| F9 | Disk full on a Linux member | clear error, no corrupted state after space returns |
| F10 | Corrupted state file | the service refuses with a clear message and does not lose the group |
| F11 | Address change (DHCP lease, Wi-Fi to mobile data) | the device is found again; away devices roam without a new invitation |
| F12 | Error messages | each failure above shows a friendly message; with `CBB_DEBUG=1` the real error under it; the log has the details in both modes |

## 9. Security tests

Sync off the home network is the project's top priority: if one of these fails, 0.4 does
not ship the feature.

| ID | Test | Pass when |
|---|---|---|
| S1 | Capture all traffic on the relay and on the away device's uplink during a full sync run | only WireGuard UDP (and, later, the VLESS transport) to the hub or relay; no TLS ClientHello, SNI, DNS name of the group, clipboard bytes or tunnel addresses in the clear; the bench searches the capture for every run marker and fails on any hit |
| S2 | The same capture on the LAN | member traffic is TLS 1.3 only; no marker in the clear |
| S3 | Client isolation through the hub | an away client cannot reach another client's tunnel address or any address but the hub's member port (scan from inside the tunnel) |
| S4 | The hub's tunnel exposes only the member port | port scan of the hub's tunnel address: one open port |
| S5 | A key that is not in the group | handshake ignored; no response that tells the key is unknown |
| S6 | Revoked device, away | its tunnel key is dropped on the hub within one record round; it cannot sync or rejoin |
| S7 | Invitation file | used once only; refused after expiry; refused without the admin's `yes`; the fingerprint shown on both sides matches |
| S8 | Relay learns little | groups on the forwarder or the open relay cannot reach each other; neither writes anything to disk but its key (file system checked before and after a run) or keeps logs; registration needs a valid certificate chain and records that do not revoke the device |
| S9 | Fail closed | with the tunnel broken, an away device sends nothing to any other address (capture shows no fallback) |
| S10 | Secrets | `copy -secret` never reaches any disk on any device (search of the state directories and swap-free check on Linux) and is gone after 60 s |
| S11 | Local access | the control socket refuses a user outside the `clipboardbridge` group on Linux, macOS and Windows |
| S12 | Installers | firewall rules open only the member port (and mDNS) to the local subnet; the tunnel port only on the hub |
| S13 | Two groups on one network (two hubs, devices in each) | no text, record or device list crosses between the groups; neither can pair into the other without a code |
| S14 | A stranger on the home network: a device in no group dials the member port, replays a captured connection, tries codes | refused; the code attempt counter stops guessing; nothing is learned about the group |
| S15 | Logs | no clipboard text, code or key in any log on any device, in either error mode (`CBB_DEBUG=0` and `1`) |
| S16 | Files at rest | the state directories hold only keys and certificates with owner-only permissions; no clipboard text is written to disk on any device |
| S17 | Commands (`cbb mode -on`): from an admin, a frozen admin, with a clock out of range, replayed | only a valid admin's command, once, within its lifetime, is taken; each refusal is explained |

## 10. Long run

A soak run of 24 hours on N1 plus one away device: a copy every 30 s from a random device,
one F-case every hour. Pass when every text arrived, memory and file descriptors of each
service stay flat (sampled every 5 minutes), and no service restarted except by a test.

## 11. Automation

**The harness** is a Go program in the repository, `tools/bench`, so it follows the rest of
the code (one language for the service and the harness, `go test`-style reports). It reads
an inventory file (devices, addresses, how to reach each one) that lives only on the
controller, never in the repository.

**Reaching the devices**: SSH from the controller with keys only (`BatchMode`), as the user
signed in on each device's desktop, so the bench reaches the real clipboard: `wl-copy` and
`wl-paste` in the Wayland session, `pbcopy` and `pbpaste` on the Mac. On Windows an SSH
session cannot reach the desktop clipboard, so `tools/bench/setup-windows.ps1` turns on the
OpenSSH server and registers two scheduled tasks that run in the signed-in session and move
text between a file and the clipboard. Headless devices, the lite member too, use `cbb copy`
and `cbb paste`. The install and uninstall cases need `sudo` without a
password for the installers only, set up by a sudoers file in step 3; on the Mac the file also
allows `launchctl kill KILL` of the daemon, for F1. The emulator over
`adb` on the Mac.

**The controller** is the machine that runs the harness. It has to be on the LAN and always
on: `pi4`. It is never a device under test, so reboots and failures of
the others do not stop a run. It reaches the router over SSH to switch networks, the Mac
to start and revert the Windows VM and the emulator (`vmrun`, `emulator`, `adb`), and the
relay over SSH.

**Starting a run**:

- by hand on the controller (`go run ./tools/bench check`, `go run ./tools/bench smoke`,
  `go run ./tools/bench full`, later `security` and `soak`; `-report DIR` writes `report.xml` and `report.txt`,
  `-only a,b` limits the run to some devices);
- from GitHub: a self-hosted runner on the controller, started **only** by
  `workflow_dispatch` and by release tags, never by pull requests (a pull request from a
  stranger must never run code on the home network). The runner gets no repository
  secrets and runs as its own user without sudo.

**Building what is tested**: the bench takes the binaries from a CI run or a release
(artifacts with checksums and attestations), never builds on the devices, so it tests what
users get.

**Reports**: a JUnit XML file for GitHub's test summary, an HTML report with the matrix
(green and red cells), every failure's logs from all devices (`journalctl`, `log show`,
Windows event log, `logcat`) with `CBB_DEBUG=1`, and the packet captures of the security
suite. Reports stay on the controller, never in the public repository: they show the home network's addresses.

**Suites**:

| Suite | Contents | Time | When |
|---|---|---|---|
| smoke | the clocks, every device in no group, pair each one into the hub's group, one text from each device to every other | ~10 min | after each merge that touches the service, on request |
| full | sections 6 to 9; so far C1 to C5, C7 and C8 between every pair of members, F1 (the Mac's service is skipped: killing it needs the owner's password), and P35 for a member in a container | ~2 h | before each release candidate |
| security | section 9 with captures | ~30 min | before each release, after each change to the tunnel or relay |
| soak | section 10 | 24 h | before each release |

## 12. Entry and exit criteria

Entry (a run may start): every device in the inventory answers; the binaries under test
come from a green CI run (`ci-ok`); the relay runs the forwarder of the same commit; the
clocks are within 1 s (NTP).

Exit (0.4 may be released):

- smoke, full, security and soak suites pass on the release candidate;
- no open defect of severity 1 or 2; every severity-3 defect is in the CHANGELOG's known
  issues;
- every row of the README's status table marked "not yet" on real devices that the bench
  covers is updated;
- every security test (S1 to S16) passes; there are no exceptions for security.

Severity: 1, data leaves the device unprotected or a device that is not in the group gets
data; 2, sync stops or data is lost; 3, a wrong message, a slow path, a cosmetic fault.

## 13. Inventory

The controller keeps the bench's inventory in `~/.config/cbb-bench/inventory.toml`, outside
the repository: it names the home network's addresses and the keys. Its shape:

```toml
controller = "pi4"

[device.deck]
os = "linux"           # linux, linux-lite, darwin, windows, docker
ssh = "user@deck.lan"     # the user signed in on the desktop
clipboard = "wayland"  # wayland, x11, none (cbb copy and paste), macos, windows
roles = ["member", "hub", "away"]

[device.win]
os = "windows"
ssh = "user@win.lan"
clipboard = "windows"
vm = { host = "mac", vmx = "~/Virtual Machines.localized/win.vmwarevm", snapshot = "clean" }

[device.nas]
os = "docker"          # cbb in a container on the host ssh reaches
ssh = "user@pi4.lan"   # a user in the docker group
container = "clipboardbridge"  # the default, compose.home.yaml's name
roles = ["member"]     # never hub: that device makes the group and holds its keys

[router]
ssh = "root@router.lan"
kind = "openwrt"
away_network = "bench_away"   # the network the bench moves the away device to

[relay]
ssh = "root@relay.example.net"
```

A device with `os = "docker"` is the image running on a host: the bench calls `docker exec
-i CONTAINER cbb` there, as the image's user, and copies and pastes with `cbb copy` and `cbb
paste` (it has no desktop clipboard). `tools/bench/setup-docker.sh setup` prepares the host
once: Docker, the SSH user in the `docker` group, and for F1 the helper
`cbbbench-kill-container`, which that user may run as root without a password (the
container's process belongs to the image's user); `setup-docker.sh up CBB` starts a new
container of the build under test, and `down` removes it with its volume. `address` (`host:port`) on a device is where the others dial it to pair when mDNS cannot
find it; a lite member always joins at an address, which `cbb pair` prints.
`tools/bench/inventory.example.toml` is a complete example. Each device needs the
controller's SSH key for its desktop user; a Windows device also runs
`tools/bench/setup-windows.ps1` once. Devices on the bench are test devices: the bench installs and wipes Clipboard Bridge
on them as it needs.

## 14. Order of work

One pull request per step, merged in order:

1. This document and the inventory format.
2. `tools/bench`: the inventory, the SSH runner, a clipboard driver per platform, the
   report, the `check` and `smoke` suites on N1; the Windows setup script.
3. The full matrix (section 6), the life-cycle cases and the features and platforms (P1 to
   P33, section 7): installing and
   removing with the installers, the snapshot of the Windows VM, the emulator, the
   router's away network.
4. Failure cases (section 8) with the network tools and automatic reverts.
5. Away cases through the hub (N3, N7) and security tests S1 to S7, S9 to S16.
6. The relay: the VPS set up as the production relay (hardening, firewall, no logs) running
   `cbb forward`; S8 and N4.
7. The GitHub runner, the soak suite, the release checklist in `docs/maintaining.md`.
8. The 0.4 test run and its report.
