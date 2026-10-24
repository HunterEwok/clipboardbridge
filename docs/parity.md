<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Platform parity

Devices of one class can do the same things. A difference is allowed only where the
system itself forces it, and then it is written here with the reason. The classes:

- **Computers**: Linux, macOS, Windows (`cbb`).
- **Phones**: Android, iPhone (the apps).
- **Lite devices**: the lite member (`cbb` in Rust) on small Linux devices, the ESP32 firmware, the ZX Spectrum
  Next through its Pi.

A feature added to one platform is planned for its whole class in the same task, or added
here as a gap. This table is kept up to date with every such change.

Marks: **yes**; **OS** (differs because the system forces it; the reason follows);
**gap** (missing for no system reason; the plan below closes it); **planned** (missing
on every platform of the class, on the roadmap).

## Computers

| Capability | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| Service, agent, autostart | yes | yes | yes | systemd and desktop autostart; LaunchDaemon and LaunchAgent; Windows service and the sign-in entry |
| Every `cbb` command (pair, revoke, admin, freeze, takeover, invite, global, holder, copy, paste) | yes | yes | yes | one program; the service is the same code |
| Secrets from password managers | yes | yes | yes | X11/Wayland hint, `ConcealedType`, the Windows clipboard formats |
| Battery detection | yes | yes | yes | |
| Installer and uninstaller, `--purge` | yes | yes | yes | |
| One-line installer with checksum check | yes (`get.sh`) | yes (`get.sh`) | yes (`get.ps1`) | |
| Package manager | Homebrew | Homebrew | **gap** | Windows: winget (G4) |
| Member port other than 8764 | yes (`--port`) | yes (`--port`) | yes (`-Port`) | |
| Inbound only from the home network, in the program | yes | yes | yes | the member port drops other addresses |
| Inbound only from the home network, by the system | yes (ufw, firewalld) | **OS** | yes (Windows Firewall) | the macOS application firewall allows or blocks a program, not an address; a Network Extension of the Mac app (roadmap item 22) |
| Outbound only to the home network until `cbb global on`, in the program | yes | yes | yes | `internal/netguard` |
| Outbound only to the home network until `cbb global on`, by the system | yes (systemd unit) | **OS** | yes (firewall rule) | as above, roadmap item 22 |
| Firewall left alone on request | `--no-firewall`, `CBB_FIREWALL=no` | `CBB_FIREWALL=no` | `-NoFirewall`, `CBB_FIREWALL=no` | `get.sh --no-firewall` works on both |
| Error details switch in `cbb` | `CBB_DEBUG=1`, debug builds | same | same | |
| Error details switch in the installers | yes (`CBB_ERROR_DETAILS=1`) | yes (`CBB_ERROR_DETAILS=1`) | yes (`-Details`, `CBB_ERROR_DETAILS=1`) | |
| Text-console helper (tmux) | yes (`--console`) | **OS** | **OS** | for a Linux machine without a desktop; a Mac and a Windows PC always have one |
| Removal from the system's app list | — | **OS** | yes (Settings, Apps) | Linux has no common list; the Mac app (item 22) brings it to macOS |
| Signed program | — | planned (`.pkg`, Developer ID) | **gap** | Windows Authenticode signing (G5) |
| Device keys in hardware | planned | planned | planned | roadmap item 13 |
| Firewall rules only with the user's consent, listed one by one; `--express` without questions | **gap** | **gap** | **gap** | today the installers add the rules without asking (G6) |
| Opening the hub's UDP port in the firewall | no | no | no | the same everywhere: the user opens it today (G6) |
| Finding a firewall the installer does not know, by a check from home | **gap** | **gap** | **gap** | G6 |
| Tested on a real device | yes | yes | not yet | the 0.4 bench |

## Phones

| Capability | Android | iPhone | Notes |
|---|---|---|---|
| Make a group, root key in hardware behind biometrics | yes | yes | StrongBox or TEE; Secure Enclave |
| Add a computer or a lite device by QR code | yes | yes | |
| Join another phone's group | yes | yes | |
| Make an admin, remove, take over from a lost root, renew certificates | yes | yes | |
| Make a computer an admin | yes | yes | |
| Sync away from home | yes, in the background | while the app runs | **OS**: iOS stops a background app's network |
| Receive copies without a tap | yes (foreground service) | **OS** | iOS lets an app read and write the clipboard only in the foreground |
| Send without a tap | yes (accessibility service) | **OS** | iOS: Back Tap or the Action button runs the app's shortcut, one gesture |
| Send from the share sheet and the text selection menu | yes | **gap** | a Share extension (P1) |
| One-tap control outside the app | Quick Settings tile, notification button | **gap** | a Control Center control, iOS 18 (P2) |
| Home-screen widget | **gap** | **gap** | in the app specification; neither has it (P3) |
| Rename a device | **gap** | **gap** | in the app specification; neither has it (P4) |
| Error details switch without developer tools | **gap** | **gap** | only `adb` or an Xcode launch argument today (P5) |
| Wallpaper colours theme | yes | **OS** | Material You exists only on Android |
| Remote invitations, remote paste, images and files | planned | planned | roadmap items 12, 18, 20 |
| Tested on a real phone | not yet | not yet | |

## Lite devices

| Capability | Lite member on Linux | ESP32 | ZX Spectrum Next | Notes |
|---|---|---|---|---|
| Join by the phone's QR code or a computer's code | yes | yes (pairing; on Linux over TAP in CI) | yes, through the Pi | |
| Sync the clipboard | yes | not yet | yes, through the Pi | the firmware's sync is the next step of roadmap item 15 |
| Listen for phones and Macs | yes | not yet | through the Pi | |
| Secrets (`copy -secret`) | yes | not yet | **gap** | the dot command could mark a copy secret (L1) |
| Sync away from home | planned | planned | planned | |
| Error details switch | yes (`-debug`, `CBB_DEBUG=1`) | not yet | yes (`.cbb -d`) | |

The ESP32 and the Next are still being built, so "not yet" is progress, not a gap: each
item is on its road to the Linux lite member's set.

## Plan

One pull request each, in this order; anything under 100 lines rides in the open one.

1. **G1**, done: `--port` in the Mac installer and `get.sh` on a Mac, kept in
   `/etc/clipboardbridge/clipboardbridge.env` as on Linux.
2. **G2**, done: `CBB_ERROR_DETAILS=1` in `install.sh`, `uninstall.sh` and `get.sh` on Linux
   and macOS shows every command as it runs; without it a failure names its exit status.
3. **P5**: an error details switch in both apps' Settings, hidden behind a few taps on the
   version, besides the developer launch arguments.
4. **P4**: rename a device in both apps (and `cbb rename` on computers), a signed record.
5. **P1, P2**: the iPhone's Share extension and Control Center control.
6. **P3**: a home-screen widget in both apps.
7. **G4, G5**: a winget manifest and Authenticode signing for Windows (signing needs a
   certificate; the manifest does not).
8. **G6**, decided by the owner: the firewall rules only with consent, the same on every
   computer. The installer finds the firewall itself (ufw, firewalld, nftables, iptables on
   Linux; Windows Firewall; the macOS application firewall), lists each rule it needs
   (protocol, port, source, purpose) and asks `Add these rules now? [y/N]`. Yes: `cbb`
   manages its rules from then on, the hub's UDP port at `cbb global hub` included (asked
   again, since it faces the internet), and removes them on uninstall. No: it prints the
   exact commands for that firewall and works while the rules are there. `--express` adds
   them without a question and prints the same list as a report. A member at home dials
   the computer back, so `cbb status` says when an unknown firewall or a closed rule keeps
   the others out. Messages are formal English, one fact per line.
9. **L1**: `.cbb copy -s`, a secret from the Next.
10. Roadmap item 22, the Mac app: the system's limits on a Mac (in and out), removal
    from the system, the signed `.pkg`.
