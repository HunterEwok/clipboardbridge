<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Devices, ports and files

What each kind of device can do, which ports Clipboard Bridge uses, and where it keeps its
files. For developers, the full comparison with its reasons is in
[Platform parity](../parity.md).

## What each device can do

"Computers" are Linux, Windows and FreeBSD, and routers with OpenWrt or OPNsense, which run
the same full member without a desktop.

| | Computers | Mac | Android | iPhone | Lite member |
|---|---|---|---|---|---|
| Sync the clipboard at home | yes | yes | yes | yes, with one gesture | yes (`cbb copy`, `paste`, `watch`) |
| Gets copies without a tap | yes | yes | yes | no: iOS allows it only in front | yes |
| Sends copies without a tap | yes | yes | with the accessibility service | no: one gesture | yes |
| Images and files | yes, on a desktop | yes | yes | yes, while the app runs | no: it passes them on and takes their text |
| Hold the group (root) | yes, [without the app](../guide/without-app.md) | yes | yes | yes | no |
| Be an admin | yes | yes | yes | yes | no |
| Be the hub | yes | not yet | while the app is open | while the app is open | no |
| Sync away from home | yes | yes | yes, also in the background | while the app is open | yes, plain WireGuard only; not on MIPS routers |
| AmneziaWG and VLESS | yes | yes | yes | yes | no |
| Join from afar by an invitation | yes | yes | not yet | not yet | no |
| Use a blind relay | yes | yes | yes | yes | no |
| Take remote paste | yes: X11, Wayland, GNOME and KDE, Windows, tmux, the text console | through the Mac app | yes, with the accessibility service | no: iOS allows no app to type into another | yes: tmux, the text console |
| Take quick actions | yes, the presets and your own | yes | no | no | `reboot`, `cancel-shutdown`, `restart` |
| Device keys | in the TPM on Linux when there is one, else in files | in files | in the security chip | in the Secure Enclave | in files |

Items that password managers mark as secret are not synced automatically. Each remote paste
target and each quick action is off until the device's own user turns it on.

## Ports

| Port | Who listens | From where | What for |
|---|---|---|---|
| TCP 8764 | every computer and lite member | the home network | the devices' connections |
| UDP 5353 | every device | the home network | mDNS, to find each other |
| UDP 8764 | the hub | the internet | the group's tunnel, with a router port forward |
| UDP and TCP 8764 | a forwarder or a relay | the internet | [your own servers](../admin/self-hosting.md) |
| TCP 443 | a forwarder with VLESS | the internet | VLESS with REALITY |

The member port can be changed when installing (`--port`, [settings](config.md)). The installers ask before they
open any of these ([the firewall](../guide/install.md#the-firewall)).

## Files and logs

| System | Keys and state | Settings | Log |
|---|---|---|---|
| Linux | `/var/lib/clipboardbridge` | `/etc/clipboardbridge` | `journalctl -u clipboardbridge`; the desktop connector in `journalctl --user` |
| FreeBSD, OPNsense | `/var/db/clipboardbridge` | `/usr/local/etc/clipboardbridge` | syslog, `/var/log/messages` |
| OpenWrt | `/etc/clipboardbridge/state`, kept by sysupgrade | `/etc/config/clipboardbridge` | `logread -e clipboardbridge` |
| Mac | `/Library/Application Support/clipboardbridge/state` | `/etc/clipboardbridge` | `/Library/Logs/clipboardbridge/service.log` |
| Windows | `ProgramData\clipboardbridge` | the service's registry key | `ProgramData\clipboardbridge\logs\service.log`, the agent's `LocalAppData\clipboardbridge\agent.log` |
| Lite member | `/var/lib/clipboardbridge` | `/etc/clipboardbridge` | `journalctl -u clipboardbridge` |

Keep the keys out of unencrypted backups, and encrypt the disk (LUKS, FileVault,
BitLocker): whoever copies them can act as that device until you remove it from the group.
