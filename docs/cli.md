<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Command reference

Every command of `cbb` (Linux, macOS, Windows) and `cbb-lite` (the lite member), with their
flags and environment variables. `cbb help` and `cbb-lite help` print the short form.
Commands other than `service`, `agent`, `desktop`, `version` and `help` talk to the running
service through its control socket, so they need the `clipboardbridge` group (Linux, Windows,
macOS) or root; `copy`, `paste` and `status` work for members of the group without `sudo`.

## cbb

| Command | What it does |
|---|---|
| `cbb copy [-secret]` | Sends standard input to the group, and to this device's own clipboard. `-secret` sends it as a secret: kept only in memory and gone 60 seconds after the copy. |
| `cbb paste` | Prints this device's clipboard text. |
| `cbb status` | This device, its group, sync away from home, and every device of the group: its system (Linux, Windows, macOS, iOS, Android), its role (`full`, `lite`, `phone`, `shortcut`), whether it is the root or an admin, when it was last seen and whether its clock is off. It also says whether this computer answers for `clipboardbridge.local`. |
| `cbb holder [auto\|first\|fallback\|never]` | Shows or sets whether this computer holds `clipboardbridge.local`, the name the iPhone shortcut reaches: `first`, only as a `fallback` when no computer set first is on, or `never`. `auto`, the default, picks `fallback` on a machine with a battery and `first` on any other. Only a computer with the group's iPhone key takes part. |
| `cbb revoke NAME` | Removes a device, by name or device ID. Runs on a device that holds the group's CA keys: a Linux member in a group that a computer created, or a computer the root phone made an admin. In a phone's group, remove devices in the app (Devices). |
| `cbb pair` | Admits a new computer: creates the group if there is none and shows a six-digit code for `cbb join -code` on the new computer. Same rule as `revoke` for who may run it. |
| `cbb pair -phone` | Creates the group if needed and pairs an iPhone or iPad with the shortcut: shows a QR code, the start of the iPhone CA's fingerprint and a code. Run it on a Linux machine: only Linux members serve the shortcut. |
| `cbb join` | Joins a group by QR code: shows a QR code for the phone app, or for the shortcut "clipboardbridge: add a computer", and waits. |
| `cbb join -code [ADDRESS]` | Joins with the code from `cbb pair`. Without an address it finds the member on the home network; with one (`host:port`) it dials it, for example through an SSH tunnel or your own VPN (see the [quick start](quickstart.md)). |
| `cbb join -invite FILE` | Joins from afar with an invitation file from `cbb invite`, through the hub's guest tunnel. Both sides show the new device's key fingerprint; the hub admits it once its admin types `yes`. |
| `cbb invite [-for DURATION] [-o FILE]` | Runs on the group's hub, with sync away from home on: writes an invitation for a device away from home (default `clipboardbridge.cbbinvite`, valid for 1h, at most 24h) and waits to confirm it. The file is a secret until it is used; copy it through a channel you trust. |
| `cbb away` | Shows sync away from home on this device: on or off, the hub, the tunnel, and what went wrong. |
| `cbb away on` | Turns sync away from home on here, after a warning about where the keys are kept. |
| `cbb away off` | Turns it off and forgets the tunnel keys. |
| `cbb away hub [-port N] [-obfuscate] [-forwarder ADDRESS:PORT -forwarder-key KEY] [ADDRESS:PORT...]` | Makes this device the group's hub, reached from the internet at these addresses, through a forwarder, or both; `-port` sets the UDP port the tunnel listens on. With `-forwarder` the hub registers with that forwarder, whose key `-forwarder-key` pins, and its clients try it after the hub's own addresses. `-obfuscate` makes the tunnel speak AmneziaWG, for networks that block WireGuard: the hub makes the group's settings once and keeps them while `-obfuscate` stays, and its clients get them at home with its offer; with a forwarder, the hub gives it the settings. The hub need not stay on: while it is off nothing syncs away from home, and at home the devices sync without it. |
| `cbb away relay ADDRESS:PORT -key KEY` | For a group without a hub: this device meets the group's other devices away from home at the blind relay at that address, whose key `-key` pins. It registers there with its member certificate, and the relay joins its member connections to the others' end to end. It replaces the hub and the hub's offer on this device. |
| `cbb forward [-listen ADDRESS:PORT] [-key FILE] [-show-key]` | Runs a forwarder on a server with a public address, for hubs that clients cannot reach directly, for example behind carrier-grade NAT (default port 8764, UDP and TCP). It holds no keys of any group and writes nothing about them; its own key is made in `-key` on the first run (default `forwarder.pem` in systemd's state directory, or in the service's state directory) and printed at start, or alone with `-show-key`. |
| `cbb relay -group TAG[,TAG...] [-listen ADDRESS:PORT] [-key FILE] [-show-key]` | Runs a blind relay on a server you run, for your groups that have no computer to be the hub (default port 8764, UDP and TCP). It serves only the groups whose tags `-group` lists (`cbb status` shows a group's tag), holds none of their keys, reads nothing of the clipboard, and writes nothing about them; it sees which devices of a group talk, when and how much. Its keys are made in `-key` on the first run (default `relay.pem` in systemd's state directory, or in the service's state directory), and the key to give `cbb away relay -key` is printed at start, or alone with `-show-key`. |
| `cbb version` | Prints the version and the platform. |
| `cbb service` | Runs the service; started by systemd, launchd or the Windows service manager, not by hand. |
| `cbb agent` | Links the Mac's or Windows clipboard to the service; started at sign-in (`cbbw.exe agent` on Windows). |
| `cbb desktop` | Links a Linux desktop's clipboard to the service; started with the desktop session. |

## cbb-lite

Global flags, before the command: `-state DIR` (default `/var/lib/cbb-lite`, or
`CBB_STATE`), `-socket PATH` (default `/run/cbb-lite/control.sock`, or `CBB_SOCKET`),
`-debug` (the details of errors). Install and use are in [lite/README.md](../lite/README.md).

| Command | What it does |
|---|---|
| `cbb-lite join [-name NAME] [-port PORT] [-addr HOST[:PORT]]...` | Joins a group by QR code, scanned by the phone app or the shortcut. `-addr` names where the phone reaches this device, when the QR code would name the wrong addresses. |
| `cbb-lite join -code HOST:PORT` | Joins with the code from `cbb pair` on a Linux member. |
| `cbb-lite run [-name NAME] [-port PORT] [-peer HOST:PORT]... [-no-mdns] [-no-listen]` | Runs the service (systemd or procd). `-peer` names a full member to dial, for networks without mDNS; `-no-mdns` turns mDNS off; `-no-listen` closes the member port, so the device only dials. |
| `cbb-lite copy [-secret]` | Sends standard input to the group. |
| `cbb-lite paste` | Prints this member's clipboard text. |
| `cbb-lite status` | This device, its group, and every device of the group with its system, role and marks. |
| `cbb-lite watch [-0]` | Prints each text the group sends here, one per line, or followed by a zero byte with `-0`. |
| `cbb-lite next paste [-max BYTES]`, `next copy LEN CRC32`, `next join [-name NAME] [-port PORT] [-addr HOST[:PORT]]...` | The same for the ZX Spectrum Next's `.cbb` dot command, in frames its Z80 reads; see [lite/README.md](../lite/README.md#zx-spectrum-next). |
| `cbb-lite version`, `cbb-lite help` | The version; this help. |

## Installers

| Installer | Options |
|---|---|
| Linux `get.sh` and `install.sh` | `--port N` another member port (kept for later runs; `--port 8764` goes back), `--no-firewall` leaves the firewall alone (`CBB_FIREWALL=no` for `install.sh`), `--console` also starts tmux on the text console. With the one-line installer, put them after `sh -s --`. `CBB_VERSION=v1.2.3` installs that release. Running it again updates. |
| Linux `uninstall.sh` (`/usr/local/share/clipboardbridge/`) | removes the program, the service and the firewall rules the installer added; `--purge` also deletes the keys in `/var/lib/clipboardbridge`. |
| macOS `install.sh` (in the release archive's `packaging/macos`, or under `$(brew --prefix)/opt/clipboardbridge/share/clipboardbridge`) | `--in-place` runs the binary where it is (Homebrew) instead of copying it; `CBB_FIREWALL=no` leaves the application firewall alone. |
| macOS `uninstall.sh` (beside `install.sh`) | removes the service, the agent and the program; `--purge` also deletes the keys. Before `brew uninstall`. |
| Windows `get.ps1` and `install.ps1` | `$env:CBB_PORT = "9000"` another port, `$env:CBB_FIREWALL = "no"` leaves Windows Firewall alone. |
| Windows `uninstall.ps1` (`$env:ProgramFiles\clipboardbridge`), or Settings, Apps | removes the service, the agent, the program and the firewall rules; `-Purge` also deletes the keys and the `clipboardbridge` group. |

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `CBB_DEBUG` | `cbb`, `cbb-lite` | `1` shows the underlying error under each message; `0` hides it in a development build, which shows it by default. The service's log always has the details. In the service's environment, also WireGuard's own messages for sync away from home. |
| `CBB_PORT` | the service, `cbb-lite run` | The member port, 8764 by default. The installers keep it: `/etc/clipboardbridge/clipboardbridge.env` on Linux, the service's registry key on Windows; change it by running the installer with `--port N` or `$env:CBB_PORT`. |
| `CBB_SOCKET` | `cbb`, `cbb-lite` | Another control socket, for tests or a second instance. |
| `CBB_STATE` | `cbb-lite` | Another state directory. |
| `CBB_FIREWALL` | Linux and macOS `install.sh`, Windows `install.ps1`/`get.ps1` | `no` leaves the firewall alone (`--no-firewall` for Linux `get.sh`). |
| `CBB_VERSION` | Linux `get.sh` | A release such as `v0.2.0` instead of the latest. |
| `CBB_ERROR_DETAILS` | Windows `install.ps1` | `1` adds the full error record to the installer's messages. |

The test-only variables (`CBB_INTEROP_OUT`, `CBB_LITE`, `CBB_SWIFT_INTEROP`, …) are in
[CONTRIBUTING.md](../CONTRIBUTING.md).
