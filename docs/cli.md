<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Command reference

Every command of `cbb`, on a full member (Linux, macOS, Windows) and on the lite member, with
their flags and environment variables. `cbb help` prints the short form of the one installed;
`cbb version` says which it is.
Commands other than `service`, `agent`, `version` and `help` talk to the running
service through its control socket, so they need the `clipboardbridge` group (Linux, Windows,
macOS) or root; `copy`, `paste` and `status` work for members of the group without `sudo`.

## cbb

| Command | What it does |
|---|---|
| `cbb copy [-secret]` | Sends standard input to the group, and to this device's own clipboard. `-secret` sends it as a secret: kept only in memory and gone 60 seconds after the copy. |
| `cbb paste` | Prints this device's clipboard text. |
| `cbb status` | This device, its group, sync away from home, and every device of the group: its system (Linux, Windows, macOS, iOS, Android), its role (`full`, `lite`, `phone`, `shortcut`), whether it is the root or an admin, when it was last seen and whether its clock is off. It also says whether this computer answers for `clipboardbridge.local`. |
| `cbb revoke NAME` | Removes a device, by name or device ID, with a signed record; the group stays. Runs on an admin: the computer that created the group (its root), a computer the root made an admin (`cbb admin`), or a computer the root phone made an admin. Removing an admin of a computer's group also replaces the iPhone CA, so iPhones that use the shortcut pair again. The root is removed with `cbb takeover`. In a phone's group, remove devices in the app (Devices). |
| `cbb admin NAME` | On the group's root: makes the computer NAME (a name or a device ID) an admin, which can then admit and remove devices and serve the shortcut. It must be connected. In a phone's group, use "Make it an admin" on the root phone. |
| `cbb upgrade` | Once, on a Linux or Windows member of a group made before 0.4, after every member runs this version: the group gets a root, this computer, and only it and the admins it makes hold keys from then on. The others delete their copies of the old keys when they hear of it; `cbb status` marks those that have not yet, and they cannot be removed until they have. The iPhone CA is replaced, so iPhones that use the shortcut pair again. No device pairs again. |
| `cbb takeover NAME` | On an admin, when the root computer NAME is lost: this computer becomes the group's root and NAME is removed. The devices stay in the group; the iPhone CA is replaced, so iPhones that use the shortcut pair again. In a phone's group an admin phone takes over instead. |
| `cbb new` | Creates a group with this computer as its root: it holds the group's root key and the iPhone CA, admits devices and makes admins. A computer in a group already keeps it. |
| `cbb pair` | Does what this computer's place calls for. In a group, on the root or an admin: admits a new computer, showing a six-digit code to type there, and waits. In no group: joins one, showing a QR code for the phone app (or the shortcut "clipboardbridge: add a computer") and taking the code of `cbb pair` on the group's root or an admin, typed meanwhile. On a member that is neither, it names the devices that admit. |
| `cbb pair -code [ADDRESS]` | Joins with the code from `cbb pair` on the group's root or an admin, read from the terminal or standard input (never from the command line, where other users could read it). Without an address it finds that computer on the home network; with one (`host:port`) it dials it, for example through an SSH tunnel or your own VPN (see the [quick start](quickstart.md)). |
| `cbb pair -phone` | Pairs an iPhone or iPad with the shortcut: shows a QR code, the start of the iPhone CA's fingerprint and a code. Run it on the root or an admin that answers for `clipboardbridge.local`, after `cbb new`. |
| `cbb pair -invite FILE` | Joins from afar with an invitation file from `cbb invite`, through the hub's guest tunnel. Both sides show the new device's key fingerprint; the hub admits it once its admin types `yes`. |
| `cbb invite [-for DURATION] [-o FILE]` | Runs on the group's hub, with sync away from home on: writes an invitation for a device away from home (default `clipboardbridge.cbbinvite`, valid for 1h, at most 24h) and waits to confirm it. The file is a secret until it is used; copy it through a channel you trust. |
| `cbb global` | Shows sync away from home on this device: on or off, the hub, the tunnel, and what went wrong. |
| `cbb global on` | Turns sync away from home on here, after a warning about where the keys are kept. |
| `cbb global off` | Turns it off and forgets the tunnel keys. |
| `cbb global hub [-port N] [-obfuscate] [-forwarder ADDRESS:PORT -forwarder-key KEY [-vless]] [ADDRESS:PORT...]` | Makes this device the group's hub, reached from the internet at these addresses, through a forwarder, or both; `-port` sets the UDP port the tunnel listens on. With `-forwarder` the hub registers with that forwarder, whose key `-forwarder-key` pins, and its clients try it after the hub's own addresses. `-obfuscate` makes the tunnel speak AmneziaWG, for networks that block WireGuard: the hub makes the group's settings once and keeps them while `-obfuscate` stays, and its clients get them at home with its offer; with a forwarder, the hub gives it the settings. `-vless` has the clients reach the forwarder only inside VLESS with REALITY, which looks like HTTPS to a well-known site, for networks that block WireGuard and AmneziaWG alike; the forwarder must run with `-vless-site`. The hub need not stay on: while it is off nothing syncs away from home, and at home the devices sync without it. |
| `cbb global relay ADDRESS:PORT -key KEY` | For a group without a hub: this device meets the group's other devices away from home at the blind relay at that address, whose key `-key` pins. It registers there with its member certificate, and the relay joins its member connections to the others' end to end. It replaces the hub and the hub's offer on this device. |
| `cbb forward [-listen ADDRESS:PORT] [-key FILE] [-show-key] [-vless-site NAME [-vless-listen ADDRESS:PORT]]` | Runs a forwarder on a server with a public address, for hubs that clients cannot reach directly, for example behind carrier-grade NAT (default port 8764, UDP and TCP). It holds no keys of any group and writes nothing about them; its own key is made in `-key` on the first run (default `forwarder.pem` in systemd's state directory, or in the service's state directory) and printed at start, or alone with `-show-key`. With `-vless-site`, it also takes VLESS with REALITY on TCP `-vless-listen` (default `:443`) for the clients of hubs that ask for it, borrowing the TLS of that well-known site (such as `www.example.com`), whose own answers whoever is not a client gets; its REALITY key is kept in the same key file. |
| `cbb relay -group TAG[,TAG...] [-listen ADDRESS:PORT] [-key FILE] [-show-key]` | Runs a blind relay on a server you run, for your groups that have no computer to be the hub (default port 8764, UDP and TCP). It serves only the groups whose tags `-group` lists (`cbb status` shows a group's tag), holds none of their keys, reads nothing of the clipboard, and writes nothing about them; it sees which devices of a group talk, when and how much. Its keys are made in `-key` on the first run (default `relay.pem` in systemd's state directory, or in the service's state directory), and the key to give `cbb global relay -key` is printed at start, or alone with `-show-key`. |
| `cbb version` | Prints the version and the platform. |

### Rarely needed

`holder` only matters when the wrong computer answers to `clipboardbridge.local`. The system
starts `service` and `agent`; they are run by hand only to look into a problem, such as to
see the agent's log in a terminal.

| Command | What it does |
|---|---|
| `cbb holder [auto\|first\|fallback\|never]` | Shows or sets whether this computer holds `clipboardbridge.local`, the name the iPhone shortcut reaches: `first`, only as a `fallback` when no computer set first is on, or `never`. `auto`, the default, picks `fallback` on a machine with a battery and `first` on any other. Only a computer with the group's iPhone key takes part. |
| `cbb service` | Runs the service; started by systemd, launchd or the Windows service manager, not by hand. |
| `cbb agent` | Links this desktop's clipboard to the service: the Mac's pasteboard, the Windows clipboard, or a Linux desktop's through Wayland or X11. It starts by itself at sign-in (`cbbw.exe agent` on Windows, the autostart entry on a Linux desktop); run it by hand only to see its log. |

## The lite member

On a small Linux device `cbb` is the lite member, with the same paths and service as a full
member (`/var/lib/clipboardbridge`, `clipboardbridge.service`) and the commands below; the
commands of a full member, such as `pair` or `global`, answer that this is the lite member.
Global flags, before the command: `-state DIR` (default `/var/lib/clipboardbridge`, or
`CBB_STATE`), `-socket PATH` (default `/run/clipboardbridge/control.sock`, or `CBB_SOCKET`),
`-debug` (the details of errors). Install and use are in [lite/README.md](../lite/README.md).

| Command | What it does |
|---|---|
| `cbb join [-name NAME] [-port PORT] [-addr HOST[:PORT]]...` | Joins a group by QR code, scanned by the phone app or the shortcut. `-addr` names where the phone reaches this device, when the QR code would name the wrong addresses. |
| `cbb join -code HOST:PORT` | Joins with the code from `cbb pair` on the group's root or an admin. |
| `cbb run [-name NAME] [-port PORT] [-peer HOST:PORT]... [-no-mdns] [-no-listen]` | Runs the service (systemd or procd). `-peer` names a full member to dial, for networks without mDNS; `-no-mdns` turns mDNS off; `-no-listen` closes the member port, so the device only dials. |
| `cbb copy [-secret]` | Sends standard input to the group. |
| `cbb paste` | Prints this member's clipboard text. |
| `cbb status` | This device, its group, and every device of the group with its system, role and marks. |
| `cbb watch [-0]` | Prints each text the group sends here, one per line, or followed by a zero byte with `-0`. |
| `cbb next paste [-max BYTES]`, `next copy LEN CRC32`, `next join [-name NAME] [-port PORT] [-addr HOST[:PORT]]...` | The same for the ZX Spectrum Next's `.cbb` dot command, in frames its Z80 reads; see [lite/README.md](../lite/README.md#zx-spectrum-next). |
| `cbb version`, `cbb help` | The version and that this is the lite member; this help. |

## Installers

| Installer | Options |
|---|---|
| `get.sh` (Linux and macOS) | Downloads this system's archive, checks it against `SHA256SUMS` and runs its `install.sh`. `--no-firewall` leaves the firewall alone; on Linux also `--port N` and `--console`, as for `install.sh`, and `--lite` for the lite member instead of the full one. With the one-line installer, put them after `sh -s --`. `CBB_VERSION=v1.2.3` installs that release. Running it again updates. |
| Linux `install.sh` (the same in the full and the lite member's archive) | `--port N` another member port (kept for later runs; `--port 8764` goes back), `--no-firewall` leaves the firewall alone (`CBB_FIREWALL=no` for `install.sh`), `--console` also starts tmux on the text console. |
| Linux `uninstall.sh` (`/usr/local/share/clipboardbridge/`) | removes the program, the service and the firewall rules the installer added; `--purge` also deletes the keys in `/var/lib/clipboardbridge`. |
| macOS `install.sh` (in the release archive's `packaging/macos`, or under `$(brew --prefix)/opt/clipboardbridge/share/clipboardbridge`) | `--in-place` runs the binary where it is (Homebrew) instead of copying it; `CBB_FIREWALL=no` leaves the application firewall alone. |
| macOS `uninstall.sh` (`/usr/local/share/clipboardbridge/`) | removes the service, the agent and the program; `--purge` also deletes the keys. Before `brew uninstall`. |
| Windows `get.ps1` and `install.ps1` | `$env:CBB_PORT = "9000"` another port, `$env:CBB_FIREWALL = "no"` leaves Windows Firewall alone. |
| Windows `uninstall.ps1` (`$env:ProgramFiles\clipboardbridge`), or Settings, Apps | removes the service, the agent, the program and the firewall rules; `-Purge` also deletes the keys and the `clipboardbridge` group. |

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `CBB_DEBUG` | `cbb` | `1` shows the underlying error under each message; `0` hides it in a development build, which shows it by default. The service's log always has the details. In the service's environment, also WireGuard's own messages for sync away from home. |
| `CBB_PORT` | the service, the lite member's `cbb run` | The member port, 8764 by default. The installers keep it: `/etc/clipboardbridge/clipboardbridge.env` on Linux, the service's registry key on Windows; change it by running the installer with `--port N` or `$env:CBB_PORT`. |
| `CBB_SOCKET` | `cbb` | Another control socket, for tests or a second instance. |
| `CBB_STATE` | the lite member | Another state directory. |
| `CBB_FIREWALL` | Linux and macOS `install.sh`, Windows `install.ps1`/`get.ps1` | `no` leaves the firewall alone (`--no-firewall` for `get.sh`). |
| `CBB_VERSION` | `get.sh` | A release such as `v0.2.0` instead of the latest. |
| `CBB_ERROR_DETAILS` | Windows `install.ps1` | `1` adds the full error record to the installer's messages. |

The test-only variables (`CBB_INTEROP_OUT`, `CBB_LITE`, `CBB_SWIFT_INTEROP`, …) are in
[CONTRIBUTING.md](../CONTRIBUTING.md).
