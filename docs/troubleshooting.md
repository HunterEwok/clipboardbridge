<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# When something does not work

Start with `cbb status` on the device that misbehaves: it says whether the service runs, which
group it is in, which members are connected and the state of sync away from home. Each
message is short; `CBB_DEBUG=1 cbb status` (on Windows `$env:CBB_DEBUG = "1"` first) shows
the underlying error under it. The service's log always has the details:

| System | Log |
|---|---|
| Linux | `journalctl -u clipboardbridge`; the desktop connector logs to the session's journal, `journalctl --user` |
| macOS | `/Library/Logs/clipboardbridge/service.log` |
| Windows | `ProgramData\clipboardbridge\logs\service.log`, and the agent's `LocalAppData\clipboardbridge\agent.log` |
| Lite member | `journalctl -u clipboardbridge`, as on Linux |

## Commands

**"the clipboardbridge service is not running"**: start it (`sudo systemctl start
clipboardbridge` on Linux; `sudo launchctl kickstart -k system/io.github.hunterewok.clipboardbridge`
on a Mac; `Start-Service clipboardbridge` on Windows) and look at its log.

**"permission denied" on the control socket, right after installing**: the installer added
you to the `clipboardbridge` group, and a group counts only from the next login. Log out and
in again (on Windows, open a new terminal); until then, `sudo cbb ...` works.

## Devices do not see each other

- **Firewall.** Members need TCP 8764 (or your port) and UDP 5353 (mDNS) from the home
  network. The installers add both to ufw, firewalld, the macOS application firewall and
  Windows Firewall when you answer Yes or pass `--express`; after a No they print the
  commands. With another firewall, or one turned on later, run the installer again or allow
  them by hand (see "Port and firewall" in the [quick start](quickstart.md)).
- **Another subnet or VLAN.** mDNS does not cross routers, so devices on, say,
  192.168.0.x and 192.168.20.x do not find each other. Turn on sync away from home with a
  hub on one side (the [quick start](quickstart.md), "Sync away from home"), or, for a lite
  member, name a computer with `cbb run -peer ADDRESS:8764` (lite/README.md).
- **Guest Wi-Fi or client isolation** on the router keeps devices from talking to each
  other at all; put them on the main network.
- **A different group.** `cbb status` shows the group; devices of two groups never
  sync. Join the right one again with `cbb pair`.

## Pairing fails

- **"wrong code"**: each pairing window allows three attempts; run `cbb pair` again for a
  new code.
- **The phone cannot reach the computer after scanning its QR code**: the phone and the
  computer must be on the same network, and the computer's port must be open (above). On
  iOS, allow Local Network for the app (Settings, Privacy & Security, Local Network).
- **The shortcut cannot reach `clipboardbridge.local`**: only Linux members serve it, on
  port 8764 only; at least one must be on. Check that the profile is installed and fully
  trusted (quick start, step 2).

## Sync away from home

`cbb global` on the device and on the hub says what is wrong. The usual causes: the router does
not forward the hub's UDP port to the hub, the hub's firewall drops it, or the address given
to `cbb global hub` is not the one the internet reaches. With `CBB_DEBUG=1` in the service's
environment the log also shows WireGuard's handshakes. On Linux:

```sh
sudo systemctl edit clipboardbridge     # add the two lines below, save
# [Service]
# Environment=CBB_DEBUG=1
sudo systemctl restart clipboardbridge
```

## Android

- **The accessibility service cannot be turned on** ("restricted setting"): on Android 13
  and later, open the app's App info, ⋮, "Allow restricted settings", then turn it on.
- **Copies from the computers stop arriving**: the foreground service may have been stopped
  by a battery saver; let the app run unrestricted in its battery settings.

## Still stuck

Open an [issue](https://github.com/HunterEwok/clipboardbridge/issues) with the output of
`CBB_DEBUG=1 cbb status`, the relevant part of the log and the systems involved. Remove
anything you copied that is private. Security problems go to [SECURITY.md](../SECURITY.md)
instead.
