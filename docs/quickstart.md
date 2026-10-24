<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Quick start

The shortest way to one clipboard: install with one command, make a group, add your devices.
Everything stays on your home network. The program is clipboardbridge, and its command is
`cbb`.

Two ways to make a group. With the clipboardbridge app on a phone (iPhone or Android), the
phone holds the group and adds each computer by its QR code: see "With the phone app" at the
end. Without the app, a Linux machine holds the group and the iPhone uses a shortcut: the
steps below.

## 1. Install on the first Linux machine

Any Linux with systemd: a Raspberry Pi, a laptop, a server, a Steam Deck.

```sh
curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh
```

The script checks the download, starts the service and opens clipboardbridge's one port, TCP
8764, and mDNS in ufw or firewalld for the home network only; with another firewall it
prints what to allow. Log out and in again once, so your user may use clipboardbridge.

### Port and firewall

clipboardbridge needs one TCP port, 8764, and mDNS (UDP 5353), both from the home network only.
The installer opens them in ufw or firewalld. If you turn a firewall on later, run the
installer again (it is also how you update). Each run first removes the rules it added
before, and never touches anyone else's. By hand with ufw, for example from `192.168.0.0/24`:

```sh
sudo ufw allow proto tcp from 192.168.0.0/24 to any port 8764 comment clipboardbridge
sudo ufw allow proto udp from 192.168.0.0/24 to any port 5353 comment 'clipboardbridge mDNS'
```

Another port, because 8764 is taken or you prefer one of your own? You don't have to change
it. If you do, pass it to the installer:

```sh
curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh -s -- --port 9000
```

The installer keeps the port for later updates and opens it instead of 8764, and the old
rules go. Allow the new port in any other firewall on the way: the installer reminds you.
`--port 8764` goes back to the default. The phone app learns the port from the QR code and
mDNS, so it needs no setting. The iPhone shortcut works only with 8764.

## 2. Make the group and pair the iPhone

This step pairs the iPhone shortcut, for an iPhone without the app. With the clipboardbridge
app (iPhone or Android), the phone makes the group itself instead: see the app's
"Connect a new device".

On that machine:

```sh
cbb new
cbb pair -phone
```

`cbb new` creates the group, with this computer as its root. `cbb pair -phone` prints a QR
code, the start of a fingerprint and a six-digit code.

1. Scan the QR code with the iPhone's camera and follow the page: install the profile.
2. Check that its fingerprint starts with the printed one (Settings → General → VPN & Device
   Management → clipboardbridge → More Details), then turn on full trust for it (Settings →
   General → About → Certificate Trust Settings).
3. Add the shortcut "clipboardbridge" from the same page and run it once; it asks for the
   six-digit code.
4. Put "clipboardbridge" on the Action button or on Back Tap (Settings → Accessibility → Touch →
   Back Tap → Double Tap).

No iPhone? Run `cbb new` and then `cbb pair`, which shows a code for the next computer.

## 3. Add more computers

Install on each computer first.

- **Linux**: the same command as in step 1.
- **Mac** (Apple silicon or Intel), in Terminal, the same command as on Linux:

  ```sh
  curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh
  ```

  Or with Homebrew, which also updates it; run the second line again after each
  `brew upgrade`:

  ```sh
  brew install hunterewok/tap/clipboardbridge
  sudo sh "$(brew --prefix)/opt/clipboardbridge/share/clipboardbridge/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/clipboardbridge/bin/cbb"
  ```

- **Windows** 10 (1809 or later) or 11, in a PowerShell opened with "Run as
  administrator":

  ```powershell
  irm https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.ps1 | iex
  ```

  It adds the user signed in at the screen to the `clipboardbridge` group and starts the
  clipboard agent for them; `cbb` works in a new terminal. Another port:
  `$env:CBB_PORT = "9000"` before it. Without the one-line installer: unpack
  `clipboardbridge-windows-amd64.zip` (or `-arm64`) and run
  `powershell -ExecutionPolicy Bypass -File clipboardbridge\packaging\windows\install.ps1`.

Then, on the new computer:

```sh
cbb pair
```

It shows a QR code for the phone app; scan it in the app (Add a device) and the computer
joins within seconds.

With the shortcut, or without a phone: run `cbb pair` on the computer that created the group
too; it shows a six-digit code, which you type into the waiting `cbb pair` on the new
computer.

The computer that created the group is its root: only it and the admins it makes can add
and remove devices and serve the iPhone shortcut. To make another computer an admin, so the
group does not depend on one machine, run on the root:

```sh
cbb admin NAME        # NAME as cbb status shows it; that computer must be on
```

If the root is lost or broken, an admin takes the group over and removes it; the other
devices stay in the group:

```sh
cbb takeover NAME     # on an admin; NAME is the lost root
```

A computer that is not on the home network joins with an invitation, once sync away from
home is on and a hub is set up (see "Sync away from home" below). On the hub, which must be
the root or an admin:

```sh
cbb invite            # writes clipboardbridge.cbbinvite, valid for an hour (-for 24h at most)
```

Copy the file to the new computer through a channel you trust (it is a secret until it is
used), and run `cbb pair -invite clipboardbridge.cbbinvite` there. Both show the new
computer's key fingerprint; on the hub, type `yes` only if they match. The new computer
then syncs through the hub wherever it is.

Or through a path you control:

- **SSH** to the root or an admin of the group: on the new computer run
  `ssh -N -L 18764:localhost:8764 user@that-machine`, then `cbb pair` there (in another SSH
  session) and `cbb pair -code 127.0.0.1:18764` here.
- **Your own VPN** that gives both machines private addresses (10.x, 172.16–31.x,
  192.168.x or IPv6 `fd..`): `cbb pair` on the root or an admin, then
  `cbb pair -code <its VPN address>:8764` here. On Linux, run the installer again after
  setting up the VPN, so its firewall rules allow the VPN's network.

The pairing code never travels in the clear: the pairing runs inside SSH or your VPN, and
inside TLS. The new computer then syncs with that machine through the same path while it
is up (until the service restarts). To keep syncing after that, turn on sync away from
home (below) on both before you close the SSH session; the machine you joined at should be
the hub. See "Joining from another network" in [design.md](design.md).

## 4. Use it

- **Between computers**: copy on one, paste on another. Nothing else to do.
- **iPhone**: one press of the Action button (or a double tap on the back) picks the
  direction. Copied on a computer a moment ago: the text comes to the iPhone. Otherwise a new
  text copied on the iPhone goes to the computers, and with nothing new on the iPhone the
  computers' latest text comes to it.
- **Without a desktop**: `cbb copy` and `cbb paste`, or copy and paste inside
  tmux.

## 5. Sync away from home (optional)

Off by default: the group syncs on the home network only. To sync when a computer is away,
one computer at home becomes the hub, and each computer that should reach it from afar turns
sync away from home on. Do it while the computers are at home. `cbb global on` and
`cbb pair -invite` run with `sudo` on Linux and in a terminal opened as administrator on
Windows: until then the service may reach only the home network, and they let it reach the
internet; `cbb global off`, run the same way, takes that back.

The hub does not have to stay on. While it is off, nothing syncs away from home, and at home
the devices sync with each other without it. So choose: a computer that is always on, one you
turn on when you need it (set the group up beforehand, turn the hub on, copy, turn it off),
or no hub, and sync only at home. To set it up:

```sh
sudo cbb global on                             # on the hub and on each computer; read what it says
cbb global hub 203.0.113.7:8764                # on the hub: the address the internet reaches it at
cbb global                                     # what it does now, and what went wrong
```

The router must forward UDP port 8764 to the hub, and the hub's firewall must allow it.
When it does not connect, `cbb global` says why; with `CBB_DEBUG=1` in the service's
environment, its log also has WireGuard's own messages, such as each handshake.

When the hub cannot be reached from the internet, for example behind carrier-grade NAT, it
can register with a forwarder: `cbb forward` on a server with a public address, which holds
no keys and passes only the tunnel's encrypted packets. On that server, as a systemd service
or in a terminal:

```sh
cbb forward                                  # prints its key, sha256:...; UDP and TCP port 8764 must be open
```

And on the hub, with or without addresses of its own:

```sh
cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key sha256:...
```

The computers then try the hub's own addresses first and the forwarder last. The project's
own forwarder is not running yet.

No computer at home to be the hub? Run a blind relay of your own on a server with a
public address. It serves only your groups and holds none of their keys, but it sees which
of your devices talk and when, which a hub would not let out. On the server, with the
group's tag from `cbb status`:

```sh
cbb relay -group 0123456789abcdef            # prints its key, sha256:...; UDP and TCP port 8764 must be open
```

And on each computer, after `cbb global on`, in place of a hub:

```sh
cbb global relay 198.51.100.9:8764 -key sha256:...
```

The computers then meet at the relay whenever they are not on one network.

The clipboard travels only inside the group's own WireGuard tunnel, end to end encrypted; a
forwarder sees only encrypted packets. `cbb global off` turns it off again and forgets its
keys. The phones cannot sync away from home yet.

## 6. Look after the group

```sh
cbb status     # this device, the group, and every device: its system, role and when it was seen
cbb revoke NAME  # remove a lost device; on the root or an admin, or Devices in the app
```

A group made before 0.4 has no root: every Linux and Windows member holds its keys, and
those members cannot be removed. Once every device runs 0.4, give it a root with one
command on one of them; nobody pairs again, except iPhones that use the shortcut:

```sh
cbb upgrade
```

Something does not work? See [troubleshooting](troubleshooting.md), or open an issue.

## Remove clipboardbridge

On Linux:

```sh
sudo sh /usr/local/share/clipboardbridge/uninstall.sh
```

It stops the service and removes the program and its settings. It also removes the firewall
rules the installer added, and only those. The device's keys stay in `/var/lib/clipboardbridge`,
so a reinstall comes back into the group. Add `--purge` to delete them too; then remove the
device from the group on another one (`cbb revoke NAME`, or Devices in the app).

On a Mac (with Homebrew, then also `brew uninstall clipboardbridge`):

```sh
sudo sh /usr/local/share/clipboardbridge/uninstall.sh
```

It stops the service and the agent and removes them and the program. The keys stay in
`/Library/Application Support/clipboardbridge/state`; `--purge` deletes them too.

On Windows: Settings, Apps, clipboardbridge, Uninstall; or, as administrator,

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\clipboardbridge\uninstall.ps1"
```

It removes the service, the agent, the program and the firewall rules the installer added.
The keys stay in `ProgramData\clipboardbridge`; `-Purge` deletes them and the
`clipboardbridge` group.

## With the phone app

With the iPhone or Android app, the phone holds the group's key, and the computers join it
(the [app guide](apps-guide.md) has more):

1. Install the app and tap "Connect a new device".
2. On each computer, install clipboardbridge (step 1 or 3) and run `cbb pair`; the app
   scans its QR code. No profile, no code to type.
3. A second phone joins from its own Start screen ("I already use clipboardbridge on another
   phone"), and the first one makes it an admin. If one phone is lost, remove it in Devices
   on the other; the computers stay in the group.

The Linux machines take part like the Mac: they sync, and still serve the shortcut for
phones without the app. The apps are built and tested in CI but not yet on a real phone;
the Android app is an APK in each release, the iPhone app comes with TestFlight.
