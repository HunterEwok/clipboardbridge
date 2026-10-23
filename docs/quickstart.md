<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Quick start

The shortest way to one clipboard: install with one command, make a group, add your devices.
Everything stays on your home network. The program is clipboardbridge, and its command is
`cbb`.

Today a Linux machine holds the group and the iPhone uses a shortcut. When the phone apps are
released, the phone becomes the centre of the group; that way is described at the end.

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
cbb pair -phone
```

This creates the group and prints a QR code, the start of a fingerprint and a six-digit code.

1. Scan the QR code with the iPhone's camera and follow the page: install the profile.
2. Check that its fingerprint starts with the printed one (Settings → General → VPN & Device
   Management → clipboardbridge → More Details), then turn on full trust for it (Settings →
   General → About → Certificate Trust Settings).
3. Add the shortcuts from the same page, "clipboardbridge" and "clipboardbridge: add a computer", and
   run "clipboardbridge" once; it asks for the six-digit code.
4. Put "clipboardbridge" on the Action button or on Back Tap (Settings → Accessibility → Touch →
   Back Tap → Double Tap).

No iPhone? Run `cbb pair` instead; it creates the group and shows a code for the next
computer.

## 3. Add more computers

Install on each computer first.

- **Linux**: the same command as in step 1.
- **Mac** (Apple silicon; `amd64` instead of `arm64` for Intel), in Terminal:

  ```sh
  curl -fsSLO https://github.com/HunterEwok/clipboardbridge/releases/latest/download/clipboardbridge-darwin-arm64.tar.gz
  tar -xzf clipboardbridge-darwin-arm64.tar.gz
  sudo sh clipboardbridge/packaging/macos/install.sh clipboardbridge/cbb
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
cbb join
```

It shows a QR code. On the iPhone, run the shortcut "clipboardbridge: add a computer" and scan
it. The computer joins within seconds.

Without the iPhone: run `cbb pair` on a Linux machine of the group, then
`cbb join -code` on the new computer and type the code it showed.

A computer that is not on the home network joins the same way through a path you control:

- **SSH** to a Linux machine of the group: on the new computer run
  `ssh -N -L 18764:localhost:8764 user@that-machine`, then `cbb pair` there (in another SSH
  session) and `cbb join -code 127.0.0.1:18764` here.
- **Your own VPN** that gives both machines private addresses (10.x, 172.16–31.x,
  192.168.x or IPv6 `fd..`): `cbb pair` on the Linux machine, then
  `cbb join -code <its VPN address>:8764` here. On Linux, run the installer again after
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

## Sync away from home (optional)

Off by default: the group syncs on the home network only. To sync when a computer is away,
one computer that is always on at home becomes the hub, and each computer that should reach
it from afar turns sync away from home on. Do it while the computers are at home:

```sh
cbb away on                                  # on the hub and on each computer; read what it says
cbb away hub 203.0.113.7:8764                # on the hub: the address the internet reaches it at
cbb away                                     # what it does now, and what went wrong
```

The router must forward UDP port 8764 to the hub, and the hub's firewall must allow it.
When it does not connect, `cbb away` says why; with `CBB_DEBUG=1` in the service's
environment, its log also has WireGuard's own messages, such as each handshake.
The clipboard travels only inside the group's own WireGuard tunnel, end to end encrypted;
nobody else's server is involved. `cbb away off` turns it off again and forgets its keys.
The phones cannot sync away from home yet.

## 5. Look after the group

```sh
cbb status     # this device, the group and the connected members
cbb devices    # every device of the group, and when it was last seen
cbb revoke NAME  # remove a lost Mac or iPhone; run it on a Linux machine
```

Something does not work? See "Problems" in the release notes, or open an issue.

## Remove clipboardbridge

On Linux:

```sh
sudo sh /usr/local/share/clipboardbridge/uninstall.sh
```

It stops the service and removes the program and its settings. It also removes the firewall
rules the installer added, and only those. The device's keys stay in `/var/lib/clipboardbridge`,
so a reinstall comes back into the group. Add `--purge` to delete them too; then remove the
device from the group on another one (`cbb revoke NAME`, or Devices in the app).

On a Mac, with the `uninstall.sh` beside the `install.sh` you ran (from Homebrew:
`$(brew --prefix)/opt/clipboardbridge/share/clipboardbridge/packaging/macos/uninstall.sh`,
then `brew uninstall clipboardbridge`):

```sh
sudo sh clipboardbridge/packaging/macos/uninstall.sh
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

## Later: the phone at the centre (planned)

When the iPhone and Android apps are released, the phone holds the group's key, and the
computers join it:

1. Install the app and tap "Scan a computer".
2. On each computer, install clipboardbridge (step 1 or 3) and run `cbb join`; the app
   scans its QR code. No profile, no code to type.
3. A second phone joins the same way, and the first one can make it an admin. If one phone is
   lost, remove it from Devices on the other; the computers stay in the group.

The Linux machines then take part like the Mac: they sync, and still serve the shortcut for
phones without the app. Until then, the steps above are the way.
