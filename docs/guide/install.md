<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Installing

Clipboard Bridge runs as a small background service on each computer. Its command is `cbb`.
Every way below installs the same program; pick the one you like.

## Linux

Any Linux with systemd (x86-64, ARM64, ARMv7, ARMv6): a laptop, a desktop, a Raspberry Pi,
a server, a Steam Deck.

```sh
curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh
```

Then log out and in again once, so your user may use `cbb` without `sudo`. A machine
without a desktop gets copy and paste inside tmux with `--console`
(`... | sudo sh -s -- --console`).

Remote paste on GNOME and KDE asks once, in a dialog on the computer, before an admin's
first paste may press the keys. To skip the dialog, add `--uinput`: a small helper then
presses the paste keys (Shift+Insert and Enter) for whoever uses the screen, never on a
login or lock screen.

Small devices that should only sync, such as a router or a Raspberry Pi Zero, can take the
lighter [lite member](../../lite/README.md) instead: `... | sudo sh -s -- --lite`.

## Mac

Apple silicon or Intel, in Terminal, the same command as on Linux:

```sh
curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh
```

Or with Homebrew, which also updates it. Run the second line again after each
`brew upgrade`:

```sh
brew install hunterewok/tap/clipboardbridge
sudo sh "$(brew --prefix)/opt/clipboardbridge/share/clipboardbridge/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/clipboardbridge/bin/cbb"
```

## Windows

Windows 10 (1809 or later) or 11, x86-64 or ARM64, in a PowerShell opened with "Run as
administrator":

```powershell
irm https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.ps1 | iex
```

It lets the user signed in at the screen use `cbb` (in a new terminal) and starts the
clipboard agent for them. Commands that change the group run in a terminal opened as
administrator, where Linux and macOS use `sudo`.

With winget, once the package is in winget's repository:

```powershell
winget install HunterEwok.clipboardbridge
cbb install           # in the administrator terminal; again after each winget upgrade
```

## OpenWrt

A router with OpenWrt 25.12 or later and room for a 25 MB program (128 MB of flash or
more, or eMMC; 256 MB of RAM), as root over SSH:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sh
```

It installs `cbb` with a procd service that runs as its own user without capabilities. The
service works only on the devices of the `lan` zone: mDNS and the member port never answer
on `wan`. Another zone, such as an IoT network, goes into `/etc/config/clipboardbridge`
(`list zone 'iot'`, then `/etc/init.d/clipboardbridge reload`); the service then opens the
member port and mDNS from that zone while it runs, without changing
`/etc/config/firewall`. After a boot it starts once NTP has set the clock. The keys live in
`/etc/clipboardbridge`, which sysupgrade keeps; an attended sysupgrade (ASU, owut) leaves
the program out, so run the command again after one.

Or from our package feed, which `apk upgrade` then keeps current. The feed's architecture
follows the router's CPU (`grep DISTRIB_ARCH /etc/openwrt_release`): `arm64` for
`aarch64_*`, `armv7` for `arm_cortex-a*` with `neon` or `vfp` in the name, `mipsle` for
`mipsel_*`, `mips` for `mips_*`, `amd64` for `x86_64`:

```sh
uclient-fetch -qO /etc/apk/keys/clipboardbridge.pem https://cbb.tools/openwrt/clipboardbridge.pem
echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
apk update && apk add clipboardbridge
```

`apk del clipboardbridge` removes it and keeps the keys in `/etc/clipboardbridge`.

## FreeBSD

FreeBSD 15, amd64 or arm64, as root (with `sudo` or `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sh
```

It installs `cbb`, an rc.d script that runs the service through daemon(8), and adds the
line `clipboardbridge_enable="YES"` to rc.conf. The keys live in `/var/db/clipboardbridge`.

On OPNsense the same installer also adds a plugin hook: the service shows under System >
Diagnostics > Services, and its firewall rules (in pf's anchor `clipboardbridge`) follow
every filter reload. Turn off the mDNS repeater (Services > mDNS Repeater) while it runs:
both need UDP port 5353, and the service answers mDNS on each home interface itself.
pfSense is not supported: the installer runs there too, but it prints the firewall rules
for Firewall > Rules instead of adding them, and an update of pfSense may remove Clipboard
Bridge.
On a desktop (X11, or Wayland with the data control protocol, as in KDE, sway and
Hyprland), the session starts `cbb agent` from XDG autostart and the clipboard joins the
group; log in again after the install. Remote paste types through XTEST on X11 and the
virtual keyboard on wlroots desktops; GNOME takes no remote paste on FreeBSD, since without
logind nothing tells whether its screen is locked.

## Docker

For a NAS or a home server that is always on
([image's README](../../packaging/docker/README.md); published with each release from 0.5).
It joins as an ordinary member: make the group on the phone or a computer you hold.

```sh
docker compose -f packaging/docker/compose.home.yaml up -d
docker compose -f packaging/docker/compose.home.yaml exec clipboardbridge cbb pair
```

## The firewall

Clipboard Bridge needs one TCP port, 8764, and mDNS (UDP 5353), both from the home network
only. The installer finds the firewall (ufw, firewalld, nftables or iptables on Linux, pf
or ipfw on FreeBSD, the Mac's application firewall, Windows Firewall), lists each rule, and
asks
`Add these rules now? [y/N]`:

- **Yes**: it adds them, keeps them current on every update and removes them when you
  uninstall. It never touches other rules.
- **No** (the default, and when there is no terminal to ask in): it adds nothing and prints
  the exact commands, for you to run yourself.
- `--express` (`-Express` on Windows) adds them without asking; `--no-firewall` answers No.

nftables and iptables always get the commands only, since rules added at run time do not
survive a restart there. On FreeBSD, pf gets the rules in an anchor of their own, which
pf reads through three marked lines the installer adds at the end of `/etc/pf.conf` and
removes again; ipfw gets them in rule set 17, added again at each start. If you turn a
firewall on later, run the installer again.

**Another port**, if 8764 is taken: `... | sudo sh -s -- --port 9000` (on Windows,
`$env:CBB_PORT = "9000"` before the installer). The phone app learns the port from the QR
code; the iPhone shortcut works only with 8764.

All installer options are in the [command reference](../reference/cli.md#installers).

## Updating

Run the same install command again. The device stays in its group and keeps its settings.
With Homebrew or winget, upgrade there and run the second line again.

## Checking a download

The one-line installers check the download against the release's `SHA256SUMS`. Every
release file also has a build provenance attestation that ties it to this repository and
the build that made it; with the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify clipboardbridge-linux-amd64.tar.gz --repo HunterEwok/clipboardbridge
```

`get.sh` checks it by itself when `gh` is installed and signed in for root
(`sudo gh auth login`); `CBB_ATTESTATION=require` refuses to install without it.

Releases are also signed with the project's own keys, which never touch CI (the root keys
sit on offline hardware keys, the release key in the maintainer's Secure Enclave):
`keys.json` names the release keys under the project's root keys, `release.json` lists every
file of the release with its hash, and `stable.json` says which release is current. Once the
root keys are built into the installers, `get.sh` (with `openssl`) and `get.ps1` check these
before they install, and refuse a release that is not signed; until then they check
`SHA256SUMS` and the attestation only. `CBB_VERIFY=skip` installs without the check.

## Removing it

On Linux and a Mac:

```sh
sudo sh /usr/local/share/clipboardbridge/uninstall.sh
```

With Homebrew, run `brew uninstall clipboardbridge` after it.

On Windows: Settings, Apps, "Clipboard Bridge", Uninstall.

This removes the program, the service and the firewall rules the installer added. The
device's keys stay, so installing again brings it back into its group. To delete them too,
add `--purge` (`-Purge` on Windows, with
`powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\clipboardbridge\uninstall.ps1" -Purge`),
then remove the device from the group on another one (`sudo cbb revoke NAME`, or on the
phone).
