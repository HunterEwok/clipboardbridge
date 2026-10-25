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

## Docker

For a NAS or a home server that is always on, and a good hub
([image's README](../../packaging/docker/README.md); published with each release from 0.5):

```sh
docker compose -f packaging/docker/compose.home.yaml up -d
docker compose -f packaging/docker/compose.home.yaml exec clipboardbridge cbb pair
```

## The firewall

Clipboard Bridge needs one TCP port, 8764, and mDNS (UDP 5353), both from the home network
only. The installer finds the firewall (ufw, firewalld, nftables or iptables on Linux, the
Mac's application firewall, Windows Firewall), lists each rule, and asks
`Add these rules now? [y/N]`:

- **Yes**: it adds them, keeps them current on every update and removes them when you
  uninstall. It never touches other rules.
- **No** (the default, and when there is no terminal to ask in): it adds nothing and prints
  the exact commands, for you to run yourself.
- `--express` (`-Express` on Windows) adds them without asking; `--no-firewall` answers No.

nftables and iptables always get the commands only, since rules added at run time do not
survive a restart there. If you turn a firewall on later, run the installer again.

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

## Removing it

On Linux and a Mac:

```sh
sudo sh /usr/local/share/clipboardbridge/uninstall.sh
```

With Homebrew, run `brew uninstall clipboardbridge` after it.

On Windows: Settings, Apps, "clipboardbridge", Uninstall.

This removes the program, the service and the firewall rules the installer added. The
device's keys stay, so installing again brings it back into its group. To delete them too,
add `--purge` (`-Purge` on Windows, with
`powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\clipboardbridge\uninstall.ps1" -Purge`),
then remove the device from the group on another one (`sudo cbb revoke NAME`, or on the
phone).
