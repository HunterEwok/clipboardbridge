# clipboardbridge

One clipboard for your Apple devices, Android phones and every Linux and Windows computer on
your home network. Its command is `cbb`: `cbb join`, `cbb pair`, `cbb devices`.

> **Status: early development.** What works, and what has been tried on real devices, is
> in the [status table](#status) below.

## Install

New here? The [quick start](docs/quickstart.md) walks through installing and pairing step
by step.

On Linux with systemd (x86-64, ARM64, ARMv7, ARMv6), from the latest release:

```sh
curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh
```

It checks the download against the release's `SHA256SUMS`, installs the service and, when
ufw or firewalld is active, allows mDNS and clipboardbridge's one port, TCP 8764, from the home
network only. Add `-s -- --console` after `sh` to also start tmux on the text console,
`--port N` for another port, or `--no-firewall` to leave the firewall alone;
`sudo sh /usr/local/share/clipboardbridge/uninstall.sh` removes it again, with the rules it added. Every release file has a build provenance attestation:
`gh attestation verify FILE --repo HunterEwok/clipboardbridge`.

On a Mac (Apple silicon; `amd64` instead of `arm64` for Intel), in Terminal, so that the
unsigned binary is not quarantined as a browser download would be:

```sh
curl -fsSLO https://github.com/HunterEwok/clipboardbridge/releases/latest/download/clipboardbridge-darwin-arm64.tar.gz
tar -xzf clipboardbridge-darwin-arm64.tar.gz
sudo sh clipboardbridge/packaging/macos/install.sh clipboardbridge/cbb
```

Or with [Homebrew](https://brew.sh), which also updates it:

```sh
brew install hunterewok/tap/clipboardbridge
sudo sh "$(brew --prefix)/opt/clipboardbridge/share/clipboardbridge/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/clipboardbridge/bin/cbb"
```

The second line starts the service and the pasteboard agent; run it again after each
`brew upgrade`. Either way, `uninstall.sh` beside that `install.sh` removes them again
(before `brew uninstall`).

On Windows 10 (1809 or later) or 11, x86-64 or ARM64, in a PowerShell opened with "Run as
administrator":

```powershell
irm https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.ps1 | iex
```

It checks the download against `SHA256SUMS`, installs the service and the clipboard agent,
adds you to the `clipboardbridge` group and allows TCP 8764 and mDNS from the local network
in Windows Firewall. `$env:CBB_PORT = "9000"` before it picks another port,
`$env:CBB_FIREWALL = "no"` leaves the firewall alone. Settings, Apps, clipboardbridge,
Uninstall removes it again, with the rules it added.

Then pair with the iPhone on a Linux machine with `cbb pair -phone`, and add each
further computer with `cbb join` and the shortcut "clipboardbridge: add a computer"; see
the [quick start](docs/quickstart.md). `cbb devices` lists the group, and
`cbb revoke` removes a lost device.

## What it does

Copy on one device and paste on another, with the normal copy and paste of each system:

| From → to       | What you do                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| Mac → Linux     | Copy on the Mac, paste on Linux. Automatic.                                 |
| Linux → Mac     | Copy on Linux, paste on the Mac. Automatic.                                 |
| Linux → Linux   | Copy on one machine, paste on any other. Automatic.                         |
| Windows ↔ others | Copy on Windows, paste on Linux or the Mac, and back. Automatic.           |
| iPhone → Linux  | Copy on the iPhone, press the Action button or double-tap the back, paste on Linux. |
| Linux → iPhone  | Copy on Linux, press the same button, paste on the iPhone.                  |
| Others → Android | Copy on a computer, paste on the phone. Automatic.                         |
| Android → others | Copy on the phone; sent by itself with the accessibility service, or with one tap. |

Apple devices on one Apple Account already share a clipboard through Universal Clipboard;
clipboardbridge connects them to Linux. The iPhone needs one press because iOS does not let apps
read the clipboard in the background.

On Linux it works with and without a desktop:

- **With a desktop** (any X11 desktop, GNOME, KDE, sway, labwc and others): the normal
  clipboard, Ctrl+V, and Shift+Insert in terminals.
- **Without a desktop** (text console): copy and paste inside tmux, and `cbb copy` and
  `cbb paste` on the command line. A console paste on a key press, which would work even at
  the login prompt, is planned.

## Principles

- **Your network only.** Devices find each other on the home network; away from home they
  reach it only through the group's own WireGuard tunnel to a computer at home, never
  through anyone else's server. No cloud, no accounts, no telemetry.
- **Encrypted and paired.** All traffic uses TLS. A device joins your group once, with a
  six-digit code, and talks only to the devices of the group.
- **No central server.** Every Linux machine, Windows PC and Mac is an equal member; any of them can be
  switched off.
- **Small.** One file per platform, no dependencies; runs on a Raspberry Pi Zero W.
- **Passwords stay put.** Items that password managers mark as secret are not synced
  automatically.

## Platforms

| Platform                                                                 | Component                                       |
|--------------------------------------------------------------------------|-------------------------------------------------|
| Linux: Ubuntu, Raspberry Pi OS and other distributions; x86-64, ARM64, ARMv7, ARMv6 (Raspberry Pi Zero W) | service, desktop connector, console helper |
| macOS                                                                    | background agent                                |
| Windows 10 (1809 or later) and 11; x86-64, ARM64                         | service, clipboard agent                        |
| iOS and iPadOS                                                           | the app, or a shortcut in the Shortcuts app     |
| Android                                                                  | the app (an APK in every release)               |
| Small Linux devices (routers, boards)                                    | the lite member, `cbb-lite` ([lite/README.md](lite/README.md)) |

## Status

| Part | State | On real devices |
|---|---|---|
| Linux service, desktop clipboard (X11, Wayland), tmux, `cbb copy`/`paste` | works | yes (Raspberry Pi, Steam Deck) |
| macOS service and pasteboard agent | works | yes |
| Windows service, clipboard agent, installer | built, CI on windows-latest | not yet |
| iPhone shortcut (Action button, Back Tap) | works | yes |
| iPhone app (the phone as the root, admin phones, devices list) | built, CI on a simulator | not yet |
| Android app | built, CI; APK in every release | not yet |
| Lite member `cbb-lite` on Linux | built, CI e2e with Go members | joined a group on a Pi Zero W |
| Lite member on the ESP32 | protocol core and TLS build for the chip; no firmware | no |
| Sync away from home between computers (`cbb away`) | built | not yet |
| Sync away from home for the phones and the lite member | planned | |
| Console paste on a key press | planned | |
| Homebrew | set up; the tap gets its first formula with the next release | not yet |
| Signed macOS `.pkg`, TestFlight, app stores | planned (needs an Apple developer account) | |

The order of what comes next is the [roadmap](docs/design.md#roadmap).

## License

clipboardbridge is free software, licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).

## Security

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Contributing

Bug reports and ideas are welcome as issues. Code contributions are not accepted at this time;
see [CONTRIBUTING.md](CONTRIBUTING.md).
