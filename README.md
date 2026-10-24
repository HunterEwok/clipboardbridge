# clipboardbridge

One clipboard for your Apple devices, Android phones and every Linux and Windows computer on
your home network. Its command is `cbb`: `cbb new`, `cbb pair`, `cbb status`.

> **Status: early development.** What works, and what has been tried on real devices, is
> in the [status table](#status) below.

## Install

The [quick start](docs/quickstart.md) walks through installing and pairing step by step.
In short, from the latest release:

```sh
# Linux with systemd (x86-64, ARM64, ARMv7, ARMv6)
curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh

# macOS, with Homebrew (the second line starts the service; run it again after brew upgrade)
brew install hunterewok/tap/clipboardbridge
sudo sh "$(brew --prefix)/opt/clipboardbridge/share/clipboardbridge/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/clipboardbridge/bin/cbb"
```

```powershell
# Windows 10 (1809 or later) or 11, x86-64 or ARM64, in an administrator PowerShell
irm https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.ps1 | iex
```

The installers check the download against the release's `SHA256SUMS` and allow
clipboardbridge's one port, TCP 8764, and mDNS from the home network in the firewall; their
options are in the [command reference](docs/cli.md#installers). Every release file has a
build provenance attestation: `gh attestation verify FILE --repo HunterEwok/clipboardbridge`.
Then make a group and add your devices, as the quick start says.

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
| Sync away from home between computers (`cbb away`, `cbb invite`) | built | not yet |
| Sync away from home for the phones and the lite member | planned | |
| Console paste on a key press | planned | |
| Homebrew | set up; the tap gets its first formula with the next release | not yet |
| Signed macOS `.pkg`, TestFlight, app stores | planned (needs an Apple developer account) | |

The order of what comes next is the [roadmap](docs/roadmap.md).

## Documentation

The [documentation index](docs/README.md) lists every document and who it is for: the
[quick start](docs/quickstart.md), the [phone apps](docs/apps-guide.md), the
[commands](docs/cli.md), [troubleshooting](docs/troubleshooting.md), the
[lite member](lite/README.md), and for developers the [design](docs/design.md) and the
[protocol](docs/protocol.md).

## License

clipboardbridge is free software, licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).

## Security

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Contributing

Bug reports and ideas are welcome as issues. Code contributions are not accepted at this time;
see [CONTRIBUTING.md](CONTRIBUTING.md).
