# clipboardbridge

One clipboard for your Apple devices and every Linux machine on your home network. Its
command is `cbb`: `cbb join`, `cbb pair`, `cbb devices`.

> **Status: early development.** Linux (with and without a desktop), macOS and the iPhone
> shortcut work; the phone apps, Windows and sync away from home are planned. The design is
> in [docs/design.md](docs/design.md), the protocol in [docs/protocol.md](docs/protocol.md).

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

Then pair with the iPhone on a Linux machine with `cbb pair -phone`, and add each
further computer with `cbb join` and the shortcut "clipboardbridge: add a computer"; see
the [quick start](docs/quickstart.md). `cbb devices` lists the group, and
`cbb revoke` removes a lost device.

## What it will do

Copy on one device and paste on another, with the normal copy and paste of each system:

| From → to       | What you do                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| Mac → Linux     | Copy on the Mac, paste on Linux. Automatic.                                 |
| Linux → Mac     | Copy on Linux, paste on the Mac. Automatic.                                 |
| Linux → Linux   | Copy on one machine, paste on any other. Automatic.                         |
| iPhone → Linux  | Copy on the iPhone, press the Action button or double-tap the back, paste on Linux. |
| Linux → iPhone  | Copy on Linux, press the same button, paste on the iPhone.                  |

Apple devices on one Apple Account already share a clipboard through Universal Clipboard;
clipboardbridge connects them to Linux. The iPhone needs one press because iOS does not let apps
read the clipboard in the background.

On Linux it works with and without a desktop:

- **With a desktop** (any X11 desktop, GNOME, KDE, sway, labwc and others): the normal
  clipboard, Ctrl+V, and Shift+Insert in terminals.
- **Without a desktop** (text console): copy and paste inside tmux, `cbb copy` and
  `cbb paste` on the command line, and an optional console paste on a key press that
  works even at the login prompt.

## Principles

- **Local network only.** Devices find each other on the home network. No cloud, no
  accounts, no telemetry.
- **Encrypted and paired.** All traffic uses TLS. A device joins your group once, with a
  six-digit code, and talks only to the devices of the group.
- **No central server.** Every Linux machine and Mac is an equal member; any of them can be
  switched off.
- **Small.** One file per platform, no dependencies; runs on a Raspberry Pi Zero W.
- **Passwords stay put.** Items that password managers mark as secret are not synced
  automatically.

## Platforms (planned)

| Platform                                                                 | Component                                       |
|--------------------------------------------------------------------------|-------------------------------------------------|
| Linux: Ubuntu, Raspberry Pi OS and other distributions; x86-64, ARM64, ARMv7, ARMv6 (Raspberry Pi Zero W) | service, desktop connector, console helper |
| macOS                                                                    | background agent                                |
| iOS and iPadOS                                                           | a shortcut in the Shortcuts app                 |

## License

clipboardbridge is free software, licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).

## Security

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Contributing

Bug reports and ideas are welcome as issues. Code contributions are not accepted at this time;
see [CONTRIBUTING.md](CONTRIBUTING.md).
