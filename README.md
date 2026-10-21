# clipbridge

One clipboard for your Apple devices and every Linux machine on your home network.

> **Status: early development.** There is nothing to use yet: the Go code so far only
> prints its version. The design is in [docs/design.md](docs/design.md).

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
clipbridge connects them to Linux. The iPhone needs one press because iOS does not let apps
read the clipboard in the background.

On Linux it works with and without a desktop:

- **With a desktop** (any X11 desktop, GNOME, KDE, sway, labwc and others): the normal
  clipboard, Ctrl+V, and Shift+Insert in terminals.
- **Without a desktop** (text console): copy and paste inside tmux, `clipbridge copy` and
  `clipbridge paste` on the command line, and an optional console paste on a key press that
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

clipbridge is free software, licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).

## Security

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Contributing

Bug reports and ideas are welcome as issues. Code contributions are not accepted at this time;
see [CONTRIBUTING.md](CONTRIBUTING.md).
