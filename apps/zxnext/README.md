# Clipboard Bridge for the ZX Spectrum Next

`.cbb` is a dot command for NextZXOS. It copies text to the Clipboard Bridge group, pastes
the group's latest text, and joins the group, all through the lite member on the Raspberry Pi
inside the Accelerated Next. The Pi is a full lite member of the group (TLS 1.3, the same
certificates as every other device). The Next talks to it only over the UART between the
two, which never leaves the case (docs/roadmap.md, item 14). The frames on that UART are
described in [lite/README.md](../../lite/README.md#zx-spectrum-next).

Not yet run on a real Next: the UART speed taken from NR 0x7F, waking NextPi's shell, the
QR code on the screen, and the timeouts are written from the manual and NextPi's own
tools. Test them on the machine before relying on them.

## Use

```
.cbb paste            show the group's latest text
.cbb paste notes.txt  save it to a file
.cbb copy notes.txt   send a file (up to 8 KB)
.cbb text Hello Next  send the words
.cbb text -s hunter2  send a secret, such as a password (copy -s FILE too)
.cbb join             join the group: scan the code on the screen with the phone app
.cbb -d paste         the same, with the cause under each error (debug mode)
```

SPACE stops a command that waits, such as `join` while the phone has not scanned yet.

Texts use the Spectrum character set: printable ASCII, the pound sign and the copyright
sign. The lite member on the Pi converts them; every other character arrives as `?`. Cyrillic
comes later.

## Set up the Pi

1. Make sure NextPi answers: `.pisend -q`.
2. Copy the lite member's binary `cbb` for the Pi Zero (from
   `clipboardbridge-lite-linux-armv6` of a release) to the Pi, for example with `.piput`, and put it on the shell's `PATH` (NextPi's root is
   read-only: `mount -o remount,rw /`, copy, `mount -o remount,ro /`).
3. Give the Pi a network: the Zero W's own Wi-Fi, which NextPi turns off, or the Next's
   ESP8266 (planned).
4. Start `cbb run` at boot, then run `.cbb join` on the Next.

The exact NextPi paths and the start script come with the first test on a real Next.

## Build

With [z88dk](https://github.com/z88dk/z88dk) 2.3 (`zcc` on the `PATH`, `ZCCCFG` pointing
at its `lib/config`):

```sh
make          # build/CBB: copy it to C:/DOT on the Next's SD card
make test     # the frame parser's tests, with the host's C compiler
```

CI's `ZX Spectrum Next` job builds z88dk from its release source, checked against a
SHA-256, and runs both.
