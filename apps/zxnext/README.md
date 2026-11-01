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
   ESP8266 (planned). Many Accelerated boards carry a Pi Zero without a radio: NextPi's
   shell shows which (`cat /proc/device-tree/model`), and `ls /sys/class/net` lists only
   `lo` on such a Pi.
4. Start `cbb run` at boot, then run `.cbb join` on the Next.

The exact NextPi paths and the start script come with the first test on a real Next.

## Test bench: the Pi's shell over the network

`.pibridge` opens NextPi's shell (`SUP>`) to a computer on the home network, so a test can
drive the Pi without typing on the Next, even on a Pi Zero without a radio. The Next's
ESP8266 dials the computer in its stock AT firmware's passthrough mode, and the Z80 copies
bytes between the Pi's UART and the ESP's until SPACE is pressed. The shell is root's and
travels in the clear: use it only on a network of your own, and only while testing.

1. Join the ESP8266 to the Wi-Fi network once, as NextZXOS's own tools do.
2. On the computer, listen on one port and take only the Next's address:

   ```sh
   socat TCP-LISTEN:2323,reuseaddr,range=NEXT_IP/32 -,raw,echo=0
   ```

3. On the Next: `.pibridge COMPUTER_IP 2323` (`.pibridge -d ...` shows the ESP's answers,
   its firmware version among them). The computer gets the `SUP>` prompt.
4. SPACE on the Next stops it. It then says how many bytes went each way, how full its ring
   towards the ESP got, and whether a receive buffer filled up, which would mean lost bytes.

It runs the Z80 at 28 MHz while it works. The ESP can take the Pi's output more slowly than
the Pi writes it, so the bridge sends the Pi XOFF when its ring is three quarters full and
XON when it has room again; that needs `ixon` on the Pi's terminal (`stty -a` shows it).

Not yet run on a real Next: the ESP's speed (115200, its stock one), the UART status bit
for a full buffer, and passthrough's timing.

## Build

With [z88dk](https://github.com/z88dk/z88dk) 2.3 (`zcc` on the `PATH`, `ZCCCFG` pointing
at its `lib/config`):

```sh
make          # build/CBB and build/PIBRIDGE: copy them to C:/DOT on the Next's SD card
make test     # the frame parser's tests, with the host's C compiler
```

CI's `ZX Spectrum Next` job builds z88dk from its release source, checked against a
SHA-256, and runs both; the run keeps `CBB` and `PIBRIDGE` as its artifact
`clipboardbridge-zxnext-dot`.
