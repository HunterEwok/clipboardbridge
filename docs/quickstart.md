<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Quick start

The shortest way to one clipboard: install with one command, make a group, add your devices.
Everything stays on your home network.

Today a Linux machine holds the group and the iPhone uses a shortcut. When the phone apps are
released, the phone becomes the centre of the group; that way is described at the end.

## 1. Install on the first Linux machine

Any Linux with systemd: a Raspberry Pi, a laptop, a server, a Steam Deck.

```sh
curl -fsSL https://github.com/HunterEwok/clipbridge/releases/latest/download/get.sh | sudo sh
```

The script checks the download, starts the service and opens clipbridge's ports in ufw or
firewalld for the home network only; with another firewall it prints what to allow. Log out
and in again once, so your user may use clipbridge.

If you turn a firewall on later, run the installer again (it is also how you update): it adds
the rules each time. By hand with ufw, from your home network, for example `192.168.0.0/24`:

```sh
sudo ufw allow proto tcp from 192.168.0.0/24 to any port 8764:8767 comment clipbridge
sudo ufw allow proto udp from 192.168.0.0/24 to any port 5353 comment 'clipbridge mDNS'
```

## 2. Make the group and pair the iPhone

On that machine:

```sh
clipbridge pair -phone
```

This creates the group and prints a QR code, the start of a fingerprint and a six-digit code.

1. Scan the QR code with the iPhone's camera and follow the page: install the profile.
2. Check that its fingerprint starts with the printed one (Settings → General → VPN & Device
   Management → clipbridge → More Details), then turn on full trust for it (Settings →
   General → About → Certificate Trust Settings).
3. Add the shortcuts from the same page, "clipbridge" and "clipbridge: add a computer", and
   run "clipbridge" once; it asks for the six-digit code.
4. Put "clipbridge" on the Action button or on Back Tap (Settings → Accessibility → Touch →
   Back Tap → Double Tap).

No iPhone? Run `clipbridge pair` instead; it creates the group and shows a code for the next
computer.

## 3. Add more computers

Install on each computer first.

- **Linux**: the same command as in step 1.
- **Mac** (Apple silicon; `amd64` instead of `arm64` for Intel), in Terminal:

  ```sh
  curl -fsSLO https://github.com/HunterEwok/clipbridge/releases/latest/download/clipbridge-darwin-arm64.tar.gz
  tar -xzf clipbridge-darwin-arm64.tar.gz
  sudo sh clipbridge/packaging/macos/install.sh clipbridge/clipbridge
  ```

Then, on the new computer:

```sh
clipbridge join
```

It shows a QR code. On the iPhone, run the shortcut "clipbridge: add a computer" and scan
it. The computer joins within seconds.

Without the iPhone: run `clipbridge pair` on a Linux machine of the group, then
`clipbridge join -code` on the new computer and type the code it showed.

## 4. Use it

- **Between computers**: copy on one, paste on another. Nothing else to do.
- **iPhone**: one press of the Action button (or a double tap on the back) picks the
  direction. Copied on a computer a moment ago: the text comes to the iPhone. Otherwise a new
  text copied on the iPhone goes to the computers, and with nothing new on the iPhone the
  computers' latest text comes to it.
- **Without a desktop**: `clipbridge copy` and `clipbridge paste`, or copy and paste inside
  tmux.

## 5. Look after the group

```sh
clipbridge status     # this device, the group and the connected members
clipbridge devices    # every device of the group, and when it was last seen
clipbridge revoke NAME  # remove a lost Mac or iPhone; run it on a Linux machine
```

Something does not work? See "Problems" in the release notes, or open an issue.

## Later: the phone at the centre (planned)

When the iPhone and Android apps are released, the phone holds the group's key, and the
computers join it:

1. Install the app and tap "Scan a computer".
2. On each computer, install clipbridge (step 1 or 3) and run `clipbridge join`; the app
   scans its QR code. No profile, no code to type.
3. A second phone joins the same way, and the first one can make it an admin. If one phone is
   lost, remove it from Devices on the other; the computers stay in the group.

The Linux machines then take part like the Mac: they sync, and still serve the shortcut for
phones without the app. Until then, the steps above are the way.
