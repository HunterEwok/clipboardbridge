<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Using the phone apps

The clipboardbridge apps for iPhone and Android make the phone the centre of the group: it
holds the group's key and admits every other device. They are built and tested in CI but not
yet on a real phone (see the [status](../README.md#status)); the Android app is an APK in each
[release](https://github.com/HunterEwok/clipboardbridge/releases), the iPhone app comes with
TestFlight. Phones without the app use the shortcut instead (the [quick start](quickstart.md)).

## Start a group

1. Install clipboardbridge on a computer (quick start, step 1 or 3) and run `cbb pair`
   there. It shows a QR code.
2. Open the app and tap **Connect a new device**. The camera opens; scan the code. The app
   makes the group's key (in the Secure Enclave on an iPhone, the Keystore on Android),
   admits the computer and opens Home.
3. Add each further computer the same way, with **+** on Home. A lite member joins the same
   way (`cbb-lite join`).

When a camera cannot be used, type the six digits the computer shows instead.

## Every day

- **Home** has one big button. It sends what the phone holds, or fetches the computers'
  latest copy if one was made in the last moments, by the same rule as the shortcut.
- **iPhone**: the app's "Sync clipboard" action works from Back Tap or the Action button
  without opening the app (Settings, Accessibility, Touch, Back Tap; or Settings, Action
  Button, Shortcut).
- **Android**: copies from the computers arrive by themselves. To send the phone's copies
  by themselves too, turn on **Send my copies by themselves** in the app (an accessibility
  service; the app explains what it reads). Without it, send with one tap: the Quick Settings
  tile "Send clipboard", the Send button in the notification, Share or text selection →
  clipboardbridge, or a back tap set to open "cbb send".

## Devices

**Devices** lists the whole group: each device's name, kind, whether it is online or when it
was last seen, and which phones are admins. On an admin phone, tap a device to rename or
remove it; removing asks once and then for Face ID, the fingerprint or the passcode.

- **A second phone**: on it, tap **I already use clipboardbridge on another phone**; it
  shows a QR code, which the first phone scans with **+**. The first phone (the root) makes
  it an admin, so that losing one phone loses nothing.
- **A lost phone**: open Devices on your other phone and remove it. The computers stay in
  the group; if the lost phone was the root, the other phone takes the group over in the
  same step.
- **A computer as admin**: on the root phone, a computer's row offers **Make it an admin**,
  after which that computer adds and removes devices with `cbb pair` and `cbb revoke`. Its
  key is a file on the computer, so do this only if you want to admit devices from a
  terminal.

## Settings

Theme (Terminal, Midnight, Amber, Light, System, and Wallpaper on Android 12 and later) and
language (System, English, Russian). Nothing else.

When something does not work, see [troubleshooting](troubleshooting.md).
