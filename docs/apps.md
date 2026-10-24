<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phone apps

The iPhone and Android apps make the phone the root of the group (see "The phone apps"
in [design.md](design.md)). This document fixes what they do and how
they look, so both apps are built to the same plan.

## Principles

- **Only what is needed.** Pair the first computer, add a computer, send and fetch the
  clipboard, see the group's devices and remove one. Nothing else: no history, no accounts,
  no cloud, no statistics.
- **As few taps as possible.** The everyday action is one tap or none: the widget, the
  Back Tap or Action button shortcut, the share sheet, the Android quick-settings tile.
  Adding a computer is "scan" and nothing more; digits are typed only when a camera cannot
  be used.
- **Modern and a little hacker-like.** A dark, deep background with a slow, subtle animated
  grid or noise; a monospaced face for codes, device IDs and fingerprints; one bright accent
  colour (default: terminal green) for the main action and live states; rounded, generous
  buttons on Liquid Glass (from iOS 26; a material before), cards and fields on glass too;
  short, plain words. Motion is sparing and honours Reduce Motion.
- **Native underneath.** SwiftUI on iOS and Jetpack Compose on Android, the platform's own
  controls, Dynamic Type and font scaling, VoiceOver and TalkBack labels, haptics on success
  and failure.

## Screens

1. **Start** (no group yet): one sentence, the big button "Connect a new device" with a hint
   below it (on a computer, run `cbb pair` and scan the code it shows; `clipboardbridge
   pair -phone` in the mode without the app), and a second button, "I already use
   clipboardbridge on another phone", which joins that phone's group. The camera opens at once;
   after the scan the app creates the group key in the Secure Enclave or StrongBox, admits
   the device and goes to Home. At the first launch the app makes this phone's own key and
   says so once, in a card: "This phone is ready", what the key is for in plain words, and
   that the next step is to connect a device. A gear opens Settings (theme and language)
   before there is a group; when the system's language has no translation, a language menu
   sits next to it, with English chosen.
2. **Home**: the one big button (send what this phone holds or fetch the computer's recent
   copy, by the same rule as the shortcut; when the phone's clipboard holds something the
   app cannot read as text, it is left as it is and the line says so), the result in one
   line, and the connected computers as a compact list with a live dot each; tapping the
   list opens Devices. A "+"
   adds a device (camera). The same button is the app's "Sync clipboard" action, which
   Shortcuts and Spotlight offer as soon as the app is installed (App Intents with an
   App Shortcut): Back Tap or the Action button runs it without opening the app; it waits
   a few seconds for a computer to connect and says what it did in one line.
3. **Add a device**: the camera with a frame; the device appears in the list when it has
   joined. Fallback: type the six digits. Another phone joins the same way: it shows its own
   QR code ("I already use clipboardbridge on another phone" on its Start screen) and this phone
   scans it.
4. **Devices**: the whole group, one row per device: its name, an icon and the name of its
   system (Linux, Windows, macOS, iOS, Android, or "device" for firmware; a lite member and an
   iPhone with the shortcut are marked so), a "root", "admin" or "frozen" mark, a live dot when it is online and
   "seen 5 min ago" otherwise, and "this phone" on its own row. The list is the group's
   device records (section 10 of [protocol.md](protocol.md)), so every app and
   `cbb status` show the same. On an admin phone, a row opens the device: rename,
   "Make it an admin" (phones only, on the root phone), "Unfreeze" for an admin computer
   that another admin froze (design.md, "Who may remove an admin"), and "Remove", which asks once, then
   needs Face ID, the fingerprint or the passcode, and is done; removing an admin phone shows
   the devices it had admitted, which stay. On the root phone a computer's row also offers
   "Make it an admin" when the computer offers an admin key (docs/protocol.md, section 10,
   "A computer as admin"): it asks once, warns that the key is a file on the computer, needs
   Face ID, and the computer then adds and removes devices with `cbb pair` and
   `cbb revoke`. If the removed phone held the root, this phone
   takes it over in the same step. A phone that is not an admin shows the list without
   actions and says which phones are admins.
5. **Settings**: theme, language, about, and once there is a group, "Away from home": one
   switch that turns sync away from home on for this phone (docs/design.md, "Sync away from
   home"), the words of the design on what changes, and where it stands: waiting for the
   hub's answer, which comes on the next connection at home; at home, syncing directly;
   connecting; connected through the tunnel. Turning it off forgets the phone's tunnel key.
   On Android the WireGuard key sits in the app's files, encrypted with a Keystore key that
   needs no unlock, so the foreground service syncs away from home as it does at home; the
   tunnel runs in the app's process (`mobile/cbbtun`) and opens a loopback port that the kit
   dials with its own member TLS, checking that the peer is the hub. On the iPhone the key
   and the hub's offer sit in the keychain, readable after the first unlock and on this
   device only; the same tunnel (`Cbbtun.xcframework`) runs while the app does, and the
   kit's `AwayFromHome` drives it in both the app and its tests. When the group's hub is
   obfuscated, its offer carries the AmneziaWG settings, and when it has its clients come
   over VLESS, the way there; both apps keep them with the offer and give them to the
   tunnel, which then reaches the hub only over VLESS. Nothing changes on the screen.

The lost phone case is one path, and the app says so in plain words: "Lost a phone? Open
Devices on your other phone and remove it." When the group has a single admin, Devices
suggests making a second phone an admin.

Errors are one line in plain words with the next step ("Turn on the computer that holds
the group", not a status code), never a dialog that must be dismissed.

## Android: the clipboard without taps

Since Android 10 an app reads the clipboard only while it has the input focus, or when it is
the default keyboard; writing works at any time. So the computers' copies reach the phone by
themselves, and the phone's copies need either the app's focus for a moment or a tap.

**Receiving, always automatic.** A foreground service (type `connectedDevice`, with the
ongoing notification Android requires) keeps one connection to each computer of the group
and puts what they copy on the phone's clipboard. It holds a multicast lock only while it
browses mDNS. Nothing to set up.

**Sending, automatic: "Send my copies by themselves".** An accessibility service that the
user turns on once, from a screen in the app that says what it is for and opens the right
page of Settings:

1. The service watches for a copy: a click on a "Copy" action (the platform's and the
   common apps' labels, in every language the system has), and from Android 13 the
   system's clipboard overlay that appears after each copy.
2. It then shows a 1-pixel accessibility overlay window that takes the focus for a moment,
   reads the clipboard, sends the text to the group and goes away. The service reads no
   screen content beyond what tells it that a copy happened, and the app says so.
3. Android 12 and later show "clipboardbridge pasted from your clipboard" each time; that
   is the system's notice and cannot be turned off.

On Android 13 and later, an APK installed from a browser or file manager cannot turn on an
accessibility service until "Allow restricted settings" is chosen in the app's App info
(⋮ menu). The setup screen shows that step with a button to App info; an install from
F-Droid or Google Play skips it. Google Play allows the service only with its accessibility
declaration; the GitHub and F-Droid builds have it from the start.

**Sending with one tap, without the service** (and always as well):

- the **Quick Settings tile** "Send clipboard";
- the **"Send" button** in the service's notification;
- **text selection → clipboardbridge** (`ACTION_PROCESS_TEXT`) and **Share → clipboardbridge**,
  which first ask "Allow" or "Always allow", since any app can hand over a text; "Always
  allow" holds for every app (Android does not tell reliably which one shared), and Settings
  turns the question on again;
- **double-tap the back**: on a Pixel, Settings → System → Gestures → Quick Tap → Open app →
  "cbb send" (a second launcher entry that sends and closes); on Samsung, Good Lock's
  RegiStar → Back-Tap action → Open app → "cbb send";
- **opening the app**, by the Home button's rule.

Each of these opens a transparent activity for a moment: it has the focus, reads the
clipboard, sends, says what it did in one line (a toast) and closes.

**To check on a device before building on it:** that the accessibility overlay gets the
focus the clipboard needs on Android 10 to 17, on a Pixel and a Samsung; which copy events
each OEM's apps give; that the restricted-settings path is as described on Android 15 to 17.
If the overlay does not get the focus, the service starts the transparent activity instead.

## Releasing the Android app

Each release carries `clipboardbridge-X.Y.Z.apk`, signed with the project's release key; the
key and its secrets are in [maintaining.md](maintaining.md#android-signing-key).

## Languages

- Every user-facing string comes from the platform's catalog from the first screen on: a
  String Catalog (`Localizable.xcstrings`) on iOS, `strings.xml` resources on Android. No
  string literal in views.
- English is the source language; Russian is the first translation. Plurals, numbers and
  dates use the platform's formatters.
- The layout survives longer translations and right-to-left scripts (no fixed widths for
  text; leading and trailing, not left and right).
- The language follows the system, with an in-app choice (System, English, Russian) in
  Settings, and on the Start screen when the system's language has no translation.

## Themes

- Colours, type, spacing and corner radii are design tokens, defined once in
  `apps/design/tokens.json` and generated into Swift and Kotlin, so both apps match.
- Built-in themes: **Terminal** (default: near-black background, green accent),
  **Midnight** (blue-violet accent), **Amber** (retro amber accent), and **Light** (a light
  background with the same accents, for bright rooms). "System" follows the system's light
  or dark mode with the Terminal and Light themes.
- A theme is a set of tokens, so adding one later is data, not code.
- On Android 12 and later a fifth choice, **Wallpaper** (Material You), takes the colours
  from the wallpaper through dynamic colour; the other themes stay as they are.
- Contrast meets WCAG AA for text in every theme.

## Layout of the repository

- `apps/ios/` — the app (SwiftUI): `project.yml` describes the Xcode project for XcodeGen
  (`cd apps/ios && xcodegen generate`; the generated project is not committed), built and
  tested on an iPhone simulator in CI without signing; and
  `apps/ios/ClipboardBridgeKit`, the Swift package with the protocol core (CPace, the pairing
  frames, the join QR code, the member protocol and the phone's sync engine). It has no UI
  and runs on Linux too; its tests check it against the vectors that the Go tests write to
  `testdata/interop/` (`go test ./internal/group ./internal/pair ./internal/phone ./internal/node -update`
  regenerates them), and CI runs it against the Go code: pairing over plain TCP on Linux,
  pairing and a member connection over real TLS on macOS.
- The app finds the Linux members by browsing `_clipboardbridge._tcp` (ClipboardBridgeKit's
  `BonjourBrowser` on iOS) and keeps one connection to each member of its group
  (`MemberDialer`). iOS asks once for local network access: the Info.plist lists
  `_clipboardbridge._tcp` under `NSBonjourServices` and explains the use in
  `NSLocalNetworkUsageDescription`.
- A phone joins another phone's group from its Start screen ("I already use clipboardbridge on
  another phone"):
  it makes its admin key, listens with `TLSListener` on a port the system picks, and shows
  the join QR code with its home network addresses (`LocalAddresses`). An admin phone scans
  it in "Add a device". The root phone makes every phone it admits an admin; an admin that
  is not the root admits phones as plain members. An admin phone that removes the root
  phone takes the group over (`PhoneGroup.takeOver`, protocol.md section 10, "Handing the
  group over"): it makes a new root key in the Secure Enclave behind Face ID, signs the
  `root` record with its admin key, then, as the new root, the revocation and its own record.
- `apps/android/` — the Gradle project (Kotlin, Compose), built and tested in CI on Linux.
- `apps/design/` — tokens and the icon (`icon/light.png` and `icon/dark.png`, the clipboard
  drawings; `go run ./tools/icon` sets each on a fill of its colour as the iPhone app's icon
  for light and dark mode, and the Android app takes the same drawings); `go run ./tools/tokens` turns `tokens.json` into
  `apps/ios/ClipboardBridge/Theme/Tokens.swift` and the Android app's `Tokens.kt` and fails when a theme misses the
  WCAG AA contrast, and CI checks that the generated files are up to date; `apps/l10n/` — the shared glossary of terms, so
  both apps use the same words.
- The protocol both apps speak is [protocol.md](protocol.md).
