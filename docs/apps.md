<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phone apps

The iPhone and Android apps make the phone the root of the group (see "Target architecture
with the phone apps" in [design.md](design.md)). This document fixes what they do and how
they look, so both apps are built to the same plan.

## Principles

- **Only what is needed.** Pair the first computer, add a computer, send and fetch the
  clipboard, see who is connected. Nothing else: no history, no accounts, no cloud, no
  statistics.
- **As few taps as possible.** The everyday action is one tap or none: the widget, the
  Back Tap or Action button shortcut, the share sheet, the Android quick-settings tile.
  Adding a computer is "scan" and nothing more; digits are typed only when a camera cannot
  be used.
- **Modern and a little hacker-like.** A dark, deep background with a slow, subtle animated
  grid or noise; a monospaced face for codes, device IDs and fingerprints; one bright accent
  colour (default: terminal green) for the main action and live states; rounded, generous
  buttons; short, plain words. Motion is sparing and honours Reduce Motion.
- **Native underneath.** SwiftUI on iOS and Jetpack Compose on Android, the platform's own
  controls, Dynamic Type and font scaling, VoiceOver and TalkBack labels, haptics on success
  and failure.

## Screens

1. **Start** (no group yet): one sentence and one button, "Scan a computer". The computer
   shows its QR code with `clipbridge join` (or `clipbridge pair -phone` in the mode
   without the app). The camera opens at once; after the scan the app creates the group
   key in the Secure Enclave or StrongBox, admits the computer and goes to Home.
2. **Home**: the one big button (send what this phone holds or fetch the computer's recent
   copy, by the same rule as the shortcut), the result in one line, and the connected
   computers as a compact list with a live dot each. A "+" adds a computer (camera).
3. **Add a computer**: the camera with a frame; the computer appears in the list when it
   has joined. Fallback: type the six digits.
4. **Settings**: theme, language, the devices of the group (rename, remove), the backup of
   the group key, about. Nothing else.

Errors are one line in plain words with the next step ("Turn on the computer that holds
the group", not a status code), never a dialog that must be dismissed.

## Languages

- Every user-facing string comes from the platform's catalog from the first screen on: a
  String Catalog (`Localizable.xcstrings`) on iOS, `strings.xml` resources on Android. No
  string literal in views.
- English is the source language; Russian is the first translation. Plurals, numbers and
  dates use the platform's formatters.
- The layout survives longer translations and right-to-left scripts (no fixed widths for
  text; leading and trailing, not left and right).
- The language follows the system, with an override in Settings.

## Themes

- Colours, type, spacing and corner radii are design tokens, defined once in
  `apps/design/tokens.json` and generated into Swift and Kotlin, so both apps match.
- Built-in themes: **Terminal** (default: near-black background, green accent),
  **Midnight** (blue-violet accent), **Amber** (retro amber accent), and **Light** (a light
  background with the same accents, for bright rooms). "System" follows the system's light
  or dark mode with the Terminal and Light themes.
- A theme is a set of tokens, so adding one later is data, not code.
- Contrast meets WCAG AA for text in every theme.

## Layout of the repository

- `apps/ios/` — the Xcode project (SwiftUI), built and tested in CI on macOS runners, and
  `apps/ios/ClipbridgeKit`, the Swift package with the protocol core (CPace, the pairing
  frames, the join QR code, later the member protocol). It has no UI and runs on Linux too;
  its tests check it against the vectors that the Go tests write to `testdata/interop/`
  (`go test ./internal/pair ./internal/phone -update` regenerates them).
- `apps/android/` — the Gradle project (Kotlin, Compose), built and tested in CI on Linux.
- `apps/design/` — tokens and the icon; `apps/l10n/` — the shared glossary of terms, so
  both apps use the same words.
- The protocol both apps speak is [protocol.md](protocol.md).
