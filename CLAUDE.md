# clipboardbridge: notes for Claude Code

clipboardbridge syncs the clipboard between Linux computers, Windows PCs, Macs and an iPhone on
the home network. A Go service (`cmd/cbb`, `internal/...`) runs on the computers; the iPhone
app (`apps/ios`) is in development, and in its groups the phone is the root of trust.
Read [README.md](README.md), [docs/design.md](docs/design.md),
[docs/protocol.md](docs/protocol.md) (the wire format, kept in step with the code) and
[docs/apps.md](docs/apps.md) before larger changes.

## Working with the owner

- Talk to the owner in **Russian**. Everything in the repository is **English**: code,
  comments, docs, commit messages, PRs. The only exception is the apps' translations
  (`*.xcstrings`, Android `values-xx/strings.xml` later); `tools/repocheck` enforces it.
- Work through a task list in order without stopping to ask; ask only when a decision is
  genuinely the owner's.
- Every change goes to `main` through a pull request: push a branch, open it as a draft,
  mark it ready, and squash-merge it yourself once CI is green (`ci-ok` and the other
  checks; CodeQL's Swift analysis is slow and not required). The Codex review bot often
  fails on usage limits; ignore that.
- After a merge, start the next branch from a fresh `origin/main`.
- Release tags are pushed by the owner from their Mac (`git tag vX.Y.Z && git push origin
  vX.Y.Z`); the release workflow builds and publishes. Move CHANGELOG's *Unreleased* to the
  version in a PR first.
- Apple signing must never block development: CI signs the app ad hoc
  (`CODE_SIGN_IDENTITY=-`, no team), which needs no account and gives the simulator a
  keychain. TestFlight waits for the owner's Apple developer account.
- Commit messages: imperative summary, blank line, details; no model names. The owner's
  personal notes and testing guides stay out of the repository.
- Follow [CONTRIBUTING.md](CONTRIBUTING.md): license headers, CHANGELOG under *Unreleased*,
  copied code under `internal/third_party`.

## Build and test

Go, from the repository root (the same as CI's `check` and `test` jobs):

```sh
gofmt -l .
go vet ./...
go tool staticcheck ./...
go tool govulncheck ./...
go tool actionlint
go run ./tools/repocheck
go run ./tools/tokens -check   # apps/design/tokens.json -> Swift, WCAG contrast
go run ./tools/icon -check     # the app icon
go test -race ./...
```

The lite member (Rust, the `lite` job in CI):

```sh
cd lite && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo build -p clipboardbridge-core --target riscv32imac-unknown-none-elf   # the core without an OS
cargo build --release && cd .. && CBB_LITE=$PWD/lite/target/release/cbb-lite \
  go test ./internal/service -run TestLiteMember   # joins by the phone, syncs with Go members
```

The Android app (`apps/android`, Gradle 9 with JDK 17 or later): the protocol core `kit` has
no Android dependencies and builds anywhere; the app needs the Android SDK and Google's Maven
repository (CI, or a Mac with Android Studio):

```sh
cd apps/android && ./gradlew -p kit test
cd apps/android && ./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug
```

The phone kit (Swift package, runs on Linux too):

```sh
cd apps/ios/ClipboardBridgeKit && swift test
```

Cross tests between Go and Swift: Swift tests write vectors that Go reads, and the other way.

- `CBB_INTEROP_OUT=<dir> swift test` writes fresh `swift-records.json`,
  `swift-renewal.json` and `swift-admin.json`; then
  `CBB_INTEROP_OUT=<dir> go test ./internal/group -run 'TestSwift'` reads them.
  Without the variable Go reads the committed copies in `testdata/interop`.
- `CBB_SWIFT_INTEROP=<path to clipboardbridge-interop>` runs
  `TestSwiftMemberAdmitsGoJoiner` (pairing over plain TCP); on macOS
  `CBB_SWIFT_INTEROP_TLS` runs the real-TLS pairing and member tests (see the
  `phone kit` job in `.github/workflows/ci.yml` for the keychain setup).
- The Kotlin kit does the same: `CBB_INTEROP_OUT=<dir> ./gradlew -p kit test` writes the
  same files, and `./gradlew -p kit interopScript` builds
  `kit/build/interop/clipboardbridge-interop`, which plays the Android phone in those three
  Go tests on Linux too (TLS from Conscrypt; the `Android app` job runs them).

The app (macOS with Xcode):

```sh
brew install xcodegen
cd apps/ios && xcodegen generate   # ClipboardBridge.xcodeproj and Info.plist are not committed
xcodebuild test -project ClipboardBridge.xcodeproj -scheme ClipboardBridge \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=  # any installed iPhone simulator
```

To run it on a phone, open the project in Xcode, pick your team under Signing, and run.

## Layout

- `internal/group`: identities, certificates (group CA, admin CAs, member certificates),
  member TLS, signed device and revocation records.
- `internal/pair`: pairing (CPace inside TLS, the Welcome), both directions.
- `internal/node`: the member protocol and sync; `internal/service`: the daemon and CLI.
- `internal/tunnel`: WireGuard for sync away from home (wireguard-go with gVisor netstack in
  the process): the hub, which opens only the member port to its clients, and the client;
  `state.go` and `internal/service/tunnel.go` exchange its keys in the member protocol
  (docs/protocol.md, section 11).
- Windows: `cmd/cbb/platform_windows.go` (the Windows service, logs),
  `internal/service/control_windows.go` (the socket's access list),
  `internal/pasteboard/pasteboard_windows.go` (the Win32 clipboard), `packaging/windows`
  (`install.ps1`, `uninstall.ps1`, `get.ps1`); CI's `windows installer` job runs them.
- `apps/ios/ClipboardBridgeKit`: the phone's protocol core: `Pairing*`, `Member`, `SyncEngine`,
  `MemberNode`, `Records`, `Certificates`, `PhoneGroup`, `Discovery`/`BonjourBrowser`,
  `TLSTransport`, `KeychainIdentity`, `SecKeySigner`; `clipboardbridge-interop` plays the phone
  in Go tests.
- `lite/`: the lite member in Rust (`cbb-lite`): no CA keys, joins by the phone's QR code,
  dials the Linux members and listens for phones and Macs (mDNS TXT `r=lite`). Its protocol core is the crate `lite/core` (`cbb_core`: `certs`,
  `records`, `clip`, `hlc`, `wire`, `pair`, `identity`, CPace under `src/third_party`, the
  interop vectors, and with the `tls` feature `tls`: rustls unbuffered with a RustCrypto
  provider, the peer checks, a sans-I/O `Session`, the pairing exporter from the key log):
  no_std with alloc, RustCrypto, no I/O, for the ESP32; CI's `esp32` job builds it for the
  C6 (RISC-V) and the S3 (Xtensa); `lite/src` adds the files, the sockets around the
  core's TLS, mDNS and the control socket.
- `apps/android/kit`: the phone's protocol core in Kotlin, the Android twin of the Swift kit;
  `apps/android/app`: the Compose app.
- `apps/ios/ClipboardBridge`: the SwiftUI app (`AppModel`, `LiveGroup`, views, theme from
  `apps/design/tokens.json`, String Catalogs in English and Russian).

## Status

Done: the Go service (0.2.0 released); the app makes its own group (root key in the Secure
Enclave, Face ID before each signing action), admits computers by QR code, syncs with them,
shows the devices and removes them, renews certificates (any admin renews any device, the
`cert` message carrying its admin CA); admin CAs under the root work in Go and in the kit
(records, chains, Welcome `issuer`); a second phone joins from its Start
screen and the root makes it an admin (`PairingJoiner`, `TLSListener`, `PhoneGroup.joined`);
an admin phone removes a lost root phone by taking the group over with `root` records
(`PhoneGroup.takeOver`, `RecordSet.roots`, Go's `Records.Roots` and `Identity.Roots`);
a computer of a phone group can be an admin: the root phone's "Make it an admin" certifies
the admin key its hello offers (`PhoneGroup.makeAdmin`, the `admin` message; Go's
`Identity.AdminKey`/`AdminCA`); the lite member for Linux (`lite/`, `cbb-lite`), with
the interop vectors and an e2e test among Go members, not yet run on a real Pi; the
Android app (`apps/android`) does what the iPhone app does, receives copies by itself in a
foreground service and sends them with the accessibility service or one tap, and each
release carries its signed APK (docs/apps.md); Homebrew (`hunterewok/tap`); sync away
from home between computers, through a hub's WireGuard tunnel (`cbb away`).

Next steps, roughly in order:

1. TestFlight (needs the Apple account), a signed macOS `.pkg`, sync away from home for
   the phones and the lite member (it works between computers: `cbb away`, docs/protocol.md
   section 11), the lite member on the ESP32 (see docs/design.md, "Roadmap").

Windows (the service, the agent, the installers) passes CI on windows-latest but is not yet
tested on a real PC.

Not yet run on a real Android phone or emulator: the Keystore keys and BiometricPrompt,
`ACCESS_LOCAL_NETWORK` on Android 17, the accessibility overlay getting the focus, the copy
events of each maker's apps, the foreground service across reboots and battery savers.

Not yet verified on a real iPhone: Secure Enclave key creation with user presence, the
Face ID prompt and reuse of its context, the keychain identity lookup for TLS, listening
for a joining phone (`TLSListener`), the admin CA in the TLS chain, making a computer an admin and the takeover (a new
Secure Enclave root key signed right after the admin key). Test these on
a device before relying on them.
