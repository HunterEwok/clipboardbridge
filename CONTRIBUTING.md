# Contributing

clipboardbridge is developed by one maintainer. Thank you for your interest.

## Issues are welcome

- **Bugs:** open an issue with the bug report form.
- **Ideas and questions:** open an issue with the feature request form.
- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).

## Code contributions

Pull requests are not accepted at this time. This keeps the copyright of the whole project
with the maintainer, so the licensing stays simple and no contributor agreement is needed.
If you have found a fix, please describe the problem and the idea of the fix in an issue.

Pull requests from forks are closed without review.

## Conventions

The maintainer follows these rules; they are written down to keep the history consistent.

- **English only** in code, comments, documentation, commit messages and issues; the apps'
  translations are the one exception.
- **License header.** Every Go file, except generated code and code copied from other
  projects, starts with:

  ```go
  // SPDX-License-Identifier: AGPL-3.0-only
  // Copyright (C) 2026 HunterEwok
  ```

  Scripts and other source files start with the same two lines in their own comment style.

- **Copied code** lives in its own directory below `internal/third_party`, with its
  `LICENSE` and a `README.md` that names the source and version; its files keep their own
  copyright notices.

- **Pull requests.** Every change goes into `main` through a pull request and is merged with
  squash. `main` is protected.
- **Commit messages.** A short summary line in the imperative mood ("Add the pairing
  window"), then a blank line and the details, if any.
- **Changelog.** User-visible changes go into [CHANGELOG.md](CHANGELOG.md) under
  *Unreleased*.
- **Go code.** `gofmt`, `go vet`, `staticcheck` and `govulncheck` pass, and tests cover the
  change.
- **Installers.** Every platform has the same three: a one-line `get` that downloads a
  release and checks it against `SHA256SUMS`, an `install` for an unpacked archive, and an
  `uninstall` that the install leaves on the machine. `get.sh` serves Linux and macOS,
  `get.ps1` Windows; CI runs each of them.
- **No secrets.** No tokens, keys, real addresses or device names in the repository.
  GitHub secret scanning with push protection is enabled.

## Development

The checks that CI runs, by part. CI also builds every target; see
`.github/workflows/ci.yml` and the job list in [docs/maintaining.md](docs/maintaining.md#ci).

### Go

clipboardbridge needs Go; `go.mod` names the exact toolchain, and the `go` command downloads
it when needed. From the repository root:

```sh
gofmt -l .                     # prints nothing when the code is formatted
go mod tidy -diff
go mod verify
go vet ./...
go tool staticcheck ./...
go tool govulncheck ./...
go tool actionlint             # GitHub Actions workflows
go run ./tools/repocheck       # English only, license headers, copied code, documentation links and names
go run ./tools/tokens -check   # apps/design/tokens.json -> Swift and Kotlin, WCAG contrast
go run ./tools/icon -check     # the app icon
go test -race ./...
go build -o /dev/null ./cmd/cbb
GOOS=linux GOARCH=arm GOARM=6 go build -o /dev/null ./cmd/cbb   # Raspberry Pi Zero W
```

### The other parts

The lite member (Rust, the `lite` job in CI):

```sh
cd lite && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo build -p clipboardbridge-core --target riscv32imac-unknown-none-elf   # the core without an OS
cargo build --release && cd .. && CBB_LITE=$PWD/lite/target/release/cbb-lite \
  go test ./internal/service -run TestLiteMember   # joins by the phone, syncs with Go members
```

The Android app (`apps/android`, Gradle 9 with JDK 17 or later): the protocol core `kit` has
no Android dependencies and builds anywhere; the app needs the Android SDK with its NDK, Go
for the tunnel (see below) and Google's Maven repository (CI, or a Mac with Android Studio):

```sh
cd apps/android && ./gradlew -p kit test
cd apps/android && ./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug
```

The phone kit (Swift package, runs on Linux too):

```sh
cd apps/ios/ClipboardBridgeKit && swift test
```

The phones' tunnel (`mobile/cbbtun`, WireGuard for sync away from home) is a Go package that
gomobile binds for both apps; the `phone tunnel` jobs build it (the Android NDK for the AAR,
Xcode for the framework):

```sh
go test -race ./mobile/...
ANDROID_NDK_HOME=<ndk> mobile/cbbtun/bind.sh android cbbtun.aar
mobile/cbbtun/bind.sh ios Cbbtun.xcframework   # macOS with Xcode
```

The Android app's build runs `bind.sh` itself (the `bindTunnel` task), so building the app
needs Go besides the Android SDK and its NDK.

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
mobile/cbbtun/bind.sh ios apps/ios/Cbbtun.xcframework   # the tunnel the app links; needs Go
brew install xcodegen
cd apps/ios && xcodegen generate   # ClipboardBridge.xcodeproj and Info.plist are not committed
xcodebuild test -project ClipboardBridge.xcodeproj -scheme ClipboardBridge \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=  # any installed iPhone simulator
```

To run it on a phone, open the project in Xcode, pick your team under Signing, and run.

