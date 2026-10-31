# Contributing

Clipboard Bridge is developed by one maintainer. Thank you for your interest.

## Issues are welcome

- **Bugs:** open an issue with the bug report form.
- **Ideas and questions:** open an issue with the feature request form.
- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).
- **A commercial license:** open an issue with the commercial license form.

Forks and packages: see [BRAND.md](BRAND.md) for the icon, the name and official builds.

## Code contributions

Pull requests are not accepted at this time. This keeps the copyright of the whole project
with the maintainer, so the licensing stays simple and no contributor agreement is needed;
it is also what lets the maintainer offer a commercial license (see the
[README](README.md#license)).
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
- **Tests.** A change keeps every test function of every language, running: one that replaces
  a test keeps its name, and a test does not skip where it did not (`t.Skip`, `#[ignore]`,
  `XCTSkip`, `@Ignore`, an `assume`). `go run ./tools/repocheck -tests-since origin/main`
  lists the tests a branch lost or made skip, and CI runs it against the pull request's base.
- **Installers.** Every platform has the same three: a one-line `get` that downloads a
  release and checks it against `SHA256SUMS`, an `install` for an unpacked archive, and an
  `uninstall` that the install leaves on the machine. `get.sh` serves Linux and macOS,
  `get.ps1` Windows; CI runs each of them.
- **Documentation.** Each page says at the top who it is for and sits in its reader's part
  of [docs/README.md](docs/README.md), which `repocheck` checks: users' guides in plain
  words (`docs/guide`), administrators' pages (`docs/admin`), exact reference without the
  reasons (`docs/reference`), and the engineers' pages. A new command, flag or `CBB_*`
  variable goes into the reference in the same change. A change to the wire format changes
  The users' guides (`docs/guide`) are also translated into every language of the website,
  in `site/docs/<language>/guide/<page>.md`: the same headings, links, pictures and code
  blocks as the English page, only the text translated. When you change a guide page, change
  its translations in the same pull request (or say in it which languages are left), then
  run `go run ./tools/site docs-sync`; `go run ./tools/site check -strict` fails on a
  translation that follows an older page. The text inside the pictures of `docs/images` is
  translated in `tools/diagrams/l10n/<language>.json`; `python3 tools/diagrams/diagrams.py`
  draws them again. Every other page stays English and opens on GitHub from the website.
    [the protocol](docs/protocol.md), which is normative (MUST, SHOULD), its registries
  (section 19), the interop vectors and every implementation together
  ([testing](docs/testing.md)). A design that is built moves from the roadmap into the
  design.
- **No secrets.** No tokens, keys, real addresses or device names in the repository.
  GitHub secret scanning with push protection is enabled.

## Development

The checks that CI runs, by part. CI also builds every target; see
`.github/workflows/ci.yml` and the job list in [docs/maintaining.md](docs/maintaining.md#ci).

### Go

Clipboard Bridge needs Go; `go.mod` names the exact toolchain, and the `go` command downloads
it when needed. From the repository root:

```sh
gofmt -l .                     # prints nothing when the code is formatted
go mod tidy -diff
go mod verify
go vet ./...
go tool staticcheck ./...
go tool govulncheck ./...
go tool actionlint             # GitHub Actions workflows
pipx run zizmor==1.31.1 --offline --min-severity low .github/workflows   # their security
go run ./tools/repocheck       # English only, license headers, copied code, no programs or files over 1 MiB, documentation links and names
go run ./tools/tokens -check   # apps/design/tokens.json -> Swift and Kotlin, WCAG contrast
go run ./tools/icon -check     # the app icon
go test -race ./...
go build -o /dev/null ./cmd/cbb
GOOS=linux GOARCH=arm GOARM=6 go build -o /dev/null ./cmd/cbb   # Raspberry Pi Zero W
GOOS=freebsd go vet ./...                                         # FreeBSD (the freebsd job runs the tests)
# Big-endian, 32-bit MIPS, as on many routers (the mips job; qemu-user-static, with binfmt
# for the tests that start the test binary again):
GOARCH=mips GOMIPS=softfloat go test -exec qemu-mips-static ./internal/service ./internal/mdns ./cmd/cbb
```

### The other parts

The model of the records' rules for claims (Quint, Node; the `model` job in CI):

```sh
npx @informalsystems/quint@0.33.1 test --backend=typescript docs/model/claims.qnt
npx @informalsystems/quint@0.33.1 run --backend=typescript --invariant=promises --max-steps=12 --max-samples=20000 docs/model/claims.qnt
```

The lite member (Rust, the `lite` job in CI):

```sh
cd lite && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo build -p clipboardbridge-core --target riscv32imac-unknown-none-elf   # the core without an OS
cargo deny --locked check licenses bans sources   # the crates' licenses and sources (lite/deny.toml, CI's advisories job)
cargo build --release && cd .. && CBB_LITE=$PWD/lite/target/release/cbb \
  go test ./internal/service -run TestLiteMember   # joins by the phone, syncs with Go members, and through the hub's tunnel
```

The Nano ESP32's network code on Linux (`lite/embassy`, root for the TAP interface):

```sh
sudo ip tuntap add name tap0 mode tap user "$USER" && sudo ip addr add 192.168.69.1/24 dev tap0 \
  && sudo ip link set tap0 up
cd lite && cargo build --release -p clipboardbridge-embassy --features host && cd .. && \
  CBB_ESP32_ON_LINUX=$PWD/lite/target/release/esp32-on-linux go test ./internal/service -run TestEmbassyJoiner
```

The Android app (`apps/android`, Gradle 9 with JDK 17 or later): the protocol core `kit` has
no Android dependencies and builds anywhere; the app needs the Android SDK with the NDK of
`cbb.ndk` in `apps/android/gradle.properties`, Go for the tunnel (see below) and Google's
Maven repository (CI, or a Mac with Android Studio). It has two builds, full and fdroid
([docs/apps.md](docs/apps.md#f-droid)):

```sh
cd apps/android && ./gradlew -p kit test
cd apps/android && ./gradlew :app:assembleDebug :app:testFullDebugUnitTest :app:testFdroidDebugUnitTest :app:lintFullDebug :app:lintFdroidDebug
sh packaging/fdroid/reproduce.sh . /tmp/cbb-reproduce   # the F-Droid build is reproducible
cd apps/android && ./gradlew :shared:testDebugUnitTest :wear:assembleDebug :wear:lintDebug
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

The group rules of records `v:2` (docs/records-v2.md) reach the phones from the Rust core:
`lite/ffi` wraps `cbb_core::authority` for UniFFI, and its `bind.sh` builds the libraries and
writes the Swift and Kotlin bindings; the `phone core` jobs run it:

```sh
cd lite && cargo test -p clipboardbridge-ffi
ANDROID_NDK_HOME=<ndk> lite/ffi/bind.sh android OUT   # needs cargo-ndk
lite/ffi/bind.sh ios OUT                              # macOS with Xcode
lite/ffi/bind.sh jvm OUT                              # the host library, for JVM tests
```

The differential run of all four implementations (Go, Rust, JDK 17 and Docker for the Swift
container; [docs/differential.md](docs/differential.md)):

```sh
sh .github/differential.sh 1 20000 500 /tmp/differential
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
mobile/cbbtun/bind.sh ios apps/ios/Cbbtun.xcframework   # the tunnel the app links; needs Go
brew install xcodegen
cd apps/ios && xcodegen generate   # ClipboardBridge.xcodeproj and Info.plist are not committed
xcodebuild test -project ClipboardBridge.xcodeproj -scheme ClipboardBridge \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=  # any installed iPhone simulator
```

To run it on a phone, open the project in Xcode, pick your team under Signing, and run.

The tray app for Linux and Windows, a Go module of its own (Linux needs GTK 4 and
WebKitGTK: `sudo apt-get install libgtk-4-dev libwebkitgtk-6.0-dev`):

```sh
cd apps/desktop && go vet ./... && go test ./... && go build -o cbb-desktop .
# Windows: go build -ldflags -H=windowsgui -o cbb-desktop.exe .
```

The Mac app (macOS with Xcode):

```sh
cd apps/macos && xcodegen generate   # ClipboardBridgeMac.xcodeproj and Info.plist are not committed
xcodebuild test -project ClipboardBridgeMac.xcodeproj -scheme ClipboardBridgeMac \
  -destination 'platform=macOS' CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=
```

