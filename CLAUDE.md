# clipbridge: notes for Claude Code

clipbridge syncs the clipboard between Linux computers, Macs and an iPhone on the home
network. A Go service (`cmd/clipbridge`, `internal/...`) runs on the computers; the iPhone
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

The phone kit (Swift package, runs on Linux too):

```sh
cd apps/ios/ClipbridgeKit && swift test
```

Cross tests between Go and Swift: Swift tests write vectors that Go reads, and the other way.

- `CLIPBRIDGE_INTEROP_OUT=<dir> swift test` writes fresh `swift-records.json`,
  `swift-renewal.json` and `swift-admin.json`; then
  `CLIPBRIDGE_INTEROP_OUT=<dir> go test ./internal/group -run 'TestSwift'` reads them.
  Without the variable Go reads the committed copies in `testdata/interop`.
- `CLIPBRIDGE_SWIFT_INTEROP=<path to clipbridge-interop>` runs
  `TestSwiftMemberAdmitsGoJoiner` (pairing over plain TCP); on macOS
  `CLIPBRIDGE_SWIFT_INTEROP_TLS` runs the real-TLS pairing and member tests (see the
  `phone kit` job in `.github/workflows/ci.yml` for the keychain setup).

The app (macOS with Xcode):

```sh
brew install xcodegen
cd apps/ios && xcodegen generate   # Clipbridge.xcodeproj and Info.plist are not committed
xcodebuild test -project Clipbridge.xcodeproj -scheme Clipbridge \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=  # any installed iPhone simulator
```

To run it on a phone, open the project in Xcode, pick your team under Signing, and run.

## Layout

- `internal/group`: identities, certificates (group CA, admin CAs, member certificates),
  member TLS, signed device and revocation records.
- `internal/pair`: pairing (CPace inside TLS, the Welcome), both directions.
- `internal/node`: the member protocol and sync; `internal/service`: the daemon and CLI.
- `apps/ios/ClipbridgeKit`: the phone's protocol core: `Pairing*`, `Member`, `SyncEngine`,
  `MemberNode`, `Records`, `Certificates`, `PhoneGroup`, `Discovery`/`BonjourBrowser`,
  `TLSTransport`, `KeychainIdentity`, `SecKeySigner`; `clipbridge-interop` plays the phone
  in Go tests.
- `apps/ios/Clipbridge`: the SwiftUI app (`AppModel`, `LiveGroup`, views, theme from
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
`Identity.AdminKey`/`AdminCA`).

Next steps, roughly in order:

1. TestFlight (needs the Apple account), Android, Windows, Homebrew, a signed macOS `.pkg`,
   sync away from home, the lite member (see docs/design.md, "Future research").

Not yet verified on a real iPhone: Secure Enclave key creation with user presence, the
Face ID prompt and reuse of its context, the keychain identity lookup for TLS, listening
for a joining phone (`TLSListener`), the admin CA in the TLS chain, making a computer an admin and the takeover (a new
Secure Enclave root key signed right after the admin key). Test these on
a device before relying on them.
