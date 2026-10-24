# Maintaining

Settings and routines that live outside the repository files. Only the owner can change them;
a checked box means the setting is in place.

## Account

- [x] Two-factor authentication on the GitHub account, preferably with a passkey or a
  security key. This protects the repository more than any setting below.
- [ ] Optional: sign commits with an SSH key (`git config gpg.format ssh`) and add the key
  to GitHub as a signing key, so commits show as Verified.

## Repository settings

**Settings → General**

- [x] Features: Wiki and Projects off; Issues on.
- [x] Pull Requests: only **squash merging**; **Automatically delete head branches** on.
- [x] Releases: **release immutability** on.

**Settings → Moderation**

- Interaction limits are for a temporary cool-down only and are normally off.
- Conduct reports go to GitHub Support through **Report content**, as
  [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) says. A repository of a personal account has no
  option to send reports to the repository admins, and no email address is published.

**Settings → Advanced Security** (named Code security on some accounts)

- [x] **Private vulnerability reporting**. [SECURITY.md](../SECURITY.md) relies on it.
- [x] **Dependency graph**, **Dependabot alerts** and **Dependabot security updates**.
- [x] **Secret scanning** and **Push protection**.
- [ ] **CodeQL** default setup off: the workflows `.github/workflows/codeql.yml` (advanced
  setup) scan GitHub Actions, Go, Rust and Kotlin on every pull request, and
  `codeql-swift.yml` scans the iPhone app and its kit when `apps/ios` changes, weekly, by
  hand and before each release. GitHub rejects their results while the default setup is on.
  The default setup cannot build the Kotlin app and builds only the kit, not the iPhone app.

**Settings → Actions → General**

- [x] Workflow permissions: **Read repository contents and packages permissions**.
- [x] **Allow GitHub Actions to create and approve pull requests** off.
- [x] Fork pull request workflows: **Require approval for all external contributors**.

**Settings → Rules → Rulesets**

Branch ruleset **Production Branch Protection** (made from the GitHub template), active,
targeting the default branch:

- [x] Restrict deletions and block force pushes.
- [x] Require linear history.
- [x] Require a pull request before merging: 0 required approvals and **Require extra
  approval for unattributed changes** off, because a single maintainer cannot approve their
  own pull request; squash is the only merge method.
- [x] Require the status check `ci-ok` from the GitHub Actions app, with the branch up to date
  before merging. `ci-ok` is the last job of [the CI workflow](../.github/workflows/ci.yml)
  and passes only when every other job passed, so CI jobs can change without touching the
  ruleset.
- [x] Bypass list empty.

Tag ruleset **releases**, active, targeting `refs/tags/v*`:

- [x] Restrict updates and deletions, and block force pushes, so a release tag cannot be
  moved. Creation stays allowed: with an empty bypass list, restricting it would block every
  release.

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every pull request and on
`main`:

- **check**: `gofmt`, `go mod tidy`, `go mod verify`, `go vet`, `staticcheck`,
  `govulncheck`, `actionlint` for the workflows,
  [the repository rules](../tools/repocheck/main.go) (English only, apart from the apps'
  translations; license headers in Go and Rust files; copied code with its license; the documentation's
  links, the old name and the command reference), and the design
  tokens (`go run ./tools/tokens -check`);
- **test**: `go test -race` on Linux x86-64, Linux ARM64 and macOS;
- **build**: a cgo-free build (`CGO_ENABLED=0`) for every Linux and Windows target, static
  on Linux, including ARMv6 for the Raspberry Pi Zero W; the macOS targets on macOS runners
  with cgo, for the pasteboard agent (see the Build section of [the design](design.md#build));
- **mdns with avahi**: the mDNS tests on real sockets, beside avahi-daemon, in a Debian
  container;
- **e2e**: the built binary as three members and an avahi resolver in Docker containers:
  pairing, sync, the holder of `clipboardbridge.local` and its handover, a wrong code
  ([tools/e2e/e2e.sh](../tools/e2e/e2e.sh));
- **desktop clipboards**: the Wayland data-control client under a headless sway and the X11
  client under Xvfb, against wl-clipboard and xclip;
- **packaging**: shellcheck for the scripts, `systemd-analyze verify` and `security` for the
  unit, and the desktop entry;
- **homebrew**: the formula written by `packaging/homebrew/formula.sh`, installed with
  Homebrew on macOS;
- **windows installer**: `install.ps1`, the service, the agent and `uninstall.ps1` on
  windows-latest;
- **phone kit**: ClipboardBridgeKit's tests on Linux and macOS, and its cross tests with the Go
  code (pairing over plain TCP on Linux; pairing and a member connection over TLS on macOS);
- **iPhone app**: the Xcode project from XcodeGen, built and tested on an iPhone simulator
  without signing;
- **Android app**: the Kotlin kit's tests and its cross tests with the Go code, and the app
  built, unit-tested and linted;
- **lite member (Rust)**: `cargo fmt`, `clippy` and the tests of `lite/`, the ARM64 and
  ARMv6 builds, and the e2e test of the lite member among Go members;
- **lite core on the ESP32**: the lite protocol core with its TLS built for the ESP32-C6 (RISC-V) and the
  ESP32-S3 (Xtensa), and the Nano ESP32 firmware (`lite/esp32`) built, its console and
  flash settings tested and its self-test run in Espressif's QEMU (both downloaded by hash);
- **ZX Spectrum Next**: the tests of the `.cbb` frame parser on the host, and the dot command
  built with z88dk (from its release source, checked by hash, cached);
- **ci-ok**: the summary that the ruleset requires.

Rules for workflows:

- Pin every action to a full commit SHA, with the version in a comment; Dependabot updates
  them.
- Set `permissions: contents: read` at the workflow level; grant more to a single job only
  when it needs it.
- Check out with `persist-credentials: false`.
- Pull request workflows get no secrets.
- Tools such as `staticcheck`, `govulncheck` and `actionlint` are pinned in `go.mod` and run
  with `go tool`. Go records them as indirect requirements, so `.github/dependabot.yml` allows
  them by name; otherwise Dependabot would never update them.

## Releases

- Before the tag, a pull request moves the changes under `## [Unreleased]` in
  `CHANGELOG.md` to a new `## [X.Y.Z] - YYYY-MM-DD` section and updates the link
  references at the end of the file; the release notes are built from that section
  (`packaging/release-notes.sh`), which fails the release if it is missing.
- Built by CI from a tag, never on a laptop: push a tag `vX.Y.Z` on main
  (`git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`), and
  `.github/workflows/release.yml` builds the archives, `SHA256SUMS` and the attestations and,
  once the iPhone app's CodeQL analysis passes on the tag (about 45 minutes),
  publishes the release, with notes generated from the merged pull requests. A tag with a
  hyphen (`v0.2.0-rc.1`) makes a pre-release, which `releases/latest` and so `get.sh` skip.
- The archives are `clipboardbridge-<os>-<arch>.tar.gz` without the version, so that
  `releases/latest/download/` has fixed names for `get.sh`; each holds `clipboardbridge/` with the
  binary, `LICENSE`, `THIRD_PARTY_NOTICES` (the licenses of the Go modules, the copied code
  and Go itself, written by `packaging/archive.sh`) and `packaging/`. The `cbb-lite-linux-*`
  archives hold `cbb-lite/` in the same way (`lite/packaging/archive.sh`), with the crates'
  licenses (`lite/packaging/notices.sh`), the same Linux installer and the lite member's unit.
- The iPhone shortcuts are the one exception: iOS imports only shortcuts signed with an
  Apple ID, which needs a Mac. When `go run ./tools/shortcut` changes `clipboardbridge.plist` or
  `clipboardbridge-add.plist`, sign each changed one (here `NAME`) on a Mac:
  `plutil -convert binary1 -o /tmp/NAME-unsigned.shortcut internal/phone/shortcut/NAME.plist`
  (`shortcuts sign` reads only the binary form) and
  `shortcuts sign --mode anyone --input /tmp/NAME-unsigned.shortcut --output internal/phone/shortcut/NAME.shortcut`,
  check the result by importing it on an iPhone, and commit the signed file.
- Published with `SHA256SUMS` and a build provenance attestation
  (`actions/attest-build-provenance`), which users can check with `gh attestation verify`.

## Homebrew

The tap is the repository
[HunterEwok/homebrew-tap](https://github.com/HunterEwok/homebrew-tap),
the one tap for all of the owner's formulae; clipboardbridge's is `Formula/clipboardbridge.rb`, and users install with
`brew install hunterewok/tap/clipboardbridge`. After each release (not a
pre-release) the `homebrew` job of `.github/workflows/release.yml` writes the formula with
`packaging/homebrew/formula.sh` from the release's `SHA256SUMS` and pushes it to the tap's
`main`. The formula installs the release archives as they are, so it needs no Apple signing,
and CI's `homebrew` job installs one with it on macOS on every pull request.

Setting it up, once:

- [x] Create the public repository `HunterEwok/homebrew-tap`, empty (no README,
  license or `.gitignore`).
- [x] Make a key for it, on any computer:
  `ssh-keygen -t ed25519 -N '' -C homebrew-tap -f homebrew-tap`.
- [x] In the tap, **Settings → Deploy keys → Add deploy key**: the contents of
  `homebrew-tap.pub`, with **Allow write access**. It can write to the tap and nothing else.
- [x] In this repository, **Settings → Secrets and variables → Actions → New repository
  secret** `CBB_HOMEBREW_TAP_KEY`: the contents of `homebrew-tap`, the private key. Then
  delete both files.

To check the key without a release, run the release workflow from a branch (**Actions →
release → Run workflow**): its `homebrew` job pushes to the tap with `--dry-run`, which
fails unless the key may write there.

Without the secret the release still succeeds and warns that the tap kept its formula. To
fill the tap for a release made before, run `formula.sh` with that tag and its
`SHA256SUMS` and commit the output to the tap by hand.

## Android signing key

The release workflow builds `clipboardbridge-X.Y.Z.apk` from the tag (version code
`X*10000 + Y*100 + Z`) and signs it with the project's release key, which lives only in the
repository's Actions secrets. Android installs an update only when it is signed with the same
key, so the key is made once and kept, with a backup, for good:

```sh
keytool -genkeypair -v -keystore clipboardbridge-release.jks -alias clipboardbridge \
  -keyalg EC -groupname secp256r1 -validity 36500 -dname "CN=clipboardbridge"
base64 -i clipboardbridge-release.jks | pbcopy   # macOS; Linux: base64 -w0 clipboardbridge-release.jks
```

The secrets: `CBB_ANDROID_KEYSTORE_BASE64` (the keystore, in base64),
`CBB_ANDROID_KEYSTORE_PASSWORD`, `CBB_ANDROID_KEY_ALIAS` (`clipboardbridge`) and
`CBB_ANDROID_KEY_PASSWORD` (the same as the keystore's for a PKCS12 keystore). Without them
the release has no APK. F-Droid, later, builds and signs with its own key.

To check the key without a release, run the release workflow by hand from a branch (Actions,
"release", "Run workflow"): it builds everything, checks the APK's signature and keeps the
files as the run's artifacts, and publishes nothing.
