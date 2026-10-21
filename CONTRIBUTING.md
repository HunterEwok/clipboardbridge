# Contributing

clipbridge is developed by one maintainer. Thank you for your interest.

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

- **English only** in code, comments, documentation, commit messages and issues.
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
- **No secrets.** No tokens, keys, real addresses or device names in the repository.
  GitHub secret scanning with push protection is enabled.

## Development

clipbridge needs Go; `go.mod` names the exact toolchain, and the `go` command downloads it
when needed. The checks that CI runs, from the repository root (CI also vets and builds every
target, see `.github/workflows/ci.yml`):

```sh
gofmt -l .                     # prints nothing when the code is formatted
go mod tidy -diff
go mod verify
go vet ./...
go tool staticcheck ./...
go tool govulncheck ./...
go tool actionlint             # GitHub Actions workflows
go run ./tools/repocheck       # English only, license headers, copied code
go test -race ./...
go build -o /dev/null ./cmd/clipbridge
GOOS=linux GOARCH=arm GOARM=6 go build -o /dev/null ./cmd/clipbridge   # Raspberry Pi Zero W
```
