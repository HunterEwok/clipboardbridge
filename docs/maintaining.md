# Maintaining

Settings and routines that live outside the repository files. Only the owner can change them.

## Account

- [ ] Two-factor authentication on the GitHub account, preferably with a passkey or a
  security key. This protects the repository more than any setting below.
- [ ] Optional: sign commits with an SSH key (`git config gpg.format ssh`) and add the key
  to GitHub as a signing key, so commits show as Verified.

## Repository settings

**Settings → General**

- [ ] Features: turn off Wiki and Projects; keep Issues.
- [ ] Pull Requests: allow only **squash merging**; turn on **Automatically delete head
  branches**.
- [ ] Releases: turn on **release immutability**, if the setting is available.

**Settings → Moderation options → Reported content**

- [ ] Accept content reports from **all users**. [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)
  sends reports this way, so no email address is published.

**Settings → Advanced Security** (named Code security on some accounts)

- [ ] **Private vulnerability reporting**: enable. [SECURITY.md](../SECURITY.md) relies on it.
- [ ] **Dependency graph**, **Dependabot alerts** and **Dependabot security updates**: enable.
- [ ] **Secret scanning** and **Push protection**: enable.
- [ ] **CodeQL** default setup: enable once the repository contains Go code.

**Settings → Actions → General**

- [ ] Workflow permissions: **Read repository contents and packages permissions**.
- [ ] Turn off **Allow GitHub Actions to create and approve pull requests**.
- [ ] Fork pull request workflows: **Require approval for all external contributors**.

**Settings → Rules → Rulesets → New branch ruleset**: name `main`, enforcement Active,
target the default branch.

- [ ] Restrict deletions and block force pushes.
- [ ] Require linear history.
- [ ] Require a pull request before merging, with 0 required approvals: a single maintainer
  cannot approve their own pull request.
- [ ] Require status checks to pass, once CI exists.
- [ ] Leave the bypass list empty.

**Settings → Rules → Rulesets → New tag ruleset**: name `releases`, target `v*`.

- [ ] Restrict creations, updates and deletions, and block force pushes, so release tags
  cannot be moved.

## CI rules

For the workflows added together with the first Go code:

- Pin every action to a full commit SHA, with the version in a comment; Dependabot updates
  them.
- Set `permissions: contents: read` at the workflow level; grant more to a single job only
  when it needs it.
- Pull request workflows get no secrets.
- Checks: `gofmt`, `go vet`, `staticcheck`, `govulncheck`, tests, the cross builds for
  every target, and a check that the repository text is in English.

## Releases

- Built by CI from a tag, never on a laptop.
- Published with `SHA256SUMS` and a build provenance attestation
  (`actions/attest-build-provenance`), which users can check with `gh attestation verify`.
