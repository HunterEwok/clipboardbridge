# Security policy

## Supported versions

clipbridge has no releases yet. Until the first release, only the `main` branch is
supported. After that, the latest release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public issue, pull request or
discussion.

Use GitHub private vulnerability reporting: open the
[Security tab](https://github.com/HunterEwok/clipBridge/security) of the repository and choose
**Report a vulnerability**. Only the maintainer can see the report.

Include, if you can:

- the affected component (service, desktop connector, console helper, macOS agent or iOS
  shortcut) and the version or commit;
- the steps to reproduce;
- the impact: what an attacker can read, change or run.

## What to expect

- An acknowledgement within 7 days.
- An assessment within 30 days: a plan for a fix, or the reason the report is not accepted.
- For an accepted report: a fix, a published GitHub security advisory, and credit if you
  want it.

Please keep the details private until the advisory is published.

## Scope

In scope: the programs in this repository, the pairing and sync protocol, the installers,
and the published iOS shortcut.

Out of scope:

- Apple Universal Clipboard, the Shortcuts app, desktop environments and terminal emulators;
- attacks that already require root on a member device or an unlocked device in the
  attacker's hands;
- text that a user deliberately copies and sends.

## Good faith

Test only on your own devices. Do not access other people's data and do not disrupt other
people's networks. The maintainer will not take legal action against research done in good
faith under this policy.

The security design is described in [docs/design.md](docs/design.md#security).
