<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Documentation

Pick the part for what you are doing. Each page says at the top who it is for.

## Using Clipboard Bridge

For anyone with a phone or a computer, in plain words.

| Document | What is in it |
|---|---|
| [Quick start](guide/quickstart.md) | the phone app, the first computer, sharing the clipboard |
| [How it works](guide/how-it-works.md) | the group and its roles, and pictures of every way the devices connect |
| [Installing](guide/install.md) | every system, Homebrew, winget, Docker, the firewall, updating, removing |
| [The apps](guide/apps.md) | the phone, watch and desktop apps |
| [Away from home](guide/away-from-home.md) | the hub, a forwarder, invitations |
| [Networks that block VPNs](guide/blocked-networks.md) | AmneziaWG and VLESS with REALITY |
| [Images, files and formatted text](guide/images-and-files.md) | what goes where, the sizes, saving received files |
| [Remote paste](guide/remote-paste.md) | an admin puts a text into the focused app on another device |
| [Quick actions](guide/quick-actions.md) | lock, sleep or restart a device from a phone or another computer |
| [Keys and attestation](guide/keys.md) | where each device keeps its keys, how devices prove it, the three levels |
| [If a device is lost](guide/lost-device.md) | remove it, freeze an admin, take the group over |
| [Without the app](guide/without-app.md) | a group held by a computer, the iPhone shortcut, joining over SSH or a VPN |
| [Troubleshooting](guide/troubleshooting.md) | logs, the firewall, pairing, other networks |

## Running servers and many devices

For administrators: your own server, a router, a NAS.

| Document | What is in it |
|---|---|
| [Running your own servers](admin/self-hosting.md) | a forwarder and a blind relay on your server, with Docker or systemd, and VLESS |
| [Docker image](../packaging/docker/README.md) | the image for a NAS, a home server or a server on the internet |
| [Lite member](../lite/README.md) | the lite member for small Linux devices: build, install, use |

## Reference

Complete and exact, without the reasons.

| Document | What is in it |
|---|---|
| [Commands](reference/cli.md) | every `cbb` command, on a full and on the lite member, with every flag |
| [Settings and environment variables](reference/config.md) | the settings files and every `CBB_*` variable |
| [Devices, ports and files](reference/devices.md) | what each device can do, the ports, where the keys and logs are |
| [Limits and lifetimes](reference/limits.md) | sizes, rates, timeouts, certificate lifetimes, the servers' limits |
| [Error messages and details](reference/errors.md) | how each part shows errors and the switch that shows their details |
| [Glossary](reference/glossary.md) | the words the documentation and the apps use |
| [Changelog](../CHANGELOG.md) | what changed in each release |
| [Security policy](../SECURITY.md) | how to report a vulnerability |

## For engineers

How it is built and why, for contributors, for anyone writing another implementation and
for security reviewers.

| Document | What is in it |
|---|---|
| [Design](design.md) | how it works and why, after the arc42 template: goals, context, building blocks, run time, deployment, concepts, quality, risks |
| [Decisions](decisions.md) | every architecture decision, D-1 to D-78, with its status |
| [Threat model](threat-model.md) | the assets, adversaries, trust boundaries, and each threat with its defence and code |
| [Protocol](protocol.md) | the wire format, for anyone writing another implementation |
| [Platform parity](parity.md) | what each computer, phone and lite device can do, the gaps and the plan to close them |
| [App specification](apps.md) | what the apps do and how they look |
| [Roadmap](roadmap.md) | what comes next, the agreed plans not built yet, research |
| [Contributing](../CONTRIBUTING.md) | conventions, building and testing every part |
| [Security audit](security-audit.md) | the plan of the security audit |

## For maintainers

Releasing and testing on real devices.

| Document | What is in it |
|---|---|
| [Maintaining](maintaining.md) | repository settings, CI, releases, signing keys, Homebrew |
| [Test bench](testbench.md) | testing on real devices before a release: the cases, the bench, the criteria |
| [Test bench catalogue](testbench-catalogue.md) | every bench case of 0.6 in one line, with how it runs and what it still needs |
| [Test bench functions](testbench-functions.md) | every function of the product with the cases that check it, for the coverage report |
| [Test bench cases](testbench-cases.md) | bench cases step by step: the rule, the devices, the steps, pass and fail |
