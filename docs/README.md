<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Documentation

## Using Clipboard Bridge

| Document | What is in it |
|---|---|
| [Quick start](guide/quickstart.md) | the phone app, the first computer, sharing the clipboard |
| [How it works](guide/how-it-works.md) | the group and its roles, and pictures of every way the devices connect |
| [Installing](guide/install.md) | every system, Homebrew, winget, Docker, the firewall, updating, removing |
| [Away from home](guide/away-from-home.md) | the hub, a forwarder, invitations |
| [Networks that block VPNs](guide/blocked-networks.md) | AmneziaWG and VLESS with REALITY |
| [Keys and attestation](guide/keys.md) | where each device keeps its keys, how Android phones prove it, the three levels |
| [The apps](guide/apps.md) | the phone, watch and desktop apps |
| [Without the app](guide/without-app.md) | a group held by a computer, the iPhone shortcut, joining over SSH or a VPN |
| [Troubleshooting](guide/troubleshooting.md) | logs, the firewall, pairing, other networks |

## Reference

| Document | What is in it |
|---|---|
| [Commands](reference/cli.md) | every `cbb` command, on a full and on the lite member, with every flag and environment variable |
| [Devices, ports and files](reference/devices.md) | what each device can do, the ports, where the keys and logs are |
| [Running your own servers](reference/self-hosting.md) | a forwarder and a blind relay on your server, with Docker or systemd, and VLESS |
| [Lite member](../lite/README.md) | the lite member for small Linux devices: build, install, use |
| [Docker image](../packaging/docker/README.md) | the image for a NAS, a home server or a server on the internet |
| [Changelog](../CHANGELOG.md) | what changed in each release |
| [Security policy](../SECURITY.md) | how to report a vulnerability |

## For developers

| Document | What is in it |
|---|---|
| [Design](design.md) | how it works and why, the security model, the decision log |
| [Protocol](protocol.md) | the wire format, for anyone writing another implementation |
| [Platform parity](parity.md) | what each computer, phone and lite device can do, the gaps and the plan to close them |
| [Roadmap](roadmap.md) | what comes next, the agreed plans not built yet, research |
| [App specification](apps.md) | what the apps do and how they look |
| [Contributing](../CONTRIBUTING.md) | conventions, building and testing every part |
| [Test bench](testbench.md) | testing on real devices before a release: the cases, the bench, the criteria |
| [Test bench catalogue](testbench-catalogue.md) | every bench case of 0.6 in one line, with how it runs and what it still needs |
| [Test bench functions](testbench-functions.md) | every function of the product with the cases that check it, for the coverage report |
| [Test bench cases](testbench-cases.md) | bench cases step by step: the rule, the devices, the steps, pass and fail |
| [Security audit](security-audit.md) | the plan of the security audit |
| [Maintaining](maintaining.md) | repository settings, CI, releases, signing keys, Homebrew |
