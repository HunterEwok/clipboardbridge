#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Writes the notes of a release to standard output:
#
#   sh packaging/release-notes.sh v1.2.3
#
# what clipboardbridge is, the version's section of CHANGELOG.md, how to install
# it, how to verify the files, where the source and the license are, and
# where to report problems. The release workflow publishes them; GitHub
# appends the list of merged pull requests.
set -eu

if [ $# -ne 1 ]; then
	echo "usage: sh packaging/release-notes.sh vX.Y.Z" >&2
	exit 2
fi
tag=$1
version=${tag#v}
root=$(cd "$(dirname "$0")/.." && pwd)
repo=https://github.com/HunterEwok/clipboardbridge

# The version's section, without its heading, up to the next one.
changes=$(awk -v v="$version" '
	index($0, "## [" v "]") == 1 { on = 1; next }
	on && /^## \[/ { exit }
	on && /^\[[^]]*\]: / { next } # the link definitions at the end of the file
	on { print }
' "$root/CHANGELOG.md" |
	# Links relative to the repository point at this tag on the release page.
	sed "s#](\([^h#)][^)]*\))#]($repo/blob/$tag/\1)#g")
if [ -z "$(printf '%s' "$changes" | tr -d '[:space:]')" ]; then
	echo "release-notes.sh: CHANGELOG.md has no section for $version" >&2
	exit 1
fi

cat <<NOTES
clipboardbridge is one clipboard for your Apple devices and every Linux machine on your home
network: copy on one device, paste on another. It works only on the local network, with
no cloud, accounts or telemetry, and all traffic is end-to-end encrypted between paired
devices.

## What's changed in $version
$changes

## Install

**Linux** with systemd (x86-64, ARM64, ARMv7, ARMv6):

\`\`\`sh
curl -fsSL $repo/releases/download/$tag/get.sh | sudo sh
\`\`\`

\`get.sh\` downloads the archive for the machine, checks it against \`SHA256SUMS\`, installs
the service and, when ufw is active, allows clipboardbridge's ports from the home network only.

**macOS** (Apple silicon; \`amd64\` instead of \`arm64\` for Intel), in Terminal:

\`\`\`sh
curl -fsSLO $repo/releases/download/$tag/clipboardbridge-darwin-arm64.tar.gz
tar -xzf clipboardbridge-darwin-arm64.tar.gz
sudo sh clipboardbridge/packaging/macos/install.sh clipboardbridge/cbb
\`\`\`

Or with Homebrew, on macOS or Linux (x86-64, ARM64): \`brew install hunterewok/tap/clipboardbridge\`,
then the command it prints to start the service.

**Android** 10 or later: open \`clipboardbridge-$version.apk\` on the phone and allow the
install. The app makes its own group and adds the computers by their \`cbb join\` QR code.

**Lite member** for small Linux devices (a router, a Raspberry Pi Zero): unpack
\`cbb-lite-linux-<arch>.tar.gz\` and follow \`cbb-lite/README.md\`, section "Install".

Then follow the [quick start]($repo/blob/$tag/docs/quickstart.md): \`cbb pair -phone\`
on a Linux machine for the iPhone, and \`cbb join\` on each further computer.

## Verify the downloads

Every file is listed in \`SHA256SUMS\` and has a build provenance attestation, signed with
Sigstore, that ties it to this repository, this tag and the GitHub Actions run that built
it:

\`\`\`sh
sha256sum --ignore-missing -c SHA256SUMS            # macOS: shasum -a 256 -c SHA256SUMS
gh attestation verify clipboardbridge-linux-arm64.tar.gz --repo HunterEwok/clipboardbridge
\`\`\`

## Files

| File | For |
|------|-----|
| \`clipboardbridge-linux-amd64.tar.gz\` | Linux, x86-64 |
| \`clipboardbridge-linux-arm64.tar.gz\` | Linux, ARM64 (Raspberry Pi 3, 4, 5 with a 64-bit system) |
| \`clipboardbridge-linux-armv7.tar.gz\` | Linux, ARMv7 (Raspberry Pi 2, 3, 4 with a 32-bit system) |
| \`clipboardbridge-linux-armv6.tar.gz\` | Linux, ARMv6 (Raspberry Pi Zero W, 1) |
| \`clipboardbridge-darwin-arm64.tar.gz\` | macOS, Apple silicon |
| \`clipboardbridge-darwin-amd64.tar.gz\` | macOS, Intel |
| \`clipboardbridge-windows-amd64.zip\` | Windows 10 (1809 or later) and 11, x86-64 |
| \`clipboardbridge-windows-arm64.zip\` | Windows 10 (1809 or later) and 11, ARM64 |
| \`cbb-lite-linux-amd64.tar.gz\` | the lite member for small Linux devices, x86-64, static |
| \`cbb-lite-linux-arm64.tar.gz\` | the lite member, ARM64, static |
| \`cbb-lite-linux-armv6.tar.gz\` | the lite member, ARMv6 and ARMv7 (Raspberry Pi Zero, 1, 2), static |
| \`clipboardbridge-$version.apk\` | Android 10 and later, signed with the project's release key |
| \`get.sh\` | the Linux installer |
| \`get.ps1\` | the Windows installer |
| \`SHA256SUMS\` | SHA-256 checksums of all of the above |

Each archive holds \`clipboardbridge/\`: the program, \`LICENSE\`, \`THIRD_PARTY_NOTICES\` with
the licenses of the code it is built from, and \`packaging/\` with the installer for its system. Each \`cbb-lite\` archive holds \`cbb-lite/\`: the program, \`LICENSE\`,
\`THIRD_PARTY_NOTICES\` with the licenses of the crates it is built from, \`README.md\` with the
install steps, and \`packaging/\` with the systemd unit.

## Source and license

clipboardbridge is free software under the [GNU Affero General Public License, version 3
only]($repo/blob/$tag/LICENSE). The complete source of this release is the tag
[\`$tag\`]($repo/tree/$tag) and the source archives below, from which these files are built
by [the release workflow]($repo/blob/$tag/.github/workflows/release.yml).

## Problems and security

Report bugs as [issues]($repo/issues). Report vulnerabilities privately, as
[SECURITY.md]($repo/blob/$tag/SECURITY.md) explains, never in a public issue.

The full list of changes is in [CHANGELOG.md]($repo/blob/$tag/CHANGELOG.md).
NOTES
