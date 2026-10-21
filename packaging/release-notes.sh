#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Writes the notes of a release to standard output:
#
#   sh packaging/release-notes.sh v1.2.3
#
# what clipbridge is, the version's section of CHANGELOG.md, how to install
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
repo=https://github.com/HunterEwok/clipbridge

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
clipbridge is one clipboard for your Apple devices and every Linux machine on your home
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
the service and, when ufw is active, allows clipbridge's ports from the home network only.

**macOS** (Apple silicon; \`amd64\` instead of \`arm64\` for Intel), in Terminal:

\`\`\`sh
curl -fsSLO $repo/releases/download/$tag/clipbridge-darwin-arm64.tar.gz
tar -xzf clipbridge-darwin-arm64.tar.gz
sudo sh clipbridge/packaging/macos/install.sh clipbridge/clipbridge
\`\`\`

Then follow the [quick start]($repo/blob/$tag/docs/quickstart.md): \`clipbridge pair -phone\`
on a Linux machine for the iPhone, and \`clipbridge join\` on each further computer.

## Verify the downloads

Every file is listed in \`SHA256SUMS\` and has a build provenance attestation, signed with
Sigstore, that ties it to this repository, this tag and the GitHub Actions run that built
it:

\`\`\`sh
sha256sum --ignore-missing -c SHA256SUMS            # macOS: shasum -a 256 -c SHA256SUMS
gh attestation verify clipbridge-linux-arm64.tar.gz --repo HunterEwok/clipbridge
\`\`\`

## Files

| File | For |
|------|-----|
| \`clipbridge-linux-amd64.tar.gz\` | Linux, x86-64 |
| \`clipbridge-linux-arm64.tar.gz\` | Linux, ARM64 (Raspberry Pi 3, 4, 5 with a 64-bit system) |
| \`clipbridge-linux-armv7.tar.gz\` | Linux, ARMv7 (Raspberry Pi 2, 3, 4 with a 32-bit system) |
| \`clipbridge-linux-armv6.tar.gz\` | Linux, ARMv6 (Raspberry Pi Zero W, 1) |
| \`clipbridge-darwin-arm64.tar.gz\` | macOS, Apple silicon |
| \`clipbridge-darwin-amd64.tar.gz\` | macOS, Intel |
| \`get.sh\` | the Linux installer |
| \`SHA256SUMS\` | SHA-256 checksums of all of the above |

Each archive holds \`clipbridge/\`: the program, \`LICENSE\`, and \`packaging/\` with the
installer for its system.

## Source and license

clipbridge is free software under the [GNU Affero General Public License, version 3
only]($repo/blob/$tag/LICENSE). The complete source of this release is the tag
[\`$tag\`]($repo/tree/$tag) and the source archives below, from which these files are built
by [the release workflow]($repo/blob/$tag/.github/workflows/release.yml).

## Problems and security

Report bugs as [issues]($repo/issues). Report vulnerabilities privately, as
[SECURITY.md]($repo/blob/$tag/SECURITY.md) explains, never in a public issue.

The full list of changes is in [CHANGELOG.md]($repo/blob/$tag/CHANGELOG.md).
NOTES
