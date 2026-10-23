#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Packs a built binary into the release archive for its platform:
#
#   sh packaging/archive.sh path/to/cbb linux|darwin|windows NAME OUTDIR
#
# writes OUTDIR/clipboardbridge-<os>-<NAME>.tar.gz, which holds clipboardbridge/ with
# the binary, LICENSE and packaging/ (the platform's installer and tmux). For
# Windows the binary is cbb.exe, with the windowless cbbw.exe beside it for
# the agent, and the archive is clipboardbridge-windows-<NAME>.zip, which
# Windows opens without other tools. The release workflow and CI both use
# it, so a wrong path fails on every pull request, not only at a release.
set -eu

if [ $# -ne 4 ]; then
	echo "usage: sh packaging/archive.sh BINARY linux|darwin|windows NAME OUTDIR" >&2
	exit 2
fi
bin=$1 os=$2 name=$3 out=$4
root=$(cd "$(dirname "$0")/.." && pwd)
case $os in
linux) dir=linux ;;
darwin) dir=macos ;;
windows) dir=windows ;;
*)
	echo "archive.sh: unknown OS $os" >&2
	exit 2
	;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/clipboardbridge/packaging" "$out"
out=$(cd "$out" && pwd)
cp "$root/LICENSE" "$work/clipboardbridge/"
if [ "$os" = windows ]; then
	cp "$bin" "$work/clipboardbridge/cbb.exe"
	cp "$(dirname "$bin")/cbbw.exe" "$work/clipboardbridge/cbbw.exe"
	cp -R "$root/packaging/windows" "$work/clipboardbridge/packaging/"
	rm -f "$out/clipboardbridge-$os-$name.zip"
	(cd "$work" && zip -qrX "$out/clipboardbridge-$os-$name.zip" clipboardbridge)
	echo "$out/clipboardbridge-$os-$name.zip"
	exit 0
fi
cp "$bin" "$work/clipboardbridge/cbb"
cp -R "$root/packaging/$dir" "$root/packaging/tmux" "$work/clipboardbridge/packaging/"
# No AppleDouble files from macOS tar.
COPYFILE_DISABLE=1 tar -czf "$out/clipboardbridge-$os-$name.tar.gz" -C "$work" clipboardbridge
echo "$out/clipboardbridge-$os-$name.tar.gz"
