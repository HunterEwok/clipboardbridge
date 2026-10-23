#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Packs a built binary into the release archive for its platform:
#
#   sh packaging/archive.sh path/to/cbb linux|darwin NAME OUTDIR
#
# writes OUTDIR/clipboardbridge-<os>-<NAME>.tar.gz, which holds clipboardbridge/ with
# the binary, LICENSE and packaging/ (the platform's installer and tmux). The
# release workflow and CI both use it, so a wrong path fails on every pull
# request, not only at a release.
set -eu

if [ $# -ne 4 ]; then
	echo "usage: sh packaging/archive.sh BINARY linux|darwin NAME OUTDIR" >&2
	exit 2
fi
bin=$1 os=$2 name=$3 out=$4
root=$(cd "$(dirname "$0")/.." && pwd)
case $os in
linux) dir=linux ;;
darwin) dir=macos ;;
*)
	echo "archive.sh: unknown OS $os" >&2
	exit 2
	;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/clipboardbridge/packaging" "$out"
cp "$bin" "$work/clipboardbridge/cbb"
cp "$root/LICENSE" "$work/clipboardbridge/"
cp -R "$root/packaging/$dir" "$root/packaging/tmux" "$work/clipboardbridge/packaging/"
# No AppleDouble files from macOS tar.
COPYFILE_DISABLE=1 tar -czf "$out/clipboardbridge-$os-$name.tar.gz" -C "$work" clipboardbridge
echo "$out/clipboardbridge-$os-$name.tar.gz"
