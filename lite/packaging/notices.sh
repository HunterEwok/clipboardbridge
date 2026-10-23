#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Writes the licenses of the crates that cbb-lite is built from, for one
# target, so that a release archive carries their notices:
#
#   sh lite/packaging/notices.sh TARGET >THIRD_PARTY_NOTICES
#
# Each crate of the normal dependency graph (not build or dev dependencies)
# appears with its name, version and license expression, followed by its
# license files from the cargo registry. It needs cargo and jq, and the
# crates downloaded (cargo fetch or a build).
set -eu

if [ $# -ne 1 ]; then
	echo "usage: sh lite/packaging/notices.sh TARGET" >&2
	exit 2
fi
target=$1
cd "$(dirname "$0")/.."

meta=$(mktemp)
trap 'rm -f "$meta"' EXIT
cargo metadata --locked --format-version 1 >"$meta"

echo "cbb-lite is free software under the GNU Affero General Public License v3.0 only"
echo "(LICENSE). It is built with the crates below, under their own licenses."
cargo tree --locked -e normal -p clipboardbridge-lite --target "$target" --prefix none \
	-f '{p}' | sed 's/ (.*//; s/ (\*)$//' | sort -u |
	while read -r name version; do
		version=${version#v}
		dir=$(jq -r --arg n "$name" --arg v "$version" \
			'.packages[] | select(.name == $n and .version == $v and .source != null) | .manifest_path' "$meta")
		[ -n "$dir" ] || continue # the workspace's own crates
		dir=$(dirname "$dir")
		license=$(jq -r --arg n "$name" --arg v "$version" \
			'.packages[] | select(.name == $n and .version == $v) | .license // "see its files"' "$meta")
		printf '\n================================================================\n'
		printf '%s %s (%s)\n' "$name" "$version" "$license"
		found=
		for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/UNLICENSE*; do
			[ -f "$f" ] || continue
			found=yes
			printf -- '\n--- %s\n\n' "${f##*/}"
			cat "$f"
		done
		if [ -z "$found" ]; then
			printf '\nThe crate ships no license file; its license is %s.\n' "$license"
		fi
	done
