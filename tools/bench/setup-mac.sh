#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Prepares a Mac on the bench, and takes it back. Run it from a checkout of
# the repository with sudo, as the user the bench connects as:
#
#   sudo sh tools/bench/setup-mac.sh setup [SHA256SUMS]  the helper and the sudoers rule
#   sudo sh tools/bench/setup-mac.sh trust SHA256SUMS    the builds the helper may install
#   sudo sh tools/bench/setup-mac.sh teardown         all of it gone again
#
# setup installs cbbbench-root (the bench's steps that need root, each
# fixed) to /usr/local/libexec/cbbbench and lets the user run it and cbb
# without a password (/etc/sudoers.d/cbbbench-root). trust copies a
# release's SHA256SUMS next to the helper: it installs only an archive whose
# SHA-256 is there, so the rule does not let anyone run any installer as
# root. cbb itself runs as root through the rule, which is as much as an
# admin of the group can do on this Mac anyway; remove it all with teardown
# when the test cycle is over.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dir=/usr/local/libexec/cbbbench
rule=/etc/sudoers.d/cbbbench-root

[ "$(id -u)" -eq 0 ] || {
	echo "setup-mac.sh: run it with sudo" >&2
	exit 1
}

case ${1:-} in
setup)
	user=${SUDO_USER:?run it with sudo as the bench user}
	install -d -o root -g wheel -m 0755 "$dir"
	install -o root -g wheel -m 0755 "$here/cbbbench-root" "$dir/cbbbench-root"
	tmp=$(mktemp)
	printf '%s ALL=(root) NOPASSWD: %s, /usr/local/bin/cbb\n' "$user" "$dir/cbbbench-root" >"$tmp"
	visudo -cf "$tmp" >/dev/null
	install -o root -g wheel -m 0440 "$tmp" "$rule"
	rm -f "$tmp"
	echo "The bench may run $dir/cbbbench-root and cbb as root."
	if [ -n "${2:-}" ]; then
		install -o root -g wheel -m 0644 "$2" "$dir/SHA256SUMS"
		echo "The helper installs the archives of $2."
	else
		echo "Trust a build next: sudo sh $0 trust SHA256SUMS"
	fi
	;;
trust)
	[ $# -eq 2 ] || {
		echo "usage: setup-mac.sh trust SHA256SUMS" >&2
		exit 2
	}
	install -o root -g wheel -m 0644 "$2" "$dir/SHA256SUMS"
	echo "The helper installs the archives of $2."
	;;
teardown)
	rm -f "$dir/cbbbench-root" "$dir/SHA256SUMS" "$rule" /etc/sudoers.d/cbbbench-cbb
	rmdir "$dir" 2>/dev/null || true
	echo "The bench's helper and sudoers rules are gone."
	;;
*)
	echo "usage: sudo sh tools/bench/setup-mac.sh setup [SHA256SUMS] | trust SHA256SUMS | teardown" >&2
	exit 2
	;;
esac
