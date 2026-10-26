#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Prepares a Mac on the bench, and takes it back. Run it from a checkout of
# the repository with sudo, as the user the bench connects as:
#
#   sudo sh tools/bench/setup-mac.sh setup [-signer KEY.pub] [SHA256SUMS]
#                                       the helper, the sudoers rule, and what it installs
#   sudo sh tools/bench/setup-mac.sh trust SHA256SUMS    one more build it may install
#   sudo sh tools/bench/setup-mac.sh teardown         all of it gone again
#
# setup installs cbbbench-root (the bench's steps that need root, each
# fixed) to /usr/local/libexec/cbbbench and lets the user run it and cbb
# without a password (/etc/sudoers.d/cbbbench-root). The helper installs
# only an archive whose SHA-256 is in a build's SHA256SUMS signed by the
# bench's signing key (-signer: its public half, kept root-owned as
# allowed_signers; the private half stays on the controller, which signs
# each build with ssh-keygen -Y sign -n cbbbench), or in a SHA256SUMS the
# person who set up the bench trusted here. So the rule lets nobody run any installer as root,
# and a new build needs no password: whoever holds the signing key can
# have this Mac install a build, which is why the key stays on the bench's
# controller. cbb itself runs as root through the rule, which is as much as an
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
	signer=
	if [ "${2:-}" = -signer ]; then
		signer=${3:?-signer needs the public half of the signing key}
		shift 2
	fi
	install -d -o root -g wheel -m 0755 "$dir"
	install -o root -g wheel -m 0755 "$here/cbbbench-root" "$dir/cbbbench-root"
	tmp=$(mktemp)
	printf '%s ALL=(root) NOPASSWD: %s, /usr/local/bin/cbb\n' "$user" "$dir/cbbbench-root" >"$tmp"
	visudo -cf "$tmp" >/dev/null
	install -o root -g wheel -m 0440 "$tmp" "$rule"
	rm -f "$tmp"
	echo "The bench may run $dir/cbbbench-root and cbb as root."
	if [ -n "$signer" ]; then
		printf 'cbbbench namespaces="cbbbench" %s\n' "$(cut -d' ' -f1,2 "$signer")" >"$dir/allowed_signers"
		chown root:wheel "$dir/allowed_signers"
		chmod 0644 "$dir/allowed_signers"
		echo "It installs the builds that $signer's key signed."
	fi
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
	rm -f "$dir/cbbbench-root" "$dir/SHA256SUMS" "$dir/allowed_signers" "$rule" /etc/sudoers.d/cbbbench-cbb
	rmdir "$dir" 2>/dev/null || true
	echo "The bench's helper and sudoers rules are gone."
	;;
*)
	echo "usage: sudo sh tools/bench/setup-mac.sh setup [-signer KEY.pub] [SHA256SUMS] | trust SHA256SUMS | teardown" >&2
	exit 2
	;;
esac
