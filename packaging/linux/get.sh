#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs or updates clipbridge on a Linux machine from a release:
#
#   curl -fsSL https://github.com/HunterEwok/clipbridge/releases/latest/download/get.sh | sudo sh
#
# Options go after "sh -s --": --console also starts tmux after a login on
# the text console; --no-firewall leaves ufw alone. CLIPBRIDGE_VERSION=v1.2.3
# picks a release instead of the latest; CLIPBRIDGE_RELEASE_DIR, for tests,
# takes the files from a directory instead of downloading them.
#
# It downloads the archive for this machine's architecture and SHA256SUMS
# from the release, checks the archive against it, runs install.sh from the
# archive, and, when ufw is active, allows clipbridge's ports from the home
# network only.
set -eu

repo=https://github.com/HunterEwok/clipbridge
console=
firewall=yes
for arg in "$@"; do
	case $arg in
	--console) console=--console ;;
	--no-firewall) firewall=no ;;
	*)
		echo "get.sh: unknown option $arg (known: --console, --no-firewall)" >&2
		exit 2
		;;
	esac
done

fail() {
	echo "get.sh: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run it with sudo: curl -fsSL $repo/releases/latest/download/get.sh | sudo sh"
[ "$(uname -s)" = Linux ] || fail "this installer is for Linux; on a Mac use packaging/macos/install.sh"
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
armv7l | armv8l) arch=armv7 ;;
armv6l) arch=armv6 ;;
*) fail "no release for the architecture $(uname -m)" ;;
esac
for tool in tar sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
if [ -n "${CLIPBRIDGE_RELEASE_DIR:-}" ]; then
	fetch() { cp "$CLIPBRIDGE_RELEASE_DIR/${1##*/}" "$2"; }
elif command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q --https-only -O "$2" "$1"; }
else
	fail "curl or wget is required"
fi

version=${CLIPBRIDGE_VERSION:-latest}
case $version in
latest) base=$repo/releases/latest/download ;;
v*) base=$repo/releases/download/$version ;;
*) fail "CLIPBRIDGE_VERSION must look like v1.2.3" ;;
esac
archive=clipbridge-linux-$arch.tar.gz

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $archive ($version)..."
fetch "$base/$archive" "$tmp/$archive" || fail "could not download $base/$archive"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $base/SHA256SUMS"
want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
got=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
[ -n "$want" ] || fail "SHA256SUMS does not list $archive"
[ "$want" = "$got" ] || fail "$archive does not match SHA256SUMS; not installing it"
tar -xzf "$tmp/$archive" -C "$tmp"

# shellcheck disable=SC2086 # $console is one word or none
sh "$tmp/clipbridge/packaging/linux/install.sh" $console "$tmp/clipbridge/clipbridge"

# ufw drops what it does not allow, and clipbridge needs mDNS and its ports
# from the other devices at home: allow them from the home network only.
if [ "$firewall" = yes ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
	nets=$(ip -o -f inet route show scope link 2>/dev/null | awk '
		$1 ~ /^10\./ || $1 ~ /^192\.168\./ || $1 ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ { print $1 }' | sort -u)
	for net in $nets fe80::/10 fc00::/7; do
		ufw allow proto udp from "$net" to any port 5353 comment 'clipbridge mDNS' >/dev/null
		ufw allow proto tcp from "$net" to any port 8764:8767 comment clipbridge >/dev/null
	done
	echo "ufw: allowed mDNS and TCP 8764-8767 from $(echo "$nets" | tr '\n' ' ')and local IPv6."
elif [ "$firewall" = yes ] && command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
	echo "firewalld is running: allow mDNS and TCP 8764-8767 in the zone of the home network, for example"
	echo "  sudo firewall-cmd --permanent --zone=home --add-service=mdns --add-port=8764-8767/tcp && sudo firewall-cmd --reload"
fi
