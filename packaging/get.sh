#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs or updates clipboardbridge on a Linux machine or a Mac from a
# release (Windows has get.ps1):
#
#   curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh
#
# Options go after "sh -s --": --no-firewall leaves the firewall alone; on
# Linux, --console also starts tmux after a login on the text console, and
# --port N moves the member port from 8764 to N. CBB_VERSION=v1.2.3 picks a
# release instead of the latest; CBB_RELEASE_DIR, for tests, takes the files
# from a directory instead of downloading them.
#
# It downloads the archive for this system and architecture and SHA256SUMS
# from the release, checks the archive against it, and runs the archive's
# install.sh for this system: on Linux it allows clipboardbridge's ports
# from the home network only when ufw or firewalld is active; on a Mac it
# lists the program in the application firewall. On a Mac, Homebrew is the
# other way (docs/quickstart.md).
set -eu

repo=https://github.com/HunterEwok/clipboardbridge
console=
port=
firewall=yes
while [ $# -gt 0 ]; do
	case $1 in
	--console) console=--console ;;
	--port)
		[ $# -gt 1 ] || {
			echo "get.sh: --port needs a port number" >&2
			exit 2
		}
		port="--port $2"
		shift
		;;
	--no-firewall) firewall=no ;;
	*)
		echo "get.sh: unknown option $1 (known: --console, --port N, --no-firewall)" >&2
		exit 2
		;;
	esac
	shift
done

fail() {
	echo "get.sh: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run it with sudo: curl -fsSL $repo/releases/latest/download/get.sh | sudo sh"
case $(uname -s) in
Linux)
	os=linux
	case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	armv7l | armv8l) arch=armv7 ;;
	armv6l) arch=armv6 ;;
	*) fail "no release for the architecture $(uname -m)" ;;
	esac
	;;
Darwin)
	os=darwin
	[ -z "$console" ] || fail "--console is for Linux"
	[ -z "$port" ] || fail "--port is for Linux; a Mac keeps the member port 8764"
	# A shell under Rosetta reports x86_64 on an Apple chip.
	if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then
		arch=arm64
	else
		arch=amd64
	fi
	;;
*) fail "this installer is for Linux and macOS; on Windows use get.ps1" ;;
esac
command -v tar >/dev/null 2>&1 || fail "tar is required"
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	fail "sha256sum or shasum is required"
fi
if [ -n "${CBB_RELEASE_DIR:-}" ]; then
	fetch() { cp "$CBB_RELEASE_DIR/${1##*/}" "$2"; }
elif command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q --https-only -O "$2" "$1"; }
else
	fail "curl or wget is required"
fi

version=${CBB_VERSION:-latest}
case $version in
latest) base=$repo/releases/latest/download ;;
v*) base=$repo/releases/download/$version ;;
*) fail "CBB_VERSION must look like v1.2.3" ;;
esac
archive=clipboardbridge-$os-$arch.tar.gz

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $archive ($version)..."
fetch "$base/$archive" "$tmp/$archive" || fail "could not download $base/$archive"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $base/SHA256SUMS"
want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
got=$(sha256 "$tmp/$archive")
[ -n "$want" ] || fail "SHA256SUMS does not list $archive"
[ "$want" = "$got" ] || fail "$archive does not match SHA256SUMS; not installing it"
tar -xzf "$tmp/$archive" -C "$tmp"

if [ "$os" = darwin ]; then
	CBB_FIREWALL=$firewall sh "$tmp/clipboardbridge/packaging/macos/install.sh" "$tmp/clipboardbridge/cbb"
else
	# shellcheck disable=SC2086 # $console and $port are words or none
	CBB_FIREWALL=$firewall sh "$tmp/clipboardbridge/packaging/linux/install.sh" $console $port "$tmp/clipboardbridge/cbb"
fi

