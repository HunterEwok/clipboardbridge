#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Binds the phones' tunnel with gomobile, from go.mod's tools:
#   bind.sh android OUT.aar          (needs ANDROID_HOME and ANDROID_NDK_HOME)
#   bind.sh ios OUT.xcframework      (needs Xcode)
# OUT is made absolute; the Android app's Gradle build and CI's jobs call it.
set -eu
if [ $# -ne 2 ]; then
	echo "usage: bind.sh android|ios OUT" >&2
	exit 2
fi
target=$1
case $target in
android | ios) ;;
*)
	echo "bind.sh: unknown target $target" >&2
	exit 2
	;;
esac
case $2 in
/*) out=$2 ;;
*) out=$(pwd)/$2 ;;
esac
root=$(cd "$(dirname "$0")/../.." && pwd)
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
cd "$root"
go build -o "$bin/" golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
PATH="$bin:$PATH"
export PATH
mkdir -p "$(dirname "$out")"
# gomobile's go.mod replaces this module and amneziawg-go by their directories, which go
# into the library's build info even with -trimpath; binding from one fixed path, a link
# to the checkout, gives the same library wherever the checkout is. The lock keeps another
# bind on this computer from moving the link meanwhile.
link=/tmp/cbbtun-bind
n=0
until mkdir "$link.lock" 2>/dev/null; do
	n=$((n + 1))
	if [ $n -ge 600 ]; then
		echo "bind.sh: $link.lock is still there; remove it if no bind is running" >&2
		exit 1
	fi
	sleep 1
done
trap 'rm -rf "$bin"; rm -f "$link"; rmdir "$link.lock"' EXIT
ln -sfn "$root" "$link"
cd "$link"
PWD=$link
export PWD
# No VCS stamp: the same tag gives the same library from a checkout or a tarball, which
# F-Droid's reproducible build needs (docs/apps.md, "F-Droid").
GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false"
export GOFLAGS
case $target in
android) gomobile bind -target=android -androidapi 29 -trimpath -ldflags=-s -o "$out" ./mobile/cbbtun ;;
ios) gomobile bind -target=ios,iossimulator -iosversion 17.0 -trimpath -ldflags=-s -o "$out" ./mobile/cbbtun ;;
esac
