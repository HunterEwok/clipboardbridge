#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Lays out the build context of the clipboardbridge image in DIR: the
# Dockerfile, the static cbb of each platform, named as the Dockerfile wants
# them (cbb-amd64, cbb-arm64, cbb-armv7), and the few directories and files
# the service needs in an image built from scratch.
#
#   sh packaging/docker/context.sh DIR amd64=path/to/cbb [arm64=path] [armv7=path]
set -eu

[ $# -ge 2 ] || {
	echo "usage: context.sh DIR ARCH=CBB..." >&2
	exit 2
}
dir=$1
shift
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dir"
cp "$here/Dockerfile" "$dir/Dockerfile"
for a in "$@"; do
	arch=${a%%=*}
	bin=${a#*=}
	case $arch in
	amd64 | arm64 | armv7) ;;
	*)
		echo "context.sh: unknown platform $arch" >&2
		exit 2
		;;
	esac
	cp "$bin" "$dir/cbb-$arch"
	chmod 0755 "$dir/cbb-$arch"
done

# The service's user, 65532, owns its state and its sockets' directory.
r=$dir/rootfs
mkdir -p "$r/etc" "$r/run/clipboardbridge" "$r/var/lib/clipboardbridge" "$r/tmp"
chmod 0750 "$r/run/clipboardbridge"
chmod 0700 "$r/var/lib/clipboardbridge"
chmod 1777 "$r/tmp"
printf 'clipboardbridge:x:65532:65532:clipboardbridge:/var/lib/clipboardbridge:/sbin/nologin\n' >"$r/etc/passwd"
printf 'clipboardbridge:x:65532:\n' >"$r/etc/group"
printf 'PRETTY_NAME="Docker container"\nNAME=Docker\n' >"$r/etc/os-release"
