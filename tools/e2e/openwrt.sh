#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Tests the OpenWrt installer on OpenWrt itself (CI's openwrt job):
#
#   sh tools/e2e/openwrt.sh rootfs RELEASE_DIR   # in openwrt/rootfs, with docker
#   sh tools/e2e/openwrt.sh vm RELEASE_DIR       # OpenWrt booted in QEMU with KVM
#   sh tools/e2e/openwrt.sh feed RELEASE_DIR     # the apk feed, in openwrt/rootfs
#
# RELEASE_DIR holds a linux-amd64 release archive, SHA256SUMS and get.sh, as
# get.sh's CBB_RELEASE_DIR takes them. rootfs installs and removes it in
# OpenWrt's root file system, without procd. vm boots OpenWrt's x86-64 image
# with lan on a user-mode network that forwards SSH, installs it, and checks
# the procd instance, the interface list, the hub's firewall rule (procd
# service data that fw4 loads), the wait for NTP, and the removal. feed
# builds the signed apk feed with packaging/openwrt/feed.sh and a key made
# for the test, and installs and removes the package from it with apk.
# The scripts in single quotes run on OpenWrt, which expands them.
# shellcheck disable=SC2016
set -eu

release=25.12.6
image=openwrt/rootfs:x86_64-$release@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af

[ $# -eq 2 ] || {
	echo "usage: sh tools/e2e/openwrt.sh rootfs|vm|feed RELEASE_DIR" >&2
	exit 2
}
mode=$1
rel=$(cd "$2" && pwd)
work=${RUNNER_TEMP:-/tmp}/openwrt-e2e
mkdir -p "$work"

# The checks after an install, and after the removal, in OpenWrt's shell.
installed_files='
test -x /usr/bin/cbb
test -x /etc/init.d/clipboardbridge
test -f /etc/config/clipboardbridge
test -f /etc/hotplug.d/ntp/50-clipboardbridge
test -f /lib/upgrade/keep.d/clipboardbridge
test -f /etc/capabilities/clipboardbridge.json
grep -q "^clipboardbridge:" /etc/passwd
grep -q "^clipboardbridge:" /etc/group
test "$(ls -ld /etc/clipboardbridge/state | awk "{print \$3}")" = clipboardbridge
ls /etc/rc.d | grep -q clipboardbridge
ash -n /etc/init.d/clipboardbridge
ash -n /usr/share/clipboardbridge/firewall.sh
'
installed="
set -e
$installed_files
test \"\$(uci get clipboardbridge.main.port)\" = 9000
"
removed='
set -e
for f in /usr/bin/cbb /etc/init.d/clipboardbridge /etc/config/clipboardbridge /etc/hotplug.d/ntp/50-clipboardbridge \
	/lib/upgrade/keep.d/clipboardbridge /etc/capabilities/clipboardbridge.json /usr/share/clipboardbridge /etc/clipboardbridge; do
	if [ -e "$f" ]; then echo "left behind: $f" >&2; exit 1; fi
done
if ls /etc/rc.d | grep -q clipboardbridge; then echo "left enabled" >&2; exit 1; fi
'

case $mode in
rootfs)
	docker run --rm -v "$rel:/rel:ro" "$image" /bin/sh -c "
		set -e
		mkdir -p /var/lock /var/run /tmp
		CBB_RELEASE_DIR=/rel sh /rel/get.sh --port 9000
		$installed
		sh /usr/share/clipboardbridge/uninstall.sh --purge
		$removed
		echo 'rootfs: installed and removed'
	"
	;;
feed)
	src=$(cd "$(dirname "$0")/../.." && pwd)
	mkdir -p "$work/key"
	openssl ecparam -name prime256v1 -genkey -noout -out "$work/key/private.pem"
	openssl ec -in "$work/key/private.pem" -pubout -out "$work/key/public.pem" 2>/dev/null
	docker run --rm -v "$rel:/rel:ro" -v "$src:/src:ro" -v "$work/key:/key:ro" "$image" /bin/sh -c "
		set -e
		mkdir -p /var/lock /var/run /tmp
		sh /src/packaging/openwrt/feed.sh v0.0.0-ci.1 /rel /feed /key/private.pem
		test -f /feed/amd64/packages.adb
		# Without our key apk refuses the feed.
		if apk add --repositories-file /dev/null --repository /feed/amd64/packages.adb clipboardbridge 2>/dev/null; then
			echo 'apk took a feed signed with an unknown key' >&2
			exit 1
		fi
		cp /key/public.pem /etc/apk/keys/clipboardbridge.pem
		apk add --repositories-file /dev/null --repository /feed/amd64/packages.adb clipboardbridge
		apk info -e clipboardbridge
		$installed_files
		apk del clipboardbridge
		for f in /usr/bin/cbb /etc/init.d/clipboardbridge /usr/share/clipboardbridge/firewall.sh; do
			if [ -e \"\$f\" ]; then echo \"apk del left \$f\" >&2; exit 1; fi
		done
		if ls /etc/rc.d | grep -q clipboardbridge; then echo 'left enabled' >&2; exit 1; fi
		echo 'feed: signed, installed and removed'
	"
	;;
vm)
	img=$work/openwrt-$release-x86-64-generic-ext4-combined.img
	if [ ! -f "$img" ]; then
		base=https://downloads.openwrt.org/releases/$release/targets/x86/64
		curl -fsSL -o "$img.gz" "$base/${img##*/}.gz"
		curl -fsSL -o "$work/sha256sums" "$base/sha256sums"
		want=$(awk -v f="*${img##*/}.gz" '$2 == f { print $1 }' "$work/sha256sums")
		if [ -z "$want" ] || [ "$(sha256sum "$img.gz" | cut -d' ' -f1)" != "$want" ]; then
			echo "the image does not match OpenWrt's sha256sums" >&2
			exit 1
		fi
		# OpenWrt pads its images, which gzip reports as trailing garbage.
		gunzip -f "$img.gz" || [ -s "$img" ]
	fi
	# lan (eth0) is OpenWrt's 192.168.1.1 on a user-mode network of that
	# range, with SSH forwarded; wan (eth1) gets an address by DHCP.
	qemu-system-x86_64 -enable-kvm -m 512 -smp 2 -display none -daemonize \
		-pidfile "$work/qemu.pid" -serial "file:$work/console.log" \
		-drive "file=$img,format=raw,if=virtio" \
		-netdev "user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dhcpstart=192.168.1.100,hostfwd=tcp:127.0.0.1:2222-192.168.1.1:22" \
		-device virtio-net-pci,netdev=lan \
		-netdev user,id=wan -device virtio-net-pci,netdev=wan
	trap 'kill "$(cat "$work/qemu.pid")" 2>/dev/null || true' EXIT
	opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no -o PasswordAuthentication=yes -p 2222"
	# A fresh OpenWrt lets root in without a password.
	# shellcheck disable=SC2086 # $opts is words
	run() { sshpass -p '' ssh $opts root@127.0.0.1 "$@"; }
	i=0
	until run true 2>/dev/null; do
		i=$((i + 1))
		if [ $i -gt 90 ]; then
			echo "OpenWrt did not answer on SSH; its console:" >&2
			cat "$work/console.log" >&2
			exit 1
		fi
		sleep 2
	done
	# Dropbear has no SFTP server, so the files go through tar.
	tar -C "$rel" -cf - . | run 'mkdir -p /tmp/rel && tar -C /tmp/rel -xf -'
	run 'CBB_RELEASE_DIR=/tmp/rel sh /tmp/rel/get.sh --port 9000'
	run "$installed"
	run '
		set -e
		ubus call service list "{\"name\":\"clipboardbridge\"}" | grep -q "\"running\": true"
		for i in $(seq 30); do cbb status 2>&1 | grep -q "in a group" && break; sleep 1; done
		cbb status 2>&1 | grep -q "in a group"
		logread -e cbb | grep -q "work only on br-lan"
		netstat -ltn | grep -q ":9000 "
		echo "vm: the service runs on br-lan, port 9000"

		# The port of the hub: service data, which fw4 loads.
		sh /usr/share/clipboardbridge/firewall.sh hub-open 51820
		test "$(sh /usr/share/clipboardbridge/firewall.sh hub-port)" = 51820
		for i in $(seq 20); do nft list ruleset | grep -q "clipboardbridge hub" && break; sleep 1; done
		nft list ruleset | grep "clipboardbridge hub" | grep -q "udp dport 51820"
		sh /usr/share/clipboardbridge/firewall.sh hub-close
		for i in $(seq 20); do nft list ruleset | grep -q "clipboardbridge hub" || break; sleep 1; done
		if nft list ruleset | grep -q "clipboardbridge hub"; then echo "the hub rule stayed" >&2; exit 1; fi
		if grep -q clipboardbridge /etc/config/firewall; then echo "/etc/config/firewall was changed" >&2; exit 1; fi
		echo "vm: the hub rule came and went with the service data"

		# After a boot the service waits for NTP; ntpd itself stays out of it.
		/etc/init.d/sysntpd stop
		/etc/init.d/clipboardbridge stop
		rm -f /var/state/clipboardbridge.time
		/etc/init.d/clipboardbridge start
		sleep 2
		if pgrep -f "cbb service" >/dev/null; then echo "it started before NTP" >&2; exit 1; fi
		ACTION=stratum sh /etc/hotplug.d/ntp/50-clipboardbridge
		for i in $(seq 20); do pgrep -f "cbb service" >/dev/null && break; sleep 1; done
		pgrep -f "cbb service" >/dev/null
		echo "vm: it waited for NTP and started after it"

		sh /usr/share/clipboardbridge/uninstall.sh --purge
		if pgrep -f "cbb service" >/dev/null; then echo "still running" >&2; exit 1; fi
	'
	run "$removed"
	echo "vm: installed, checked and removed"
	;;
*)
	echo "usage: sh tools/e2e/openwrt.sh rootfs|vm|feed RELEASE_DIR" >&2
	exit 2
	;;
esac
