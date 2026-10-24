#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Keeps the clipboardbridge service on the home network with pf, as its
# systemd unit does on Linux and a firewall rule on Windows:
#
#   sudo sh /usr/local/share/clipboardbridge/pf.sh load|unload
#
# load puts the rules into the anchor com.apple/clipboardbridge, which the
# system's /etc/pf.conf already evaluates (anchor "com.apple/*"), so that
# file stays as Apple ships it, and enables pf. The rules match the packets
# of the service's user, _clipboardbridge, and of no other program:
#
#   - only the home network reaches the member port (TCP), always;
#   - until sync away from home is on, the service sends to and takes
#     packets from the home network only. cbb away on writes
#     /etc/clipboardbridge/away and runs load again, which leaves these
#     rules out, since the tunnel reaches the hub, forwarder or relay on
#     the internet over UDP; cbb away off removes the file and loads them.
#
# The home network: loopback, private IPv4, link-local, multicast and
# broadcast, unique-local, link-local and multicast IPv6.
# pf forgets its rules at a restart; the LaunchDaemon
# io.github.hunterewok.clipboardbridge.pf runs load at boot. unload, from
# uninstall.sh, empties the anchor and gives back the reference that
# enabled pf, so pf stays on only if something else enabled it.
set -eu

anchor=com.apple/clipboardbridge
etc=/etc/clipboardbridge
token=$etc/pf-token

rules() {
	echo 'table <cbb_home> const { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255, ::1, fe80::/10, fc00::/7, ff00::/8 }'
	echo 'block return in quick proto tcp from ! <cbb_home> to any user _clipboardbridge'
	if [ ! -e "$etc/away" ]; then
		echo 'block return in quick proto udp from ! <cbb_home> to any user _clipboardbridge'
		echo 'block return out quick proto { tcp, udp } from any to ! <cbb_home> user _clipboardbridge'
	fi
}

case ${1:-} in
load)
	install -d -m 0755 "$etc"
	rules | pfctl -q -a "$anchor" -f -
	# pfctl -E counts a reference and prints its token; the last one taken
	# is the one unload gives back.
	if [ -f "$token" ]; then
		pfctl -q -X "$(cat "$token")" 2>/dev/null || true
	fi
	pfctl -E 2>&1 | sed -n 's/^Token : //p' >"$token"
	;;
unload)
	pfctl -q -a "$anchor" -F all 2>/dev/null || true
	if [ -f "$token" ]; then
		pfctl -q -X "$(cat "$token")" 2>/dev/null || true
		rm -f "$token"
	fi
	;;
*)
	echo "usage: sudo sh pf.sh load|unload" >&2
	exit 2
	;;
esac
