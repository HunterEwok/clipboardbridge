#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Opens and closes clipbridge's ports in the firewall:
#
#   sudo sh firewall.sh open PORT...   # e.g. 8764
#   sudo sh firewall.sh close
#
# open allows mDNS and the TCP ports from the home network only, when ufw or
# firewalld is active, and remembers in /etc/clipbridge/firewall what it
# added; a bare nftables or iptables setup that drops input gets the commands
# to run. close removes exactly what open added and nothing else, so open
# first closes, and a changed port leaves no old rule behind. install.sh and
# uninstall.sh run it.
set -eu
# The firewall tools answer in the user's language; what this reads is English.
export LC_ALL=C

state=/etc/clipbridge/firewall

usage() {
	echo "usage: sudo sh firewall.sh open PORT... | close" >&2
	exit 2
}

# The firewall rules in /etc/clipbridge/firewall: "ufw", which tagged its
# rules with the comments clipbridge and "clipbridge mDNS", or "firewalld"
# followed by the rich rules it added, one "rule ..." per line. Without the
# file it looks for tagged ufw rules, which get.sh added before the file.
close() {
	kind=ufw
	if [ -f "$state" ]; then
		kind=$(head -n 1 "$state")
	fi
	case $kind in
	ufw)
		if command -v ufw >/dev/null 2>&1; then
			# Delete from the last number down, since a deletion renumbers
			# the rules after it.
			ours=$(ufw status numbered 2>/dev/null |
				sed -n 's/^\[ *\([0-9][0-9]*\)\].*# clipbridge\( mDNS\)\{0,1\} *$/\1/p' | sort -rn)
			for n in $ours; do
				ufw --force delete "$n" >/dev/null
			done
			if [ -n "$ours" ]; then
				echo "ufw: removed the clipbridge rules."
			fi
		fi
		;;
	firewalld)
		if command -v firewall-cmd >/dev/null 2>&1; then
			tail -n +2 "$state" | while read -r rule; do
				firewall-cmd --permanent --remove-rich-rule="$rule" >/dev/null 2>&1 || true
			done
			rm -f /etc/firewalld/services/clipbridge.xml
			firewall-cmd --reload >/dev/null 2>&1 || true
			echo "firewalld: removed the clipbridge rules and service."
		fi
		;;
	esac
	rm -f "$state"
}

# firewalld_service writes the clipbridge service with the TCP ports.
firewalld_service() {
	{
		echo '<?xml version="1.0" encoding="utf-8"?>'
		echo '<!-- Written by clipbridge'"'"'s firewall.sh; removed with the rules. -->'
		echo '<service>'
		echo '  <short>clipbridge</short>'
		echo '  <description>clipbridge shared clipboard between the devices at home.</description>'
		for p in "$@"; do
			echo "  <port protocol=\"tcp\" port=\"$(echo "$p" | tr : -)\"/>"
		done
		echo '</service>'
	} >/etc/firewalld/services/clipbridge.xml
	chmod 0644 /etc/firewalld/services/clipbridge.xml
}

open() {
	close
	nets=$(ip -o -f inet route show scope link 2>/dev/null | awk '
		$1 ~ /^10\./ || $1 ~ /^192\.168\./ || $1 ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ { print $1 }' | sort -u)
	example=$(echo "$nets" | head -n 1)
	example=${example:-192.168.0.0/24}
	ports=$(echo "$*" | sed 's/ /, /g')
	from="$(echo "$nets" | tr '\n' ' ')and local IPv6"
	install -d -m 0755 /etc/clipbridge
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
		echo ufw >"$state"
		for net in $nets fe80::/10 fc00::/7; do
			ufw allow proto udp from "$net" to any port 5353 comment 'clipbridge mDNS' >/dev/null
			for p in "$@"; do
				ufw allow proto tcp from "$net" to any port "$p" comment clipbridge >/dev/null
			done
		done
		echo "ufw: allowed mDNS and TCP $ports from $from."
	elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		echo firewalld >"$state"
		firewalld_service "$@"
		firewall-cmd --reload >/dev/null
		for net in $nets fe80::/10 fc00::/7; do
			family=ipv4
			case $net in *:*) family=ipv6 ;; esac
			for svc in clipbridge mdns; do
				rule="rule family=$family source address=$net service name=$svc accept"
				# A rule that was there before is not ours to remove.
				if ! firewall-cmd --permanent --query-rich-rule="$rule" >/dev/null 2>&1; then
					firewall-cmd --permanent --add-rich-rule="$rule" >/dev/null
					echo "$rule" >>"$state"
				fi
			done
		done
		firewall-cmd --reload >/dev/null
		echo "firewalld: allowed mDNS and TCP $ports from $from in the default zone."
	elif { command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'hook input.*policy drop'; } ||
		{ command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; }; then
		echo "A firewall drops incoming connections here, and clipbridge cannot change it for you."
		echo "Allow TCP $ports and UDP 5353 from the home network, for example with iptables:"
		for p in "$@"; do
			echo "  sudo iptables -I INPUT -s $example -p tcp --dport $p -j ACCEPT"
		done
		echo "  sudo iptables -I INPUT -s $example -p udp --dport 5353 -j ACCEPT"
		echo "and make the rules permanent the way your system keeps them."
	fi
}

[ $# -ge 1 ] || usage
if [ "$(id -u)" -ne 0 ]; then
	echo "firewall.sh: run it with sudo" >&2
	exit 1
fi
cmd=$1
shift
case $cmd in
open)
	[ $# -ge 1 ] || usage
	open "$@"
	;;
close)
	[ $# -eq 0 ] || usage
	close
	;;
*) usage ;;
esac
