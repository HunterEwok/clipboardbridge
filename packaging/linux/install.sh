#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipbridge on a Linux machine with systemd:
#
#   sudo sh install.sh [--console] path/to/clipbridge
#
# It installs the binary to /usr/local/bin, the service user, the systemd
# unit, the desktop autostart entry and the tmux configuration, adds the user
# who ran sudo to the clipbridge group, and starts or restarts the service. --console also starts tmux after
# a login on the text console. When ufw or firewalld is active it allows
# clipbridge's ports from the home network, on every run, so that an update fixes a
# firewall turned on after the first install; CLIPBRIDGE_FIREWALL=no leaves
# the firewall alone.
set -eu

console=no
if [ "${1:-}" = "--console" ]; then
	console=yes
	shift
fi
if [ $# -ne 1 ]; then
	echo "usage: sudo sh install.sh [--console] path/to/clipbridge" >&2
	exit 2
fi
bin=$1
# A bare file name would be looked up in PATH, not here.
case $bin in
*/*) ;;
*) bin=./$bin ;;
esac
here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: run it with sudo" >&2
	exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
	echo "install.sh: systemd is required" >&2
	exit 1
fi
if ! "$bin" version >/dev/null 2>&1; then
	echo "install.sh: $bin does not run on this machine; is it built for $(uname -m)?" >&2
	exit 1
fi

install -m 0755 "$bin" /usr/local/bin/clipbridge
install -m 0644 "$here/clipbridge.sysusers" /usr/lib/sysusers.d/clipbridge.conf
systemd-sysusers /usr/lib/sysusers.d/clipbridge.conf
install -m 0644 "$here/clipbridge.service" /etc/systemd/system/clipbridge.service
# Desktop sessions start the connector with the session.
install -d -m 0755 /etc/xdg/autostart
install -m 0644 "$here/clipbridge-desktop.desktop" /etc/xdg/autostart/clipbridge-desktop.desktop

# tmux reads /etc/tmux.conf; source the clipbridge part from there once.
install -d -m 0755 /usr/local/share/clipbridge
install -m 0644 "$here/../tmux/clipbridge.conf" /usr/local/share/clipbridge/tmux.conf
line='source-file -q /usr/local/share/clipbridge/tmux.conf'
if ! grep -qsF "$line" /etc/tmux.conf; then
	echo "$line" >>/etc/tmux.conf
fi
if [ "$console" = yes ]; then
	install -m 0644 "$here/../tmux/clipbridge-console.sh" /etc/profile.d/clipbridge-console.sh
fi

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	usermod -a -G clipbridge "$SUDO_USER"
	echo "Added $SUDO_USER to the clipbridge group; log in again to use clipbridge copy and paste."
fi

# A firewall drops what it does not allow, and clipbridge needs mDNS and its
# ports from the other devices at home: allow them from the home network
# only. ufw and firewalld get the rules (both skip one they already have); a
# bare nftables or iptables setup that drops input gets the commands to run.
nets=$(ip -o -f inet route show scope link 2>/dev/null | awk '
	$1 ~ /^10\./ || $1 ~ /^192\.168\./ || $1 ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ { print $1 }' | sort -u)
example=$(echo "$nets" | head -n 1)
example=${example:-192.168.0.0/24}
if [ "${CLIPBRIDGE_FIREWALL:-yes}" = no ]; then
	:
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
	for net in $nets fe80::/10 fc00::/7; do
		ufw allow proto udp from "$net" to any port 5353 comment 'clipbridge mDNS' >/dev/null
		ufw allow proto tcp from "$net" to any port 8764:8767 comment clipbridge >/dev/null
	done
	echo "ufw: allowed mDNS and TCP 8764-8767 from $(echo "$nets" | tr '\n' ' ')and local IPv6."
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
	install -m 0644 "$here/clipbridge.firewalld.xml" /etc/firewalld/services/clipbridge.xml
	firewall-cmd --reload >/dev/null
	for net in $nets; do
		for svc in clipbridge mdns; do
			firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$net service name=$svc accept" >/dev/null
		done
	done
	for net in fe80::/10 fc00::/7; do
		for svc in clipbridge mdns; do
			firewall-cmd --permanent --add-rich-rule="rule family=ipv6 source address=$net service name=$svc accept" >/dev/null
		done
	done
	firewall-cmd --reload >/dev/null
	echo "firewalld: allowed mDNS and TCP 8764-8767 from $(echo "$nets" | tr '\n' ' ')and local IPv6 in the default zone."
elif { command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'hook input.*policy drop'; } ||
	{ command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; }; then
	echo "A firewall drops incoming connections here, and clipbridge cannot change it for you."
	echo "Allow TCP 8764-8767 and UDP 5353 from the home network, for example with iptables:"
	echo "  sudo iptables -I INPUT -s $example -p tcp --dport 8764:8767 -j ACCEPT"
	echo "  sudo iptables -I INPUT -s $example -p udp --dport 5353 -j ACCEPT"
	echo "and make the rules permanent the way your system keeps them."
fi

systemctl daemon-reload
systemctl enable clipbridge.service
systemctl restart clipbridge.service # also takes a new binary on a reinstall
echo "clipbridge is running. Next: see docs/quickstart.md; in short, clipbridge pair -phone on the first Linux machine, clipbridge join on the others."
