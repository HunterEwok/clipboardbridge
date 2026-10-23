#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipbridge on a Linux machine with systemd:
#
#   sudo sh install.sh [--console] [--port N] path/to/clipbridge
#
# It installs the binary to /usr/local/bin, the service user, the systemd
# unit, the desktop autostart entry and the tmux configuration, adds the user
# who ran sudo to the clipbridge group, and starts or restarts the service.
# --console also starts tmux after a login on the text console. --port moves
# the member port from 8764 to N, kept in /etc/clipbridge/clipbridge.env
# until the next --port; --port 8764 goes back. When ufw or firewalld is
# active it allows mDNS and clipbridge's port from the home network, on every run, so
# that an update fixes a firewall turned on after the first install, and
# removes the rules it added before, so an old port stays closed;
# CLIPBRIDGE_FIREWALL=no leaves the firewall alone. uninstall.sh removes it
# all again.
set -eu
# The firewall tools answer in the user's language; what this reads is English.
export LC_ALL=C

usage() {
	echo "usage: sudo sh install.sh [--console] [--port N] path/to/clipbridge" >&2
	exit 2
}
console=no
port=
while [ $# -gt 1 ]; do
	case $1 in
	--console) console=yes ;;
	--port)
		port=$2
		shift
		;;
	*) usage ;;
	esac
	shift
done
[ $# -eq 1 ] || usage
case $port in
'') ;;
*[!0-9]*) usage ;;
*)
	if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
		echo "install.sh: --port takes a port from 1024 to 65535" >&2
		exit 2
	fi
	;;
esac
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

# The port: the one given, else the one kept from before, else 8764.
env=/etc/clipbridge/clipbridge.env
install -d -m 0755 /etc/clipbridge
if [ -n "$port" ]; then
	if [ "$port" -eq 8764 ]; then
		rm -f "$env"
	else
		{
			echo "# Written by clipbridge's install.sh; change it with install.sh --port N."
			echo "CLIPBRIDGE_PORT=$port"
		} >"$env"
		chmod 0644 "$env"
	fi
fi
port=$(sed -n 's/^CLIPBRIDGE_PORT=//p' "$env" 2>/dev/null | tail -n 1)
port=${port:-8764}

# A firewall drops what it does not allow, and clipbridge needs mDNS and its
# port from the other devices at home. firewall.sh first takes away what it
# opened before, so a changed port leaves nothing open behind it.
install -m 0644 "$here/firewall.sh" /usr/local/share/clipbridge/firewall.sh
install -m 0644 "$here/uninstall.sh" /usr/local/share/clipbridge/uninstall.sh
if [ "${CLIPBRIDGE_FIREWALL:-yes}" != no ]; then
	sh /usr/local/share/clipbridge/firewall.sh open "$port"
fi
if [ "$port" != 8764 ]; then
	echo "clipbridge uses TCP port $port instead of 8764. If a firewall here or on the network"
	echo "limits incoming connections, allow TCP $port from the home network. The iPhone shortcut"
	echo "works only with 8764; the clipbridge app takes any port."
fi

systemctl daemon-reload
systemctl enable clipbridge.service
systemctl restart clipbridge.service # also takes a new binary on a reinstall
echo "clipbridge is running on TCP port $port. To remove it: sudo sh /usr/local/share/clipbridge/uninstall.sh"
echo "Next: see docs/quickstart.md; in short, clipbridge pair -phone on the first Linux machine, clipbridge join on the others."
