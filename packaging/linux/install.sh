#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipboardbridge on a Linux machine with systemd:
#
#   sudo sh install.sh [--console] [--port N] path/to/cbb
#
# The full member's archive and the lite member's (cbb-lite-linux-*) both
# carry this script, each with its own systemd unit beside it; cbb version
# tells the two apart. It installs the binary to /usr/local/bin, the service
# user, the systemd unit, for the full member the desktop autostart entry,
# and the tmux configuration, adds the user
# who ran sudo to the clipboardbridge group, and starts or restarts the service.
# --console also starts tmux after a login on the text console. --port moves
# the member port from 8764 to N, kept in /etc/clipboardbridge/clipboardbridge.env
# until the next --port; --port 8764 goes back. When ufw or firewalld is
# active it allows mDNS and clipboardbridge's port from the home network, on every run, so
# that an update fixes a firewall turned on after the first install, and
# removes the rules it added before, so an old port stays closed;
# CBB_FIREWALL=no leaves the firewall alone. uninstall.sh removes it
# all again.
set -eu

# A failure says so with its exit status; CBB_ERROR_DETAILS=1 shows every
# command as it runs, so that the output shows where and why it failed.
if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		echo "install.sh: failed (exit status $rc). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." >&2
	fi
}
trap 'failed $?' EXIT
# The firewall tools answer in the user's language; what this reads is English.
export LC_ALL=C

usage() {
	echo "usage: sudo sh install.sh [--console] [--port N] path/to/cbb" >&2
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

# The full member and the lite member share the command, the paths and the
# service, but neither can use the other's keys: switching is a new device.
kind_of() {
	if "$1" version 2>/dev/null | grep -q 'lite member'; then echo lite; else echo full; fi
}
kind=$(kind_of "$bin")
if [ -x /usr/local/bin/cbb ] && [ "$(kind_of /usr/local/bin/cbb)" != "$kind" ]; then
	echo "install.sh: the $(kind_of /usr/local/bin/cbb) member is installed here, and the $kind member cannot use its keys;" >&2
	echo "remove it first: sudo sh /usr/local/share/clipboardbridge/uninstall.sh --purge" >&2
	exit 1
fi

# Up to 0.2.0 clipboardbridge was called clipbridge, and its protocol does
# not reach this one: remove it, with its keys, user and firewall rules, so
# this device pairs again.
if [ -e /usr/local/bin/clipbridge ] || [ -e /etc/systemd/system/clipbridge.service ]; then
	if [ -f /usr/local/share/clipbridge/uninstall.sh ]; then
		sh /usr/local/share/clipbridge/uninstall.sh --purge >/dev/null
	else
		systemctl disable --now clipbridge.service >/dev/null 2>&1 || true
		if command -v ufw >/dev/null 2>&1; then
			old=$(ufw status numbered 2>/dev/null |
				sed -n 's/^\[ *\([0-9][0-9]*\)\].*# clipbridge\( mDNS\)\{0,1\} *$/\1/p' | sort -rn)
			for n in $old; do
				ufw --force delete "$n" >/dev/null
			done
		fi
		rm -f /etc/systemd/system/clipbridge.service /etc/xdg/autostart/clipbridge-desktop.desktop \
			/etc/profile.d/clipbridge-console.sh /usr/lib/sysusers.d/clipbridge.conf /usr/local/bin/clipbridge
		systemctl daemon-reload || true
		rm -rf /usr/local/share/clipbridge /etc/clipbridge /var/lib/clipbridge
	fi
	if [ -f /etc/tmux.conf ]; then
		grep -vxF 'source-file -q /usr/local/share/clipbridge/tmux.conf' /etc/tmux.conf >/etc/tmux.conf.old || true
		cat /etc/tmux.conf.old >/etc/tmux.conf
		rm -f /etc/tmux.conf.old
	fi
	userdel clipbridge 2>/dev/null || true
	groupdel clipbridge 2>/dev/null || true
	echo "Removed clipbridge, as clipboardbridge was called before; pair this device again."
fi

# The lite member was the command cbb-lite, with its own user and paths. Its
# keys move to the shared paths for the lite member, which stays in its group.
moved=no
if [ -e /usr/local/bin/cbb-lite ] || [ -e /etc/systemd/system/cbb-lite.service ]; then
	systemctl disable --now cbb-lite.service >/dev/null 2>&1 || true
	rm -rf /etc/systemd/system/cbb-lite.service /etc/systemd/system/cbb-lite.service.d \
		/usr/lib/sysusers.d/cbb-lite.conf /usr/local/bin/cbb-lite
	systemctl daemon-reload || true
	if [ "$kind" = lite ] && [ -d /var/lib/cbb-lite ] && [ ! -e /var/lib/clipboardbridge ]; then
		mv /var/lib/cbb-lite /var/lib/clipboardbridge
		moved=yes
	fi
	rm -rf /var/lib/cbb-lite
	userdel cbb-lite 2>/dev/null || true
	groupdel cbb-lite 2>/dev/null || true
	if [ "$moved" = yes ]; then
		echo "Renamed cbb-lite to cbb; this device stays in its group."
	else
		echo "Removed cbb-lite, as the lite member was called before; pair this device again."
	fi
fi

install -m 0755 "$bin" /usr/local/bin/cbb
install -m 0644 "$here/clipboardbridge.sysusers" /usr/lib/sysusers.d/clipboardbridge.conf
systemd-sysusers /usr/lib/sysusers.d/clipboardbridge.conf
if [ "$moved" = yes ]; then
	chown -R clipboardbridge:clipboardbridge /var/lib/clipboardbridge
fi
install -m 0644 "$here/clipboardbridge.service" /etc/systemd/system/clipboardbridge.service
# Desktop sessions start the connector with the session; the lite member has
# none.
if [ "$kind" = full ]; then
	install -d -m 0755 /etc/xdg/autostart
	install -m 0644 "$here/clipboardbridge-desktop.desktop" /etc/xdg/autostart/clipboardbridge-desktop.desktop
fi

# tmux reads /etc/tmux.conf; source the clipboardbridge part from there once.
install -d -m 0755 /usr/local/share/clipboardbridge
install -m 0644 "$here/../tmux/clipboardbridge.conf" /usr/local/share/clipboardbridge/tmux.conf
line='source-file -q /usr/local/share/clipboardbridge/tmux.conf'
if ! grep -qsF "$line" /etc/tmux.conf; then
	echo "$line" >>/etc/tmux.conf
fi
if [ "$console" = yes ]; then
	install -m 0644 "$here/../tmux/clipboardbridge-console.sh" /etc/profile.d/clipboardbridge-console.sh
fi

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	usermod -a -G clipboardbridge "$SUDO_USER"
	echo "Added $SUDO_USER to the clipboardbridge group; log in again to use cbb copy and paste."
fi

# The port: the one given, else the one kept from before, else 8764.
env=/etc/clipboardbridge/clipboardbridge.env
install -d -m 0755 /etc/clipboardbridge
if [ -n "$port" ]; then
	if [ "$port" -eq 8764 ]; then
		rm -f "$env"
	else
		{
			echo "# Written by clipboardbridge's install.sh; change it with install.sh --port N."
			echo "CBB_PORT=$port"
		} >"$env"
		chmod 0644 "$env"
	fi
fi
port=$(sed -n 's/^CBB_PORT=//p' "$env" 2>/dev/null | tail -n 1)
port=${port:-8764}

# A firewall drops what it does not allow, and clipboardbridge needs mDNS and its
# port from the other devices at home. firewall.sh first takes away what it
# opened before, so a changed port leaves nothing open behind it.
install -m 0644 "$here/firewall.sh" /usr/local/share/clipboardbridge/firewall.sh
install -m 0644 "$here/uninstall.sh" /usr/local/share/clipboardbridge/uninstall.sh
if [ "${CBB_FIREWALL:-yes}" != no ]; then
	sh /usr/local/share/clipboardbridge/firewall.sh open "$port"
fi
if [ "$port" != 8764 ]; then
	echo "clipboardbridge uses TCP port $port instead of 8764. If a firewall here or on the network"
	echo "limits incoming connections, allow TCP $port from the home network. The iPhone shortcut"
	echo "works only with 8764; the clipboardbridge app takes any port."
fi

systemctl daemon-reload
systemctl enable clipboardbridge.service
systemctl restart clipboardbridge.service # also takes a new binary on a reinstall
echo "clipboardbridge is running on TCP port $port. To remove it: sudo sh /usr/local/share/clipboardbridge/uninstall.sh"
if [ "$kind" = lite ]; then
	echo "Next: see lite/README.md; in short, sudo -u clipboardbridge cbb join here, and scan its QR code with the phone app."
else
	echo "Next: see docs/quickstart.md; in short, cbb new and cbb pair -phone on the first computer, cbb pair on the others."
fi
