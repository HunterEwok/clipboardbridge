#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipboardbridge on FreeBSD, as root:
#
#   sh install.sh [--port N] [--home-cgnat on|off] [--express | --no-firewall] path/to/cbb
#
# It installs the binary to /usr/local/bin, makes the user and group
# clipboardbridge (pw), the rc.d script, which runs the service through
# daemon(8), and enables it in rc.conf, adds the user who ran sudo or doas
# to the group, and starts or restarts the service. The keys live in
# /var/db/clipboardbridge, the settings in /usr/local/etc/clipboardbridge;
# desktop sessions start the clipboard agent from XDG autostart.
# --port, --home-cgnat, --express and --no-firewall work as in the Linux
# installer; the firewall is pf or ipfw (firewall.sh). uninstall.sh removes
# it all again.
set -eu

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
export LC_ALL=C

usage() {
	echo "usage: sh install.sh [--port N] [--home-cgnat on|off] [--express | --no-firewall] path/to/cbb" >&2
	exit 2
}
port=
cgnat=${CBB_HOME_CGNAT:-}
firewall=${CBB_FIREWALL:-ask}
while [ $# -gt 1 ]; do
	case $1 in
	--express) firewall=express ;;
	--no-firewall) firewall=no ;;
	--port)
		port=$2
		shift
		;;
	--home-cgnat)
		case $2 in
		on) cgnat=1 ;;
		off) cgnat=0 ;;
		*) usage ;;
		esac
		shift
		;;
	*) usage ;;
	esac
	shift
done
[ $# -eq 1 ] || usage
case $cgnat in
'' | 0 | 1) ;;
*)
	echo "install.sh: CBB_HOME_CGNAT is 1 or 0, not $cgnat" >&2
	exit 2
	;;
esac
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
case $firewall in
ask | express | no) ;;
yes) firewall=ask ;;
*)
	echo "install.sh: CBB_FIREWALL is ask, express or no, not $firewall" >&2
	exit 2
	;;
esac
bin=$1
case $bin in
*/*) ;;
*) bin=./$bin ;;
esac
here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: run it as root (sudo or doas)" >&2
	exit 1
fi
if [ "$(uname -s)" != FreeBSD ]; then
	echo "install.sh: this installer is for FreeBSD" >&2
	exit 1
fi
if ! "$bin" version >/dev/null 2>&1; then
	echo "install.sh: $bin does not run on this machine; is it built for $(uname -m)?" >&2
	exit 1
fi

if ! pw groupshow clipboardbridge >/dev/null 2>&1; then
	pw groupadd clipboardbridge
fi
if ! pw usershow clipboardbridge >/dev/null 2>&1; then
	pw useradd clipboardbridge -g clipboardbridge -d /nonexistent -s /usr/sbin/nologin -c "Clipboard Bridge"
fi
install -m 0755 "$bin" /usr/local/bin/cbb
install -d -m 0755 /usr/local/etc/rc.d /usr/local/share/clipboardbridge /usr/local/etc/clipboardbridge
install -m 0555 "$here/clipboardbridge" /usr/local/etc/rc.d/clipboardbridge
install -d -o clipboardbridge -g clipboardbridge -m 0700 /var/db/clipboardbridge

user=${SUDO_USER:-${DOAS_USER:-}}
if [ -n "$user" ] && [ "$user" != root ]; then
	pw groupmod clipboardbridge -m "$user"
	echo "Added $user to the clipboardbridge group; log in again to use cbb copy and paste."
fi

env=/usr/local/etc/clipboardbridge/clipboardbridge.env
if [ -z "$port" ]; then
	port=$(sed -n 's/^CBB_PORT=//p' "$env" 2>/dev/null | tail -n 1)
fi
port=${port:-8764}
if [ -z "$cgnat" ]; then
	cgnat=$(sed -n 's/^CBB_HOME_CGNAT=//p' "$env" 2>/dev/null | tail -n 1)
fi
[ "$cgnat" = 1 ] || cgnat=0
if [ "$port" = 8764 ] && [ "$cgnat" = 0 ]; then
	rm -f "$env"
else
	{
		echo "# Written by clipboardbridge's install.sh; change it with install.sh --port N and --home-cgnat on|off."
		if [ "$port" != 8764 ]; then
			echo "CBB_PORT=$port"
		fi
		if [ "$cgnat" = 1 ]; then
			echo "CBB_HOME_CGNAT=1"
		fi
	} >"$env"
	chmod 0644 "$env"
fi

install -m 0644 "$here/firewall.sh" /usr/local/share/clipboardbridge/firewall.sh
install -m 0644 "$here/uninstall.sh" /usr/local/share/clipboardbridge/uninstall.sh
# Desktop sessions (KDE, GNOME, Xfce and others that read XDG autostart)
# start the clipboard agent, cbb agent, at login.
install -d -m 0755 /usr/local/etc/xdg/autostart
install -m 0644 "$here/clipboardbridge-desktop.desktop" /usr/local/etc/xdg/autostart/clipboardbridge-desktop.desktop
sh /usr/local/share/clipboardbridge/firewall.sh setup "$firewall" "$port"
if [ "$port" != 8764 ]; then
	echo "Clipboard Bridge uses TCP port $port instead of 8764. The iPhone shortcut works only"
	echo "with 8764; the Clipboard Bridge app takes any port."
fi

sysrc -q clipboardbridge_enable=YES >/dev/null
service clipboardbridge restart >/dev/null 2>&1 || service clipboardbridge start

answers() { # cbb
	i=0
	while [ $i -lt 40 ]; do
		out=$("$1" status 2>&1) && return 0
		case $out in *"in a group"* | *"no group"*) return 0 ;; esac
		sleep 0.25
		i=$((i + 1))
	done
	echo "install.sh: the service did not answer within 10 s: $out" >&2
	return 1
}
answers /usr/local/bin/cbb || true
echo "Clipboard Bridge is running on TCP port $port. To remove it: sh /usr/local/share/clipboardbridge/uninstall.sh"
echo "Next: run cbb pair as root and scan its QR code with the Clipboard Bridge app on your phone; without the app, see docs/guide/without-app.md."
