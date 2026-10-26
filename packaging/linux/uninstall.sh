#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed:
#
#   sudo sh /usr/local/share/clipboardbridge/uninstall.sh [--purge]
#
# It stops the service and removes the binary, the unit, the autostart entry,
# the tmux and console configuration, the settings in /etc/clipboardbridge and the
# firewall rules that install.sh added, and only those. The device's keys and
# group, in /var/lib/clipboardbridge, stay for a reinstall unless --purge; the
# clipboardbridge user and group stay too, since files may still belong to them.
set -eu

# A failure says so with its exit status; CBB_ERROR_DETAILS=1 shows every
# command as it runs, so that the output shows where and why it failed.
if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		echo "uninstall.sh: failed (exit status $rc). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." >&2
	fi
}
trap 'failed $?' EXIT
# The firewall tools answer in the user's language; what this reads is English.
export LC_ALL=C

purge=no
case ${1:-} in
'') ;;
--purge) purge=yes ;;
*)
	echo "usage: sudo sh uninstall.sh [--purge]" >&2
	exit 2
	;;
esac
if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh: run it with sudo" >&2
	exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now clipboardbridge.service >/dev/null 2>&1 || true
fi
share=/usr/local/share/clipboardbridge
if [ -f "$share/firewall.sh" ]; then
	sh "$share/firewall.sh" close
	sh "$share/firewall.sh" hub-close
fi
rm -f /etc/systemd/system/clipboardbridge.service.d/away.conf /etc/systemd/system/clipboardbridge.service.d/cgnat.conf
rmdir /etc/systemd/system/clipboardbridge.service.d 2>/dev/null || true
rm -f /etc/systemd/system/clipboardbridge.service /etc/xdg/autostart/clipboardbridge-desktop.desktop \
	/etc/profile.d/clipboardbridge-console.sh /usr/lib/sysusers.d/clipboardbridge.conf /usr/local/bin/cbb
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
if [ -f /etc/tmux.conf ]; then
	line='source-file -q /usr/local/share/clipboardbridge/tmux.conf'
	grep -vxF "$line" /etc/tmux.conf >/etc/tmux.conf.clipboardbridge || true
	cat /etc/tmux.conf.clipboardbridge >/etc/tmux.conf
	rm -f /etc/tmux.conf.clipboardbridge
fi
rm -rf "$share" /etc/clipboardbridge
if [ "$purge" = yes ]; then
	rm -rf /var/lib/clipboardbridge
	echo "Clipboard Bridge is removed, with this device's keys; it left its group."
else
	echo "Clipboard Bridge is removed. Its keys stay in /var/lib/clipboardbridge for a reinstall; --purge removes them."
fi
