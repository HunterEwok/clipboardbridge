#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed:
#
#   sudo sh /usr/local/share/clipbridge/uninstall.sh [--purge]
#
# It stops the service and removes the binary, the unit, the autostart entry,
# the tmux and console configuration, the settings in /etc/clipbridge and the
# firewall rules that install.sh added, and only those. The device's keys and
# group, in /var/lib/clipbridge, stay for a reinstall unless --purge; the
# clipbridge user and group stay too, since files may still belong to them.
set -eu

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
	systemctl disable --now clipbridge.service >/dev/null 2>&1 || true
fi
share=/usr/local/share/clipbridge
if [ -f "$share/firewall.sh" ]; then
	sh "$share/firewall.sh" close
fi
rm -f /etc/systemd/system/clipbridge.service /etc/xdg/autostart/clipbridge-desktop.desktop \
	/etc/profile.d/clipbridge-console.sh /usr/lib/sysusers.d/clipbridge.conf /usr/local/bin/clipbridge
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
if [ -f /etc/tmux.conf ]; then
	line='source-file -q /usr/local/share/clipbridge/tmux.conf'
	grep -vxF "$line" /etc/tmux.conf >/etc/tmux.conf.clipbridge || true
	cat /etc/tmux.conf.clipbridge >/etc/tmux.conf
	rm -f /etc/tmux.conf.clipbridge
fi
rm -rf "$share" /etc/clipbridge
if [ "$purge" = yes ]; then
	rm -rf /var/lib/clipbridge
	echo "clipbridge is removed, with this device's keys; it left its group."
else
	echo "clipbridge is removed. Its keys stay in /var/lib/clipbridge for a reinstall; --purge removes them."
fi
