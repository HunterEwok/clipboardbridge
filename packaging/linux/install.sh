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
# a login on the text console.
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

systemctl daemon-reload
systemctl enable clipbridge.service
systemctl restart clipbridge.service # also takes a new binary on a reinstall
echo "clipbridge is running. Next: see docs/quickstart.md; in short, clipbridge pair -phone on the first Linux machine, clipbridge join on the others."
