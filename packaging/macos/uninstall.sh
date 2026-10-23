#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed on a Mac:
#
#   sudo sh uninstall.sh [--purge]
#
# It stops the service and the pasteboard agent of every user and removes
# their plists, the binary in /usr/local/bin (but not Homebrew's link there:
# brew uninstall removes that) and the logs. The device's keys and group, in
# /Library/Application Support/clipboardbridge/state, stay for a reinstall
# unless --purge; the hidden _clipboardbridge user and group stay too, since
# files may still belong to them.
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

daemon=io.github.hunterewok.clipboardbridge
agent=io.github.hunterewok.clipboardbridge.agent
launchctl bootout "system/$daemon" 2>/dev/null || true
# The agent runs in each signed-in user's session.
for uid in $(ps -axo uid=,comm= | awk '$2 ~ /(^|\/)cbb$/ { print $1 }' | sort -u); do
	launchctl bootout "gui/$uid/$agent" 2>/dev/null || true
done
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	launchctl bootout "gui/$(id -u "$SUDO_USER")/$agent" 2>/dev/null || true
fi
rm -f "/Library/LaunchDaemons/$daemon.plist" "/Library/LaunchAgents/$agent.plist"
if [ -f /usr/local/bin/cbb ] && [ ! -L /usr/local/bin/cbb ]; then
	rm -f /usr/local/bin/cbb
fi
rm -rf /Library/Logs/clipboardbridge
support="/Library/Application Support/clipboardbridge"
if [ "$purge" = yes ]; then
	rm -rf "$support"
	echo "clipboardbridge is removed, with this Mac's keys; it left its group."
else
	rm -f "$support/control.sock"
	echo "clipboardbridge is removed. Its keys stay in $support/state for a reinstall; --purge removes them."
fi
