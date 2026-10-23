#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipboardbridge on a Mac:
#
#   sudo sh install.sh path/to/cbb
#
# It creates the hidden _clipboardbridge user and group, installs the binary to
# /usr/local/bin, the service as a LaunchDaemon and the pasteboard agent as
# a LaunchAgent, adds the user who ran sudo to the group, and starts both.
set -eu

if [ $# -ne 1 ]; then
	echo "usage: sudo sh install.sh path/to/cbb" >&2
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
if ! "$bin" version >/dev/null 2>&1; then
	echo "install.sh: $bin does not run on this Mac" >&2
	exit 1
fi

# Up to 0.2.0 clipboardbridge was called clipbridge, and its protocol does
# not reach this one: remove it, with its keys and user, so this Mac pairs
# again.
old=io.github.hunterewok.clipbridge
if [ -e /usr/local/bin/clipbridge ] || [ -e "/Library/LaunchDaemons/$old.plist" ]; then
	launchctl bootout "system/$old" 2>/dev/null || true
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		launchctl bootout "gui/$(id -u "$SUDO_USER")/$old.agent" 2>/dev/null || true
	fi
	rm -f "/Library/LaunchDaemons/$old.plist" "/Library/LaunchAgents/$old.agent.plist" /usr/local/bin/clipbridge
	rm -rf "/Library/Application Support/clipbridge" /Library/Logs/clipbridge
	dscl . -delete /Users/_clipbridge 2>/dev/null || true
	dscl . -delete /Groups/_clipbridge 2>/dev/null || true
	echo "Removed clipbridge, as clipboardbridge was called before; pair this Mac again."
fi

name=_clipboardbridge
if ! dscl . -read "/Groups/$name" >/dev/null 2>&1; then
	# A free ID below 500, so the account stays hidden.
	id=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | sort -n | awk 'BEGIN{n=300} $1==n{n++} END{print n}')
	dscl . -create "/Groups/$name" PrimaryGroupID "$id"
	dscl . -create "/Groups/$name" RealName "clipboardbridge"
fi
gid=$(dscl . -read "/Groups/$name" PrimaryGroupID | awk '{print $2}')
if ! dscl . -read "/Users/$name" >/dev/null 2>&1; then
	uid=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | awk -v n="$gid" '$1==n{n++} END{print n}')
	dscl . -create "/Users/$name" UniqueID "$uid"
	dscl . -create "/Users/$name" PrimaryGroupID "$gid"
	dscl . -create "/Users/$name" UserShell /usr/bin/false
	dscl . -create "/Users/$name" NFSHomeDirectory /var/empty
	dscl . -create "/Users/$name" RealName "clipboardbridge service"
	dscl . -create "/Users/$name" IsHidden 1
fi

install -d -m 0755 /usr/local/bin
install -m 0755 "$bin" /usr/local/bin/cbb
# The socket's directory: members of the group may reach the socket, and
# only the service its state.
install -d -o "$name" -g "$name" -m 0750 "/Library/Application Support/clipboardbridge"
install -d -o "$name" -g "$name" -m 0700 "/Library/Application Support/clipboardbridge/state"
install -d -o "$name" -g "$name" -m 0750 /Library/Logs/clipboardbridge

daemon=io.github.hunterewok.clipboardbridge
agent=io.github.hunterewok.clipboardbridge.agent
install -m 0644 "$here/$daemon.plist" "/Library/LaunchDaemons/$daemon.plist"
install -m 0644 "$here/$agent.plist" "/Library/LaunchAgents/$agent.plist"

user=${SUDO_USER:-}
if [ -n "$user" ] && [ "$user" != root ]; then
	dseditgroup -o edit -a "$user" -t user "$name"
fi

launchctl bootout "system/$daemon" 2>/dev/null || true
launchctl bootstrap system "/Library/LaunchDaemons/$daemon.plist"
if [ -n "$user" ] && [ "$user" != root ]; then
	uid=$(id -u "$user")
	launchctl bootout "gui/$uid/$agent" 2>/dev/null || true
	launchctl bootstrap "gui/$uid" "/Library/LaunchAgents/$agent.plist"
fi
echo "clipboardbridge is running. Join the group: cbb join, and scan its QR code with the iPhone shortcut \"clipboardbridge: add a computer\"; or cbb pair on a Linux member, then cbb join -code here."
