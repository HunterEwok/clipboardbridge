#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipbridge on a Mac:
#
#   sudo sh install.sh path/to/clipbridge
#
# It creates the hidden _clipbridge user and group, installs the binary to
# /usr/local/bin, the service as a LaunchDaemon and the pasteboard agent as
# a LaunchAgent, adds the user who ran sudo to the group, and starts both.
set -eu

if [ $# -ne 1 ]; then
	echo "usage: sudo sh install.sh path/to/clipbridge" >&2
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

name=_clipbridge
if ! dscl . -read "/Groups/$name" >/dev/null 2>&1; then
	# A free ID below 500, so the account stays hidden.
	id=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | sort -n | awk 'BEGIN{n=300} $1==n{n++} END{print n}')
	dscl . -create "/Groups/$name" PrimaryGroupID "$id"
	dscl . -create "/Groups/$name" RealName "clipbridge"
fi
gid=$(dscl . -read "/Groups/$name" PrimaryGroupID | awk '{print $2}')
if ! dscl . -read "/Users/$name" >/dev/null 2>&1; then
	uid=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | awk -v n="$gid" '$1==n{n++} END{print n}')
	dscl . -create "/Users/$name" UniqueID "$uid"
	dscl . -create "/Users/$name" PrimaryGroupID "$gid"
	dscl . -create "/Users/$name" UserShell /usr/bin/false
	dscl . -create "/Users/$name" NFSHomeDirectory /var/empty
	dscl . -create "/Users/$name" RealName "clipbridge service"
	dscl . -create "/Users/$name" IsHidden 1
fi

install -d -m 0755 /usr/local/bin
install -m 0755 "$bin" /usr/local/bin/clipbridge
# The socket's directory: members of the group may reach the socket, and
# only the service its state.
install -d -o "$name" -g "$name" -m 0750 "/Library/Application Support/clipbridge"
install -d -o "$name" -g "$name" -m 0700 "/Library/Application Support/clipbridge/state"
install -d -o "$name" -g "$name" -m 0750 /Library/Logs/clipbridge

daemon=io.github.hunterewok.clipbridge
agent=io.github.hunterewok.clipbridge.agent
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
echo "clipbridge is running. Join the group with: clipbridge join (run clipbridge pair on a Linux member first)."
