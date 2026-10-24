#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipboardbridge on a Mac:
#
#   sudo sh install.sh [--in-place] path/to/cbb
#
# It creates the hidden _clipboardbridge user and group, installs the binary to
# /usr/local/bin, the service as a LaunchDaemon and the pasteboard agent as
# a LaunchAgent, adds the user who ran sudo to the group, lets the service
# take connections through the application firewall, and starts or
# restarts both. With --in-place both run the binary where it is instead of
# a copy, for Homebrew, whose upgrades replace it there: the formula's
# caveats pass its opt path, and running this again after an upgrade
# restarts them on the new one. uninstall.sh removes it all again.
set -eu

usage() {
	echo "usage: sudo sh install.sh [--in-place] path/to/cbb" >&2
	exit 2
}
inplace=no
if [ "${1:-}" = --in-place ]; then
	inplace=yes
	shift
fi
[ $# -eq 1 ] || usage
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

if [ "$inplace" = yes ]; then
	# launchd takes the path as it is: absolute, and plain enough for the plists.
	run=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")
	case $run in
	*[!A-Za-z0-9/._+-]*)
		echo "install.sh: --in-place needs a path of letters, digits and / . _ + -, not $run" >&2
		exit 2
		;;
	esac
	# A copy from an install without --in-place would shadow it in PATH;
	# on an Intel Mac /usr/local/bin/cbb is Homebrew's own link.
	if [ -f /usr/local/bin/cbb ] && [ ! -L /usr/local/bin/cbb ]; then
		rm -f /usr/local/bin/cbb
	fi
else
	run=/usr/local/bin/cbb
	if [ -L "$run" ]; then
		echo "install.sh: $run is a link, likely Homebrew's; run this with --in-place $run" >&2
		exit 1
	fi
	install -d -m 0755 /usr/local/bin
	install -m 0755 "$bin" "$run"
fi
# The socket's directory: members of the group may reach the socket, and
# only the service its state.
install -d -o "$name" -g "$name" -m 0750 "/Library/Application Support/clipboardbridge"
install -d -o "$name" -g "$name" -m 0700 "/Library/Application Support/clipboardbridge/state"
install -d -o "$name" -g "$name" -m 0750 /Library/Logs/clipboardbridge

daemon=io.github.hunterewok.clipboardbridge
agent=io.github.hunterewok.clipboardbridge.agent
for p in "/Library/LaunchDaemons/$daemon.plist" "/Library/LaunchAgents/$agent.plist"; do
	sed "s|<string>/usr/local/bin/cbb</string>|<string>$run</string>|" "$here/$(basename "$p")" >"$p.new"
	chmod 0644 "$p.new"
	mv "$p.new" "$p"
done

user=${SUDO_USER:-}
if [ -n "$user" ] && [ "$user" != root ]; then
	dseditgroup -o edit -a "$user" -t user "$name"
fi

# The service takes connections from phones, other Macs and lite members at
# home. With the application firewall on, an unsigned program gets none until
# it is listed; the firewall knows the program by its real path, not a link.
# CBB_FIREWALL=no leaves the firewall alone. uninstall.sh takes the entry away.
fw=/usr/libexec/ApplicationFirewall/socketfilterfw
listed="/Library/Application Support/clipboardbridge/firewall"
if [ -x "$fw" ]; then
	if [ -f "$listed" ]; then
		"$fw" --remove "$(cat "$listed")" >/dev/null 2>&1 || true
		rm -f "$listed"
	fi
	if [ "${CBB_FIREWALL:-yes}" != no ]; then
		real=$(readlink -f "$run" 2>/dev/null || echo "$run")
		"$fw" --add "$real" >/dev/null
		"$fw" --unblockapp "$real" >/dev/null
		echo "$real" >"$listed"
	fi
fi

# restart DOMAIN LABEL PLIST stops the job if it runs and starts it again.
# bootout returns before launchd has let the job go, and a bootstrap in that
# moment fails with "5: Input/output error", so wait for it to be gone.
restart() {
	launchctl bootout "$1/$2" 2>/dev/null || true
	for _ in $(seq 50); do
		launchctl print "$1/$2" >/dev/null 2>&1 || break
		sleep 0.2
	done
	launchctl bootstrap "$1" "$3"
}

restart system "$daemon" "/Library/LaunchDaemons/$daemon.plist"
if [ -n "$user" ] && [ "$user" != root ]; then
	restart "gui/$(id -u "$user")" "$agent" "/Library/LaunchAgents/$agent.plist"
fi
echo "clipboardbridge is running. Join the group: cbb join, and scan its QR code with the iPhone shortcut \"clipboardbridge: add a computer\"; or cbb pair on a Linux member, then cbb join -code here."
