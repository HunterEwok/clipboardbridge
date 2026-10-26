#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Lets the bench's controller reach itself over SSH, for a device on the
# controller (the container of setup-docker.sh, with ssh = "user@localhost"
# in the inventory), and takes it back:
#
#   sh tools/bench/setup-controller.sh setup [KEY]   KEY: the bench's key, ~/.ssh/cbb_bench
#   sh tools/bench/setup-controller.sh teardown
#
# setup adds the bench's public key to the user's authorized_keys, the
# localhost host key to known_hosts and a Host localhost block that uses the
# bench's key to ~/.ssh/config, each marked cbb-bench-localhost; teardown
# removes what carries the mark.
set -eu

mark=cbb-bench-localhost
ssh=$HOME/.ssh

case ${1:-} in
setup)
	key=${2:-$ssh/cbb_bench}
	[ -f "$key.pub" ] || {
		echo "setup-controller.sh: no $key.pub" >&2
		exit 1
	}
	pub=$(cut -d' ' -f1,2 "$key.pub")
	grep -qF "$pub" "$ssh/authorized_keys" 2>/dev/null || echo "$pub $mark" >>"$ssh/authorized_keys"
	chmod 0600 "$ssh/authorized_keys"
	grep -q "$mark" "$ssh/known_hosts" 2>/dev/null ||
		ssh-keyscan -t ed25519 localhost 2>/dev/null | sed "s/\$/ $mark/" >>"$ssh/known_hosts"
	grep -q "^# $mark" "$ssh/config" 2>/dev/null ||
		printf '\n# %s: the bench reaches devices on this controller\nHost localhost\n  IdentityFile %s\n  IdentitiesOnly yes\n' "$mark" "$key" >>"$ssh/config"
	ssh -o BatchMode=yes localhost true
	echo "This controller reaches itself over SSH with the bench's key."
	;;
teardown)
	for f in authorized_keys known_hosts; do
		[ ! -f "$ssh/$f" ] || { sed -i.bak "/$mark/d" "$ssh/$f" && rm -f "$ssh/$f.bak"; }
	done
	ssh-keygen -R localhost >/dev/null 2>&1 || true
	if [ -f "$ssh/config" ]; then
		awk -v m="# $mark" '$0 ~ "^" m {skip = 1; next} skip && /^(Host |$)/ && !/^Host localhost/ {skip = 0} skip {next} {print}' "$ssh/config" >"$ssh/config.new"
		mv "$ssh/config.new" "$ssh/config"
		chmod 0600 "$ssh/config"
	fi
	echo "This controller no longer reaches itself with the bench's key."
	;;
*)
	echo "usage: sh tools/bench/setup-controller.sh setup [KEY] | teardown" >&2
	exit 2
	;;
esac
