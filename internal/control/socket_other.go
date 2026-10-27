// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !darwin && !windows

package control

import (
	"runtime"

	"github.com/HunterEwok/clipboardbridge/internal/openwrt"
)

// DefaultSocket is where the service listens: in the runtime directory that
// systemd makes for it on Linux, and that the init script makes in
// /var/run on FreeBSD and OpenWrt, which have no /run.
var DefaultSocket = defaultSocket()

func defaultSocket() string {
	if runtime.GOOS == "linux" && !openwrt.Is() {
		return "/run/clipboardbridge/control.sock"
	}
	return "/var/run/clipboardbridge/control.sock"
}

// Group is the group whose members may use the control socket.
const Group = "clipboardbridge"

// permissionHint tells a user without access to the socket what to do.
const permissionHint = "add your user to the " + Group + " group and log in again"

// startHint tells a user whose service is not running how to start it.
const startHint = "start it with: sudo systemctl start clipboardbridge"

// adminSocketName is the admin socket's name next to the control socket.
const adminSocketName = "admin.sock"

// adminHint tells a user without access to the admin socket what to do.
const adminHint = "run it with sudo"
