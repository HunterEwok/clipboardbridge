// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !darwin && !windows

package control

// DefaultSocket is where the service listens: in the runtime directory that
// systemd makes for it.
const DefaultSocket = "/run/clipboardbridge/control.sock"

// Group is the group whose members may use the control socket.
const Group = "clipboardbridge"

// permissionHint tells a user without access to the socket what to do.
const permissionHint = "add your user to the " + Group + " group and log in again"

// adminSocketName is the admin socket's name next to the control socket.
const adminSocketName = "admin.sock"

// adminHint tells a user without access to the admin socket what to do.
const adminHint = "run it with sudo"
