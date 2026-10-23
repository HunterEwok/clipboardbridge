// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package control

// DefaultSocket is where the service listens on macOS: in a directory that
// only the _clipboardbridge group may enter.
const DefaultSocket = "/Library/Application Support/clipboardbridge/control.sock"

// Group is the group whose members may use the control socket.
const Group = "_clipboardbridge"

// permissionHint tells a user without access to the socket what to do.
const permissionHint = "add your user to the " + Group + " group and log in again"
