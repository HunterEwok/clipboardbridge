// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package control

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// DefaultSocket is where the service listens on Windows: in a directory of
// its own under ProgramData, whose access list lets only the service,
// administrators and the clipboardbridge group reach the socket.
var DefaultSocket = filepath.Join(ProgramData(), "clipboardbridge", "run", "control.sock")

// Group is the local group whose members may use the control socket.
const Group = "clipboardbridge"

// ProgramData returns the folder for data of all users, usually
// C:\ProgramData. It is asked from the system rather than taken from the
// environment, so the service and every client agree on it.
func ProgramData() string {
	if d, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil {
		return d
	}
	return `C:\ProgramData`
}

// permissionHint tells a user without access to the socket what to do.
const permissionHint = "add your user to the " + Group + " group (install.ps1 adds the user who runs it) and sign in again"

// adminSocketName is the admin socket's place next to the control socket:
// in a directory of its own, whose access list lets only the service and
// administrators in.
var adminSocketName = filepath.Join("admin", "admin.sock")

// adminHint tells a user without access to the admin socket what to do.
const adminHint = "run it from a terminal opened as administrator"
