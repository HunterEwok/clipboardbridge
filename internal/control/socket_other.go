// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !darwin

package control

// DefaultSocket is where the service listens: in the runtime directory that
// systemd makes for it.
const DefaultSocket = "/run/clipbridge/control.sock"

// Group is the group whose members may use the control socket.
const Group = "clipbridge"
