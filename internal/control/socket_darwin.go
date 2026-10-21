// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package control

// DefaultSocket is where the service listens on macOS: in a directory that
// only the _clipbridge group may enter.
const DefaultSocket = "/Library/Application Support/clipbridge/control.sock"

// Group is the group whose members may use the control socket.
const Group = "_clipbridge"
