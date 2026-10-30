// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || darwin || freebsd

package service

import "os"

// privileged reports root and the service's own user.
func (p peer) privileged() bool {
	return p.uid == 0 || p.uid == uint32(os.Getuid())
}
