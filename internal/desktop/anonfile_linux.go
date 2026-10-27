// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package desktop

import "golang.org/x/sys/unix"

// anonFile opens a file in memory with no name, for the compositor to map.
func anonFile(name string) (int, error) {
	return unix.MemfdCreate(name, unix.MFD_CLOEXEC)
}
