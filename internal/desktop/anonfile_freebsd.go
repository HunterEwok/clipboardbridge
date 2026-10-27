// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package desktop

import (
	"os"

	"golang.org/x/sys/unix"
)

// anonFile opens a file with no name, for the compositor to map: a new
// file in the session's runtime directory, removed at once.
func anonFile(name string) (int, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, name+"-")
	if err != nil {
		return -1, err
	}
	defer f.Close()
	os.Remove(f.Name())
	return unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
}
