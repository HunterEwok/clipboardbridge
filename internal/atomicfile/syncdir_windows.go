// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package atomicfile

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// syncDir does nothing on Windows: a directory cannot be flushed there,
// and NTFS journals the rename itself.
func syncDir(string) error { return nil }

// rename replaces to with from. On Windows a file that another process, or
// another goroutine, holds open cannot be replaced, which a virus scanner or
// a reader of the file does for moments; so it tries again for up to two
// seconds.
func rename(from, to string) error {
	const errSharingViolation syscall.Errno = 32
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.Rename(from, to)
		if err == nil || time.Now().After(deadline) ||
			!errors.Is(err, syscall.ERROR_ACCESS_DENIED) && !errors.Is(err, errSharingViolation) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
