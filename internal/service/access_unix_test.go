// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix

package service

import (
	"io/fs"
	"os"
	"testing"
)

// checkSocketAccess checks that only the service's user and group may
// connect.
func checkSocketAccess(t *testing.T, _ string, fi fs.FileInfo) {
	t.Helper()
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v", fi.Mode())
	}
}
