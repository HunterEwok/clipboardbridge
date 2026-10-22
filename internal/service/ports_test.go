// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPorts(t *testing.T) {
	dir := t.TempDir()
	old := EnvFile
	t.Cleanup(func() { EnvFile = old })
	EnvFile = filepath.Join(dir, "missing.env")

	// Nothing set: the defaults.
	if p, err := Port(); err != nil || p != MemberPort {
		t.Errorf("default: %d %v", p, err)
	}
	// The file, as install.sh writes it; the last line wins.
	EnvFile = filepath.Join(dir, "clipbridge.env")
	os.WriteFile(EnvFile, []byte("# written by install.sh\nCLIPBRIDGE_PORT=9000\nOTHER=1\nCLIPBRIDGE_PORT=\"9100\"\n"), 0o644)
	if p, err := Port(); err != nil || p != 9100 {
		t.Errorf("from the file: %d %v", p, err)
	}
	// The environment wins over the file, as systemd sets it.
	t.Setenv("CLIPBRIDGE_PORT", "9200")
	if p, err := Port(); err != nil || p != 9200 {
		t.Errorf("from the environment: %d %v", p, err)
	}
	for _, bad := range []string{"80", "65536", "port", "-1"} {
		t.Setenv("CLIPBRIDGE_PORT", bad)
		if _, err := Port(); err == nil || !strings.Contains(err.Error(), "CLIPBRIDGE_PORT") {
			t.Errorf("CLIPBRIDGE_PORT=%s: %v", bad, err)
		}
	}
}
