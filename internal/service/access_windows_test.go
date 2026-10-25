// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// checkSocketAccess checks that the socket's directory has a protected
// access list, which its files inherit, and that it lets in no broad
// group: everyone, authenticated users or all users.
func checkSocketAccess(t *testing.T, path string, _ fs.FileInfo, admin bool) {
	t.Helper()
	for _, p := range []string{filepath.Dir(path), path} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		sddl := sd.String()
		if p == filepath.Dir(path) && !strings.HasPrefix(sddl, "D:P") {
			t.Errorf("%s: the access list is not protected: %s", p, sddl)
		}
		if admin && strings.Count(sddl, "(A;") > 3 {
			t.Errorf("%s: the admin socket lets in more than the system, administrators and the service: %s", p, sddl)
		}
		for _, broad := range []string{";;;WD)", ";;;AU)", ";;;BU)"} {
			if strings.Contains(sddl, broad) {
				t.Errorf("%s: the access list lets in %s: %s", p, broad, sddl)
			}
		}
	}
}
