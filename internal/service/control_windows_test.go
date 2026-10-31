// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestOwnDirMovesLinksAside checks that a junction or a file in the place
// of the admin socket's directory is moved aside, never followed: what the
// junction points to keeps its files and its access list.
func TestOwnDirMovesLinksAside(t *testing.T) {
	run := t.TempDir()
	target := filepath.Join(run, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(target, "kept.txt")
	if err := os.WriteFile(kept, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(run, "admin")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
	ln, err := listenControl(filepath.Join(dir, "cbb.sock"), true)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if _, err := os.Stat(kept); err != nil {
		t.Errorf("the junction's target lost its file: %v", err)
	}
	after, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Errorf("the junction's target was narrowed: %s, was %s", after, before)
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		t.Errorf("%s is not a plain directory now: %v %v", dir, fi, err)
	}
	if aside, _ := filepath.Glob(dir + ".untrusted-*"); len(aside) != 1 {
		t.Errorf("moved aside: %v, want the junction", aside)
	}

	// A file in its place goes aside too.
	file := filepath.Join(run, "admin2")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)")
	if err != nil {
		t.Fatal(err)
	}
	h, err := ownDir(file, sd)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	if fi, err := os.Lstat(file); err != nil || !fi.IsDir() {
		t.Errorf("%s is not a directory now: %v %v", file, fi, err)
	}

	// A directory it makes has its list from the start.
	fresh := filepath.Join(run, "admin3")
	h, err = ownDir(fresh, sd)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	got, err := windows.GetNamedSecurityInfo(fresh, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if c, _, err := got.Control(); err != nil || c&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s was made without its protected list: %s", fresh, got)
	}

	// The service's own directory stays as it is.
	h, err = ownDir(dir, sd)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	if aside, _ := filepath.Glob(dir + ".untrusted-*"); len(aside) != 1 {
		t.Errorf("the service's own directory was moved: %v", aside)
	}
}
