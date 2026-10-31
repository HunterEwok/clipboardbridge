// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTestNames(t *testing.T) {
	got := testNames(map[string][]byte{
		"a/x_test.go":   []byte("func TestA(t *testing.T) {}\nfunc FuzzB(f *testing.F) {}\nfunc helper() {}\n"),
		"b/x_test.go":   []byte("func TestA(t *testing.T) {}\n"),
		"lite/src/x.rs": []byte("#[test]\nfn one() {}\n#[test]\n#[ignore]\npub fn two() {}\nfn three() {}\n"),
		"k/Tests/T/X.swift": []byte("    func testOne() throws {\n    func helper() {\n    @Test func two() async {\n" +
			"    func testArgs(_ x: Int) {\n"),
		"kit/src/test/kotlin/X.kt": []byte("    @Test\n    fun one() {\n    fun helper() {\n    @Test fun `two words`() {\n"),
	})
	want := []string{"Go a TestA", "Go a FuzzB", "Go b TestA", "Rust one", "Rust two", "Swift testOne", "Swift two",
		"Kotlin one", "Kotlin `two words`"}
	if len(got) != len(want) {
		t.Errorf("%d tests, want %d: %v", len(got), len(want), got)
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("no %q in %v", w, got)
		}
	}
}

func TestTestsKept(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "-q")
	os.MkdirAll(filepath.Join(repo, "p"), 0o755)
	os.WriteFile(filepath.Join(repo, "p/a_test.go"), []byte("func TestKept(t *testing.T) {}\nfunc TestGone(t *testing.T) {}\nfunc TestMoved(t *testing.T) {}\n"), 0o644)
	runGit("add", "-A")
	runGit("-c", "user.name=test", "-c", "user.email=test@example.org", "commit", "-q", "-m", "initial")
	t.Chdir(repo)
	now := map[string][]byte{
		"p/a_test.go": []byte("func TestKept(t *testing.T) {}\n"),
		"p/b_test.go": []byte("func TestMoved(t *testing.T) {}\n"),
	}
	problems, err := checkTestsKept("HEAD", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "TestGone") {
		t.Fatalf("%q", problems)
	}
}
