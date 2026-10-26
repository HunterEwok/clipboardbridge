// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package tpmtest starts swtpm, a software TPM, for the tests of the code
// that keeps keys in a TPM, and points tpmkey.Open at it.
package tpmtest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Start starts swtpm with its state in a temporary directory and sets
// CBB_TPM_SIMULATOR for the test. It skips the test when swtpm is not
// installed, unless CBB_TPM_REQUIRED is set, as in CI.
func Start(t testing.TB) {
	t.Helper()
	path, err := exec.LookPath("swtpm")
	if err != nil {
		if os.Getenv("CBB_TPM_REQUIRED") != "" {
			t.Fatal("swtpm is not installed")
		}
		t.Skip("swtpm is not installed")
	}
	port := freePorts(t)
	dir := t.TempDir()
	cmd := exec.Command(path, "socket", "--tpm2", "--tpmstate", "dir="+dir,
		"--server", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port+1),
		"--flags", "not-need-init,startup-clear")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if i == 100 {
			t.Fatalf("swtpm does not listen: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Setenv("CBB_TPM_SIMULATOR", addr)
}

// freePorts returns a port that is free with the one after it.
func freePorts(t testing.TB) int {
	for range 50 {
		a, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := a.Addr().(*net.TCPAddr).Port
		b, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p+1))
		a.Close()
		if err == nil {
			b.Close()
			return p
		}
	}
	t.Fatal("no two free ports")
	return 0
}
