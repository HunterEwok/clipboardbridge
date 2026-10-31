// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package tpmtest starts swtpm, a software TPM, for the tests of the code
// that keeps keys in a TPM, and points tpmkey.Open at it.
package tpmtest

import (
	"fmt"
	"math/rand/v2"
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
	dir := t.TempDir()
	// Ports found free can be taken before swtpm binds them, by another
	// test's listener or connection when many run at once: they are taken
	// from below the systems' ranges of ephemeral ports, and swtpm is
	// started again on other ports when it cannot bind them.
	for try := 0; ; try++ {
		port := freePorts(t)
		cmd := exec.Command(path, "socket", "--tpm2", "--tpmstate", "dir="+dir,
			"--server", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port),
			"--ctrl", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port+1),
			"--flags", "not-need-init,startup-clear")
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		if listening(addr, exited) {
			t.Cleanup(func() {
				cmd.Process.Kill()
				<-exited
			})
			t.Setenv("CBB_TPM_SIMULATOR", addr)
			return
		}
		cmd.Process.Kill()
		<-exited
		if try == 10 {
			t.Fatalf("swtpm does not listen on %s", addr)
		}
	}
}

// listening waits until swtpm, which has not exited, takes connections at
// addr. It does not connect: swtpm serves one client at a time.
func listening(addr string, exited <-chan struct{}) bool {
	for range 100 {
		select {
		case <-exited:
			return false
		case <-time.After(50 * time.Millisecond):
		}
		if l, err := net.Listen("tcp", addr); err == nil {
			l.Close() // nobody listens there yet
			continue
		}
		// Somebody does; it is swtpm if it is still running.
		select {
		case <-exited:
			return false
		case <-time.After(50 * time.Millisecond):
			return true
		}
	}
	return false
}

// freePorts returns a port that is free with the one after it, from 20000
// to 29999: below the ranges the systems take ephemeral ports from (49152
// on macOS and Windows, 32768 on Linux), where other tests' listeners and
// connections land.
func freePorts(t testing.TB) int {
	for range 200 {
		p := 20000 + rand.IntN(9999)
		a, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
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
