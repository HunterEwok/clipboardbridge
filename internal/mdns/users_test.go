// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package mdns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The users the children of TestOtherUsers run as: avahi's stand-in, and
// the service's.
const (
	holderUID  = 65534 // nobody
	serviceUID = 1     // daemon
)

// TestOtherUsers shares port 5353 with a responder of another user, as
// with avahi: on FreeBSD a socket shares it only when root opened it
// (Preopen, cbb service -user), on Linux any socket does. Each side runs
// in a child process as its own user, and the service's finds the other
// responder through the socket it opened as root. It needs root, so it
// runs only when CBB_TEST_MDNS_USERS is set.
func TestOtherUsers(t *testing.T) {
	if os.Getenv("CBB_TEST_MDNS_USERS") == "" {
		t.Skip("set CBB_TEST_MDNS_USERS and run it as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("TestOtherUsers needs root")
	}
	// The children run as other users, who cannot reach go test's build
	// directory: the binary goes where they can.
	dir, err := os.MkdirTemp("", "cbb-mdns-users")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	exe := filepath.Join(dir, "mdns.test")
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	child := func(role string, uid uint32) *exec.Cmd {
		cmd := exec.Command(exe, "-test.run", "^TestOtherUsersChild$", "-test.v")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CBB_MDNS_CHILD="+role)
		if uid != 0 {
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		}
		return cmd
	}

	holder := child("holder", holderUID)
	stdin, _ := holder.StdinPipe()
	stdout, _ := holder.StdoutPipe()
	holder.Stderr = os.Stderr
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); holder.Wait() }()
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if l := sc.Text(); strings.HasPrefix(l, "holder:") {
				ready <- l
			}
		}
		close(ready)
	}()
	select {
	case l := <-ready:
		if l == "holder: skip" {
			t.Skip("no interface with a private address")
		}
		if l != "holder: ready" {
			t.Fatal(l)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the other user's responder did not start")
	}

	out, _ := child("plain", serviceUID).CombinedOutput()
	plain := string(out)
	if runtime.GOOS == "freebsd" && (!strings.Contains(plain, "plain: cannot listen") || !strings.Contains(plain, "held by")) {
		t.Errorf("FreeBSD let a socket of another user share port 5353, or did not say who holds it:\n%s", plain)
	}
	if runtime.GOOS == "linux" && !strings.Contains(plain, "plain: ok") {
		t.Errorf("Linux kept a socket of another user off port 5353:\n%s", plain)
	}

	out, err = child("preopen", 0).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "preopen: found") {
		t.Errorf("the socket root opened did not work after giving up root: %v\n%s", err, out)
	}
}

// TestOtherUsersChild is a child of TestOtherUsers.
func TestOtherUsersChild(t *testing.T) {
	role := os.Getenv("CBB_MDNS_CHILD")
	if role == "" {
		t.Skip("a child of TestOtherUsers")
	}
	switch role {
	case "holder":
		probe, err := listen(t.Logf, nil)
		if err != nil {
			fmt.Println("holder:", err)
			return
		}
		ifaces, _ := probe.interfaces()
		probe.close()
		if len(ifaces) == 0 {
			fmt.Println("holder: skip")
			return
		}
		stop := run(t, idB, 4002, nil)
		defer stop()
		fmt.Println("holder: ready")
		io.Copy(io.Discard, os.Stdin) // until the parent closes it
	case "plain":
		u, err := listen(t.Logf, nil)
		if err != nil {
			fmt.Println("plain: cannot listen:", err)
			return
		}
		u.close()
		fmt.Println("plain: ok")
	case "preopen":
		if err := Preopen(); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setgroups([]int{serviceUID}); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setgid(serviceUID); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setuid(serviceUID); err != nil {
			t.Fatal(err)
		}
		// Twice: the second responder takes the sockets the first gave
		// back, and joins the groups again.
		for range 2 {
			found := make(chan struct{})
			stop := run(t, idA, 4001, func(p []Peer) {
				for _, peer := range p {
					if peer.ID == idB && peer.Port == 4002 {
						select {
						case <-found:
						default:
							close(found)
						}
					}
				}
			})
			select {
			case <-found:
			case <-time.After(10 * time.Second):
				t.Fatal("did not find the other user's responder")
			}
			stop()
		}
		fmt.Println("preopen: found")
	}
}

// run starts a responder and returns the function that stops it.
func run(t *testing.T, id string, port uint16, onPeers func([]Peer)) func() {
	r, err := New(Config{ID: id, Port: port, TXT: []string{"v=1"}, OnPeers: onPeers, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	return func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}
}
