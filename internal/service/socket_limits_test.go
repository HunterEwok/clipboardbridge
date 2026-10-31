// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlUsers(t *testing.T) {
	var u controlUsers
	for range maxControlPerUser {
		if !u.add("uid 1000") {
			t.Fatal("refused below the limit")
		}
	}
	if u.add("uid 1000") {
		t.Error("took one past the limit")
	}
	if !u.add("uid 1001") {
		t.Error("another user was refused")
	}
	u.done("uid 1000")
	if !u.add("uid 1000") {
		t.Error("a closed connection did not make room")
	}
}

func TestControlIdleConnection(t *testing.T) {
	defer func(d time.Duration) { firstRequestTime = d }(firstRequestTime)
	firstRequestTime = 50 * time.Millisecond
	s := &Service{}
	c, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.handleControl(context.Background(), c, false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an idle connection stays open")
	}
	if _, err := client.Read(make([]byte, 1)); err != io.EOF && err != io.ErrClosedPipe {
		t.Errorf("read after the deadline: %v", err)
	}
}

// The control socket closes a user's connection past maxControlPerUser at
// once, and keeps the ones before it open.
func TestControlUsersOnTheSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&Service{logf: t.Logf}).serveControl(ctx, ln, false)
	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for range maxControlPerUser {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the connection past the limit: %v, want it closed", err)
	}
	// The first one is still open: it times out, it is not closed.
	open[0].SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := open[0].Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a connection within the limit: %v", err)
	}
}
