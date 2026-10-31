// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"io"
	"net"
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
