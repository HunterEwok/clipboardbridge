// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestLingerKeepsWhatWasSent checks that a connection ended by linger
// leaves the peer what it sent, even when the peer had sent data that was
// never read: closing the socket at once would reset the connection, and
// the reset makes the peer drop what it had received but not yet read, as
// an admin lost the result of cbb global off -on.
func TestLingerKeepsWhatWasSent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c := <-accepted
	if c == nil {
		t.Fatal("no connection")
	}
	// The peer sends something this side never reads, as a ping or an
	// event that crossed the result.
	if _, err := peer.Write(bytes.Repeat([]byte{1}, 4096)); err != nil {
		t.Fatal(err)
	}
	result := []byte("the result")
	if _, err := c.Write(result); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // the peer's data has arrived
	done := make(chan struct{})
	go func() {
		defer close(done)
		linger(c)
		c.Close()
	}()
	// The peer reads late, after this side has ended the connection.
	time.Sleep(200 * time.Millisecond)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(peer)
	if err != nil {
		t.Fatalf("the peer read %q, then %v", got, err)
	}
	if !bytes.Equal(got, result) {
		t.Errorf("the peer read %q, want %q", got, result)
	}
	peer.Close()
	<-done
}
