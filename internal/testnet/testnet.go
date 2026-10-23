// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package testnet gives tests a connected pair of local stream sockets.
// Unlike net.Pipe the pair buffers, as TCP does, so a side that sends an
// alert does not wait for the other to read it.
package testnet

import (
	"net"
	"testing"
)

// SocketPair returns the two ends of a connected local socket; they are
// closed when the test ends.
func SocketPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	a, b, err := pair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
