// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net"
	"sync/atomic"
	"testing"
)

// addrConn is one end of a pipe that says it comes from addr and tells
// when it is closed.
type addrConn struct {
	net.Conn
	addr   net.Addr
	closed *atomic.Bool
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

func (c addrConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// The connections the member port passes on to the shortcut's and the
// profile's servers are bounded, in all and by address, while they are open.
func TestPassedBounded(t *testing.T) {
	l := newConnListener(&net.TCPAddr{})
	defer l.Close()
	accepted := make(chan net.Conn, 2*maxPassed)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	// pass hands the listener a connection from ip and returns what the
	// server got, or nil when the listener refused it.
	pass := func(ip string, port int) net.Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() })
		closed := new(atomic.Bool)
		l.pass(addrConn{a, &net.TCPAddr{IP: net.ParseIP(ip), Port: port}, closed})
		// A refused connection is closed before pass returns.
		if closed.Load() {
			return nil
		}
		return <-accepted
	}
	var first []net.Conn
	for i := range maxPassedAddress + 4 {
		c := pass("192.168.1.10", 1000+i)
		if (c != nil) != (i < maxPassedAddress) {
			t.Fatalf("connection %d from one address passed %v", i, c != nil)
		}
		if c != nil {
			first = append(first, c)
		}
	}
	// A closed connection gives its address its place back.
	first[0].Close()
	if pass("192.168.1.10", 1100) == nil {
		t.Fatal("a connection was refused after one from its address closed")
	}
	n := maxPassedAddress
	for i := 0; n < maxPassed+4; i++ {
		c := pass(net.IPv4(192, 168, 2, byte(i)).String(), 2000)
		if (c != nil) != (n < maxPassed) {
			t.Fatalf("connection %d in all passed %v", n, c != nil)
		}
		n++
	}
}
