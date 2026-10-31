// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"errors"
	"net"
)

// errNotConnected is a connection through the tunnel that was closed or
// reset before its addresses were read.
var errNotConnected = errors.New("tunnel: the connection is no longer open")

// addrConn is a connection through the tunnel with the addresses it had when
// it was set up. The netstack's own connection asks its endpoint each time
// and has no address once the endpoint is closed or reset, so code that reads
// the address later would otherwise get nil.
type addrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c *addrConn) LocalAddr() net.Addr  { return c.local }
func (c *addrConn) RemoteAddr() net.Addr { return c.remote }

// withAddrs returns c with its addresses kept, or errNotConnected, with c
// closed, if it has none any more.
func withAddrs(c net.Conn) (net.Conn, error) {
	local, remote := c.LocalAddr(), c.RemoteAddr()
	if local == nil || remote == nil {
		c.Close()
		return nil, errNotConnected
	}
	return &addrConn{Conn: c, local: local, remote: remote}, nil
}

// addrListener hands out connections whose addresses stay readable, and
// drops one that was closed or reset before it was taken.
type addrListener struct{ net.Listener }

func (l addrListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if c, err := withAddrs(c); err == nil {
			return c, nil
		}
	}
}
