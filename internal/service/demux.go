// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"net"
	"sync"
)

// The member port is clipboardbridge's only port. Its connections are told
// apart by their first bytes: plain HTTP for the profile while an iPhone
// pairing window is open, else TLS, where the ALPN protocol the client
// offers picks pairing, the member protocol, or HTTPS for the iPhone
// shortcut.

// recordHandshake is the first byte of a TLS connection: a handshake record.
const recordHandshake = 0x16

// peekedConn is a connection whose first bytes were read ahead.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// peek reads the first byte of raw without taking it from the connection.
func peek(raw net.Conn) (net.Conn, byte, error) {
	r := bufio.NewReader(raw)
	b, err := r.Peek(1)
	if err != nil {
		return raw, 0, err
	}
	return &peekedConn{raw, r}, b[0], nil
}

// connListener is a net.Listener that hands out the connections that the
// member port passes to it, for an http.Server.
type connListener struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

// pass hands c to the server, or closes it once the listener is closed.
func (l *connListener) pass(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }
