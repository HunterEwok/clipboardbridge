// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

// Package eitest is an EIS server for tests: it gives one client a
// keyboard and reports the keys it gets.
package eitest

import (
	"encoding/binary"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// A Key is a key the client sent.
type Key struct {
	Code  uint32
	Press bool
}

// Server serves one client.
type Server struct {
	Keys chan Key
	c    net.Conn
}

// New returns a server and the descriptor of the client's end, which the
// caller hands on, as the portal's ConnectToEIS does.
func New() (*Server, int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, -1, err
	}
	f := os.NewFile(uintptr(fds[1]), "eis")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		unix.Close(fds[0])
		return nil, -1, err
	}
	s := &Server{Keys: make(chan Key, 64), c: c}
	go s.serve()
	return s, fds[0], nil
}

// Close ends the connection.
func (s *Server) Close() error { return s.c.Close() }

const (
	conn = 0xff00000000000001
	seat = 0xff00000000000002
	dev  = 0xff00000000000003
	kbd  = 0xff00000000000004
)

func (s *Server) send(id uint64, op uint32, args ...[]byte) {
	n := 16
	for _, a := range args {
		n += len(a)
	}
	m := binary.NativeEndian.AppendUint64(nil, id)
	m = binary.NativeEndian.AppendUint32(m, uint32(n))
	m = binary.NativeEndian.AppendUint32(m, op)
	for _, a := range args {
		m = append(m, a...)
	}
	s.c.Write(m)
}

func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.NativeEndian.AppendUint64(nil, v) }
func str(v string) []byte {
	b := u32(uint32(len(v) + 1))
	b = append(append(b, v...), 0)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// serve runs the protocol: the handshake, a seat with a keyboard, a
// resumed device once the client binds it, then the keys.
func (s *Server) serve() {
	defer close(s.Keys)
	s.send(0, 0, u32(1)) // ei_handshake.handshake_version
	for {
		id, op, body, err := s.read()
		if err != nil {
			return
		}
		switch {
		case id == 0 && op == 1: // ei_handshake.finish
			s.send(0, 2, u32(1), u64(conn), u32(1)) // connection
			s.send(conn, 1, u64(seat), u32(1))      // seat
			s.send(seat, 2, u64(1<<5), str("ei_keyboard"))
			s.send(seat, 3) // done
		case id == seat && op == 1: // bind
			s.send(seat, 4, u64(dev), u32(1))                    // device
			s.send(dev, 5, u64(kbd), str("ei_keyboard"), u32(1)) // interface
			s.send(dev, 6)                                       // done
			s.send(dev, 7, u32(2))                               // resumed
		case id == kbd && op == 1 && len(body) >= 8: // key
			s.Keys <- Key{Code: binary.NativeEndian.Uint32(body), Press: binary.NativeEndian.Uint32(body[4:]) == 1}
		}
	}
}

func (s *Server) read() (uint64, uint32, []byte, error) {
	h := make([]byte, 16)
	if _, err := io.ReadFull(s.c, h); err != nil {
		return 0, 0, nil, err
	}
	body := make([]byte, binary.NativeEndian.Uint32(h[8:])-16)
	if _, err := io.ReadFull(s.c, body); err != nil {
		return 0, 0, nil, err
	}
	return binary.NativeEndian.Uint64(h), binary.NativeEndian.Uint32(h[12:]), body, nil
}
