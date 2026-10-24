// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package relay is the blind relay: a meeting point for a group that has no
// computer to be its hub, on a server the user runs (docs/design.md, "Blind
// relay"). It holds none of the group's keys. Each member registers with
// its member certificate and proves its WireGuard key, and gets a tunnel to
// the relay; inside the tunnels the relay joins two members' connections
// end to end, so the member protocol's TLS runs between the two members
// and the relay passes only its ciphertext. It is still a star: members
// reach only the relay, and the relay decides which two connections to
// join, only within one group. The wire format is in docs/protocol.md,
// section 14.
package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

// Protocol is the ALPN protocol of a member's registration.
const Protocol = "clipboardbridge-relay/1"

// proofLabel is the label of the key, from the registration's TLS, under
// which a member proves its WireGuard key.
const proofLabel = "clipboardbridge relay key"

// Addr is the relay's own address inside the tunnels; it gives each member
// another one.
var Addr = netip.MustParseAddr("fd00:cbb::1")

// The registration's messages, one JSON object a line, as the forwarder's
// (docs/protocol.md, section 14).
type (
	challenge struct {
		E []byte `json:"e"` // the relay's ephemeral X25519 key
	}
	claim struct {
		Key   []byte `json:"key"`   // the member's WireGuard public key
		Proof []byte `json:"proof"` // HMAC-SHA256(X25519(member key, e), the TLS proof key)
	}
	welcome struct {
		Error string `json:"error,omitempty"` // why the relay refused it
		Key   []byte `json:"key,omitempty"`   // the relay's WireGuard public key
		PSK   []byte `json:"psk,omitempty"`   // this member's preshared key
		Addr  string `json:"addr,omitempty"`  // this member's tunnel address
	}
)

// The messages inside the tunnel, at the relay's member port: each
// connection starts with one request line; the relay answers with notes.
type (
	request struct {
		Watch  bool   `json:"watch,omitempty"`  // keep this connection for the notes
		Dial   string `json:"dial,omitempty"`   // join this connection to that device's
		Answer string `json:"answer,omitempty"` // the ticket of a call this connection answers
	}
	note struct {
		Online *[]string `json:"online,omitempty"` // the other devices of the group on the relay now
		Call   string    `json:"call,omitempty"`   // a device that dials this one
		Ticket string    `json:"ticket,omitempty"` // to answer that call with
		OK     bool      `json:"ok,omitempty"`     // joined: the member protocol follows
		Error  string    `json:"error,omitempty"`
	}
)

// maxLine bounds a request or a note.
const maxLine = 64 << 10

// writeLine sends v as one line, within d.
func writeLine(c net.Conn, v any, d time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.SetWriteDeadline(time.Now().Add(d))
	_, err = c.Write(append(b, '\n'))
	c.SetWriteDeadline(time.Time{})
	return err
}

// readLine reads one line into v, a byte at a time, so nothing after it is
// taken from the connection: the member protocol follows an answer's line.
func readLine(c net.Conn, v any, d time.Duration) error {
	if d > 0 {
		c.SetReadDeadline(time.Now().Add(d))
		defer c.SetReadDeadline(time.Time{})
	}
	var b bytes.Buffer
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c, one); err != nil {
			return err
		}
		if one[0] == '\n' {
			break
		}
		if b.Len() >= maxLine {
			return errors.New("relay: a line too long")
		}
		b.WriteByte(one[0])
	}
	return json.Unmarshal(b.Bytes(), v)
}
