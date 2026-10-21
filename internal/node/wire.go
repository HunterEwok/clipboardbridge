// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/HunterEwok/clipbridge/internal/clip"
	"github.com/HunterEwok/clipbridge/internal/group"
)

// The member protocol runs over a TLS connection made with the group's
// member configuration. Each side sends frames of a 4-byte big-endian length
// and a JSON message. The first message of each side is a hello; then
// events follow, and a ping whenever the side has sent nothing for a while,
// so a silent connection is a dead one. A member that holds the group CA key
// sends a cert message with a renewed certificate to a peer whose
// certificate is due for renewal. The group's signed records travel in
// records messages to a peer whose hello names other records.
const (
	typeHello = "hello"
	typeEvent = "event"
	typePing  = "ping"
	typeBye   = "bye"
	typeCert  = "cert"
	typeRecs  = "records"

	// maxFrame bounds a frame: a text of up to 1 MiB, which JSON may
	// escape to six bytes per byte for control characters, and the rest
	// of the event.
	maxFrame = 7 << 20

	// minRate is the slowest transfer a frame is given time for, on top
	// of the timeout, so a large text over a slow link still arrives.
	minRate = 16 << 10 // bytes per second
)

// Role tells what kind of member is at the other end.
type Role string

const (
	Linux Role = "linux" // listens, can hold clipbridge.local
	Mac   Role = "mac"   // only dials
	Phone Role = "phone" // a phone app: only dials, never dialed
	Lite  Role = "lite"  // a lite member for small devices: only dials
)

// known reports whether a peer may claim the role in its hello.
func (r Role) known() bool {
	switch r {
	case Linux, Mac, Phone, Lite:
		return true
	}
	return false
}

// message is one frame of the member protocol. The hello and the event are
// decoded on their own, so an event this member cannot read, for example
// from a newer version, is dropped without ending the connection.
type message struct {
	Type  string          `json:"t"`
	Role  Role            `json:"role,omitempty"`  // in a hello
	Hello json.RawMessage `json:"hello,omitempty"` // in a hello: clip.Hello
	Event json.RawMessage `json:"event,omitempty"` // in an event: clip.Event
	Cert  []byte          `json:"cert,omitempty"`  // in a cert: the renewed member certificate, DER

	Records []group.Record `json:"records,omitempty"` // in a records message
}

// helloBody is the content of a hello, with its current event left to
// decode on its own.
type helloBody struct {
	Wall    int64           `json:"wall_ms"`
	Current json.RawMessage `json:"current,omitempty"`
	Records string          `json:"records,omitempty"` // the digest of the sender's records
	Name    string          `json:"name,omitempty"`    // the sender's device name
}

// helloOut is the hello this member sends: the engine's hello, the digest
// of its records and its name.
type helloOut struct {
	clip.Hello
	Records string `json:"records,omitempty"`
	Name    string `json:"name,omitempty"`
}

// recordsChunk bounds the records of one message, well below maxFrame.
const recordsChunk = 1 << 20

// chunkRecords splits records into groups whose encoded size stays near
// recordsChunk, so each fits a frame.
func chunkRecords(rs []group.Record) [][]group.Record {
	var out [][]group.Record
	var cur []group.Record
	size := 0
	for _, r := range rs {
		n := len(r.Body) + len(r.Sig)
		for _, c := range r.Chain {
			n += len(c)
		}
		n = n*4/3 + 64 // base64 and the JSON around it
		if len(cur) > 0 && size+n > recordsChunk {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, r)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// encode marshals v as JSON without escaping <, > and &, which would make
// texts that contain them up to six times longer.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// transferTime is how long a frame of n bytes may take, beyond the timeout.
func transferTime(n int) time.Duration { return time.Duration(n/minRate) * time.Second }

// frame encodes a message as a frame.
func frame(m *message) ([]byte, error) {
	data, err := encode(m)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFrame {
		return nil, errors.New("node: message too large")
	}
	return append(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(data)), uint32(len(data))), data...), nil
}

// deadliner is the part of a connection readMessage needs to give a large
// frame more time once its length is known.
type deadliner interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

// readMessage reads one frame. The caller sets the deadline for its
// start; once the length is known, the deadline grows with it.
func readMessage(r deadliner, timeout time.Duration) (*message, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > maxFrame {
		return nil, fmt.Errorf("node: a frame of %d bytes is too large", size)
	}
	r.SetReadDeadline(time.Now().Add(timeout + transferTime(int(size))))
	// Read the body as it arrives, rather than allocating what the length
	// promises before a byte of it came.
	data, err := io.ReadAll(io.LimitReader(r, int64(size)))
	if err != nil {
		return nil, err
	}
	if len(data) != int(size) {
		return nil, io.ErrUnexpectedEOF
	}
	var m message
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, errors.New("node: a frame is not a message")
	}
	return &m, nil
}
