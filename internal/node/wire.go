// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/HunterEwok/clipbridge/internal/clip"
)

// The member protocol runs over a TLS connection made with the group's
// member configuration. Each side sends frames of a 4-byte big-endian length
// and a JSON message. The first message of each side is a hello; then
// events follow, and a ping whenever the side has sent nothing for a while,
// so a silent connection is a dead one.
const (
	typeHello = "hello"
	typeEvent = "event"
	typePing  = "ping"
	typeBye   = "bye"

	// maxFrame bounds a frame: a text of up to 1 MiB, which JSON may
	// escape to six bytes per byte for control characters, and the rest
	// of the event.
	maxFrame = 7 << 20
)

// Role tells what kind of member is at the other end.
type Role string

const (
	Linux Role = "linux" // listens, can hold clipbridge.local
	Mac   Role = "mac"   // only dials
)

// message is one frame of the member protocol.
type message struct {
	Type  string      `json:"t"`
	Role  Role        `json:"role,omitempty"`  // in a hello
	Hello *clip.Hello `json:"hello,omitempty"` // in a hello
	Event *clip.Event `json:"event,omitempty"` // in an event
}

func writeMessage(w io.Writer, m *message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return errors.New("node: message too large")
	}
	buf := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(data)), uint32(len(data)))
	_, err = w.Write(append(buf, data...))
	return err
}

func readMessage(r io.Reader) (*message, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > maxFrame {
		return nil, fmt.Errorf("node: a frame of %d bytes is too large", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	var m message
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("node: bad message: %w", err)
	}
	return &m, nil
}
