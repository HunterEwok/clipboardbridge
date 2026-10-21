// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package control is the protocol of the service's local control socket,
// which the command line, tmux, the desktop connector, the Mac's pasteboard
// agent and the console helper use.
//
// Every message is a JSON header on one line, followed by Len bytes of raw
// payload, usually a clipboard text. A client sends a request and reads the
// answers; a watcher keeps its connection open, receives writes and reports
// copies on it. Who may connect is decided by the socket's file permissions:
// only root and the clipbridge group.
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxHeader  = 64 << 10
	maxPayload = 1<<20 + 64 // a text of up to 1 MiB
)

// Operations.
const (
	OpCopy      = "copy"      // client → service: make an event from a deliberate action
	OpPaste     = "paste"     // client → service: ask for the member's own clipboard text
	OpStatus    = "status"    // client → service: ask for the status
	OpPair      = "pair"      // client → service: open a pairing window; answers follow
	OpJoin      = "join"      // client → service: join a group with a code
	OpWatch     = "watch"     // watcher → service: start watching, with what the clipboard holds now
	OpCopied    = "copied"    // watcher → service: the clipboard changed
	OpClipboard = "clipboard" // watcher → service: what the clipboard holds, without a change
	OpWrite     = "write"     // service → watcher: put this text into the clipboard
	OpReply     = "reply"     // service → client: the answer to a request
)

// Kinds and the ways a text came, as Header.Kind and Header.Via carry them.
const (
	KindText     = "text"
	KindSecret   = "secret"
	ViaCopy      = "copy"                // copied on the member
	ViaPhone     = "iphone"              // sent by the iPhone button
	ViaUniversal = "universal-clipboard" // reached a Mac through Universal Clipboard
)

// Header is the JSON line of a message. Fields that an operation does not
// use stay empty.
type Header struct {
	Op    string `json:"op"`
	Kind  string `json:"kind,omitempty"`   // KindText or KindSecret; text if empty
	Via   string `json:"via,omitempty"`    // ViaCopy, ViaPhone or ViaUniversal; copy if empty
	Seq   uint64 `json:"seq,omitempty"`    // the order of writes
	TTLMS int64  `json:"ttl_ms,omitempty"` // how long a written secret may stay in the clipboard
	Len   int    `json:"len,omitempty"`    // the length of the payload
	Error string `json:"error,omitempty"`  // a failed request
	Done  bool   `json:"done,omitempty"`   // the last answer to a request

	Code    string   `json:"code,omitempty"`    // pairing code
	Address string   `json:"address,omitempty"` // a member's address for join
	Name    string   `json:"name,omitempty"`    // a device name
	Expires int      `json:"expires,omitempty"` // seconds a pairing window stays open
	Status  *Status  `json:"status,omitempty"`
	Devices []Device `json:"devices,omitempty"`
}

// Status describes the service for clipbridge status.
type Status struct {
	Device  string   `json:"device"`
	Group   string   `json:"group,omitempty"` // the group tag; empty when in no group
	Role    string   `json:"role"`
	Holder  bool     `json:"holder,omitempty"` // answers for clipbridge.local
	Peers   []Device `json:"peers,omitempty"`
	Version string   `json:"version"`
}

// Device is a member as status shows it.
type Device struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	SkewMS int64  `json:"skew_ms,omitempty"` // how far its clock is ahead of this one
}

// Message is a header and its payload.
type Message struct {
	Header
	Payload []byte
}

// Write sends a message.
func Write(w io.Writer, m *Message) error {
	m.Len = len(m.Payload)
	if m.Len > maxPayload {
		return errors.New("control: the text is larger than 1 MiB")
	}
	line, err := json.Marshal(m.Header)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(line)+1+len(m.Payload))
	buf = append(append(append(buf, line...), '\n'), m.Payload...)
	_, err = w.Write(buf)
	return err
}

// Reader reads messages from a connection.
type Reader struct {
	r *bufio.Reader
}

// NewReader returns a reader for r.
func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReaderSize(r, 4096)} }

// Read reads the next message.
func (r *Reader) Read() (*Message, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > maxHeader {
			return nil, errors.New("control: header too long")
		}
		if !isPrefix {
			break
		}
	}
	var m Message
	if err := json.Unmarshal(line, &m.Header); err != nil {
		return nil, fmt.Errorf("control: bad header: %w", err)
	}
	if m.Len < 0 || m.Len > maxPayload {
		return nil, fmt.Errorf("control: bad payload length %d", m.Len)
	}
	if m.Len > 0 {
		m.Payload = make([]byte, m.Len)
		if _, err := io.ReadFull(r.r, m.Payload); err != nil {
			return nil, err
		}
	}
	return &m, nil
}
