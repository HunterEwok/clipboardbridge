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
// only root and the clipboardbridge group.
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
	OpCopy      = "copy"       // client → service: make an event from a deliberate action
	OpPaste     = "paste"      // client → service: ask for the member's own clipboard text
	OpStatus    = "status"     // client → service: ask for the status
	OpPair      = "pair"       // client → service: open a pairing window; answers follow
	OpPairPhone = "pair-phone" // client → service: open an iPhone pairing window; answers follow
	OpJoin      = "join"       // client → service: join a group with a code
	OpDevices   = "devices"    // client → service: list the group's devices
	OpRevoke    = "revoke"     // client → service: remove the device Name names (a name or a device ID)
	OpAway      = "away"       // client → service: Name "on", "off" or "hub": sync away from home
	OpInvite    = "invite"     // client → service: make a remote invitation on the hub; answers and a question follow
	OpAnswer    = "answer"     // client → service: Consent answers the service's question during a request
	OpWatch     = "watch"      // watcher → service: start watching, with what the clipboard holds now
	OpCopied    = "copied"     // watcher → service: the clipboard changed
	OpClipboard = "clipboard"  // watcher → service: what the clipboard holds, without a change
	OpWrite     = "write"      // service → watcher: put this text into the clipboard
	OpReply     = "reply"      // service → client: the answer to a request
)

// Kinds and the ways a text came, as Header.Kind and Header.Via carry them.
const (
	KindText     = "text"
	KindSecret   = "secret"
	ViaCopy      = "copy"                // copied on the member
	ViaPhone     = "phone"               // sent from a phone: the app, or the iPhone shortcut
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

	Code         string   `json:"code,omitempty"`        // pairing code
	Fingerprint  string   `json:"fingerprint,omitempty"` // of the iPhone CA, for the user to compare; of the joiner's certificate, for its QR code
	Address      string   `json:"address,omitempty"`     // a member's address for join
	Addrs        []string `json:"addrs,omitempty"`       // where a listening join waits, for its QR code
	Listen       bool     `json:"listen,omitempty"`      // join: wait for a member to dial this device
	Name         string   `json:"name,omitempty"`        // a device name
	Expires      int      `json:"expires,omitempty"`     // seconds a pairing window stays open; for a listening join, seconds to wait
	Port         int      `json:"port,omitempty"`        // away hub: the UDP port; 0 for the default
	Forwarder    string   `json:"forwarder,omitempty"`   // away hub: the forwarder's address, with its key in ForwarderKey
	ForwarderKey string   `json:"forwarder_key,omitempty"`
	Relay        string   `json:"relay,omitempty"` // away relay: the relay's address, with its key in RelayKey
	RelayKey     string   `json:"relay_key,omitempty"`
	Obfuscate    bool     `json:"obfuscate,omitempty"` // away hub: speak AmneziaWG instead of plain WireGuard
	Consent      bool     `json:"consent,omitempty"`   // away on, join with an invitation: the user agreed to what the warning says; answer: yes
	Invite       string   `json:"invite,omitempty"`    // the text of a remote invitation: made by invite, used by join
	Joining      *Joining `json:"joining,omitempty"`   // invite: a device to confirm, before it is admitted
	Status       *Status  `json:"status,omitempty"`
	Devices      []Device `json:"devices,omitempty"`
}

// Status describes the service for cbb status.
type Status struct {
	Device  string   `json:"device"`
	Group   string   `json:"group,omitempty"` // the group tag; empty when in no group
	Role    string   `json:"role"`
	Holder  bool     `json:"holder,omitempty"` // answers for clipboardbridge.local
	Peers   []Device `json:"peers,omitempty"`
	Away    *Away    `json:"away,omitempty"` // sync away from home; nil while it is off
	Version string   `json:"version"`
}

// Away describes sync away from home on this device.
type Away struct {
	Hub        bool       `json:"hub,omitempty"`        // this device is the group's hub
	Port       int        `json:"port,omitempty"`       // the hub's UDP port
	Endpoints  []string   `json:"endpoints,omitempty"`  // the hub's addresses away from home
	Clients    int        `json:"clients,omitempty"`    // on the hub: the devices it admitted
	HubDevice  string     `json:"hub_device,omitempty"` // on a client: the hub; "" until the hub offered its tunnel
	Through    bool       `json:"through,omitempty"`    // on a client: connected to the hub through the tunnel now
	KeysInFile bool       `json:"keys_in_file,omitempty"`
	Obfuscated bool       `json:"obfuscated,omitempty"` // the tunnel speaks AmneziaWG
	Error      string     `json:"error,omitempty"`      // what went wrong last, for the user
	Forwarder  *Forwarder `json:"forwarder,omitempty"`  // on the hub: its forwarder; nil without one
	Relay      *Relay     `json:"relay,omitempty"`      // on a device that meets the others at a relay; nil without one
	Detail     string     `json:"detail,omitempty"`     // the underlying error, for debugging
}

// Forwarder describes a hub's registration on its forwarder.
type Forwarder struct {
	Endpoint   string `json:"endpoint"`
	Registered bool   `json:"registered,omitempty"`
	Seen       string `json:"seen,omitempty"`   // where the forwarder reaches the hub's port
	Error      string `json:"error,omitempty"`  // why the hub is not registered
	Detail     string `json:"detail,omitempty"` // the underlying error, for debugging
}

// Relay describes a device's link to its blind relay.
type Relay struct {
	Endpoint  string   `json:"endpoint"`
	Connected bool     `json:"connected,omitempty"` // registered, with its tunnel
	Online    []string `json:"online,omitempty"`    // the other devices of the group on the relay
	Error     string   `json:"error,omitempty"`     // why it is not connected
	Detail    string   `json:"detail,omitempty"`    // the underlying error, for debugging
}

// Joining is a device that used a remote invitation, for the admin to
// confirm with an answer.
type Joining struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	OS          string `json:"os"`
	Fingerprint string `json:"fingerprint"` // of its key, as cbb join shows it on the device
}

// Device is a member as status shows it, or a device of the group as
// devices lists it.
type Device struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	SkewMS int64  `json:"skew_ms,omitempty"` // how far its clock is ahead of this one

	Admin      bool  `json:"admin,omitempty"`        // it can admit and remove devices
	Online     bool  `json:"online,omitempty"`       // connected to this member now
	LastSeenMS int64 `json:"last_seen_ms,omitempty"` // when this member last saw it connected, Unix milliseconds; 0 if never
	Self       bool  `json:"self,omitempty"`         // this device
	Listed     bool  `json:"listed,omitempty"`       // it has a device record; a member that joined before the list existed may have none yet
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
	if len(line) > maxHeader {
		return errors.New("control: header too long")
	}
	// Both parts are bounded above, so the size cannot overflow.
	buf := make([]byte, 0, len(line)+1+m.Len)
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
