// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/relay"
)

// RelayEvents is how the kit takes part in the phone's link to a blind
// relay (docs/protocol.md, section 14). The relay joins the phone's member
// connections to the other devices' end to end; the kit runs member TLS
// over them on the loopback address.
type RelayEvents interface {
	// Dial: the relay joined a connection to peer, which the kit takes by
	// connecting to 127.0.0.1:port and running member TLS as the client,
	// expecting peer's certificate. The port takes one connection.
	Dial(peer string, port int)
	// Calling: peer called, and its connection comes to the kit's member
	// listener from 127.0.0.1:localPort. The kit serves it only if the
	// client certificate names peer, so the relay cannot pose as another
	// device of the group.
	Calling(peer string, localPort int)
	// Wanted tells whether to connect to peer through the relay: false
	// while the kit is connected to it another way.
	Wanted(peer string) bool
	// Changed: the link stands as State says now.
	Changed(state string)
}

// RelayState is how the phone's link to its relay stands, in JSON as
// RelayEvents.Changed gets it: registered with its tunnel and its watch,
// the other devices of the group on the relay, the member connections
// through it, and why it is not connected.
type RelayState struct {
	Connected bool     `json:"connected"`
	Online    []string `json:"online"`
	Through   int      `json:"through"`
	Error     string   `json:"error,omitempty"`
}

// dialWait is how long a Dial's port waits for the kit's connection.
const dialWait = 10 * time.Second

// Relay is the phone's link to its blind relay while the app is open.
type Relay struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	records []group.Record
}

// StartRelay keeps the phone registered with the blind relay at endpoint
// ("ip:port"), whose key pin pins, until Close: private is its WireGuard
// private key, device its device ID, chain and signer its member
// certificate and key as Hub.Register takes them, records the group's
// authority records, and memberPort the loopback port of the kit's member
// listener, to which the calls go.
func StartRelay(private []byte, device, endpoint, pin, chain string, signer Signer, records string, memberPort int, events RelayEvents) (*Relay, error) {
	k, err := key(private, "private key")
	if err != nil {
		return nil, err
	}
	ep, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("cbbtun: %q is not an endpoint: %w", endpoint, err)
	}
	if err := relay.CheckPin(pin); err != nil {
		return nil, fmt.Errorf("cbbtun: %w", err)
	}
	if _, err := group.ParseDeviceID(device); err != nil {
		return nil, fmt.Errorf("cbbtun: %w", err)
	}
	if memberPort <= 0 || memberPort > 65535 {
		return nil, fmt.Errorf("cbbtun: %d is not the member listener's port", memberPort)
	}
	if events == nil {
		return nil, errors.New("cbbtun: no events for the relay")
	}
	cert, err := memberCert(chain, signer)
	if err != nil {
		return nil, err
	}
	recs, err := parseRecords(records)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{ctx: ctx, cancel: cancel, done: make(chan struct{}), records: recs}
	member := net.JoinHostPort("127.0.0.1", strconv.Itoa(memberPort))
	cfg := relay.MemberConfig{
		Link: relay.Link{Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), Pin: pin},
		Self: device, Key: k,
		Cert: func() tls.Certificate { return cert },
		Records: func() []group.Record {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.records
		},
		Want: events.Wanted,
		Dialed: func(ctx context.Context, peer string, c net.Conn) error {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return err
			}
			defer ln.Close()
			events.Dial(peer, ln.Addr().(*net.TCPAddr).Port)
			go func() {
				select {
				case <-ctx.Done():
				case <-time.After(dialWait):
				}
				ln.Close()
			}()
			k, err := ln.Accept()
			if err != nil {
				return fmt.Errorf("the app did not take the connection to %s: %w", peer, err)
			}
			ln.Close()
			return join(ctx, c, k)
		},
		Called: func(ctx context.Context, peer string, c net.Conn) error {
			var d net.Dialer
			k, err := d.DialContext(ctx, "tcp", member)
			if err != nil {
				return err
			}
			// The kit learns whose connection it is before a byte of TLS
			// reaches it.
			events.Calling(peer, k.LocalAddr().(*net.TCPAddr).Port)
			return join(ctx, c, k)
		},
		Report: func(rp relay.Report) {
			st := RelayState{Connected: rp.Connected, Online: rp.Online, Through: rp.Through}
			if st.Online == nil {
				st.Online = []string{}
			}
			if rp.Err != nil {
				st.Error = rp.Err.Error()
			}
			b, _ := json.Marshal(st)
			events.Changed(string(b))
		},
	}
	go func() {
		defer close(r.done)
		relay.Join(ctx, cfg)
	}()
	return r, nil
}

// join copies between the relay's connection and the kit's until either
// ends or ctx is done.
func join(ctx context.Context, a, b net.Conn) error {
	stop := context.AfterFunc(ctx, func() {
		a.Close()
		b.Close()
	})
	defer stop()
	splice(a, b)
	return nil
}

// SetRecords replaces the authority records that the next registration
// shows the relay, as StartRelay takes them.
func (r *Relay) SetRecords(records string) error {
	recs, err := parseRecords(records)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.records = recs
	r.mu.Unlock()
	return nil
}

// Close leaves the relay and ends every connection through it.
func (r *Relay) Close() {
	r.cancel()
	<-r.done
}
