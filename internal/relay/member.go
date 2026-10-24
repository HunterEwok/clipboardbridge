// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/forward"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// Link is a member's relay: its address, the same for UDP and TCP, and the
// pin of its key, which the member checks before it sends anything.
type Link struct {
	Endpoint netip.AddrPort
	Pin      string
}

// CheckPin tells whether s looks like a relay's key as cbb relay prints it.
func CheckPin(s string) error {
	if forward.CheckPin(s) != nil {
		return fmt.Errorf("%q is not a relay's key; cbb relay prints it, starting with \"sha256\"", s)
	}
	return nil
}

// MemberConfig configures a member's link to its relay.
type MemberConfig struct {
	Link Link
	Self string     // this device's ID
	Key  tunnel.Key // its WireGuard private key

	// Cert returns the member certificate with its chain to the group's
	// root; it is asked at each registration, so a renewed certificate is
	// taken.
	Cert func() tls.Certificate

	// Want tells whether to connect to a device through the relay now:
	// false while it is connected already, for example on the home
	// network.
	Want func(peer string) bool

	// Dialed runs the member protocol, as the TLS client, over a
	// connection the relay joined to peer's; Called runs it as the TLS
	// server over one from a device the relay says is peer, which Called
	// must check. Both return when the connection ends.
	Dialed func(ctx context.Context, peer string, conn net.Conn) error
	Called func(ctx context.Context, peer string, conn net.Conn) error

	// Report, if set, hears how the link stands.
	Report func(Report)

	Logf    func(format string, args ...any)
	Verbose bool // also log WireGuard's own messages
}

// Report is how a member's link to its relay stands.
type Report struct {
	Connected bool     // registered, with its tunnel and its watch
	Online    []string // the other devices of the group on the relay
	Through   int      // member connections through the relay now
	Err       error    // why it is not connected
}

// Backoff of the registration and of the dials.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
	// wantCheck is how often a dialer looks again whether it has to
	// connect, while the device is connected another way.
	wantCheck = 5 * time.Second
)

// Join keeps the member registered with its relay until ctx is done, and
// connects it through the relay to the other devices of its group there:
// the device with the lower ID dials, the other answers.
func Join(ctx context.Context, cfg MemberConfig) {
	if cfg.Report == nil {
		cfg.Report = func(Report) {}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	backoff := minBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := joinOnce(ctx, cfg)
		if ctx.Err() != nil {
			return
		}
		cfg.Report(Report{Err: err})
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// session is one registration with its tunnel.
type session struct {
	cfg    MemberConfig
	client *tunnel.Client

	wg      sync.WaitGroup // the dialers and the answers
	mu      sync.Mutex
	online  []string
	dialers map[string]context.CancelFunc
	through int
}

func joinOnce(ctx context.Context, cfg MemberConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tc, w, err := register(ctx, cfg)
	if err != nil {
		return err
	}
	defer tc.Close()
	addr, err := netip.ParseAddr(w.Addr)
	if err != nil {
		return errors.New("the relay gave a bad tunnel address")
	}
	var relayKey, psk tunnel.Key
	if len(w.Key) != len(relayKey) || len(w.PSK) != len(psk) {
		return errors.New("the relay's keys are not 32 bytes")
	}
	copy(relayKey[:], w.Key)
	copy(psk[:], w.PSK)
	client, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: cfg.Key, PresharedKey: psk, Addr: addr,
		HubPublicKey: relayKey, HubAddr: Addr, Endpoint: cfg.Link.Endpoint, Logf: cfg.Logf, Verbose: cfg.Verbose})
	if err != nil {
		return err
	}
	defer client.Close()
	s := &session{cfg: cfg, client: client, dialers: map[string]context.CancelFunc{}}
	defer func() {
		cancel()
		s.wg.Wait()
	}()
	go func() {
		// The relay sends nothing more on the registration; reading tells
		// when it is gone.
		io.Copy(io.Discard, tc)
		cancel()
	}()

	dctx, dcancel := context.WithTimeout(ctx, setupTimeout)
	watch, err := client.Dial(dctx)
	dcancel()
	if err != nil {
		return fmt.Errorf("the relay's tunnel does not answer: %w", err)
	}
	defer watch.Close()
	stop := context.AfterFunc(ctx, func() { watch.Close() })
	defer stop()
	if err := writeLine(watch, request{Watch: true}, setupTimeout); err != nil {
		return fmt.Errorf("the relay's tunnel does not answer: %w", err)
	}
	defer s.stopDialers()
	dec := json.NewDecoder(watch)
	for {
		var n note
		if err := dec.Decode(&n); err != nil {
			if ctx.Err() != nil {
				return errors.New("the relay ended the registration")
			}
			return fmt.Errorf("the relay's watch ended: %w", err)
		}
		switch {
		case n.Online != nil:
			s.setOnline(ctx, *n.Online)
		case n.Call != "" && n.Ticket != "":
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.answer(ctx, n.Call, n.Ticket)
			}()
		}
	}
}

// register runs the registration's setup and returns its connection, which
// the member keeps open while it is registered.
func register(ctx context.Context, cfg MemberConfig) (*tls.Conn, welcome, error) {
	d := net.Dialer{Timeout: setupTimeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", cfg.Link.Endpoint.String())
	if err != nil {
		return nil, welcome{}, fmt.Errorf("reaching the relay: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	fail := func(err error) (*tls.Conn, welcome, error) {
		stop()
		raw.Close()
		return nil, welcome{}, err
	}
	raw.SetDeadline(time.Now().Add(setupTimeout))
	tc := tls.Client(raw, forward.PinnedTLS(cfg.Cert(), Protocol, cfg.Link.Pin, "relay"))
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	cs := tc.ConnectionState()
	enc, dec := json.NewEncoder(tc), json.NewDecoder(io.LimitReader(tc, 1<<20))
	var ch challenge
	if err := dec.Decode(&ch); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	priv, err := ecdh.X25519().NewPrivateKey(cfg.Key[:])
	if err != nil {
		return fail(err)
	}
	e, err := ecdh.X25519().NewPublicKey(ch.E)
	if err != nil {
		return fail(errors.New("registering with the relay: a bad challenge"))
	}
	shared, err := priv.ECDH(e)
	if err != nil {
		return fail(errors.New("registering with the relay: a bad challenge"))
	}
	p, err := proof(shared, cs)
	if err != nil {
		return fail(err)
	}
	if err := enc.Encode(claim{Key: priv.PublicKey().Bytes(), Proof: p}); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	var w welcome
	if err := dec.Decode(&w); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	if w.Error != "" {
		return fail(fmt.Errorf("the relay refused the registration: %s", w.Error))
	}
	raw.SetDeadline(time.Time{})
	// The registration lasts until ctx is done or the relay drops it.
	return tc, w, nil
}

func (s *session) report() {
	s.mu.Lock()
	r := Report{Connected: true, Online: slices.Clone(s.online), Through: s.through}
	s.mu.Unlock()
	s.cfg.Report(r)
}

// setOnline keeps a dialer for each device on the relay that this one
// dials: the ones with a higher ID.
func (s *session) setOnline(ctx context.Context, online []string) {
	s.mu.Lock()
	s.online = online
	for p, stop := range s.dialers {
		if !slices.Contains(online, p) {
			stop()
			delete(s.dialers, p)
		}
	}
	for _, p := range online {
		if _, ok := s.dialers[p]; ok || strings.Compare(s.cfg.Self, p) >= 0 {
			continue
		}
		pctx, stop := context.WithCancel(ctx)
		s.dialers[p] = stop
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dial(pctx, p)
		}()
	}
	s.mu.Unlock()
	s.report()
}

func (s *session) stopDialers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, stop := range s.dialers {
		stop()
		delete(s.dialers, p)
	}
}

// dial connects to peer through the relay whenever it is not connected
// another way, until ctx is done.
func (s *session) dial(ctx context.Context, peer string) {
	backoff := minBackoff
	for ctx.Err() == nil {
		wait := wantCheck
		if s.cfg.Want(peer) {
			start := time.Now()
			err := s.dialOnce(ctx, peer)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				s.cfg.Logf("cbb: sync away from home: connecting to %s through the relay: %v", peer, err)
			}
			if time.Since(start) > maxBackoff {
				backoff = minBackoff
			}
			wait, backoff = backoff, min(2*backoff, maxBackoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *session) dialOnce(ctx context.Context, peer string) error {
	c, err := s.open(ctx, request{Dial: peer})
	if err != nil {
		return err
	}
	return s.run(ctx, peer, c, s.cfg.Dialed)
}

// answer takes a call from peer and runs the member protocol on it.
func (s *session) answer(ctx context.Context, peer, ticket string) {
	c, err := s.open(ctx, request{Answer: ticket})
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.Logf("cbb: sync away from home: answering %s through the relay: %v", peer, err)
		}
		return
	}
	if err := s.run(ctx, peer, c, s.cfg.Called); err != nil && ctx.Err() == nil {
		s.cfg.Logf("cbb: sync away from home: connection from %s through the relay: %v", peer, err)
	}
}

// open opens a connection to the relay's member port, sends req and waits
// until the relay joined it.
func (s *session) open(ctx context.Context, req request) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, setupTimeout)
	c, err := s.client.Dial(dctx)
	cancel()
	if err != nil {
		return nil, err
	}
	if err := writeLine(c, req, setupTimeout); err != nil {
		c.Close()
		return nil, err
	}
	var n note
	if err := readLine(c, &n, callTimeout+setupTimeout); err != nil {
		c.Close()
		return nil, err
	}
	if !n.OK {
		c.Close()
		if n.Error == "" {
			n.Error = "no answer"
		}
		return nil, fmt.Errorf("the relay: %s", n.Error)
	}
	return c, nil
}

// run runs a member connection the relay joined, counting it.
func (s *session) run(ctx context.Context, peer string, c net.Conn, f func(context.Context, string, net.Conn) error) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	s.mu.Lock()
	s.through++
	s.mu.Unlock()
	s.report()
	err := f(ctx, peer, c)
	c.Close()
	s.mu.Lock()
	s.through--
	s.mu.Unlock()
	s.report()
	return err
}
