// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Link is a hub's forwarder: its address, the same for UDP and TCP, and the
// pin of its key, which the hub checks before it sends anything.
type Link struct {
	Endpoint netip.AddrPort
	Pin      string
}

// pinPrefix starts a pin: the SHA-256 of the forwarder's public key, in
// base64url without padding.
const pinPrefix = "sha256:"

// Pin returns the pin of a forwarder's certificate.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return pinPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// CheckPin tells whether s looks like a pin.
func CheckPin(s string) error {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, pinPrefix))
	if !strings.HasPrefix(s, pinPrefix) || err != nil || len(b) != sha256.Size {
		return fmt.Errorf("%q is not a forwarder's key; cbb forward prints it, starting with %s", s, pinPrefix)
	}
	return nil
}

// HubConfig configures a hub's registration.
type HubConfig struct {
	Link Link
	Key  [32]byte // the hub's WireGuard private key
	// Cert returns the hub's member certificate with its chain to the
	// group's root; it is asked at each registration, so a renewed
	// certificate is taken.
	Cert func() tls.Certificate

	// Send sends a packet from the hub's WireGuard port, so that the
	// forwarder learns where that port is reached.
	Send func(to netip.AddrPort, p []byte) error

	// Report, if set, hears how the registration stands.
	Report func(Report)
}

// Report is how a hub's registration stands.
type Report struct {
	Registered bool
	Seen       netip.AddrPort // where the forwarder reaches the hub's WireGuard port
	Err        error          // why the hub is not registered
}

// Hellos go every helloEvery, which keeps the NAT mapping of the hub's port
// open, and every second until the forwarder saw one.
const (
	helloEvery = 15 * time.Second
	helloFirst = time.Second
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// Register keeps the hub registered with its forwarder until ctx is done,
// registering again whenever the connection breaks.
func Register(ctx context.Context, cfg HubConfig) {
	report := cfg.Report
	if report == nil {
		report = func(Report) {}
	}
	backoff := minBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := registerOnce(ctx, cfg, report)
		if ctx.Err() != nil {
			return
		}
		report(Report{Err: err})
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

// TLSVerifiedByPin builds the TLS of a registration with a server known only
// by the pin of its key, a forwarder or a relay (what, in the errors): the
// server has no name and a self-signed certificate, so crypto/tls cannot
// check it, and VerifyConnection checks its key against the pin instead. (The
// name, like the pairing's clientTLSVerifiedByFingerprint, tells CodeQL that
// InsecureSkipVerify is checked here.)
func TLSVerifiedByPin(cert tls.Certificate, protocol, pin, what string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{protocol},
		// The server has no name; the pin names it. Without a name the
		// hello carries no server name either.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || Pin(cs.PeerCertificates[0]) != pin {
				return fmt.Errorf("the %s's key is not the one given for it", what)
			}
			if cs.NegotiatedProtocol != protocol {
				return fmt.Errorf("the %s does not speak the registration protocol", what)
			}
			return nil
		},
	}
}

func registerOnce(ctx context.Context, cfg HubConfig, report func(Report)) error {
	d := net.Dialer{Timeout: setupTimeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", cfg.Link.Endpoint.String())
	if err != nil {
		return fmt.Errorf("reaching the forwarder: %w", err)
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(setupTimeout))
	tc := tls.Client(raw, TLSVerifiedByPin(cfg.Cert(), Protocol, cfg.Link.Pin, "forwarder"))
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("registering with the forwarder: %w", err)
	}
	cs := tc.ConnectionState()
	enc, dec := json.NewEncoder(tc), json.NewDecoder(io.LimitReader(tc, 1<<20))
	var ch challenge
	if err := dec.Decode(&ch); err != nil {
		return fmt.Errorf("registering with the forwarder: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(cfg.Key[:])
	if err != nil {
		return err
	}
	e, err := ecdh.X25519().NewPublicKey(ch.E)
	if err != nil {
		return errors.New("registering with the forwarder: a bad challenge")
	}
	shared, err := priv.ECDH(e)
	if err != nil {
		return errors.New("registering with the forwarder: a bad challenge")
	}
	p, err := proof(shared, cs)
	if err != nil {
		return err
	}
	if err := enc.Encode(claim{Key: priv.PublicKey().Bytes(), Proof: p}); err != nil {
		return fmt.Errorf("registering with the forwarder: %w", err)
	}
	var a answer
	if err := dec.Decode(&a); err != nil {
		return fmt.Errorf("registering with the forwarder: %w", err)
	}
	if a.Error != "" {
		return fmt.Errorf("the forwarder refused the registration: %s", a.Error)
	}
	raw.SetDeadline(time.Time{})
	report(Report{Registered: true})
	var key [32]byte
	hk, err := cs.ExportKeyingMaterial(helloLabel, nil, 32)
	if err != nil {
		return err
	}
	copy(key[:], hk)

	answers := make(chan answer)
	failed := make(chan error, 1)
	go func() {
		for {
			var a answer
			if err := dec.Decode(&a); err != nil {
				failed <- err
				return
			}
			select {
			case answers <- a:
			case <-ctx.Done():
				return
			}
		}
	}()
	var counter uint64
	seen := netip.AddrPort{}
	every := helloFirst
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			return fmt.Errorf("the connection to the forwarder broke: %w", err)
		case a := <-answers:
			if ep, err := netip.ParseAddrPort(a.Seen); err == nil && ep != seen {
				seen, every = ep, helloEvery
				report(Report{Registered: true, Seen: seen})
			}
		case <-t.C:
			counter = max(counter+1, uint64(time.Now().UnixNano()))
			// A hello that cannot go out now goes with the next one.
			_ = cfg.Send(cfg.Link.Endpoint, hello(&key, a.ID, counter))
			t.Reset(every)
		}
	}
}
