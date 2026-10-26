// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// maxChain is the most certificates a member may present: its member
// certificate, its admin CA and the group's roots.
const maxChain = 8

// maxClaim bounds a claim, which carries the group's authority records,
// and maxClaimRecords the records in it, whose signatures the relay checks.
const (
	maxClaim        = 1 << 20
	maxClaimRecords = 1024
)

// rootOf returns the root among certs that names the group tag.
func rootOf(certs []*x509.Certificate, tag string) *x509.Certificate {
	for _, c := range certs[1:] {
		if c.IsCA && c.CheckSignatureFrom(c) == nil && group.Tag(c) == tag {
			return c
		}
	}
	return nil
}

// serverTLS is the registrations' TLS: TLS 1.3, the relay's own
// certificate, and a member certificate whose chain the relay checks
// itself against the groups it serves.
func (r *Relay) serverTLS() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{r.cfg.Keys.Cert},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{Protocol},
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != Protocol {
				return errors.New("relay: the device does not speak the registration protocol")
			}
			_, _, err := r.groupOf(cs.PeerCertificates, time.Now())
			return err
		},
	}
}

// groupOf checks that the certificates a device presented are a member
// certificate with its chain to the root of a group the relay serves, and
// returns that group's tag and the device's ID. A root that the device
// presents counts only if the relay serves its group.
func (r *Relay) groupOf(certs []*x509.Certificate, now time.Time) (tag, device string, err error) {
	if len(certs) == 0 || len(certs) > maxChain {
		return "", "", errors.New("relay: the device presented no member certificate chain")
	}
	id, err := group.DeviceOf(certs[0])
	if err != nil {
		return "", "", fmt.Errorf("relay: %w", err)
	}
	inter := x509.NewCertPool()
	var roots []*x509.Certificate
	for _, c := range certs[1:] {
		if c.IsCA && c.CheckSignatureFrom(c) == nil {
			if r.cfg.Open || r.allowed[group.Tag(c)] {
				roots = append(roots, c)
			}
		} else {
			inter.AddCert(c)
		}
	}
	for _, root := range roots {
		pool := x509.NewCertPool()
		pool.AddCert(root)
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots: pool, Intermediates: inter, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err == nil {
			return group.Tag(root), string(id), nil
		}
	}
	return "", "", errors.New("relay: the device is not of a group this relay serves")
}

// acceptRegistrations takes the members' TLS connections.
func (r *Relay) acceptRegistrations() {
	for {
		conn, err := r.tcp.Accept()
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			r.logf("cbb relay: accepting registrations: %v", err)
			return
		}
		if !r.takeSlot() {
			conn.Close()
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.serveRegistration(conn)
		}()
	}
}

// serveRegistration registers one device and holds its registration while
// the connection lasts.
func (r *Relay) serveRegistration(raw net.Conn) {
	m, err := r.register(raw)
	r.freeSlot()
	if err != nil {
		raw.Close()
		return
	}
	// The device sends nothing more; reading tells when it goes.
	io.Copy(io.Discard, m.conn)
	r.mu.Lock()
	r.dropLocked(m)
	r.mu.Unlock()
}

// register runs a registration's setup: TLS with the device's member
// certificate, then the proof that it holds its WireGuard key, bound to
// this TLS session, as with the forwarder.
func (r *Relay) register(raw net.Conn) (*member, error) {
	raw.SetDeadline(time.Now().Add(setupTimeout))
	tc := tls.Server(raw, r.tlsCfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	tag, device, err := r.groupOf(cs.PeerCertificates, time.Now())
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	enc, dec := json.NewEncoder(tc), json.NewDecoder(io.LimitReader(tc, maxClaim))
	if err := enc.Encode(challenge{E: eph.PublicKey().Bytes()}); err != nil {
		return nil, err
	}
	var c claim
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	refuse := func(msg string) (*member, error) {
		enc.Encode(welcome{Error: msg})
		return nil, errors.New(msg)
	}
	if len(c.Key) != 32 {
		return refuse("the WireGuard key is not 32 bytes")
	}
	pub, err := ecdh.X25519().NewPublicKey(c.Key)
	if err != nil {
		return refuse("the WireGuard key is not an X25519 key")
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return refuse("the WireGuard key is not an X25519 key")
	}
	want, err := proof(shared, cs)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(want, c.Proof) {
		return refuse("the device does not hold that WireGuard key")
	}
	if len(c.Records) > maxClaimRecords {
		return refuse("too many records")
	}
	leaf := group.KeyHashOf(cs.PeerCertificates[0])
	r.mu.Lock()
	known := r.records[tag]
	r.mu.Unlock()
	// The signatures take time, so the records are checked outside the lock.
	recs := group.NewRecords(rootOf(cs.PeerCertificates, tag))
	recs.AddAll(known)
	recs.AddAll(c.Records)
	if recs.Revoked(leaf) {
		return refuse("the device was removed from its group")
	}
	psk, err := tunnel.NewPresharedKey()
	if err != nil {
		return nil, err
	}
	m := &member{tag: tag, device: device, leaf: leaf, psk: psk, conn: tc, raw: raw, streams: map[net.Conn]bool{}, from: addrOf(raw)}
	copy(m.key[:], c.Key)
	r.mu.Lock()
	select {
	case <-r.done:
		r.mu.Unlock()
		return refuse("the relay is stopping")
	default:
	}
	if len(c.Records) > 0 {
		if all := recs.All(); len(all) > len(r.records[tag]) {
			r.records[tag] = all
			// The devices the new records remove go now.
			for _, o := range r.groups[tag] {
				if recs.Revoked(o.leaf) {
					r.dropLocked(o)
				}
			}
		}
	}
	if err := r.addLocked(m); err != nil {
		r.mu.Unlock()
		return refuse(err.Error())
	}
	r.mu.Unlock()
	relayKey := r.cfg.Keys.WireGuard.Public()
	if err := enc.Encode(welcome{Key: relayKey[:], PSK: psk[:], Addr: m.addr.String()}); err != nil {
		r.mu.Lock()
		r.dropLocked(m)
		r.mu.Unlock()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return m, nil
}

// proof is what a device sends to prove it holds its WireGuard key: an
// HMAC, under the X25519 secret of its key and the relay's ephemeral one,
// of a key from this TLS session, so it proves nothing on another
// connection.
func proof(shared []byte, cs tls.ConnectionState) ([]byte, error) {
	k, err := cs.ExportKeyingMaterial(proofLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, shared)
	m.Write(k)
	return m.Sum(nil), nil
}
