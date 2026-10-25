// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/HunterEwok/clipboardbridge/internal/forward"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// Signer signs with the phone's member key, which never leaves the Secure
// Enclave or the Keystore and signs without the user: the kit's key behind
// the phone's TLS identity.
type Signer interface {
	// SignDigest returns an ECDSA signature, ASN.1 DER, of a SHA-256
	// digest.
	SignDigest(digest []byte) ([]byte, error)
}

// Hub is the phone as the group's hub while its app is open (docs/design.md,
// "The phone as the hub", D-64): the end of every client's tunnel, whose
// member port leads to the kit's member listener on the loopback address,
// and its registration with the group's forwarder.
type Hub struct {
	hub        *tunnel.Hub
	key        tunnel.Key
	obf        *tunnel.Obfuscation
	memberPort int
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	registered bool // Register was called
	records    []group.Record
	report     forward.Report
}

// Client is one of a hub's clients as SetClients takes it, in JSON: the
// device ID, its tunnel key and the preshared key the hub's offer gave it.
type Client struct {
	Device string `json:"device"`
	Key    []byte `json:"key"`
	PSK    []byte `json:"psk"`
}

// StartHub brings the hub up with its WireGuard private key, the phone's
// device ID, the loopback TCP port of the kit's member listener, to which
// each connection through the tunnel goes, the group's obfuscation
// settings as JSON or "" for plain WireGuard, and its clients as SetClients
// takes them.
func StartHub(private []byte, device string, memberPort int, obfuscation, clients string) (*Hub, error) {
	priv, err := key(private, "private key")
	if err != nil {
		return nil, err
	}
	addr, err := tunnel.Addr(device)
	if err != nil {
		return nil, err
	}
	if memberPort <= 0 || memberPort > 65535 {
		return nil, fmt.Errorf("cbbtun: %d is not a port", memberPort)
	}
	var obf *tunnel.Obfuscation
	if obfuscation != "" {
		obf = new(tunnel.Obfuscation)
		if err := json.Unmarshal([]byte(obfuscation), obf); err != nil {
			return nil, fmt.Errorf("cbbtun: the obfuscation settings: %w", err)
		}
	}
	peers, err := parseClients(clients)
	if err != nil {
		return nil, err
	}
	h, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: priv, Addr: addr, Peers: peers, Obfuscation: obf})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	ph := &Hub{hub: h, key: priv, obf: obf, memberPort: memberPort, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
	ph.wg.Add(1)
	go ph.serve()
	return ph, nil
}

// SetClients replaces the hub's clients, a JSON array of Client; "" is
// none. A client left out is cut off at once.
func (h *Hub) SetClients(clients string) error {
	peers, err := parseClients(clients)
	if err != nil {
		return err
	}
	return h.hub.SetPeers(peers)
}

func parseClients(s string) ([]tunnel.Peer, error) {
	if s == "" {
		return nil, nil
	}
	var cs []Client
	if err := json.Unmarshal([]byte(s), &cs); err != nil {
		return nil, fmt.Errorf("cbbtun: the clients: %w", err)
	}
	peers := make([]tunnel.Peer, 0, len(cs))
	for _, c := range cs {
		pub, err := key(c.Key, "client's key")
		if err != nil {
			return nil, err
		}
		psk, err := key(c.PSK, "client's preshared key")
		if err != nil {
			return nil, err
		}
		a, err := tunnel.Addr(c.Device)
		if err != nil {
			return nil, err
		}
		peers = append(peers, tunnel.Peer{PublicKey: pub, PresharedKey: psk, Addr: a})
	}
	return peers, nil
}

// UDPPort is the hub's WireGuard port.
func (h *Hub) UDPPort() int { return h.hub.UDPPort() }

// Register keeps the hub registered with the group's forwarder until Close
// (docs/protocol.md, section 13): the forwarder's endpoint ("ip:port") and
// the pin of its key, the phone's member certificate chain as a JSON array
// of DER certificates (the leaf, its admin CA if it has one, then the
// group's roots), the signer of the member key, the group's authority
// records as a JSON array of records, which show the forwarder that the
// member key is the root's or an admin's, and the group's VLESS user ID or
// "". Status tells how it stands.
func (h *Hub) Register(endpoint, pin, chain string, signer Signer, records, vlessID string) error {
	ep, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return fmt.Errorf("cbbtun: %q is not an endpoint: %w", endpoint, err)
	}
	if err := forward.CheckPin(pin); err != nil {
		return fmt.Errorf("cbbtun: %w", err)
	}
	cert, err := memberCert(chain, signer)
	if err != nil {
		return err
	}
	recs, err := parseRecords(records)
	if err != nil {
		return err
	}
	if vlessID != "" {
		if err := tunnel.CheckVLESSID(vlessID); err != nil {
			return fmt.Errorf("cbbtun: %w", err)
		}
	}
	h.mu.Lock()
	if h.registered {
		h.mu.Unlock()
		return errors.New("cbbtun: the hub registers already")
	}
	if h.ctx.Err() != nil {
		h.mu.Unlock()
		return errors.New("cbbtun: the hub is closed")
	}
	h.registered = true
	h.records = recs
	h.mu.Unlock()
	cfg := forward.HubConfig{
		Link:        forward.Link{Endpoint: ep, Pin: pin},
		Key:         h.key,
		Obfuscation: h.obf,
		VLESSID:     vlessID,
		Cert:        func() tls.Certificate { return cert },
		Authority: func() (*ecdsa.PrivateKey, *x509.Certificate, []group.Record) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return nil, nil, h.records
		},
		Send: h.hub.Send,
		Report: func(r forward.Report) {
			h.mu.Lock()
			// A failure leaves where the forwarder last saw the hub.
			if r.Err != nil {
				r.Seen = h.report.Seen
			}
			h.report = r
			h.mu.Unlock()
		},
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		forward.Register(h.ctx, cfg)
	}()
	return nil
}

// SetRecords replaces the authority records that the next registration
// shows the forwarder, as Register takes them: after a removal or a new
// admin, so that the forwarder learns it the next time the hub registers.
func (h *Hub) SetRecords(records string) error {
	recs, err := parseRecords(records)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.records = recs
	h.mu.Unlock()
	return nil
}

func parseRecords(s string) ([]group.Record, error) {
	if s == "" {
		return nil, nil
	}
	var recs []group.Record
	if err := json.Unmarshal([]byte(s), &recs); err != nil {
		return nil, fmt.Errorf("cbbtun: the records: %w", err)
	}
	return recs, nil
}

// memberCert is the phone's member certificate with its chain, whose key
// signs through signer.
func memberCert(chain string, signer Signer) (tls.Certificate, error) {
	if signer == nil {
		return tls.Certificate{}, errors.New("cbbtun: no signer for the member key")
	}
	var ders [][]byte
	if err := json.Unmarshal([]byte(chain), &ders); err != nil {
		return tls.Certificate{}, fmt.Errorf("cbbtun: the certificate chain: %w", err)
	}
	if len(ders) == 0 {
		return tls.Certificate{}, errors.New("cbbtun: the certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cbbtun: the member certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return tls.Certificate{}, errors.New("cbbtun: the member certificate has no ECDSA key")
	}
	return tls.Certificate{Certificate: ders, Leaf: leaf, PrivateKey: digestSigner{pub: pub, s: signer}}, nil
}

// digestSigner is the member key as a crypto.Signer for crypto/tls.
type digestSigner struct {
	pub *ecdsa.PublicKey
	s   Signer
}

func (d digestSigner) Public() crypto.PublicKey { return d.pub }

func (d digestSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("cbbtun: the member key signs SHA-256 digests only, not %v", opts.HashFunc())
	}
	return d.s.SignDigest(digest)
}

// Status tells how the registration stands, as JSON: registered (bool),
// seen (where the forwarder reaches the hub's WireGuard port, "ip:port"),
// vless (the way to the forwarder over VLESS that the hub's offer gives
// its clients) and error (why it is not registered); {} before Register.
func (h *Hub) Status() string {
	h.mu.Lock()
	r := h.report
	h.mu.Unlock()
	var s struct {
		Registered bool          `json:"registered,omitempty"`
		Seen       string        `json:"seen,omitempty"`
		VLESS      *tunnel.VLESS `json:"vless,omitempty"`
		Error      string        `json:"error,omitempty"`
	}
	s.Registered, s.VLESS = r.Registered, r.VLESS
	if r.Seen.IsValid() {
		s.Seen = r.Seen.String()
	}
	if r.Err != nil {
		s.Error = r.Err.Error()
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// Close stops the registration, the hub and every connection through it.
func (h *Hub) Close() error {
	h.cancel()
	h.hub.Listener().Close()
	h.mu.Lock()
	for c := range h.conns {
		c.Close()
	}
	h.mu.Unlock()
	h.wg.Wait()
	return h.hub.Close()
}

// serve takes the connections through the tunnel to the member port and
// joins each to the kit's member listener.
func (h *Hub) serve() {
	defer h.wg.Done()
	member := net.JoinHostPort("127.0.0.1", strconv.Itoa(h.memberPort))
	for {
		c, err := h.hub.Listener().Accept()
		if err != nil {
			return
		}
		if !h.track(c) {
			c.Close()
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer h.untrack(c)
			d := net.Dialer{Timeout: dialTimeout}
			m, err := d.DialContext(h.ctx, "tcp", member)
			if err != nil {
				return
			}
			if !h.track(m) {
				m.Close()
				return
			}
			defer h.untrack(m)
			splice(c, m)
		}()
	}
}

func (h *Hub) track(c net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ctx.Err() != nil {
		return false
	}
	h.conns[c] = struct{}{}
	return true
}

func (h *Hub) untrack(c net.Conn) {
	h.mu.Lock()
	delete(h.conns, c)
	h.mu.Unlock()
	c.Close()
}
