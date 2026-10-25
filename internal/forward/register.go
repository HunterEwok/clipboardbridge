// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
	"github.com/HunterEwok/clipboardbridge/internal/vless"
)

// Protocol is the ALPN protocol of a hub's registration.
const Protocol = "clipboardbridge-forward/1"

// The labels of the keys the registration takes from TLS: the one the hub
// proves its WireGuard key under, and the one its hellos carry a MAC of.
const (
	proofLabel = "clipboardbridge forwarder key"
	helloLabel = "clipboardbridge forwarder hello"
	// adminLabel is the key the hub's root or admin CA signs, with the
	// hub's WireGuard key, to show the hub may register its group.
	adminLabel = "clipboardbridge forwarder admin"
)

// maxClaim bounds a claim, which carries the group's authority records,
// and maxClaimRecords the records in it, whose signatures the forwarder
// checks.
const (
	maxClaim        = 1 << 20
	maxClaimRecords = 1024
)

// setupTimeout bounds a registration from the TCP connection to the
// forwarder's answer.
const setupTimeout = 15 * time.Second

// maxChain is the most certificates a hub may present: its member
// certificate, its admin CA and the group's roots.
const maxChain = 8

// The registration's messages, one JSON object a line (docs/protocol.md,
// section 13).
type (
	challenge struct {
		E []byte `json:"e"` // the forwarder's ephemeral X25519 key
	}
	claim struct {
		Key   []byte `json:"key"`   // the hub's WireGuard public key
		Proof []byte `json:"proof"` // HMAC-SHA256(X25519(hub key, e), the TLS proof key)
		// Obfuscation is the group's AmneziaWG settings, without which the
		// forwarder cannot read an obfuscated group's packets.
		Obfuscation *tunnel.Obfuscation `json:"obfuscation,omitempty"`
		// VLESS is the group's VLESS user ID, for a hub whose clients come
		// over VLESS.
		VLESS string `json:"vless,omitempty"`
		// Admin is the admin CA that signed AdminSig, or empty when a root
		// of the group did; AdminSig signs SHA-256 of the TLS admin key and
		// the WireGuard key (adminMessage). Only the root or an admin may
		// register its group.
		Admin    []byte `json:"admin,omitempty"`
		AdminSig []byte `json:"admin_sig"`
		// Records are the group's authority records
		// (group.Records.AuthorityRecords), so that the forwarder refuses
		// a removed or frozen hub.
		Records []group.Record `json:"records,omitempty"`
	}
	answer struct {
		ID    uint64       `json:"id,omitempty"`    // the registration, for the hellos
		Mask  []byte       `json:"mask,omitempty"`  // the key of the hellos' mask
		VLESS *vlessAnswer `json:"vless,omitempty"` // how clients reach the forwarder over VLESS
		Error string       `json:"error,omitempty"` // why the forwarder refused it
		Seen  string       `json:"seen,omitempty"`  // where the hub's WireGuard port is reached
	}
	vlessAnswer struct {
		Port       uint16 `json:"port"`        // the TCP port, at the forwarder's address
		PublicKey  []byte `json:"public_key"`  // the REALITY key
		ShortID    string `json:"short_id"`    // REALITY's short ID
		ServerName string `json:"server_name"` // the site the handshakes name
	}
)

// serverTLS is the forwarder's TLS: TLS 1.3, its own certificate, and a
// client certificate whose chain the forwarder checks itself, since it
// knows no group beforehand.
func (f *Forwarder) serverTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{Protocol},
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != Protocol {
				return errors.New("forward: the hub does not speak the registration protocol")
			}
			_, err := groupOf(cs.PeerCertificates, time.Now())
			return err
		},
	}
}

// groupOf checks that the certificates a hub presented are a member
// certificate with its chain to a group's root, and returns that group's
// tag. The root is the self-signed CA among them; any group may register,
// but only a member of a group can register it.
func groupOf(certs []*x509.Certificate, now time.Time) (string, error) {
	if len(certs) == 0 || len(certs) > maxChain {
		return "", errors.New("forward: the hub presented no member certificate chain")
	}
	if _, err := group.DeviceOf(certs[0]); err != nil {
		return "", fmt.Errorf("forward: %w", err)
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range certs[1:] {
		if c.IsCA && c.CheckSignatureFrom(c) == nil {
			roots.AddCert(c)
		} else {
			inter.AddCert(c)
		}
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return "", fmt.Errorf("forward: the hub's certificate: %w", err)
	}
	c := chains[0]
	return group.Tag(c[len(c)-1]), nil
}

// acceptRegistrations takes the hubs' TLS connections.
func (f *Forwarder) acceptRegistrations() {
	for {
		conn, err := f.tcp.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			f.logf("cbb forward: accepting registrations: %v", err)
			return
		}
		var from netip.Addr
		if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			from = ta.AddrPort().Addr().Unmap()
		}
		nw := network(from)
		f.mu.Lock()
		busy := f.setting >= f.limits.Connections || f.fromAddr[from] >= f.limits.PerAddress || f.fromNet[nw] >= f.limits.PerNetwork
		if !busy {
			f.setting++
			f.fromAddr[from]++
			f.fromNet[nw]++
		}
		f.mu.Unlock()
		if busy {
			conn.Close()
			continue
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer func() {
				f.mu.Lock()
				if f.fromAddr[from]--; f.fromAddr[from] == 0 {
					delete(f.fromAddr, from)
				}
				if f.fromNet[nw]--; f.fromNet[nw] == 0 {
					delete(f.fromNet, nw)
				}
				f.mu.Unlock()
			}()
			f.serveRegistration(conn)
		}()
	}
}

// serveRegistration registers one hub and holds its registration while the
// connection lasts.
func (f *Forwarder) serveRegistration(raw net.Conn) {
	r, err := f.register(raw)
	f.mu.Lock()
	f.setting--
	f.mu.Unlock()
	if err != nil {
		raw.Close()
		return
	}
	defer func() {
		f.mu.Lock()
		f.dropRegLocked(r)
		f.mu.Unlock()
	}()
	enc := json.NewEncoder(r.conn)
	gone := make(chan struct{})
	go func() {
		// The hub sends nothing more; reading tells when it goes.
		_, _ = io.Copy(io.Discard, r.conn)
		close(gone)
	}()
	for {
		select {
		case <-gone:
			return
		case <-f.done:
			return
		case ep := <-r.seen:
			r.conn.SetWriteDeadline(time.Now().Add(setupTimeout))
			if enc.Encode(answer{Seen: ep.String()}) != nil {
				return
			}
		}
	}
}

// register runs a registration's setup: TLS with the hub's member
// certificate, then the proof that the hub holds its WireGuard key, bound
// to this TLS session.
func (f *Forwarder) register(raw net.Conn) (*reg, error) {
	raw.SetDeadline(time.Now().Add(setupTimeout))
	tc := tls.Server(raw, f.tlsCfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	tag, err := groupOf(cs.PeerCertificates, time.Now())
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
	refuse := func(msg string) (*reg, error) {
		enc.Encode(answer{Error: msg})
		return nil, errors.New(msg)
	}
	if len(c.Records) > maxClaimRecords {
		return refuse("too many records")
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
		return refuse("the hub does not hold that WireGuard key")
	}
	if c.Obfuscation != nil {
		if err := c.Obfuscation.Check(); err != nil {
			return refuse("the obfuscation settings are not usable")
		}
	}
	if c.VLESS != "" {
		if f.vless == nil {
			return refuse("this forwarder has no VLESS; run cbb forward with -vless-site")
		}
		if err := tunnel.CheckVLESSID(c.VLESS); err != nil {
			return refuse("the VLESS user ID is not usable")
		}
	}
	adminMsg, err := adminMessage(cs, c.Key)
	if err != nil {
		return nil, err
	}
	r := &reg{tag: tag, obf: c.Obfuscation, vlessID: c.VLESS, seen: make(chan netip.AddrPort, 1), clients: map[netip.AddrPort]int{}, conn: tc, raw: raw}
	copy(r.key[:], c.Key)
	r.mac1 = mac1Key(r.key)
	hk, err := cs.ExportKeyingMaterial(helloLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	copy(r.helloKey[:], hk)
	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	r.id = binary.BigEndian.Uint64(idb[:])
	now := time.Now()
	r.packets, r.bytes = *newBucket(f.limits.PacketRate, now), *newBucket(f.limits.ByteRate, now)

	f.mu.Lock()
	old := f.regs[tag]
	f.mu.Unlock()
	known := f.memory.records(tag)
	// The records are checked outside the lock: their signatures take time.
	records, err := authority(cs.PeerCertificates, c, adminMsg, known)
	if err != nil {
		return refuse(err.Error())
	}
	f.mu.Lock()
	if o := f.regs[tag]; o != old {
		// Another registration of the group came meanwhile; this one
		// holds the records of the one it checked against only.
		f.mu.Unlock()
		return refuse("the group registered meanwhile; try again")
	}
	for _, o := range f.regs {
		if o.key == r.key && o.tag != tag {
			f.mu.Unlock()
			return refuse("another group registered that WireGuard key")
		}
	}
	if old == nil && len(f.regs) >= f.limits.Groups {
		f.mu.Unlock()
		return refuse("the forwarder is full")
	}
	if o := f.byVLESS[r.vlessID]; r.vlessID != "" && o != nil && o.tag != tag {
		f.mu.Unlock()
		return refuse("another group registered that VLESS user ID")
	}
	if old != nil {
		// The group's hub registers again, or another hub took over.
		f.dropRegLocked(old)
	}
	a := answer{ID: r.id, Mask: f.mask[:]}
	if r.vlessID != "" {
		if err := f.vless.AddUser(r.vlessID); err != nil {
			f.mu.Unlock()
			return refuse("the VLESS user ID is not usable")
		}
		f.byVLESS[r.vlessID] = r
		pub, err := vless.PublicKey(f.vlessCfg.Key)
		if err != nil {
			f.mu.Unlock()
			return nil, err
		}
		a.VLESS = &vlessAnswer{Port: f.vless.Port(), PublicKey: pub, ShortID: vless.ShortID(f.vlessCfg.Key), ServerName: f.vlessCfg.Site}
	}
	f.regs[tag], f.byID[r.id] = r, r
	if r.obf != nil {
		f.byInit[initSize(r.obf)] = append(f.byInit[initSize(r.obf)], r)
	}
	f.mu.Unlock()
	if err := f.memory.keep(tag, records); err != nil {
		f.logf("forward: keeping the records of a group: %v", err)
	}
	if err := enc.Encode(a); err != nil {
		f.mu.Lock()
		f.dropRegLocked(r)
		f.mu.Unlock()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return r, nil
}

// adminMessage is what the hub's root or admin CA signs: SHA-256 of a key
// from this TLS session and the hub's WireGuard key, so the signature
// proves nothing on another connection or for another key.
func adminMessage(cs tls.ConnectionState, wgKey []byte) ([]byte, error) {
	k, err := cs.ExportKeyingMaterial(adminLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append(k, wgKey...))
	return sum[:], nil
}

// SignAdmin signs a registration's admin message with the key of the
// group's root or of an admin CA.
func SignAdmin(key *ecdsa.PrivateKey, cs tls.ConnectionState, wgKey []byte) ([]byte, error) {
	msg, err := adminMessage(cs, wgKey)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, key, msg)
}

// authority checks that a root or an admin of the hub's group signed the
// registration, and that neither it nor the hub was removed or frozen, by
// the records the hub sent and those the group's last registration left
// (known). It returns the records to keep for the group: the forwarder
// keeps them in memory while the group stays registered, so a removed admin
// that registers next cannot leave them out. It knows the group only by the
// root the hub presented first, the group CA in ForwarderCertificate.
func authority(certs []*x509.Certificate, c claim, msg []byte, known []group.Record) ([]group.Record, error) {
	var groupCA *x509.Certificate
	for _, cert := range certs[1:] {
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			groupCA = cert
			break
		}
	}
	if groupCA == nil {
		return nil, errors.New("the hub presented no root")
	}
	recs := group.NewRecords(groupCA)
	recs.AddAll(known)
	recs.AddAll(c.Records)
	path := append([]*x509.Certificate{groupCA}, recs.Roots()...)
	var admin *x509.Certificate
	if len(c.Admin) != 0 {
		ca, err := x509.ParseCertificate(c.Admin)
		if err != nil {
			return nil, errors.New("the admin CA cannot be read")
		}
		for _, root := range path {
			if group.CheckAdminCA(ca, root) == nil {
				admin = ca
				break
			}
		}
	}
	var signer *x509.Certificate
	for _, cand := range path {
		if admin != nil {
			cand = admin
		}
		if pub, ok := cand.PublicKey.(*ecdsa.PublicKey); ok && ecdsa.VerifyASN1(pub, msg, c.AdminSig) {
			signer = cand
			break
		}
		if admin != nil {
			break
		}
	}
	if signer == nil && memberOfAuthority(recs, certs[0]) {
		signer = certs[0]
	}
	if signer == nil {
		return nil, errors.New("only the group's root or an admin may register it, and this hub is neither")
	}
	s, leaf := group.KeyHashOf(signer), group.KeyHashOf(certs[0])
	if recs.Revoked(s) || recs.Revoked(leaf) {
		return nil, errors.New("the hub was removed from its group")
	}
	if recs.Frozen(s) || recs.Frozen(leaf) {
		return nil, errors.New("the hub is a frozen admin of its group")
	}
	return recs.AuthorityRecords(), nil
}

// memberOfAuthority reports whether the records make the device of leaf,
// with leaf's key, the group's root or an admin: a phone hub, whose root or
// admin key signs only after Face ID, registers with its member key alone
// (docs/protocol.md, section 13).
func memberOfAuthority(recs *group.Records, leaf *x509.Certificate) bool {
	dev, err := group.DeviceOf(leaf)
	if err != nil {
		return false
	}
	k := group.KeyHashOf(leaf)
	if root, key := recs.RootMember(); root == dev && key == k {
		return true
	}
	for _, d := range recs.Devices() {
		if d.ID == dev && d.Key == k && d.Admin && !d.Frozen {
			return true
		}
	}
	return false
}

// proof is what a hub sends to prove it holds its WireGuard key: an HMAC,
// under the X25519 secret of its key and the forwarder's ephemeral one, of
// a key from this TLS session, so it proves nothing on another connection.
func proof(shared []byte, cs tls.ConnectionState) ([]byte, error) {
	k, err := cs.ExportKeyingMaterial(proofLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, shared)
	m.Write(k)
	return m.Sum(nil), nil
}
