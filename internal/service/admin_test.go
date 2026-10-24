// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// fakePhone is the root phone of a group, which dials a computer and sends
// it member protocol messages as the app does.
type fakePhone struct {
	t  *testing.T
	id *group.Identity
	tc *tls.Conn
}

func (p *fakePhone) dial(h *hub, to *group.Identity) {
	p.t.Helper()
	addr := ""
	h.mu.Lock()
	for m := range h.members {
		if m.cfg.ID == string(to.ID) {
			addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(m.cfg.Port)))
		}
	}
	h.mu.Unlock()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { raw.Close() })
	p.tc = tls.Client(raw, p.id.ClientTLS(to.ID, group.TLSOptions{}))
	if err := p.tc.Handshake(); err != nil {
		p.t.Fatal(err)
	}
	p.send(map[string]any{"t": "hello", "role": "phone", "hello": map[string]any{"wall_ms": time.Now().UnixMilli()}})
}

func (p *fakePhone) send(m map[string]any) {
	p.t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.tc.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(data))), data...)); err != nil {
		p.t.Fatal(err)
	}
}

// adminCAFor issues the admin CA of the computer id under root.
func adminCAFor(t *testing.T, root *group.CA, id *group.Identity) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: group.AdminName(id.ID)},
		NotBefore:             root.Cert.NotBefore,
		NotAfter:              root.Cert.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, &id.AdminKey.PublicKey, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestComputerAdmin checks a computer of a phone group that the root phone
// makes an admin: it offers its admin key, takes the admin CA from the
// phone, then admits a computer and removes it, which the other members
// follow, and refuses to remove the root phone.
func TestComputerAdmin(t *testing.T) {
	root := testCA(t, nil)
	piDir, pi := memberIn(t, root, root)
	deckDir, deck := memberIn(t, root, root)
	_, phone := memberIn(t, root, root)

	g := root.Cert
	pk, dk, phk := group.KeyHashOf(pi.Cert), group.KeyHashOf(deck.Cert), group.KeyHashOf(phone.Cert)
	recs := group.NewRecords(g)
	if _, errs := recs.AddAll([]group.Record{
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: phone.ID, Name: "iphone", Role: group.RolePhone, Key: &phk, By: phone.ID}, root.Key),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: pi.ID, Name: "pi", Role: group.RoleFull, Key: &pk, By: phone.ID}, root.Key),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: deck.ID, Name: "deck", Role: group.RoleFull, Key: &dk, By: phone.ID}, root.Key),
	}); len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, dir := range []string{piDir, deckDir} {
		if err := recs.Save(dir); err != nil {
			t.Fatal(err)
		}
	}

	var h hub
	a := startIn(t, &h, &testService{name: "pi", dir: piDir, os: group.OSLinux})
	b := startIn(t, &h, &testService{name: "deck", dir: deckDir, os: group.OSLinux})
	waitFor(t, "pi and deck connected", func() bool { return len(a.status(t).Peers) == 1 })
	if _, err := a.do(t, control.Header{Op: control.OpRevoke, Name: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("revoke before the pi is an admin: %v", err)
	}
	pending, err := group.Load(piDir)
	if err != nil || pending.AdminKey == nil || pending.AdminCA != nil {
		t.Fatalf("the pi has no admin key: %v", err)
	}

	// The root phone makes the pi an admin, and lists it as one.
	ca := adminCAFor(t, root, pending)
	ak := group.KeyHashOf(ca)
	p := &fakePhone{t: t, id: phone}
	p.dial(&h, pi)
	p.send(map[string]any{"t": "admin", "admin_ca": ca.Raw})
	p.send(map[string]any{"t": "records", "records": []group.Record{
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: pi.ID, Name: "pi", Role: group.RoleFull, Key: &pk, Admin: &ak, By: phone.ID}, root.Key),
	}})
	waitFor(t, "the pi keeps its admin CA", func() bool {
		id, err := group.Load(piDir)
		return err == nil && id.AdminCA != nil && id.AdminCA.Equal(ca)
	})
	for _, s := range []*testService{a, b} {
		waitFor(t, s.name+" lists the pi as an admin", func() bool {
			for _, d := range s.devices(t) {
				if d.Name == "pi" {
					return d.Admin
				}
			}
			return false
		})
	}

	if _, err := a.do(t, control.Header{Op: control.OpRevoke, Name: "iphone"}, ""); err == nil || !strings.Contains(err.Error(), "group's root") {
		t.Errorf("revoking the root phone: %v", err)
	}
	// The pi admits a computer from its admin CA, which every member
	// lists, and removes it again.
	c := startService(t, &h, "laptop")
	pairWith(t, a, c)
	joined, err := group.Load(c.dir)
	if err != nil || joined.Issuer == nil || !joined.Issuer.Equal(ca) || joined.AdminKey == nil {
		t.Fatalf("the new computer's identity: %v", err)
	}
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" lists the laptop", func() bool { return listed(s.devices(t)) == "deck iphone laptop pi" })
		waitFor(t, s.name+" connected", func() bool { return len(s.status(t).Peers) >= 2 })
	}
	if _, err := a.do(t, control.Header{Op: control.OpRevoke, Name: "laptop"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck drops the laptop", func() bool { return listed(b.devices(t)) == "deck iphone pi" })
	waitFor(t, "the laptop is cut off", func() bool { return len(c.status(t).Peers) == 0 })
}
