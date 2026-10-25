// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

func newGroup(t *testing.T) *group.CA {
	t.Helper()
	ca, err := group.NewGroupCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// device is a member of a group as the relay sees it: its certificate with
// the chain, its ID and its WireGuard key.
type device struct {
	cert    tls.Certificate
	id      string
	key     tunnel.Key
	records []group.Record
}

func newDevice(t *testing.T, ca *group.CA) device {
	t.Helper()
	now := time.Now()
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	id := group.NewDeviceID()
	leaf, err := ca.IssueMember(id, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	wg, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return device{cert: tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, id: string(id), key: wg}
}

func startRelay(t *testing.T, groups ...*group.CA) (*Relay, Link) {
	t.Helper()
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, g := range groups {
		tags = append(tags, group.Tag(g.Cert))
	}
	r, err := Listen(Config{Listen: "127.0.0.1:0", Keys: keys, Groups: tags, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	ep := netip.MustParseAddrPort(r.Addr().String())
	return r, Link{Endpoint: ep, Pin: keys.Pin()}
}

// joined is a member's link to the relay in a test: it echoes each line it
// is sent on a connection it answers, and reports what happens.
type joined struct {
	mu      sync.Mutex
	reports []Report
	called  chan string
	dialed  chan string
	stop    context.CancelFunc
	done    chan struct{}
}

func (j *joined) last() Report {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.reports) == 0 {
		return Report{}
	}
	return j.reports[len(j.reports)-1]
}

// join starts d's link; a dialed connection sends "hello from <id>" and
// expects it back.
func join(t *testing.T, link Link, d device) *joined {
	t.Helper()
	j := &joined{called: make(chan string, 8), dialed: make(chan string, 8), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	j.stop = cancel
	cfg := MemberConfig{
		Link: link, Self: d.id, Key: d.key,
		Cert:    func() tls.Certificate { return d.cert },
		Records: func() []group.Record { return d.records },
		Want:    func(string) bool { return true },
		Dialed: func(ctx context.Context, peer string, c net.Conn) error {
			msg := "hello from " + d.id + "\n"
			if _, err := c.Write([]byte(msg)); err != nil {
				return err
			}
			got, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return err
			}
			if got != msg {
				return errors.New("a wrong echo " + got)
			}
			j.dialed <- peer
			<-ctx.Done()
			return nil
		},
		Called: func(ctx context.Context, peer string, c net.Conn) error {
			got, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return err
			}
			if got != "hello from "+peer+"\n" {
				return errors.New("a call from someone else: " + got)
			}
			if _, err := c.Write([]byte(got)); err != nil {
				return err
			}
			j.called <- peer
			<-ctx.Done()
			return nil
		},
		Report: func(r Report) {
			j.mu.Lock()
			j.reports = append(j.reports, r)
			j.mu.Unlock()
		},
		Logf: t.Logf,
	}
	go func() {
		defer close(j.done)
		Join(ctx, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		<-j.done
	})
	return j
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func receive(t *testing.T, ch chan string, what string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(20 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return ""
	}
}

func TestThroughRelay(t *testing.T) {
	g := newGroup(t)
	_, link := startRelay(t, g)
	a, b := newDevice(t, g), newDevice(t, g)
	if a.id > b.id {
		a, b = b, a
	}
	ja := join(t, link, a)
	jb := join(t, link, b)
	if got := receive(t, ja.dialed, "a's dial"); got != b.id {
		t.Errorf("a dialed %s, want %s", got, b.id)
	}
	if got := receive(t, jb.called, "b's answer"); got != a.id {
		t.Errorf("b was called by %s, want %s", got, a.id)
	}
	waitFor(t, "both count the connection", func() bool {
		ra, rb := ja.last(), jb.last()
		return ra.Connected && rb.Connected && ra.Through == 1 && rb.Through == 1 &&
			slices.Equal(ra.Online, []string{b.id}) && slices.Equal(rb.Online, []string{a.id})
	})
	select {
	case p := <-jb.dialed:
		t.Errorf("the higher ID dialed %s too", p)
	default:
	}

	// When b goes, a hears it and its connection ends.
	jb.stop()
	<-jb.done
	waitFor(t, "a sees b gone", func() bool {
		r := ja.last()
		return r.Connected && len(r.Online) == 0 && r.Through == 0
	})
}

func TestGroupsApart(t *testing.T) {
	g1, g2 := newGroup(t), newGroup(t)
	r, link := startRelay(t, g1, g2)
	a, c := newDevice(t, g1), newDevice(t, g2)
	ja := join(t, link, a)
	jc := join(t, link, c)
	waitFor(t, "both registered", func() bool {
		_, n := r.Stats()
		return n == 2 && ja.last().Connected && jc.last().Connected
	})
	time.Sleep(200 * time.Millisecond)
	if o := ja.last().Online; len(o) != 0 {
		t.Errorf("a sees %v of another group", o)
	}

	// Asked by hand, the relay does not join a to the other group's
	// device either.
	cl, stop := rawTunnel(t, link, newDevice(t, g1))
	defer stop()
	conn, err := cl.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeLine(conn, request{Dial: c.id}, time.Second); err != nil {
		t.Fatal(err)
	}
	var n note
	if err := readLine(conn, &n, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n.OK || !strings.Contains(n.Error, "not on the relay") {
		t.Errorf("a dial to another group's device: %+v", n)
	}
}

// rawTunnel registers d and brings its tunnel up, without a watch.
func rawTunnel(t *testing.T, link Link, d device) (*tunnel.Client, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := MemberConfig{Link: link, Self: d.id, Key: d.key, Cert: func() tls.Certificate { return d.cert }}
	tc, w, err := register(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var relayKey, psk tunnel.Key
	copy(relayKey[:], w.Key)
	copy(psk[:], w.PSK)
	cl, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: d.key, PresharedKey: psk, Addr: netip.MustParseAddr(w.Addr),
		HubPublicKey: relayKey, HubAddr: Addr, Endpoint: link.Endpoint})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return cl, func() {
		cl.Close()
		tc.Close()
		cancel()
	}
}

func TestRefused(t *testing.T) {
	g, other := newGroup(t), newGroup(t)
	r, link := startRelay(t, g)
	ctx := context.Background()

	stranger := newDevice(t, other)
	_, _, err := register(ctx, MemberConfig{Link: link, Key: stranger.key, Cert: func() tls.Certificate { return stranger.cert }})
	if err == nil {
		t.Error("a device of a group the relay does not serve registered")
	}

	d := newDevice(t, g)
	bad := link
	bad.Pin = "sha256:" + strings.Repeat("A", 43)
	_, _, err = register(ctx, MemberConfig{Link: bad, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
	if err == nil || !strings.Contains(err.Error(), "not the one given") {
		t.Errorf("a wrong pin: %v", err)
	}

	tc, _, err := register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	thief := newDevice(t, g)
	_, _, err = register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return thief.cert }})
	if err == nil || !strings.Contains(err.Error(), "another device") {
		t.Errorf("another device with the same WireGuard key: %v", err)
	}

	// The same device registering again takes the place of the first.
	tc2, _, err := register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
	if err != nil {
		t.Fatal(err)
	}
	defer tc2.Close()
	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tc.Read(make([]byte, 1)); err == nil {
		t.Error("the first registration still holds")
	}
	if _, n := r.Stats(); n != 1 {
		t.Errorf("the relay holds %d devices, want 1", n)
	}
}

func TestListen(t *testing.T) {
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(Config{Listen: "127.0.0.1:0", Keys: keys}); err == nil {
		t.Error("a relay for no group")
	}
	if _, err := Listen(Config{Listen: "127.0.0.1:0", Keys: keys, Groups: []string{"nope"}}); err == nil {
		t.Error("a relay for a bad tag")
	}
}

func TestKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.pem")
	k1, err := LoadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Pin() != k2.Pin() || k1.WireGuard != k2.WireGuard {
		t.Error("the keys changed when read again")
	}
	if err := CheckPin(k1.Pin()); err != nil {
		t.Error(err)
	}
}

// TestRemovedDevice checks that the records one member sends make the relay
// drop, and then refuse, a device its group removed.
func TestRemovedDevice(t *testing.T) {
	ca := newGroup(t)
	_, link := startRelay(t, ca)
	gone, stays := newDevice(t, ca), newDevice(t, ca)
	j := join(t, link, gone)
	waitFor(t, "the device to connect", func() bool { return j.last().Connected })
	revoke, err := group.SignRecord(group.RecordBody{Type: group.RecordRevoke, Group: group.Tag(ca.Cert), TimeMS: time.Now().UnixMilli(),
		Keys: []group.KeyHash{group.KeyHashOf(gone.cert.Leaf)}}, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	stays.records = []group.Record{revoke}
	k := join(t, link, stays)
	waitFor(t, "the other device to connect", func() bool { return k.last().Connected })
	waitFor(t, "the removed device to be refused", func() bool {
		r := j.last()
		return !r.Connected && r.Err != nil && strings.Contains(r.Err.Error(), "removed")
	})
}
