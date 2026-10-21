// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/clipbridge/internal/clip"
	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/hlc"
)

func socketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) net.Conn {
		f := os.NewFile(uintptr(fd), "socketpair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	return conn(fds[0]), conn(fds[1])
}

// member is a node with its engine and the writes it received.
type member struct {
	*Node
	id     *group.Identity
	engine *clip.Engine
	writes chan Write
}

var admin *group.Identity

func newMember(t *testing.T, role Role) *member {
	t.Helper()
	if admin == nil {
		var err error
		if admin, err = group.Create(time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	devID := group.NewDeviceID()
	cert, err := admin.GroupCA.IssueMember(devID, &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := &group.Identity{ID: devID, Key: key, Cert: cert, GroupCA: group.CA{Cert: admin.GroupCA.Cert}}
	e := clip.New(clip.Config{Self: string(devID), Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	m := &member{id: id, engine: e, writes: make(chan Write, 64)}
	m.Node = New(Config{
		Identity: id, Role: role, Engine: e,
		OnWrite:   func(w Write) { m.writes <- w },
		PingEvery: 50 * time.Millisecond, Timeout: 300 * time.Millisecond,
		Logf: t.Logf,
	})
	t.Cleanup(m.Close)
	return m
}

// link connects client to server and returns a channel with the result of
// each side's Serve, client first.
func link(t *testing.T, client, server *member) (clientDone, serverDone chan error) {
	t.Helper()
	a, b := socketPair(t)
	clientDone, serverDone = make(chan error, 1), make(chan error, 1)
	go func() {
		serverDone <- server.Serve(context.Background(), tls.Server(b, server.ServerTLS()))
	}()
	go func() {
		clientDone <- client.Serve(context.Background(), tls.Client(a, client.id.ClientTLS(server.id.ID, group.TLSOptions{})))
	}()
	return clientDone, serverDone
}

func waitPeers(t *testing.T, m *member, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(m.Peers()) != n {
		if time.Now().After(deadline) {
			t.Fatalf("%s has %d peers, want %d", m.id.ID, len(m.Peers()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitWrite(t *testing.T, m *member, text string) Write {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case w := <-m.writes:
			if w.Text == text {
				return w
			}
		case <-timeout:
			t.Fatalf("%s never wrote %q", m.id.ID, text)
		}
	}
}

func current(m *member) string {
	ev, ok := m.engine.Current()
	if !ok {
		return ""
	}
	return ev.Text
}

func TestCopyReachesTheOtherMember(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	waitPeers(t, pi, 1)
	if p := mac.Peers()[0]; p.ID != pi.id.ID || p.Role != Linux {
		t.Errorf("the Mac sees %+v", p)
	}
	if ok, err := mac.Copied("hello from the Mac", clip.Text, clip.Copy); err != nil || !ok {
		t.Fatalf("Copied = %v, %v", ok, err)
	}
	w := waitWrite(t, pi, "hello from the Mac")
	if w.Kind != clip.Text || w.Seq == 0 {
		t.Errorf("write %+v", w)
	}
	if err := pi.Send("hello from tmux", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, pi, "hello from tmux") // the member's own clipboard
	waitWrite(t, mac, "hello from tmux")
}

func TestHelloCarriesTheCurrentText(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	if _, err := pi.Copied("copied while alone", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	mac.Rejoin() // the Mac just woke up: it takes the group's text
	link(t, mac, pi)
	waitWrite(t, mac, "copied while alone")
}

func TestForwardedThroughAMember(t *testing.T) {
	a, b, c := newMember(t, Mac), newMember(t, Linux), newMember(t, Linux)
	link(t, a, b)
	link(t, b, c)
	waitPeers(t, b, 2)
	waitPeers(t, c, 1)
	if _, err := a.Copied("over two hops", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, c, "over two hops")
	// The event comes back to nobody twice: b forwarded it to c only.
	select {
	case w := <-a.writes:
		t.Errorf("the copy came back to its origin: %+v", w)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSilentPeerIsDropped(t *testing.T) {
	pi := newMember(t, Linux)
	mac := newMember(t, Mac)
	a, b := socketPair(t)
	done := make(chan error, 1)
	go func() { done <- pi.Serve(context.Background(), tls.Server(b, pi.ServerTLS())) }()
	// A client that completes TLS, sends its hello and then nothing.
	tc := tls.Client(a, mac.id.ClientTLS(pi.id.ID, group.TLSOptions{}))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	h := mac.engine.Connected(string(pi.id.ID))
	if err := writeMessage(tc, &message{Type: typeHello, Role: Mac, Hello: &h}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, err := readMessage(tc); err != nil {
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve returned no error for a silent peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a silent peer was never dropped")
	}
}

func TestPingsKeepAnIdleConnection(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	cd, sd := link(t, mac, pi)
	waitPeers(t, mac, 1)
	select {
	case err := <-cd:
		t.Fatalf("the client ended: %v", err)
	case err := <-sd:
		t.Fatalf("the server ended: %v", err)
	case <-time.After(time.Second): // more than three timeouts
	}
}

func TestByeEndsTheConnectionAtOnce(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	_, sd := link(t, mac, pi)
	waitPeers(t, pi, 1)
	start := time.Now()
	mac.Close()
	select {
	case err := <-sd:
		if err != nil {
			t.Errorf("Serve after a goodbye: %v", err)
		}
		if time.Since(start) > 250*time.Millisecond {
			t.Errorf("the goodbye took %v to notice", time.Since(start))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never noticed the goodbye")
	}
	if len(pi.Peers()) != 0 {
		t.Errorf("peers after the goodbye: %v", pi.Peers())
	}
}

func TestRejoinClosesTheConnectionsFirst(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	cd, _ := link(t, mac, pi)
	waitPeers(t, mac, 1)
	mac.Rejoin()
	// The old connection is gone when Rejoin returns.
	if len(mac.Peers()) != 0 {
		t.Errorf("peers after Rejoin: %v", mac.Peers())
	}
	select {
	case <-cd:
	case <-time.After(time.Second):
		t.Fatal("the old connection did not end")
	}
	// After the rejoin, an old text of the group is taken, as after a wake.
	if _, err := pi.Copied("copied while the Mac slept", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	link(t, mac, pi)
	waitWrite(t, mac, "copied while the Mac slept")
}

func TestReconnectReplacesTheOldConnection(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	cd1, _ := link(t, mac, pi)
	waitPeers(t, pi, 1)
	link(t, mac, pi)
	select {
	case <-cd1:
	case <-time.After(5 * time.Second):
		t.Fatal("the old connection stayed open")
	}
	waitPeers(t, pi, 1)
	if _, err := mac.Copied("after the reconnect", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, pi, "after the reconnect")
}

func TestBadFirstMessage(t *testing.T) {
	pi, mac := newMember(t, Linux), newMember(t, Mac)
	a, b := socketPair(t)
	done := make(chan error, 1)
	go func() { done <- pi.Serve(context.Background(), tls.Server(b, pi.ServerTLS())) }()
	tc := tls.Client(a, mac.id.ClientTLS(pi.id.ID, group.TLSOptions{}))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	ev := clip.Event{ID: clip.NewID(), Origin: string(mac.id.ID), Time: hlc.Timestamp{Wall: 1}, Text: "sneaky"}
	writeMessage(tc, &message{Type: typeEvent, Event: &ev})
	if err := <-done; err == nil {
		t.Error("Serve accepted an event before the hello")
	}
	if current(pi) != "" {
		t.Error("the event before the hello was applied")
	}
}

func TestBadEventIsDropped(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	// An invalid event, as a buggy or newer member might send it, is
	// dropped, and the connection goes on.
	mac.mu.Lock()
	for _, c := range mac.conns {
		c.enqueue(&message{Type: typeEvent, Event: &clip.Event{ID: "bad"}})
		c.enqueue(&message{Type: "from-the-future"})
	}
	mac.mu.Unlock()
	if _, err := mac.Copied("still connected", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, pi, "still connected")
}

func TestConnectingToItself(t *testing.T) {
	pi := newMember(t, Linux)
	a, b := socketPair(t)
	go pi.Serve(context.Background(), tls.Server(b, pi.ServerTLS()))
	err := pi.Serve(context.Background(), tls.Client(a, pi.id.ClientTLS(pi.id.ID, group.TLSOptions{})))
	if err == nil {
		t.Error("a member connected to itself")
	}
}

func TestClosedNodeRefuses(t *testing.T) {
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	pi.Close()
	cd, sd := link(t, mac, pi)
	if err := <-sd; err == nil {
		t.Error("a closed node served a connection")
	}
	<-cd
}

func TestSecretsAndOrdering(t *testing.T) {
	// Many copies from both sides end with both members on the same text.
	mac, pi := newMember(t, Mac), newMember(t, Linux)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	waitPeers(t, pi, 1)
	var wg sync.WaitGroup
	for i, m := range []*member{mac, pi} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				kind := clip.Text
				if j%7 == 0 {
					kind = clip.Secret
				}
				m.Copied(string(rune('a'+i))+string(rune('A'+j%26))+time.Now().String(), kind, clip.Copy)
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, _ := mac.engine.Current()
		b, _ := pi.engine.Current()
		if a.ID == b.ID && a.ID != "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the members did not converge: %s vs %s", a.ID, b.ID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
