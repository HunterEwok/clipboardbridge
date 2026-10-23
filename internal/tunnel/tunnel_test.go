// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// A negative dial waits this long: several handshake attempts would be made
// if anything answered.
const refuseWait = 3 * time.Second

type testDevice struct {
	id   string
	addr netip.Addr
	priv Key
	psk  Key
}

func newDevice(t *testing.T) testDevice {
	t.Helper()
	var raw [16]byte
	rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	addr, err := Addr(id)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{id: id, addr: addr, priv: priv, psk: psk}
}

func (d testDevice) peer() Peer {
	return Peer{PublicKey: d.priv.Public(), PresharedKey: d.psk, Addr: d.addr}
}

type testHub struct {
	*Hub
	dev testDevice
}

// startHub starts a hub on the loopback address that echoes every line it
// receives, prefixed with the client's tunnel address.
func startHub(t *testing.T, peers ...Peer) testHub {
	t.Helper()
	d := newDevice(t)
	h, err := StartHub(HubConfig{PrivateKey: d.priv, Addr: d.addr, Peers: peers, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	go func() {
		for {
			c, err := h.Listener().Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				from := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
				fmt.Fprintf(c, "%s %s", from, buf[:n])
			}()
		}
	}()
	return testHub{h, d}
}

func (h testHub) endpoint() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.UDPPort()))
}

func startClient(t *testing.T, h testHub, d testDevice) *Client {
	t.Helper()
	c, err := StartClient(ClientConfig{
		PrivateKey: d.priv, PresharedKey: d.psk, Addr: d.addr,
		HubPublicKey: h.dev.priv.Public(), HubAddr: h.dev.addr, Endpoint: h.endpoint(),
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// roundTrip sends a line to the hub and returns its answer.
func roundTrip(ctx context.Context, c *Client) (string, error) {
	conn, err := c.Dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "hello"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	return string(b), err
}

func TestClientsReachTheHub(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())
	for _, d := range []testDevice{a, b} {
		c := startClient(t, h, d)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		got, err := roundTrip(ctx, c)
		cancel()
		if err != nil {
			t.Fatalf("client %s: %v", d.addr, err)
		}
		// The hub sees each client by its own tunnel address.
		if want := d.addr.String() + " hello"; got != want {
			t.Fatalf("hub answered %q, want %q", got, want)
		}
	}
}

func TestOnlyTheMemberPortIsOpen(t *testing.T) {
	a := newDevice(t)
	h := startHub(t, a.peer())
	c := startClient(t, h, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{22, 80, 443, Port + 1} {
		conn, err := c.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(h.dev.addr, port))
		if err == nil {
			conn.Close()
			t.Fatalf("port %d of the hub accepted a connection", port)
		}
	}
}

// rawClient is a tunnel to the hub that a hostile client configures by
// hand: any local address, and any destination routed to the hub.
func rawClient(t *testing.T, h testHub, d testDevice, local netip.Addr) *netstack.Net {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{local}, nil, MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=::/0\n",
		d.priv.hex(), h.dev.priv.Public().hex(), d.psk.hex(), h.endpoint())
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return tnet
}

func TestClientsCannotReachEachOther(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())

	// b is up and listening on the member port of its own stack.
	bc := startClient(t, h, b)
	l, err := bc.net.ListenTCPAddrPort(netip.AddrPortFrom(b.addr, Port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := roundTrip(ctx, bc); err != nil {
		t.Fatal(err)
	}
	cancel()

	// a sends everything to the hub, b's address included.
	an := rawClient(t, h, a, a.addr)
	ctx, cancel = context.WithTimeout(context.Background(), refuseWait)
	defer cancel()
	if c, err := an.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(b.addr, Port)); err == nil {
		c.Close()
		t.Fatal("a client reached another client through the hub")
	}
	select {
	case <-accepted:
		t.Fatal("a client's connection reached another client")
	default:
	}
	// The same tunnel does reach the hub.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := an.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(h.dev.addr, Port))
	if err != nil {
		t.Fatalf("the hostile client's tunnel does not work at all: %v", err)
	}
	c.Close()
}

func TestClientCannotUseAnotherAddress(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())
	// a claims b's address.
	an := rawClient(t, h, a, b.addr)
	ctx, cancel := context.WithTimeout(context.Background(), refuseWait)
	defer cancel()
	if c, err := an.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(h.dev.addr, Port)); err == nil {
		c.Close()
		t.Fatal("the hub accepted a client with another client's address")
	}
}

func TestUnknownKeysAreDropped(t *testing.T) {
	a := newDevice(t)
	h := startHub(t, a.peer())

	stranger := newDevice(t)
	wrongPSK := a
	wrongPSK.psk, _ = NewPresharedKey()
	for name, d := range map[string]testDevice{"unknown key": stranger, "wrong preshared key": wrongPSK} {
		c := startClient(t, h, d)
		ctx, cancel := context.WithTimeout(context.Background(), refuseWait)
		_, err := roundTrip(ctx, c)
		cancel()
		if err == nil {
			t.Fatalf("%s: the hub answered", name)
		}
	}
}

func TestRemovedClientIsDropped(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())
	c := startClient(t, h, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}
	cancel()

	if err := h.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), refuseWait)
	defer cancel()
	if _, err := roundTrip(ctx, c); err == nil {
		t.Fatal("the hub still answers a removed client")
	}
}

func TestSetEndpoint(t *testing.T) {
	a := newDevice(t)
	h := startHub(t, a.peer())
	c, err := StartClient(ClientConfig{
		PrivateKey: a.priv, PresharedKey: a.psk, Addr: a.addr,
		HubPublicKey: h.dev.priv.Public(), HubAddr: h.dev.addr,
		Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), // nothing there
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetEndpoint(h.endpoint()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}
}

func TestPeersAreChecked(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	hub := newDevice(t)
	sameAddr := b.peer()
	sameAddr.Addr = a.addr
	sameKey := b.peer()
	sameKey.PublicKey = a.priv.Public()
	noPSK := b.peer()
	noPSK.PresharedKey = Key{}
	outside := b.peer()
	outside.Addr = netip.MustParseAddr("fd00::1")
	hubAddr := b.peer()
	hubAddr.Addr = hub.addr
	for name, p := range map[string]Peer{
		"same address": sameAddr, "same key": sameKey, "no preshared key": noPSK,
		"outside the prefix": outside, "the hub's address": hubAddr,
	} {
		if _, err := StartHub(HubConfig{PrivateKey: hub.priv, Addr: hub.addr, Peers: []Peer{a.peer(), p}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAddr(t *testing.T) {
	got, err := Addr("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("fd00:cbb:123:4567:89ab:cdef:123:4567"); got != want {
		t.Fatalf("Addr = %v, want %v", got, want)
	}
	for _, bad := range []string{"", "0123", "0123456789ABCDEF0123456789ABCDEF", "zz23456789abcdef0123456789abcdef"} {
		if _, err := Addr(bad); err == nil {
			t.Errorf("Addr(%q) accepted", bad)
		}
	}
}

func TestPublicKey(t *testing.T) {
	// RFC 7748, section 6.1: Alice's keys.
	var priv Key
	hex.Decode(priv[:], []byte("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	pub := priv.Public()
	if got, want := pub.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"; got != want {
		t.Fatalf("public key %s, want %s", got, want)
	}
}
