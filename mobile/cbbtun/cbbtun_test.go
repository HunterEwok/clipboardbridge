// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

const (
	hubID   = "00112233445566778899aabbccddeeff"
	phoneID = "ffeeddccbbaa99887766554433221100"
)

// TestThroughTunnel connects to the loopback port and reaches the hub's
// member port, both ways.
func TestThroughTunnel(t *testing.T) {
	priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	psk, _ := tunnel.NewPresharedKey()
	hubKey, _ := tunnel.NewPrivateKey()
	hubAddr, _ := tunnel.Addr(hubID)
	phoneAddr, _ := tunnel.Addr(phoneID)
	var pk tunnel.Key
	copy(pk[:], pub)
	hub, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: hubKey, Addr: hubAddr,
		Peers: []tunnel.Peer{{PublicKey: pk, PresharedKey: psk, Addr: phoneAddr}}})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	go func() {
		for {
			c, err := hub.Listener().Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	hubPub := hubKey.Public()
	tun, err := Start(priv, psk[:], hubPub[:], phoneID, hubID, fmt.Sprintf("127.0.0.1:%d", hub.UDPPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	for i := range 2 {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port()))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(30 * time.Second))
		msg := []byte(fmt.Sprintf("hello %d", i))
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
		c.Close()
	}
	if err := tun.SetEndpoint(fmt.Sprintf("[::1]:%d", hub.UDPPort())); err != nil {
		t.Fatal(err)
	}
}

// TestCloseEndsConnections checks that Close ends a connection in use and
// closes the port.
func TestCloseEndsConnections(t *testing.T) {
	priv, _ := NewKey()
	psk, _ := tunnel.NewPresharedKey()
	hubKey, _ := tunnel.NewPrivateKey()
	hubPub := hubKey.Public()
	// No hub answers: the connection waits in the dial until Close.
	tun, err := Start(priv, psk[:], hubPub[:], phoneID, hubID, "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %v", d)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the connection read data after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connection stayed open after Close")
	}
	if _, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port())); err == nil {
		t.Fatal("the port still accepts after Close")
	}
}

func TestBadArguments(t *testing.T) {
	priv, _ := NewKey()
	k := make([]byte, 32)
	k[0] = 1
	cases := []struct {
		name                    string
		priv, psk, hub          []byte
		device, hubID, endpoint string
	}{
		{"short key", priv[:31], k, k, phoneID, hubID, "127.0.0.1:1"},
		{"short psk", priv, nil, k, phoneID, hubID, "127.0.0.1:1"},
		{"bad device", priv, k, k, "phone", hubID, "127.0.0.1:1"},
		{"bad hub", priv, k, k, phoneID, "HUB", "127.0.0.1:1"},
		{"bad endpoint", priv, k, k, phoneID, hubID, "example.org:1"},
	}
	for _, tc := range cases {
		if tun, err := Start(tc.priv, tc.psk, tc.hub, tc.device, tc.hubID, tc.endpoint); err == nil {
			tun.Close()
			t.Errorf("%s: Start succeeded", tc.name)
		}
	}
	if _, err := PublicKey(nil); err == nil {
		t.Error("PublicKey(nil) succeeded")
	}
}
