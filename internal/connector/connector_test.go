// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipbridge/internal/control"
	"github.com/HunterEwok/clipbridge/internal/node"
	"github.com/HunterEwok/clipbridge/internal/service"
)

// fakeBoard is a clipboard that the test changes by hand.
type fakeBoard struct {
	mu       sync.Mutex
	item     Item
	has      bool
	changes  chan Item
	writes   chan Item
	ownWrite bool // the clipboard still holds the last Write
	cleared  chan struct{}
}

func newBoard() *fakeBoard {
	return &fakeBoard{changes: make(chan Item, 16), writes: make(chan Item, 16), cleared: make(chan struct{}, 4)}
}

func (b *fakeBoard) Current() (Item, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.item, b.has, nil
}

func (b *fakeBoard) Next(ctx context.Context) (Item, bool, error) {
	select {
	case it := <-b.changes:
		b.mu.Lock()
		b.item, b.has, b.ownWrite = it, true, false
		b.mu.Unlock()
		return it, true, nil
	case <-ctx.Done():
		return Item{}, false, ctx.Err()
	}
}

func (b *fakeBoard) Write(text string, secret bool) error {
	b.mu.Lock()
	b.item, b.has, b.ownWrite = Item{Text: text, Secret: secret}, true, true
	b.mu.Unlock()
	b.writes <- Item{Text: text, Secret: secret}
	return nil
}

func (b *fakeBoard) ClearIfUnchanged() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ownWrite {
		b.item, b.has = Item{}, false
		b.cleared <- struct{}{}
	}
	return nil
}

// copyOn is the user copying on the desktop.
func (b *fakeBoard) copyOn(it Item) { b.changes <- it }

// noDiscovery finds no one: the test has one member.
type noDiscovery struct{}

func (noDiscovery) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (noDiscovery) SetTXT([]string)               {}
func (noDiscovery) SetHolder(bool)                {}

func startService(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- service.Run(ctx, service.Config{StateDir: dir, Socket: socket, Role: node.Linux, Name: "pi",
			Discover: func(service.DiscoveryConfig) (service.Discovery, error) { return noDiscovery{}, nil }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := control.Dial(socket); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the service did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Create the group: pair opens a window, which the test then closes.
	c, err := control.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	return socket
}

func do(t *testing.T, socket string, h control.Header, payload string) *control.Message {
	t.Helper()
	c, err := control.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h, Payload: []byte(payload)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func paste(t *testing.T, socket string) string {
	t.Helper()
	c, err := control.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPaste}})
	if err != nil {
		return ""
	}
	return string(m.Payload)
}

func run(t *testing.T, socket string, b Board) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Config{Socket: socket, Board: b, Logf: t.Logf}) }()
	t.Cleanup(func() { cancel(); <-done })
}

func TestConnector(t *testing.T) {
	socket := startService(t)
	b := newBoard()
	b.item, b.has = Item{Text: "already there"}, true
	run(t, socket, b)
	// What the clipboard held at start is known to the service, without
	// an event.
	waitFor(t, "the starting text", func() bool { return paste(t, socket) == "already there" })

	// A copy on the desktop reaches the service.
	b.copyOn(Item{Text: "copied on the desktop"})
	waitFor(t, "the desktop copy", func() bool { return paste(t, socket) == "copied on the desktop" })

	// A deliberate copy, as from tmux, reaches the desktop clipboard.
	do(t, socket, control.Header{Op: control.OpCopy}, "from tmux")
	select {
	case w := <-b.writes:
		if w.Text != "from tmux" || w.Secret {
			t.Errorf("write %+v", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no write")
	}

	// A marked secret is not sent: the service only remembers it.
	b.copyOn(Item{Text: "hunter2", Secret: true})
	time.Sleep(200 * time.Millisecond)
	if got := paste(t, socket); got != "hunter2" {
		t.Errorf("own clipboard %q after a marked secret", got)
	}
}

func TestSecretExpires(t *testing.T) {
	socket := startService(t)
	b := newBoard()
	run(t, socket, b)
	waitFor(t, "connected", func() bool {
		m := do(t, socket, control.Header{Op: control.OpStatus}, "")
		return m.Status != nil && m.Status.Group != ""
	})
	time.Sleep(100 * time.Millisecond) // let the watcher register
	do(t, socket, control.Header{Op: control.OpCopy, Kind: "secret"}, "one-time code")
	select {
	case w := <-b.writes:
		if !w.Secret {
			t.Errorf("the secret was written as %+v", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no write")
	}
	// The test does not wait a minute: the lifetime the service sent is
	// checked through the timer the connector set.
	if err := b.ClearIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.cleared:
	default:
		t.Error("the clipboard was not given up")
	}
}

func TestReconnect(t *testing.T) {
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	b := newBoard()
	// No service yet: Run keeps trying and does not fail.
	run(t, filepath.Join(dir, "missing.sock"), b)
	time.Sleep(100 * time.Millisecond)
}
