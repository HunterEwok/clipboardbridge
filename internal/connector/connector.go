// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package connector links a desktop clipboard to the service: the Mac's
// pasteboard agent and the Linux desktop connector run it with their own
// clipboard access.
//
// It watches the service's control socket: copies on the desktop go to the
// service, and the writes the service decides on go to the clipboard, in
// order. A secret it wrote is given up when it expires, unless the user
// copied something else meanwhile. When the service goes away, it connects
// again with a growing pause.
package connector

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/HunterEwok/clipbridge/internal/control"
)

// ErrBoardGone is the error a Board returns when its display connection is
// gone; Run then returns, so the caller can open the display again.
var ErrBoardGone = errors.New("connector: the display connection is gone")

// Item is what the clipboard holds.
type Item struct {
	Text   string
	Secret bool // a password manager marked it; it is never sent
	Remote bool // it came through Universal Clipboard
}

// A Board is a desktop clipboard.
type Board interface {
	// Current returns what the clipboard holds now, and false if no text.
	Current() (Item, bool, error)
	// Next blocks until the clipboard changes, other than by Write, and
	// returns the new item, or false if it holds no text.
	Next(ctx context.Context) (Item, bool, error)
	// Write puts a text into the clipboard.
	Write(text string, secret bool) error
	// ClearIfUnchanged empties the clipboard if it still holds what the
	// last Write put there.
	ClearIfUnchanged() error
}

// Config configures Run.
type Config struct {
	Socket string // the control socket
	Board  Board
	Logf   func(format string, args ...any)
}

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// Run links the clipboard to the service until ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	backoff := minBackoff
	for {
		start := time.Now()
		err := session(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrBoardGone) {
			return err
		}
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		cfg.Logf("clipbridge: the service connection ended: %v; trying again in %v", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// session runs one connection to the service.
func session(ctx context.Context, cfg Config) error {
	c, err := control.Dial(cfg.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpWatch}}); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	var sendMu sync.Mutex
	send := func(m *control.Message) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return c.Send(m)
	}
	// Tell the service what the clipboard holds now, without an event.
	if it, ok, err := cfg.Board.Current(); err == nil && ok {
		if err := send(report(control.OpClipboard, it)); err != nil {
			return err
		}
	}
	errc := make(chan error, 2)
	go func() { errc <- watch(ctx, cfg.Board, send) }()
	go func() { errc <- apply(ctx, cfg.Board, c, cfg.Logf) }()
	err = <-errc
	cancel()
	return err
}

// report makes the message for a clipboard item: a copy, or, for a marked
// secret, only what the clipboard holds, so the service remembers it.
func report(op string, it Item) *control.Message {
	kind, via := "text", "copy"
	if it.Secret {
		kind, op = "secret", control.OpClipboard
	}
	if it.Remote {
		via = "universal"
	}
	return &control.Message{Header: control.Header{Op: op, Kind: kind, Via: via}, Payload: []byte(it.Text)}
}

// watch reports clipboard changes to the service.
func watch(ctx context.Context, b Board, send func(*control.Message) error) error {
	for {
		it, ok, err := b.Next(ctx)
		if err != nil {
			return err
		}
		if !ok || it.Text == "" {
			continue
		}
		if err := send(report(control.OpCopied, it)); err != nil {
			return err
		}
	}
}

// apply writes what the service sends into the clipboard, in order, and
// gives up a secret when it expires.
func apply(ctx context.Context, b Board, c *control.Client, logf func(string, ...any)) error {
	var last uint64
	var expiry *time.Timer
	defer func() {
		if expiry != nil {
			expiry.Stop()
		}
	}()
	for {
		m, err := c.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if m.Op != control.OpWrite || m.Seq <= last {
			continue
		}
		last = m.Seq
		secret := m.Kind == "secret"
		if err := b.Write(string(m.Payload), secret); err != nil {
			logf("clipbridge: writing the clipboard: %v", err)
			continue
		}
		if expiry != nil {
			expiry.Stop()
			expiry = nil
		}
		if secret {
			ttl := time.Duration(m.TTLMS) * time.Millisecond
			if ttl <= 0 {
				ttl = time.Minute
			}
			expiry = time.AfterFunc(ttl, func() {
				if err := b.ClearIfUnchanged(); err != nil {
					logf("clipbridge: giving up an expired secret: %v", err)
				}
			})
		}
	}
}
