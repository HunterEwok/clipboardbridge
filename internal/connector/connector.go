// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package connector links a desktop clipboard to the service: the Mac's
// pasteboard agent and the Linux desktop connector run it with their own
// clipboard access.
//
// It watches the service's control socket: copies on the desktop go to the
// service, and the writes the service decides on go to the clipboard, in
// order. A secret it wrote is given up when it expires, unless the user
// copied something else meanwhile. A text the group does not carry, such as
// one over 1 MiB, is not sent. When the service goes away, it connects
// again with a growing pause.
package connector

import (
	"context"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/HunterEwok/clipbridge/internal/clip"
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

// Run links the clipboard to the service until ctx is done. A secret it
// wrote is given up when it expires, also when the service connection ended
// meanwhile, and at once when Run returns because ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	exp := &expiry{b: cfg.Board, logf: cfg.Logf}
	backoff := minBackoff
	for {
		start := time.Now()
		err := session(ctx, cfg, exp)
		if ctx.Err() != nil {
			exp.now()
			return nil
		}
		if errors.Is(err, ErrBoardGone) {
			exp.stop()
			return err
		}
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		cfg.Logf("clipbridge: the service connection ended: %v; trying again in %v", err, backoff)
		select {
		case <-ctx.Done():
			exp.now()
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// expiry gives up a written secret when it expires.
type expiry struct {
	b    Board
	logf func(string, ...any)
	mu   sync.Mutex
	t    *time.Timer
}

// set starts the timer for a secret just written, or stops it for a text.
func (e *expiry) set(secret bool, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.t != nil {
		e.t.Stop()
		e.t = nil
	}
	if secret {
		e.t = time.AfterFunc(ttl, e.clear)
	}
}

func (e *expiry) stop() { e.set(false, 0) }

// now gives up a pending secret at once.
func (e *expiry) now() {
	e.mu.Lock()
	pending := e.t != nil && e.t.Stop()
	e.t = nil
	e.mu.Unlock()
	if pending {
		e.clear()
	}
}

func (e *expiry) clear() {
	if err := e.b.ClearIfUnchanged(); err != nil {
		e.logf("clipbridge: giving up an expired secret: %v", err)
	}
}

// session runs one connection to the service. The watch request tells the
// service what the clipboard holds now, without an event.
func session(ctx context.Context, cfg Config, exp *expiry) error {
	c, err := control.Dial(cfg.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	watchReq := &control.Message{Header: control.Header{Op: control.OpWatch}}
	if it, ok, err := cfg.Board.Current(); err == nil && ok {
		if m := report(control.OpClipboard, it); m != nil {
			watchReq.Kind, watchReq.Via, watchReq.Payload = m.Kind, m.Via, m.Payload
		}
	}
	if _, err := c.Do(watchReq); err != nil {
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
	errc := make(chan error, 2)
	go func() { errc <- watch(ctx, cfg.Board, send, cfg.Logf) }()
	go func() { errc <- apply(ctx, cfg.Board, c, exp, cfg.Logf) }()
	err = <-errc
	cancel()
	return err
}

// report makes the message for a clipboard item: a copy, or, for a marked
// secret, only what the clipboard holds, so the service remembers it. It
// returns nil for a text the group does not carry: empty, larger than
// clip.MaxText, or not valid UTF-8.
func report(op string, it Item) *control.Message {
	if it.Text == "" || len(it.Text) > clip.MaxText || !utf8.ValidString(it.Text) {
		return nil
	}
	kind, via := control.KindText, control.ViaCopy
	if it.Secret {
		kind, op = control.KindSecret, control.OpClipboard
	}
	if it.Remote {
		via = control.ViaUniversal
	}
	return &control.Message{Header: control.Header{Op: op, Kind: kind, Via: via}, Payload: []byte(it.Text)}
}

// watch reports clipboard changes to the service.
func watch(ctx context.Context, b Board, send func(*control.Message) error, logf func(string, ...any)) error {
	for {
		it, ok, err := b.Next(ctx)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		m := report(control.OpCopied, it)
		if m == nil {
			if it.Text != "" {
				logf("clipbridge: a copy of %d bytes is not synced: larger than 1 MiB, or not UTF-8 text", len(it.Text))
			}
			continue
		}
		if err := send(m); err != nil {
			return err
		}
	}
}

// apply writes what the service sends into the clipboard, in order, and
// sets the expiry of a secret.
func apply(ctx context.Context, b Board, c *control.Client, exp *expiry, logf func(string, ...any)) error {
	var last uint64
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
		secret := m.Kind == control.KindSecret
		if err := b.Write(string(m.Payload), secret); err != nil {
			logf("clipbridge: writing the clipboard: %v", err)
			continue
		}
		ttl := time.Duration(m.TTLMS) * time.Millisecond
		if ttl <= 0 {
			ttl = time.Minute
		}
		exp.set(secret, ttl)
	}
}
