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
// again with a growing pause; while the service refuses to be watched, as
// on a device in no group yet, it asks again every refusedWait, so the
// first text after the device joins reaches the clipboard soon.
//
// A connector whose Board is also a Target, or that has a Target of its
// own, offers it for remote paste: the service sends it the pastes an
// admin signed for this device (design.md, "Remote paste"). The tmux and
// console helpers run a connector with a Target and no Board.
package connector

import (
	"context"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
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

// A Target puts a text where the focus is, for remote paste.
type Target interface {
	// Target names what it pastes into, as the watch request offers it:
	// "desktop", "tmux" or "console"; "" offers nothing, as an X11 board
	// in a Wayland session, whose windows its keys would not reach.
	Target() string
	// Inject puts text where the focus is, by method "paste" (through the
	// clipboard and the paste keys) or "type" (key by key), then presses
	// Enter if enter is set. It checks first that the session is not
	// locked. A secret leaves no copy behind. An error that is a *Refusal
	// says why it would not; any other says how it failed.
	Inject(ctx context.Context, text, method string, enter, secret bool) error
}

// A Refusal is a Target's reason not to paste, such as a locked session.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// Config configures Run.
type Config struct {
	Socket string // the control socket
	Board  Board  // nil for a paste target without a clipboard
	Target Target // nil to use Board's when it is one
	Logf   func(format string, args ...any)
}

// target returns the paste target the connector offers, or nil.
func (cfg Config) target() Target {
	if cfg.Target != nil {
		return cfg.Target
	}
	if t, ok := cfg.Board.(Target); ok && t.Target() != "" {
		return t
	}
	return nil
}

const (
	minBackoff  = time.Second
	maxBackoff  = 30 * time.Second
	refusedWait = 2 * time.Second
)

// refusedError is the service's answer to a watch request it turned down.
type refusedError struct{ err error }

func (e *refusedError) Error() string { return e.err.Error() }
func (e *refusedError) Unwrap() error { return e.err }

// Run links the clipboard to the service until ctx is done. A secret it
// wrote is given up when it expires, also when the service connection ended
// meanwhile, and at once when Run returns because ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	var exp *expiry
	if cfg.Board != nil {
		exp = &expiry{b: cfg.Board, logf: cfg.Logf}
	}
	backoff := minBackoff
	refused := "" // the last refusal logged, so a waiting connector logs it once
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
		wait := backoff
		var re *refusedError
		if errors.As(err, &re) {
			wait, backoff = refusedWait, minBackoff
			if err.Error() != refused {
				refused = err.Error()
				cfg.Logf("cbb: the service does not take the clipboard yet: %v; asking again every %v", err, wait)
			}
		} else {
			refused = ""
			cfg.Logf("cbb: the service connection ended: %v; trying again in %v", err, wait)
			backoff = min(2*backoff, maxBackoff)
		}
		select {
		case <-ctx.Done():
			exp.now()
			return nil
		case <-time.After(wait):
		}
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
	if e == nil {
		return
	}
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
	if e == nil {
		return
	}
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
		e.logf("cbb: giving up an expired secret: %v", err)
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
	tgt := cfg.target()
	if tgt != nil {
		watchReq.Inject = tgt.Target()
	}
	if cfg.Board != nil {
		if it, ok, err := cfg.Board.Current(); err == nil && ok {
			if m := report(control.OpClipboard, it); m != nil {
				watchReq.Kind, watchReq.Via, watchReq.Payload = m.Kind, m.Via, m.Payload
			}
		}
	}
	if m, err := c.Do(watchReq); err != nil {
		if m != nil {
			return &refusedError{err}
		}
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
	if cfg.Board != nil {
		go func() { errc <- watch(ctx, cfg.Board, send, cfg.Logf) }()
	}
	go func() { errc <- apply(ctx, cfg.Board, tgt, c, send, exp, cfg.Logf) }()
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
				logf("cbb: a copy of %d bytes is not synced: larger than 1 MiB, or not UTF-8 text", len(it.Text))
			}
			continue
		}
		if err := send(m); err != nil {
			return err
		}
	}
}

// apply writes what the service sends into the clipboard, in order, and
// sets the expiry of a secret; it hands remote pastes to the target, one
// at a time, and answers each.
func apply(ctx context.Context, b Board, tgt Target, c *control.Client, send func(*control.Message) error, exp *expiry, logf func(string, ...any)) error {
	var last uint64
	for {
		m, err := c.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if m.Op == control.OpInject {
			if err := send(injected(ctx, tgt, m, logf)); err != nil {
				return err
			}
			continue
		}
		if b == nil || m.Op != control.OpWrite || m.Seq <= last {
			continue
		}
		last = m.Seq
		secret := m.Kind == control.KindSecret
		if err := b.Write(string(m.Payload), secret); err != nil {
			logf("cbb: writing the clipboard: %v", err)
			continue
		}
		ttl := time.Duration(m.TTLMS) * time.Millisecond
		if ttl <= 0 {
			ttl = time.Minute
		}
		exp.set(secret, ttl)
	}
}

// injected carries out an inject and makes its answer. A refusal's reason
// is for the sender as it is; a failure keeps its cause in Detail.
func injected(ctx context.Context, tgt Target, m *control.Message, logf func(string, ...any)) *control.Message {
	ans := &control.Message{Header: control.Header{Op: control.OpInjected, Seq: m.Seq}}
	if tgt == nil {
		ans.Error, ans.Refused = "this watcher does not paste", true
		return ans
	}
	err := tgt.Inject(ctx, string(m.Payload), m.Method, m.Enter, m.Kind == control.KindSecret)
	var r *Refusal
	switch {
	case err == nil:
	case errors.As(err, &r):
		ans.Error, ans.Refused = r.Reason, true
	default:
		ans.Error, ans.Detail = "the "+tgt.Target()+" target could not paste", err.Error()
		logf("cbb: a remote paste failed: %v", err)
	}
	return ans
}
