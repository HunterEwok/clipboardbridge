// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/ei"
	"github.com/HunterEwok/clipboardbridge/internal/lockcheck"
	"github.com/HunterEwok/clipboardbridge/internal/uinput"
)

// pasteBoard is the clipboard a paste goes through.
type pasteBoard interface {
	Current() (connector.Item, bool, error)
	Write(text string, secret bool) error
	ClearIfUnchanged() error
	// holds reports whether the clipboard still holds text from this
	// board's own write.
	holds(text string) bool
}

// pasteThrough puts text into the clipboard, lets press press the paste
// keys, and gives the clipboard back what it held, after restoreAfter,
// unless the user copied meanwhile. A secret leaves no copy behind.
func pasteThrough(b pasteBoard, text string, secret bool, press func() error) error {
	prev, had, _ := b.Current()
	if err := b.Write(text, secret); err != nil {
		return err
	}
	err := press()
	time.Sleep(restoreAfter)
	switch {
	case !b.holds(text): // the user copied meanwhile
	case had:
		if werr := b.Write(prev.Text, prev.Secret); werr != nil && err == nil {
			err = werr
		}
	default:
		if cerr := b.ClearIfUnchanged(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// keyboard presses a paste's keys where the board's own way cannot: the
// RemoteDesktop portal, or the uinput helper.
type keyboard interface {
	// ready returns once the keys can be pressed, or why not.
	ready() error
	paste() error // Shift+Insert
	enter() error
}

// keysInject pastes through the clipboard and kb, on GNOME and KDE and
// where the user installed the uinput helper.
func keysInject(kb keyboard, b pasteBoard, text, method string, enter, secret bool) error {
	switch method {
	case "paste":
	case "type":
		return &connector.Refusal{Reason: "on this desktop remote paste pastes but does not type key by key; send it as a paste"}
	default:
		return &connector.Refusal{Reason: fmt.Sprintf("this desktop pastes, not %q", method)}
	}
	if why := lockcheck.Reason(); why != "" {
		return &connector.Refusal{Reason: why}
	}
	if err := kb.ready(); err != nil {
		return err
	}
	err := pasteThrough(b, text, secret, kb.paste)
	if err == nil && enter {
		err = kb.enter()
	}
	return err
}

func (p *portal) paste() error {
	return p.press([]ei.Key{{Code: ei.KeyLeftShift, Press: true}, {Code: ei.KeyInsert, Press: true},
		{Code: ei.KeyInsert}, {Code: ei.KeyLeftShift}})
}

func (p *portal) enter() error {
	return p.press([]ei.Key{{Code: ei.KeyEnter, Press: true}, {Code: ei.KeyEnter}})
}

// pasteKeys returns the way to press a paste's keys where the session
// offers no protocol for it: the uinput helper when the user installed it,
// since they chose it and it asks nothing on the screen, else the
// RemoteDesktop portal; nil when neither is there.
func pasteKeys(logf func(string, ...any)) keyboard {
	if k := newKeysHelper(); k != nil {
		return k
	}
	if p := newPortal(logf); p != nil {
		return p
	}
	return nil
}

func closeKeys(k keyboard) {
	if p, ok := k.(*portal); ok {
		p.close()
	}
}

// keysHelper is the uinput helper (internal/uinput), which presses the
// keys for the user of the active session.
type keysHelper struct{ socket string }

// newKeysHelper returns the helper when install.sh --uinput installed it,
// or nil.
func newKeysHelper() keyboard {
	if _, err := os.Stat(uinput.Socket); err != nil {
		return nil
	}
	return keysHelper{socket: uinput.Socket}
}

func (k keysHelper) ready() error { return nil }
func (k keysHelper) paste() error { return k.ask("paste") }
func (k keysHelper) enter() error { return k.ask("enter") }

func (k keysHelper) ask(req string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return uinput.Ask(ctx, k.socket, req)
}
