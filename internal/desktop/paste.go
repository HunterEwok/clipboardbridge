// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"fmt"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
	"github.com/HunterEwok/clipboardbridge/internal/ei"
	"github.com/HunterEwok/clipboardbridge/internal/lockcheck"
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

// portalInject pastes through the clipboard and the RemoteDesktop
// portal's keyboard, on GNOME and KDE.
func portalInject(p *portal, b pasteBoard, text, method string, enter, secret bool) error {
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
	if err := p.ready(); err != nil {
		return err
	}
	err := pasteThrough(b, text, secret, func() error {
		return p.press([]ei.Key{{Code: ei.KeyLeftShift, Press: true}, {Code: ei.KeyInsert, Press: true},
			{Code: ei.KeyInsert}, {Code: ei.KeyLeftShift}})
	})
	if err == nil && enter {
		err = p.press([]ei.Key{{Code: ei.KeyEnter, Press: true}, {Code: ei.KeyEnter}})
	}
	return err
}
