// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"context"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
)

// pollEvery is how often the agent looks at the change counter.
const pollEvery = 500 * time.Millisecond

// Watch adapts a pasteboard to the connector: it polls the change counter,
// and does not report the changes its own writes make.
type Watch struct {
	b *Board

	mu   sync.Mutex
	seen int64 // the change counter last reported or written
	own  int64 // the change counter after the last write, 0 if none
}

// NewWatch returns a watch of b.
func NewWatch(b *Board) *Watch { return &Watch{b: b, seen: b.ChangeCount()} }

func item(it Item) connector.Item {
	return connector.Item{Text: it.Text, Secret: it.Secret, Remote: it.Remote}
}

// Current returns what the pasteboard holds now.
func (w *Watch) Current() (connector.Item, bool, error) {
	it, ok, err := w.b.Read()
	if err != nil || !ok {
		return connector.Item{}, false, err
	}
	w.mu.Lock()
	w.seen = it.Change
	w.mu.Unlock()
	return item(it), true, nil
}

// Next waits for a change that is not the agent's own.
func (w *Watch) Next(ctx context.Context) (connector.Item, bool, error) {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return connector.Item{}, false, ctx.Err()
		case <-t.C:
		}
		change := w.b.ChangeCount()
		w.mu.Lock()
		if change == w.seen {
			w.mu.Unlock()
			continue
		}
		w.seen = change
		w.mu.Unlock()
		it, ok, err := w.b.Read()
		if err != nil {
			return connector.Item{}, false, err
		}
		w.mu.Lock()
		own := it.Change == w.own
		w.seen = it.Change
		w.mu.Unlock()
		if own {
			continue
		}
		return item(it), ok, nil
	}
}

// Write puts a text on the pasteboard.
func (w *Watch) Write(text string, secret bool) error {
	change, err := w.b.Write(text, secret)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.own, w.seen = change, change
	w.mu.Unlock()
	return nil
}

// ClearIfUnchanged empties the pasteboard if it still holds the last write.
func (w *Watch) ClearIfUnchanged() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.own != 0 && w.b.ChangeCount() == w.own {
		w.seen = w.b.Clear()
		w.own = 0
	}
	return nil
}
