// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
)

// cacheBytes adds up the files in the cache.
func cacheBytes(t *testing.T, dir string) int64 {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, e := range ents {
		if i, err := e.Info(); err == nil {
			n += i.Size()
		}
	}
	return n
}

// TestLeftPartsSwept: what fetches that ended without the whole part left
// counts against twice the limit and goes contentKeep after no copy needs
// it, while what the current copy's fetch left, and what a fetch writes,
// stays.
func TestLeftPartsSwept(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := filepath.Join(t.TempDir(), contentDir)
	store, err := openContent(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	const limit = 1 << 20
	left := func(sum [sha256.Size]byte) {
		f, _, _, err := store.partial(sum)
		if err != nil {
			t.Fatal(err)
		}
		f.Write(make([]byte, limit))
		store.leave(f, sum)
		store.fetchEnded(sum)
	}
	for i := range 20 {
		left([sha256.Size]byte{byte(i)})
		store.setCurrent(nil, limit) // the next copy replaces it
		now = now.Add(time.Second)
	}
	if n := cacheBytes(t, dir); n > 2*limit {
		t.Errorf("%d bytes of left parts held, over twice the limit", n)
	}

	// One of the current copy stays, one a fetch writes too.
	cur := [sha256.Size]byte{0xc0}
	left(cur)
	store.setCurrent(&clip.Manifest{Size: limit, Parts: []clip.Part{{SHA256: cur[:], Size: limit}}}, limit)
	busy := [sha256.Size]byte{0xb0}
	f, _, _, err := store.partial(busy)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(make([]byte, limit))
	now = now.Add(time.Hour)
	store.sweep(limit)
	for _, sum := range [][sha256.Size]byte{cur, busy} {
		if _, err := os.Stat(store.path(sum) + ".part"); err != nil {
			t.Errorf("the part %x: %v", sum[:1], err)
		}
	}
	if n := cacheBytes(t, dir); n != 2*limit {
		t.Errorf("%d bytes held after an hour, want the current copy's and the fetch's", n)
	}
}
