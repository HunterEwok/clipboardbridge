// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/seal"
)

// TestSealKeysRecorded: each computer makes its key for sealed messages
// and offers it in its hello, and the root puts it in the device records,
// its own included, which every member then holds.
func TestSealKeysRecorded(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	want := map[string][]byte{}
	for _, s := range []*testService{pi, deck} {
		secret, err := group.LoadSealSecret(s.dir)
		if err != nil {
			t.Fatal(err)
		}
		if want[s.name], err = seal.PublicKey(secret); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*testService{pi, deck} {
		waitFor(t, s.name+" holds both keys", func() bool {
			id, err := group.Load(s.dir)
			if err != nil {
				return false
			}
			recs, err := group.LoadRecords(s.dir, id.GroupCA.Cert)
			if err != nil {
				return false
			}
			n := 0
			for _, d := range recs.Devices() {
				if bytes.Equal(d.Seal, want[d.Name]) {
					n++
				}
			}
			return n == 2
		})
	}
	// The secret stays: loading it again gives the same key.
	again, err := group.LoadSealSecret(deck.dir)
	if err != nil {
		t.Fatal(err)
	}
	if pub, _ := seal.PublicKey(again); !bytes.Equal(pub, want["deck"]) {
		t.Error("the deck's key changed")
	}
}
