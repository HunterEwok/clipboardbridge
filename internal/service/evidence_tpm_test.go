// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tpmkey"
	"github.com/HunterEwok/clipboardbridge/internal/tpmkey/tpmtest"
)

// TestTPMEvidence checks that a computer whose member key is in a TPM with
// an EK certificate proves it to the group's root: the root records the
// key as hardware from the hello, then as proven once the TPM opened the
// root's credential. Without the maker's certificate it stays hardware.
func TestTPMEvidence(t *testing.T) {
	tpmtest.Start(t)
	roots := tpmtest.ProvisionEK(t)
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	tpmRoots = roots
	t.Cleanup(func() { tpmRoots = nil })

	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	id, err := group.Load(deck.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := id.Key.(*tpmkey.Key); !ok {
		t.Fatal("the deck's member key is not in the TPM")
	}
	store := func(s *testService, name string) string {
		for _, d := range s.devices(t) {
			if d.Name == name {
				return d.Store
			}
		}
		return ""
	}
	waitFor(t, "the root records the deck's key as proven", func() bool { return store(pi, "deck") == group.StoreProven })
}

// TestTPMEvidenceUnknownMaker checks that a TPM whose maker the root does
// not know leaves the key as hardware.
func TestTPMEvidenceUnknownMaker(t *testing.T) {
	tpmtest.Start(t)
	tpmtest.ProvisionEK(t)
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	tpmRoots = tpmtest.OtherRoots(t)
	t.Cleanup(func() { tpmRoots = nil })

	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	if id, err := group.Load(deck.dir); err != nil {
		t.Fatal(err)
	} else if _, ok := id.Key.(*tpmkey.Key); !ok {
		t.Fatal("the deck's member key is not in the TPM")
	}
	waitFor(t, "deck is listed as hardware", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "deck" {
				return d.Store == group.StoreHardware
			}
		}
		return false
	})
}
