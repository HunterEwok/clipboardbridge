// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
)

// recoveryWorld is a group whose root made the offline key K its recovery
// key: an admin CA for K and a recovery record naming it, no device.
func recoveryWorld(t *testing.T) *world {
	w := newWorld(t)
	w.admin("K", "root")
	k := w.adminKey("K")
	w.sign("recovery K", "root", authority.Body{Type: authority.TypeRecovery, Admin: &k}, nil)
	return w
}

// TestRecoveryKey: the recovery key may only claim the group, with the
// delay the root set for admins, and the root cancels or removes it as it
// does an admin.
func TestRecoveryKey(t *testing.T) {
	w := recoveryWorld(t)
	k := w.adminKey("K")
	s := w.evalAll(nil)
	if s.Recovery == nil || *s.Recovery != k || findDevice(s, w.ids["K"]) != nil {
		t.Fatalf("the state should name the recovery key and no device of it: %s", mustEncode(t, s))
	}

	// It admits no device and signs no settings.
	d := w.device("K", "laptop", "full", nil, nil, false)
	st := w.sign("K's settings", "K", authority.Body{Type: authority.TypeSettings, TakeoverDelayMS: ptr(int64(0))}, nil)
	s = w.evalAll(nil)
	if findDevice(s, w.ids["laptop"]) != nil || ignoredWhy(s, d.ID()) != authority.WhyPower || ignoredWhy(s, st.ID()) != authority.WhyPower {
		t.Fatalf("the recovery key should have no power but takeover: %s", mustEncode(t, s))
	}

	// Its claim waits the delay and takes effect.
	c := w.claim("K", "R2", nil)
	first := map[authority.Hash]int64{c.ID(): 0}
	w.now = authority.DefaultDelay - 1
	if s = w.evalAll(first); len(s.Roots) != 1 || claimState(s, c.ID()) != "pending" {
		t.Fatalf("the claim should wait: %s", mustEncode(t, s))
	}
	w.now = authority.DefaultDelay
	if s = w.evalAll(first); len(s.Roots) != 2 || claimState(s, c.ID()) != "effective" {
		t.Fatalf("the claim should take effect: %s", mustEncode(t, s))
	}
	// The root comes back and cancels it.
	w.sign("cancel", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{c.ID()}}, nil)
	if s = w.evalAll(first); len(s.Roots) != 1 || claimState(s, c.ID()) != "cancelled" {
		t.Fatalf("the root should cancel the claim: %s", mustEncode(t, s))
	}
}

// TestRecoveryDelay: the recovery key waits the delay of the root's
// settings, as an admin does.
func TestRecoveryDelay(t *testing.T) {
	w := newWorld(t)
	w.sign("settings", "root", authority.Body{Type: authority.TypeSettings, TakeoverDelayMS: ptr(int64(1000))}, nil)
	w.admin("K", "root")
	k := w.adminKey("K")
	w.sign("recovery K", "root", authority.Body{Type: authority.TypeRecovery, Admin: &k}, nil)
	c := w.claim("K", "R2", nil)
	first := map[authority.Hash]int64{c.ID(): 0}
	w.now = 999
	if s := w.evalAll(first); claimState(s, c.ID()) != "pending" {
		t.Fatalf("the claim should wait the root's delay: %s", mustEncode(t, s))
	}
	w.now = 1000
	if s := w.evalAll(first); len(s.Roots) != 2 {
		t.Fatalf("the claim should take effect after the root's delay: %s", mustEncode(t, s))
	}
}

// TestRecoveryRemoved: a removed recovery key leaves the state, and its
// claim does not count.
func TestRecoveryRemoved(t *testing.T) {
	w := recoveryWorld(t)
	w.sign("remove K", "root", revoke(w.adminKey("K")), nil)
	c := w.claim("K", "R2", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if s.Recovery != nil || len(s.Roots) != 1 || claimState(s, c.ID()) == "effective" {
		t.Fatalf("a removed recovery key should not take the group: %s", mustEncode(t, s))
	}
}

// TestRecoveryReplaced: a newer recovery record names another key; the
// old one can no longer claim.
func TestRecoveryReplaced(t *testing.T) {
	w := recoveryWorld(t)
	w.admin("K2", "root")
	k2 := w.adminKey("K2")
	w.sign("recovery K2", "root", authority.Body{Type: authority.TypeRecovery, Admin: &k2}, nil)
	c := w.claim("K", "R2", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if s.Recovery == nil || *s.Recovery != k2 || len(s.Roots) != 1 || ignoredWhy(s, c.ID()) != authority.WhyPower {
		t.Fatalf("only the newest recovery key should count: %s", mustEncode(t, s))
	}
}

// TestRecoveryByAdmin: an admin cannot name a recovery key.
func TestRecoveryByAdmin(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.admin("K", "root")
	k := w.adminKey("K")
	r := w.sign("recovery by A", "A", authority.Body{Type: authority.TypeRecovery, Admin: &k}, nil)
	c := w.claim("K", "R2", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if s.Recovery != nil || ignoredWhy(s, r.ID()) != authority.WhyPower || len(s.Roots) != 1 || ignoredWhy(s, c.ID()) != authority.WhyPower {
		t.Fatalf("an admin's recovery record should not count: %s", mustEncode(t, s))
	}
}
