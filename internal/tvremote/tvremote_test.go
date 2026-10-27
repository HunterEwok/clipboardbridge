// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tvremote

import (
	"context"
	"errors"
	"testing"
)

func TestState(t *testing.T) {
	dir := t.TempDir()
	st, err := Load(dir)
	if err != nil || len(st.TVs) != 0 {
		t.Fatalf("empty: %+v, %v", st, err)
	}
	if _, err := st.Find(""); err == nil {
		t.Error("Find found a TV in none")
	}
	st.Put(TV{Name: "Living room", Kind: AndroidTV, Host: "192.168.1.5", Pin: []byte{1}})
	st.TVs[0].Pastes = true
	// The same address again replaces it and keeps where pastes go.
	st.Put(TV{Name: "Lounge", Kind: AndroidTV, Host: "192.168.1.5", Pin: []byte{2}})
	st.Put(TV{Name: "Bedroom", Kind: Roku, Host: "192.168.1.6"})
	if err := Save(dir, st); err != nil {
		t.Fatal(err)
	}
	st, err = Load(dir)
	if err != nil || len(st.TVs) != 2 {
		t.Fatalf("loaded %+v, %v", st, err)
	}
	if i, err := st.Find("lounge"); err != nil || st.TVs[i].Pin[0] != 2 {
		t.Errorf("Find(lounge): %d, %v", i, err)
	}
	if _, err := st.Find(""); err == nil {
		t.Error("Find with no name took one of two")
	}
	if p, ok := st.Pasting(); !ok || p.Name != "Lounge" {
		t.Errorf("Pasting: %+v, %v", p, ok)
	}
	for range MaxTVs {
		st.Put(TV{Name: "x" + string(rune('a'+len(st.TVs))), Kind: Roku, Host: string(rune('a' + len(st.TVs)))})
	}
	if len(st.TVs) != MaxTVs {
		t.Errorf("%d TVs, at most %d", len(st.TVs), MaxTVs)
	}
}

func TestCheckHost(t *testing.T) {
	for host, ok := range map[string]bool{
		"192.168.1.5": true, " 10.0.0.2 ": true, "127.0.0.1:6467": true, "fd00::5": true,
		"8.8.8.8": false, "[2001:db8::1]:6467": false, "": false,
	} {
		_, err := CheckHost(context.Background(), host)
		if ok != (err == nil) {
			t.Errorf("CheckHost(%q): %v", host, err)
		}
		if !ok && host != "" && !errors.Is(err, ErrOutside) {
			t.Errorf("CheckHost(%q): %v, not ErrOutside", host, err)
		}
	}
}
