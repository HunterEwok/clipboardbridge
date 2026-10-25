// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"testing"
	"time"
)

func TestModes(t *testing.T) {
	for _, tc := range []struct {
		mode            Mode
		sends, receives bool
	}{
		{Shared, true, true},
		{Own, false, false},
		{Receive, false, true},
		{SendOnly, true, false},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			w := newWorld()
			e := w.member(idA)
			e.SetMode(tc.mode)
			if e.Mode() != tc.mode {
				t.Fatalf("Mode() = %v", e.Mode())
			}
			ev, ok, err := e.Copied("mine", Text, Copy)
			if err != nil || ok != tc.sends {
				t.Fatalf("Copied = %v, %v; want %v", ok, err, tc.sends)
			}
			if ok && ev.Text != "mine" {
				t.Fatalf("the event has %q", ev.Text)
			}
			// What a watcher reported is the clipboard's text in every mode.
			if text, _, _, ok := e.Local(); !ok || text != "mine" {
				t.Fatalf("Local() = %q, %v", text, ok)
			}
			if cur, ok := e.Current(); ok != tc.sends || ok && cur.Text != "mine" {
				t.Fatalf("Current() = %q, %v", cur.Text, ok)
			}

			w.advance(time.Second)
			res := mustReceive(t, e, event(w, "theirs", 0, 0))
			if res.Write != tc.receives || res.Forward == nil {
				t.Fatalf("Received: Write %v, forwarded %v; want %v, true", res.Write, res.Forward != nil, tc.receives)
			}
			// The group's text is at hand in every mode.
			if cur, ok := e.Current(); !ok || cur.Text != "theirs" {
				t.Fatalf("Current() = %q, %v", cur.Text, ok)
			}
			want := "mine"
			if tc.receives {
				want = "theirs"
			}
			if text, _, _, _ := e.Local(); text != want {
				t.Fatalf("Local() = %q, want %q", text, want)
			}

			// A deliberate action makes an event and fills the clipboard in every mode.
			ev, res, err = e.Send("sent", Text, Phone)
			if err != nil || ev.Text != "sent" || !res.Write {
				t.Fatalf("Send = %q, %+v, %v", ev.Text, res, err)
			}
		})
	}
}

func TestModeSecretStaysSecret(t *testing.T) {
	w := newWorld()
	e := w.member(idA)
	e.SetMode(Own)
	if _, ok, _ := e.Copied("hunter2", Secret, Copy); ok {
		t.Fatal("own mode sent a secret")
	}
	// Offered again without its mark, it is still known as a secret.
	if !e.KnownSecret("hunter2") {
		t.Fatal("the secret is forgotten")
	}
}

func TestParseMode(t *testing.T) {
	for m := Shared; m <= SendOnly; m++ {
		if got, err := ParseMode(m.String()); err != nil || got != m {
			t.Fatalf("ParseMode(%q) = %v, %v", m, got, err)
		}
	}
	if _, err := ParseMode("everything"); err == nil {
		t.Fatal("ParseMode took an unknown mode")
	}
}
