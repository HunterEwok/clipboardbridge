// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package remotepaste

import (
	"fmt"
	"testing"
	"time"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"ls -l\n":                  "ls -l\n",
		"a\tb\r\nc\rd":             "a\tb\nc\nd",
		"Grüße, 世界 🙂":              "Grüße, 世界 🙂",
		"red \x1b[31mtext\x1b[0m":  "red text",
		"title \x1b]0;pwned\x07ok": "title ok",
		"osc \x1b]8;;x\x1b\\link":  "osc link",
		"csi \u009b2Jclear":        "csi clear",
		"bell\x07 nul\x00 del\x7f": "bell nul del",
		"bad \xff\xfe utf8":        "bad  utf8",
		"esc at the end \x1b":      "esc at the end ",
		"keypad \x1b=on":           "keypad on",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLimiter(t *testing.T) {
	var l Limiter
	now := time.Unix(1_761_400_000, 0)
	if !l.Allow("a", now) || l.Allow("a", now.Add(500*time.Millisecond)) {
		t.Fatal("not one a second")
	}
	if !l.Allow("b", now) {
		t.Error("another sender waits for the first")
	}
	for i := 1; i < Burst; i++ {
		if !l.Allow("a", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("paste %d refused", i+1)
		}
	}
	if l.Allow("a", now.Add(Burst*time.Second)) {
		t.Error("more than the burst in a minute")
	}
	if !l.Allow("a", now.Add(61*time.Second)) {
		t.Error("refused after a minute")
	}
}

func TestSettingsAndLog(t *testing.T) {
	dir := t.TempDir()
	if s, err := Load(dir); err != nil || s.On {
		t.Fatalf("a new device: %+v, %v", s, err)
	}
	if err := Save(dir, Settings{On: true, Enter: true}); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(dir); !s.On || !s.Enter || s.Console {
		t.Errorf("saved: %+v", s)
	}
	if err := Save(dir, Settings{On: true, NoLockCheck: true}); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(dir); !s.On || !s.NoLockCheck || s.Enter {
		t.Errorf("saved without the lock check: %+v", s)
	}
	Save(dir, Settings{Enter: true, NoLockCheck: true})
	if s, _ := Load(dir); s.Enter || s.NoLockCheck {
		t.Error("a switch stays on when remote paste is off")
	}
	for i := range LogSize + 5 {
		if err := Append(dir, Entry{TimeMS: int64(i), By: fmt.Sprint(i), Len: i, Method: "paste", Result: "done"}); err != nil {
			t.Fatal(err)
		}
	}
	es, err := ReadLog(dir)
	if err != nil || len(es) != LogSize || es[0].TimeMS != 5 {
		t.Errorf("the log: %d entries from %d, %v", len(es), es[0].TimeMS, err)
	}
}
