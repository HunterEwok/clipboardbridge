// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/remotepaste"
)

func TestRemotePaste(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	paste := func(text string, h control.Header) error {
		h.Op, h.Device = control.OpPasteOn, "deck"
		_, err := pi.do(t, h, text)
		return err
	}
	wantRefused := func(what, text string, h control.Header, reason string) {
		t.Helper()
		if err := paste(text, h); err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v, want %q", what, err, reason)
		}
	}
	wantRefused("off", "ls", control.Header{}, "remote paste is off on this device")
	if _, err := pi.do(t, control.Header{Op: control.OpReceive, Name: "on", Device: "deck"}, ""); err == nil {
		t.Error("an admin turned remote paste on on another device")
	}
	if m, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil || m.Status.Paste == nil || !m.Status.Paste.On {
		t.Fatalf("paste-receive on: %+v, %v", m, err)
	}
	wantRefused("no target", "ls", control.Header{}, "nothing on this device can paste")

	// A desktop connector on deck offers to paste.
	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetDesktop}}); err != nil {
		t.Fatal(err)
	}
	got := make(chan *control.Message, 4)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op != control.OpInject {
				continue
			}
			got <- m
			ans := control.Header{Op: control.OpInjected, Seq: m.Seq}
			if strings.Contains(string(m.Payload), "locked") {
				ans.Error, ans.Refused = "the session is locked", true
			}
			w.Send(&control.Message{Header: ans})
		}
	}()
	waitFor(t, "deck offers the desktop", func() bool {
		p := deck.status(t).Paste
		return p != nil && len(p.Targets) == 1 && p.Targets[0] == targetDesktop
	})
	time.Sleep(time.Second) // the paste without a target counted
	if err := paste("echo \x1b[31mhi\x1b[0m\r\n", control.Header{Method: "type"}); err != nil {
		t.Fatal(err)
	}
	m := <-got
	if string(m.Payload) != "echo hi\n" || m.Method != "type" || m.Enter {
		t.Errorf("the desktop got %q %+v", m.Payload, m.Header)
	}
	time.Sleep(time.Second) // one paste a second from one sender
	wantRefused("enter", "ls", control.Header{Enter: true}, "without Enter only")
	time.Sleep(time.Second)
	wantRefused("locked", "locked", control.Header{}, "the session is locked")
	<-got
	if wantRefused("too fast", "ls", control.Header{}, "too many pastes"); len(got) != 0 {
		t.Error("a paste too fast reached the desktop")
	}
	time.Sleep(time.Second)
	if err := paste("hunter2", control.Header{Kind: control.KindSecret}); err != nil {
		t.Fatal(err)
	}
	if m := <-got; m.Kind != control.KindSecret {
		t.Errorf("a secret came as %q", m.Kind)
	}

	// The log keeps who and how, never the text, and no secret.
	log, err := remotepaste.ReadLog(deck.dir)
	if err != nil || len(log) != 6 {
		t.Fatalf("the log: %d entries, %v", len(log), err)
	}
	for _, e := range log {
		if e.Name != "pi" && e.Name != "" {
			t.Errorf("an entry names %q", e.Name)
		}
	}
	if e := log[2]; e.Result != "done" || e.Len != len("echo hi\n") || e.Method != "type" {
		t.Errorf("the paste's entry: %+v", e)
	}

	// Any admin turns it off.
	if _, err := pi.do(t, control.Header{Op: control.OpReceive, Name: "off", Device: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	if p := deck.status(t).Paste; p == nil || p.On {
		t.Errorf("after paste-off: %+v", p)
	}
	time.Sleep(time.Second)
	wantRefused("off again", "ls", control.Header{}, "remote paste is off")
	// A member that is not an admin sends none.
	if _, err := deck.do(t, control.Header{Op: control.OpPasteOn, Device: "pi"}, "ls"); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("deck pasted on pi: %v", err)
	}
}
