// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipbridge/internal/clip"
	"github.com/HunterEwok/clipbridge/internal/group"
)

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) *group.CA {
	t.Helper()
	id, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	return id.PhoneCA
}

func TestToken(t *testing.T) {
	ca := newCA(t)
	tok, id, err := NewToken(ca)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "cb1.") || len(id) != 32 {
		t.Errorf("token %q, id %q", tok, id)
	}
	if got, err := CheckToken(ca, tok); err != nil || got != id {
		t.Errorf("CheckToken = %q, %v; want %q", got, err, id)
	}
	tok2, id2, _ := NewToken(ca)
	if tok2 == tok || id2 == id {
		t.Error("two tokens are the same")
	}
	// Another group's CA, a changed token, or junk are refused.
	if _, err := CheckToken(newCA(t), tok); err == nil {
		t.Error("another group accepted the token")
	}
	flipped := []byte(tok)
	flipped[len(flipped)-2] ^= 1
	for _, bad := range []string{string(flipped), "", "cb1.", "cb1.!!!", "cb2." + tok[4:], tok + "AA", "Bearer " + tok} {
		if _, err := CheckToken(ca, bad); err == nil {
			t.Errorf("CheckToken(%q) succeeded", bad)
		}
	}
	// A member without the CA key cannot check or issue.
	if _, _, err := NewToken(&group.CA{Cert: ca.Cert}); err == nil {
		t.Error("issued a token without the CA key")
	}
}

// fakeGroup is the member as the iPhone endpoint sees it.
type fakeGroup struct {
	ca    *group.CA
	cur   clip.Event
	has   bool
	local string
	kind  clip.Kind
	age   time.Duration
	sent  []string
}

func (g *fakeGroup) Current() (clip.Event, bool) { return g.cur, g.has }
func (g *fakeGroup) Local() (string, clip.Kind, time.Duration, bool) {
	return g.local, g.kind, g.age, g.local != ""
}
func (g *fakeGroup) Send(text string, kind clip.Kind, via clip.Via) error {
	if via != clip.Phone {
		panic("the iPhone button sends with via Phone")
	}
	g.sent = append(g.sent, text)
	g.local, g.kind, g.age = text, kind, 0
	return nil
}
func (g *fakeGroup) PhoneCA() *group.CA { return g.ca }

func doSync(t *testing.T, g *fakeGroup, token, body string) syncReply {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	SyncHandler(g).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var rep syncReply
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("reply %q: %v", rec.Body, err)
	}
	return rep
}

func body(text string) string {
	b, _ := json.Marshal(syncRequest{V: 1, Text: text})
	return string(b)
}

func TestSyncDirections(t *testing.T) {
	ca := newCA(t)
	tok, _, _ := NewToken(ca)
	computerCopy := func(text string, age time.Duration, via clip.Via) clip.Event {
		return clip.Event{Text: text, Via: via, Kind: clip.Text, Age: age.Milliseconds()}
	}
	tests := []struct {
		name  string
		g     fakeGroup
		phone string
		dir   string
		copy  string
		sent  bool
	}{
		{name: "a computer copied a moment ago", g: fakeGroup{cur: computerCopy("from the Mac", 5*time.Second, clip.Copy), has: true, local: "from the Mac"},
			phone: "old phone text", dir: "to_iphone", copy: "from the Mac"},
		{name: "a computer copied long ago, the phone has something new", g: fakeGroup{cur: computerCopy("old", time.Minute, clip.Copy), has: true, local: "old"},
			phone: "new on the phone", dir: "from_iphone", sent: true},
		{name: "the recent text came from the phone itself", g: fakeGroup{cur: computerCopy("from the phone", 2*time.Second, clip.Universal), has: true, local: "from the phone"},
			phone: "newer on the phone", dir: "from_iphone", sent: true},
		{name: "the phone already has the computer's copy", g: fakeGroup{cur: computerCopy("same", 2*time.Second, clip.Copy), has: true, local: "same"},
			phone: "same", dir: "none"},
		{name: "the member's own clipboard holds another text", g: fakeGroup{cur: computerCopy("group text", time.Minute, clip.Copy), has: true, local: "own text"},
			phone: "group text", dir: "to_iphone", copy: "own text"},
		{name: "nothing anywhere", g: fakeGroup{}, phone: "", dir: "none"},
		{name: "a first copy into an empty group", g: fakeGroup{}, phone: "first", dir: "from_iphone", sent: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := tt.g
			g.ca = ca
			rep := doSync(t, &g, tok, body(tt.phone))
			if rep.Direction != tt.dir || rep.Copy != tt.copy || (len(g.sent) > 0) != tt.sent || rep.V != 1 {
				t.Errorf("reply %+v, sent %v", rep, g.sent)
			}
		})
	}
}

func TestSyncSecret(t *testing.T) {
	ca := newCA(t)
	tok, _, _ := NewToken(ca)
	g := &fakeGroup{ca: ca, cur: clip.Event{Text: "hunter2", Kind: clip.Secret, Via: clip.Copy, Age: 15_000}, has: true,
		local: "hunter2", kind: clip.Secret, age: 15 * time.Second}
	rep := doSync(t, g, tok, body("x"))
	if rep.Direction != "to_iphone" || rep.Copy != "hunter2" || rep.ExpiresIn < 40 || rep.ExpiresIn > 46 {
		t.Errorf("reply %+v", rep)
	}
	if strings.Contains(rep.Message, "hunter2") {
		t.Error("the secret appears in the message")
	}
	// A secret from the phone becomes a secret event.
	g = &fakeGroup{ca: ca}
	b, _ := json.Marshal(syncRequest{V: 1, Text: "otp 123456", Secret: true})
	if rep := doSync(t, g, tok, string(b)); rep.Direction != "from_iphone" || g.kind != clip.Secret {
		t.Errorf("reply %+v, kind %v", rep, g.kind)
	}
}

func TestSyncErrors(t *testing.T) {
	ca := newCA(t)
	tok, _, _ := NewToken(ca)
	otherTok, _, _ := NewToken(newCA(t))
	g := &fakeGroup{ca: ca}
	for name, tt := range map[string]struct{ token, body string }{
		"no token":        {"", body("x")},
		"another group":   {otherTok, body("x")},
		"bad JSON":        {tok, "{"},
		"another version": {tok, `{"v":2,"text":"x"}`},
		"too large":       {tok, `{"v":1,"text":"` + strings.Repeat("x", maxBody) + `"}`},
	} {
		t.Run(name, func(t *testing.T) {
			rep := doSync(t, g, tt.token, tt.body)
			if rep.Direction != "error" || rep.Message == "" {
				t.Errorf("reply %+v", rep)
			}
		})
	}
	if len(g.sent) != 0 {
		t.Error("a bad request sent a text")
	}
	// GET is refused too, still with 200 and JSON.
	req := httptest.NewRequest(http.MethodGet, "/sync", nil)
	rec := httptest.NewRecorder()
	SyncHandler(g).ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte(`"error"`)) {
		t.Errorf("GET: %d %s", rec.Code, rec.Body)
	}
}
