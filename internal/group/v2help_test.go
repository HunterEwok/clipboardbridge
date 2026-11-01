// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
)

// heads keeps, for each signer of the tests, the record it signed last
// and the group of it, so that the records a test signs one after another
// form the chains of version 2 (docs/records-v2.md, "Chains and numbers").
var heads = struct {
	sync.Mutex
	m     map[KeyHash]authority.Head
	group map[KeyHash]string
}{m: map[KeyHash]authority.Head{}, group: map[KeyHash]string{}}

// signRecord signs body as the next record of key for the tests: seq and
// prev follow the key's last test record, and a removal, freeze or claim
// saw every record signed for its group until now. adminCA, if any, is the
// first of chain.
func signRecord(body RecordBody, key crypto.Signer, chain ...*x509.Certificate) (Record, error) {
	signer, err := authority.PublicKeyHash(key.Public())
	if err != nil {
		return Record{}, err
	}
	heads.Lock()
	defer heads.Unlock()
	h := heads.m[signer]
	body.Seq = h.Seq + 1
	if h.Seq > 0 {
		prev := h.ID
		body.Prev = &prev
	}
	switch body.Type {
	case RecordRevoke, RecordFreeze, RecordClaim:
		if body.Seen == nil {
			body.Seen = []authority.Seen{{Key: signer, Seq: h.Seq}}
			for k, o := range heads.m {
				if k != signer && heads.group[k] == body.Group {
					body.Seen = append(body.Seen, authority.Seen{Key: k, Seq: o.Seq})
				}
			}
		}
	}
	var adminCA *x509.Certificate
	if len(chain) > 0 {
		adminCA = chain[0]
	}
	r, err := authority.Sign(body, key, adminCA)
	if err != nil {
		return Record{}, err
	}
	heads.m[signer] = authority.Head{Key: signer, Seq: body.Seq, ID: r.ID()}
	heads.group[signer] = body.Group
	return r, nil
}

// v2Case is a case of testdata/interop/v2-records.json.
type v2Case struct {
	Name        string   `json:"name"`
	GroupCA     []byte   `json:"group_ca"`
	Group       string   `json:"group"`
	NowMS       int64    `json:"now_ms"`
	TimeUnknown bool     `json:"time_unknown"`
	Records     []Record `json:"records"`
	FirstSeen   []struct {
		Record KeyHash `json:"record"`
		MS     int64   `json:"ms"`
	} `json:"first_seen"`
	State string `json:"state"`
}

// checkV2Cases checks that a Records set given each case of
// testdata/interop/v2-records.json whose name starts with one of prefixes
// says the case's state, byte for byte: the set's own checks take every
// record of the vectors, and its state is the one rule's (internal/core).
// A case where the member does not know the time is for the core's tests.
func checkV2Cases(t *testing.T, prefixes ...string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "v2-records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []v2Case `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range f.Cases {
		if c.TimeUnknown || !slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(c.Name, p) }) {
			continue
		}
		n++
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		s := NewRecords(ca)
		s.tag = c.Group
		s.SetClock(func() time.Time { return time.UnixMilli(c.NowMS) })
		// The set leaves out a record that does not verify or is of
		// another group, which the state of the whole input lists as
		// ignored.
		refused := map[string]bool{}
		for _, r := range c.Records {
			if _, err := s.Add(r); err != nil {
				refused[r.ID().String()] = true
			}
		}
		clear(s.firstSeen)
		for _, fs := range c.FirstSeen {
			s.firstSeen[fs.Record] = fs.MS
		}
		s.st = nil
		got, err := s.State().Encode()
		if err != nil {
			t.Fatal(err)
		}
		var gotV, wantV map[string]any
		if json.Unmarshal(got, &gotV) != nil || json.Unmarshal([]byte(c.State), &wantV) != nil {
			t.Fatalf("%s: a state does not read", c.Name)
		}
		if ig, ok := wantV["ignored"].([]any); ok && len(refused) > 0 {
			ig = slices.DeleteFunc(ig, func(e any) bool {
				m, _ := e.(map[string]any)
				id, _ := m["record"].(string)
				return refused[id]
			})
			if len(ig) == 0 {
				delete(wantV, "ignored")
			} else {
				wantV["ignored"] = ig
			}
		}
		if !reflect.DeepEqual(gotV, wantV) || len(refused) == 0 && string(got) != c.State {
			t.Errorf("%s:\n got %s\nwant %s", c.Name, got, c.State)
		}
	}
	if n == 0 {
		t.Fatalf("no case starts with %q", prefixes)
	}
}

// computerPowers are the powers the root gives an admin computer, takeover
// among them when the root is a computer (docs/records-v2.md, "Who signs
// what").
func computerPowers(takeover bool) []string {
	p := []string{authority.PowerAdmit, authority.PowerFreeze, authority.PowerHub, authority.PowerRemove, authority.PowerRenew}
	if takeover {
		p = append(p, authority.PowerTakeover)
	}
	return p
}

// claimRecord is an admin's claim to take the group over with root.
func claimRecord(t *testing.T, group *x509.Certificate, signer *CA, chain []*x509.Certificate, root *x509.Certificate) Record {
	t.Helper()
	r, err := signRecord(RecordBody{Type: RecordClaim, Group: Tag(group), TimeMS: nextTime(), Root: root.Raw}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// afterDelay returns a clock past the default takeover delay.
func afterDelay() time.Time {
	return time.Now().Add(time.Duration(authority.DefaultDelay+1000) * time.Millisecond)
}

// writeV2Vectors writes v as testdata/interop/name with -update: the
// vectors in records v:2 that the phone kits read once they ask the core.
func writeV2Vectors(t *testing.T, name string, v any) {
	t.Helper()
	if !*update {
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("..", "..", "testdata", "interop", name), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// checkV1Refused checks that a set refuses every record of version 1 in the
// interop file name, which the phone kits read until they move to the core:
// there is no migration, and a member that holds records of version 1
// refuses them (docs/records-v2.md).
func checkV1Refused(t *testing.T, name string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", name))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var recs []Record
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if _, ok := v["body"]; ok {
				if _, ok := v["sig"]; ok {
					b, _ := json.Marshal(v)
					var r Record
					if json.Unmarshal(b, &r) == nil {
						recs = append(recs, r)
						return
					}
				}
			}
			for _, e := range v {
				walk(e)
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(doc)
	if len(recs) == 0 {
		t.Fatalf("%s holds no records", name)
	}
	var ca *x509.Certificate
	if m, ok := doc.(map[string]any); ok {
		if s, ok := m["group_ca"].(string); ok {
			var der []byte
			if json.Unmarshal([]byte(`"`+s+`"`), &der) == nil {
				ca, _ = x509.ParseCertificate(der)
			}
		}
	}
	if ca == nil {
		g, err := NewRootCA(t0)
		if err != nil {
			t.Fatal(err)
		}
		ca = g.Cert
	}
	s := NewRecords(ca)
	for i, r := range recs {
		if ok, err := s.Add(r); ok || err == nil {
			t.Errorf("%s: the set took record %d of version 1", name, i)
		}
	}
}
