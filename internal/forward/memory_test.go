// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// fakeRecords returns n records of about size bytes each; the memory does
// not check them, authority did.
func fakeRecords(n, size int) []group.Record {
	rs := make([]group.Record, n)
	for i := range rs {
		b := make([]byte, size)
		rand.Read(b)
		rs[i] = group.Record{Body: b, Sig: []byte{1}}
	}
	return rs
}

// noSource is where the records the tests keep came from.
var noSource = netip.MustParseAddr("192.0.2.1")

// total returns the groups, records and bytes the memory keeps.
func (m *memory) total() (groups, records, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.groups {
		records += len(g.recs)
	}
	return len(m.groups), records, m.bytes
}

// TestMemoryBoundsGroupAndTotal checks that what the forwarder remembers of
// groups that are not registered has a size limit for each group and for
// all, and that the group kept least recently goes first.
func TestMemoryBoundsGroupAndTotal(t *testing.T) {
	m := newMemory(nil)
	m.keep("big", noSource, fakeRecords(100, 8<<10)) // 800 KiB offered
	if _, _, n := m.total(); n > rememberedGroupBytes {
		t.Errorf("one group keeps %d bytes, limit %d", n, rememberedGroupBytes)
	}
	if len(m.records("big")) == 0 {
		t.Error("a group that offered too much keeps nothing")
	}
	for i := 0; i < 1000; i++ {
		m.keep(fmt.Sprintf("g%d", i), noSource, fakeRecords(20, 6<<10))
		if _, _, n := m.total(); n > rememberedBytes {
			t.Fatalf("after %d groups the memory keeps %d bytes, limit %d", i+1, n, rememberedBytes)
		}
	}
	if len(m.records("big")) != 0 || len(m.records("g0")) != 0 {
		t.Error("the groups kept least recently are still there")
	}
	if len(m.records("g999")) == 0 {
		t.Error("the group kept last is gone")
	}
}

// TestMemoryKeepsRegisteredGroups checks that records of a group that is
// registered now are not forgotten however many groups come after it.
func TestMemoryKeepsRegisteredGroups(t *testing.T) {
	m := newMemory(func(tag string) bool { return tag == "mine" })
	m.keep("mine", noSource, fakeRecords(3, 200))
	for i := 0; i < 1000; i++ {
		m.keep(fmt.Sprintf("g%d", i), noSource, fakeRecords(20, 6<<10))
	}
	if n := len(m.records("mine")); n != 3 {
		t.Errorf("a registered group keeps %d records, want 3", n)
	}
}

// TestMemoryMergesByID checks that a group that registers again keeps its
// records once, and the earlier ones next to the new.
func TestMemoryMergesByID(t *testing.T) {
	m := newMemory(nil)
	a, b, c := fakeRecords(1, 100), fakeRecords(1, 100), fakeRecords(1, 100)
	m.keep("g", noSource, append(append([]group.Record{}, a...), b...))
	m.keep("g", noSource, append(append([]group.Record{}, b...), c...))
	if g, r, _ := m.total(); g != 1 || r != 3 {
		t.Errorf("%d groups, %d records, want 1 and 3", g, r)
	}
}

// TestMemoryKeepIsLinear checks that taking in many records of one group,
// again and again, does not take time in proportion to their square.
func TestMemoryKeepIsLinear(t *testing.T) {
	m := newMemory(nil)
	rs := fakeRecords(15, 8<<10)
	start := time.Now()
	for i := 0; i < 2000; i++ {
		m.keep("g", noSource, rs)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("2000 registrations with known records took %v", d)
	}
}

// TestRegistrationKeepsBoundedRecords checks that a group whose authority
// records come to more than the forwarder keeps for one group is refused
// and leaves nothing behind, and that one within the bound is kept.
func TestRegistrationKeepsBoundedRecords(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	register := func(records, keys int) (string, string) {
		cert, tag, ca := member(t)
		var recs []group.Record
		for i := 0; i < records; i++ {
			var hs []group.KeyHash
			for k := 0; k < keys; k++ {
				var h group.KeyHash
				rand.Read(h[:])
				hs = append(hs, h)
			}
			r, err := group.SignRecord(group.RecordBody{Type: group.RecordRevoke, Group: tag, TimeMS: time.Now().UnixMilli(), Keys: hs}, ca.Key)
			if err != nil {
				t.Fatal(err)
			}
			recs = append(recs, r)
		}
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return tag, rawRegister(t, f, pin, cert, k.PublicKey().Bytes(), k, hubAuth{key: ca.Key, records: recs}).Error
	}
	tag, msg := register(100, 110) // about 700 KiB
	if !strings.Contains(msg, "too large") {
		t.Errorf("a group with too many records registered: %q", msg)
	}
	if n := len(f.memory.records(tag)); n != 0 {
		t.Errorf("a refused group left %d records", n)
	}
	tag, msg = register(5, 10)
	if msg != "" {
		t.Fatalf("a group with a few records: %s", msg)
	}
	if n := len(f.memory.records(tag)); n != 5 {
		t.Errorf("the forwarder keeps %d records of the group, want 5", n)
	}
}
