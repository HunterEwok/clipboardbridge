// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// What the forwarder keeps of the groups that are not registered now. A
// group's authority records are a few kilobytes (a handful of roots, admins
// and removals); the bounds leave a genuine group room to spare and stop a
// group nobody knows from filling the forwarder's memory.
const (
	// rememberedGroups bounds the groups whose records, or credential
	// versions, the forwarder keeps after their registration ends; past it
	// the group kept least recently is forgotten first.
	rememberedGroups = 100_000
	// rememberedGroupBytes bounds the records kept for one group: a
	// registration whose authority records come to more is refused, so
	// that none of them is left out.
	rememberedGroupBytes = 256 << 10
	// rememberedBytes bounds the records kept for all groups that are not
	// registered now; past it the group kept least recently is forgotten
	// first.
	rememberedBytes = 32 << 20
)

// memory keeps in memory, for each group that registered with records (a
// hub from before the credentials, docs/protocol.md, section 13), its
// authority records (group.Records.AuthorityRecords: revocations, freezes,
// thaws, roots and the root's own device records, which make phones admins
// or not). A hub that the group removed, or an admin it demoted, could
// otherwise register again while the group's own hub is away, with the
// records from before. Nothing of them is written to disk: a group that
// registers with a credential needs none of them (versions).
//
// The records of a group that is registered now are never forgotten; the
// others are bounded in count and in bytes, per group and in all.
type memory struct {
	mu     sync.Mutex
	live   func(tag string) bool // whether the group is registered now; nil: none is
	groups map[string]*kept
	order  *list.List // of *kept, the group kept least recently first
	bytes  int        // the size of every group's records
}

// kept is one group's records.
type kept struct {
	tag   string
	recs  []group.Record
	ids   map[[sha256.Size]byte]struct{}
	bytes int
	elem  *list.Element
}

func newMemory(live func(tag string) bool) *memory {
	return &memory{live: live, groups: map[string]*kept{}, order: list.New()}
}

// recordBytes is what a record costs in memory, about.
func recordBytes(r group.Record) int {
	n := len(r.Body) + len(r.Sig) + 64
	for _, c := range r.Chain {
		n += len(c)
	}
	return n
}

// fits reports whether the forwarder can keep records for one group.
func fits(records []group.Record) bool {
	n := 0
	for _, r := range records {
		n += recordBytes(r)
	}
	return n <= rememberedGroupBytes
}

// records returns what the forwarder knows of the group's authority.
func (m *memory) records(tag string) []group.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g := m.groups[tag]; g != nil {
		return slices.Clone(g.recs)
	}
	return nil
}

// keep remembers the group's authority records, checked ones only: what
// authority returned, which fits. Records the group already has are not
// looked at again; a record that would take the group past its bound,
// which only a registration of the group at the same time can bring, is
// left out.
func (m *memory) keep(tag string, records []group.Record) {
	// Each new record is hashed once, outside the lock.
	ids := make([][sha256.Size]byte, len(records))
	for i, r := range records {
		ids[i] = r.ID()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[tag]
	if g == nil {
		g = &kept{tag: tag, ids: map[[sha256.Size]byte]struct{}{}}
		g.elem = m.order.PushBack(g)
		m.groups[tag] = g
	} else {
		m.order.MoveToBack(g.elem)
	}
	for i, r := range records {
		// Another registration of the group may have kept records meanwhile.
		if _, ok := g.ids[ids[i]]; ok {
			continue
		}
		n := recordBytes(r)
		if g.bytes+n > rememberedGroupBytes {
			continue
		}
		g.ids[ids[i]] = struct{}{}
		g.recs = append(g.recs, r)
		g.bytes += n
		m.bytes += n
	}
	// Forget the groups kept least recently, but never one that is
	// registered now.
	for e := m.order.Front(); e != nil && (len(m.groups) > rememberedGroups || m.bytes > rememberedBytes); {
		next := e.Next()
		if o := e.Value.(*kept); o != g && (m.live == nil || !m.live(o.tag)) {
			m.order.Remove(e)
			delete(m.groups, o.tag)
			m.bytes -= o.bytes
		}
		e = next
	}
}

// RemoveGroupFiles deletes the files that earlier versions kept in dir, one
// for each group that registered, with its roots and removals, and then dir
// itself when nothing else is left in it. It returns how many it deleted.
func RemoveGroupFiles(dir string) (int, error) {
	es, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range es {
		name := e.Name()
		tag, ok := strings.CutSuffix(strings.TrimSuffix(name, ".tmp"), ".json")
		if !ok || !validTag(tag) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return n, err
		}
		n++
	}
	os.Remove(dir) // only when it is empty
	return n, nil
}

// validTag reports whether tag is a group tag, 16 lowercase hex digits.
func validTag(tag string) bool {
	if len(tag) != 16 {
		return false
	}
	_, err := hex.DecodeString(tag)
	return err == nil && tag == strings.ToLower(tag)
}
