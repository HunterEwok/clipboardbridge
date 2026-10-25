// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"cmp"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// rememberedGroups bounds the groups whose records the forwarder keeps
// after their registration ends; past it the group that registered least
// recently is forgotten first.
const rememberedGroups = 100_000

// memory keeps, for each group that registered, its authority records
// (group.Records.AuthorityRecords: revocations, freezes, thaws, roots and
// the root's own device records, which make phones admins or not;
// docs/protocol.md, section 13). A hub that the group removed, or an admin
// it demoted, could otherwise register again while the group's own hub is
// away, with the records from before. With a directory it also writes
// there, one file per group, the records that are no device records
// (D-39): the removals, freezes and roots outlive a restart, and no device
// name is ever written.
type memory struct {
	dir string // "" keeps them in memory only

	mu     sync.Mutex
	groups map[string][]group.Record // by group tag
	order  []string                  // the tags, least recently saved first
	loaded bool
}

func newMemory(dir string) *memory { return &memory{dir: dir, groups: map[string][]group.Record{}} }

// records returns what the forwarder knows of the group's authority.
func (m *memory) records(tag string) []group.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadLocked()
	return m.groups[tag]
}

// keep remembers the group's authority records, checked ones only: what
// authority returned.
func (m *memory) keep(tag string, kept []group.Record) error {
	if !validTag(tag) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadLocked()
	if i := slices.Index(m.order, tag); i >= 0 {
		m.order = slices.Delete(m.order, i, i+1)
	}
	m.order = append(m.order, tag)
	// Another registration of the group may have kept records meanwhile.
	for _, r := range m.groups[tag] {
		if !slices.ContainsFunc(kept, func(k group.Record) bool { return k.ID() == r.ID() }) {
			kept = append(kept, r)
		}
	}
	m.groups[tag] = kept
	var gone []string
	for len(m.order) > rememberedGroups {
		gone = append(gone, m.order[0])
		delete(m.groups, m.order[0])
		m.order = m.order[1:]
	}
	if m.dir == "" {
		return nil
	}
	for _, t := range gone {
		os.Remove(m.file(t))
	}
	var lasting []group.Record
	for _, r := range kept {
		if r.Type() != group.RecordDevice {
			lasting = append(lasting, r)
		}
	}
	b, err := json.Marshal(lasting)
	if err != nil {
		return err
	}
	return writeFile(m.file(tag), b)
}

func (m *memory) file(tag string) string { return filepath.Join(m.dir, tag+".json") }

// loadLocked reads the directory once, the files saved least recently
// first.
func (m *memory) loadLocked() {
	if m.loaded || m.dir == "" {
		m.loaded = true
		return
	}
	m.loaded = true
	es, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	type saved struct {
		tag string
		mod int64
	}
	var all []saved
	for _, e := range es {
		name := e.Name()
		tag, ok := strings.CutSuffix(name, ".json")
		if !ok || !validTag(tag) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, saved{tag, info.ModTime().UnixNano()})
	}
	slices.SortFunc(all, func(a, b saved) int { return cmp.Compare(a.mod, b.mod) })
	for _, s := range all {
		b, err := os.ReadFile(m.file(s.tag))
		if err != nil {
			continue
		}
		var rs []group.Record
		if json.Unmarshal(b, &rs) != nil {
			continue
		}
		m.groups[s.tag] = rs
		m.order = append(m.order, s.tag)
	}
}

// validTag reports whether tag is a group tag, 16 lowercase hex digits, and
// so a safe file name.
func validTag(tag string) bool {
	if len(tag) != 16 {
		return false
	}
	_, err := hex.DecodeString(tag)
	return err == nil && tag == strings.ToLower(tag)
}

// writeFile writes b to name through a temporary file, so that a crash
// leaves the old file or the new one.
func writeFile(name string, b []byte) error {
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}
