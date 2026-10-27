// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
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

// rememberedGroups bounds the groups whose records, or credential
// versions, the forwarder keeps after their registration ends; past it the
// group that registered least recently is forgotten first.
const rememberedGroups = 100_000

// memory keeps in memory, for each group that registered with records (a
// hub from before the credentials, docs/protocol.md, section 13), its
// authority records (group.Records.AuthorityRecords: revocations, freezes,
// thaws, roots and the root's own device records, which make phones admins
// or not). A hub that the group removed, or an admin it demoted, could
// otherwise register again while the group's own hub is away, with the
// records from before. Nothing of them is written to disk: a group that
// registers with a credential needs none of them (versions).
type memory struct {
	mu     sync.Mutex
	groups map[string][]group.Record // by group tag
	order  []string                  // the tags, least recently kept first
}

func newMemory() *memory { return &memory{groups: map[string][]group.Record{}} }

// records returns what the forwarder knows of the group's authority.
func (m *memory) records(tag string) []group.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.groups[tag]
}

// keep remembers the group's authority records, checked ones only: what
// authority returned.
func (m *memory) keep(tag string, kept []group.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	for len(m.order) > rememberedGroups {
		delete(m.groups, m.order[0])
		m.order = m.order[1:]
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
