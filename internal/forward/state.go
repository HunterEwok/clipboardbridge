// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sync"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// stateLabel names the key that hashes what the state table keeps.
const stateLabel = "clipboardbridge forwarder state"

// versions is all the forwarder keeps about the groups that registered with
// a credential (docs/protocol.md, section 18): under a hash of each
// period's tag, the version of its newest hubs' credential and a hash of
// the period key that signed it, so that an older credential, or one of
// another key, is refused. Both hashes are keyed with a secret from the
// forwarder's own key, so the table names no group by itself; and a period
// lasts about a month, so it cannot link one month of a group to the next.
// It is bounded at rememberedGroups; past it the period that registered
// least recently is forgotten first. With a file the table outlives a
// restart.
type versions struct {
	file   string // "" keeps it in memory only
	secret []byte

	mu      sync.Mutex
	entries map[string]versionEntry // by hashed tag
	seq     uint64
}

// A versionEntry is one period's newest credential: its version, the
// hashed period key, and when it was kept, as a counter, for the bound.
type versionEntry struct {
	Version uint64 `json:"version"`
	Key     string `json:"key"`
	Seq     uint64 `json:"seq"`
}

// newVersions returns the table, read from file if there is one; its
// hashes are keyed with a secret from the forwarder's key.
func newVersions(file string, key any) (*versions, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, der)
	m.Write([]byte(stateLabel))
	v := &versions{file: file, secret: m.Sum(nil), entries: map[string]versionEntry{}}
	if file == "" {
		return v, nil
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &v.entries); err != nil {
		return nil, err
	}
	for _, e := range v.entries {
		v.seq = max(v.seq, e.Seq)
	}
	return v, nil
}

func (v *versions) hash(parts ...[]byte) string {
	m := hmac.New(sha256.New, v.secret)
	for _, p := range parts {
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// check reports whether the period's credential may register its group:
// with nothing kept for its tag, any (the first period key the forwarder
// sees for a tag is the group's); else the same period key must have
// signed it, at the version kept or later.
func (v *versions) check(p *group.Presented) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.entries[v.hash([]byte(p.Tag))]
	switch {
	case !ok:
		return nil
	case v.hash([]byte(p.Tag), p.Signer[:]) != e.Key:
		return errors.New("another key registered this group's period first")
	case p.Hubs.Version < e.Version:
		return errors.New("the group's hubs' credential is older than one this forwarder saw")
	}
	return nil
}

// keep remembers the period's credential as the group's newest, and writes
// the table when it changed.
func (v *versions) keep(p *group.Presented) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	t := v.hash([]byte(p.Tag))
	next := versionEntry{Version: p.Hubs.Version, Key: v.hash([]byte(p.Tag), p.Signer[:])}
	if e, ok := v.entries[t]; ok && e.Version == next.Version && e.Key == next.Key {
		return nil
	}
	v.seq++
	next.Seq = v.seq
	v.entries[t] = next
	if len(v.entries) > rememberedGroups {
		oldest := slices.MinFunc(slices.Collect(maps.Keys(v.entries)), func(a, b string) int {
			return cmp.Compare(v.entries[a].Seq, v.entries[b].Seq)
		})
		delete(v.entries, oldest)
	}
	if v.file == "" {
		return nil
	}
	data, err := json.Marshal(v.entries)
	if err != nil {
		return err
	}
	return atomicfile.Write(v.file, data, 0o600)
}
