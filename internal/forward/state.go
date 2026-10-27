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
// a credential (docs/protocol.md, section 18): under a hash of each group's
// tag, the version of its newest hubs' credential and a hash of the root
// that signed it, so that an older credential, or one from a root that a
// later one left behind, is refused. Both hashes are keyed with a secret
// from the forwarder's own key, so the table names no group by itself. It
// is bounded at rememberedGroups; past it the group that registered least
// recently is forgotten first. With a file the table outlives a restart.
type versions struct {
	file   string // "" keeps it in memory only
	secret []byte

	mu      sync.Mutex
	entries map[string]versionEntry // by hashed tag
	seq     uint64
}

// A versionEntry is one group's newest credential: its version, the
// hashed key of its root, and when it was kept, as a counter, for the
// bound.
type versionEntry struct {
	Version uint64 `json:"version"`
	Root    string `json:"root"`
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

// tagged reports whether the group of tag ever registered with a
// credential: it never registers with records again.
func (v *versions) tagged(tag string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.entries[v.hash([]byte(tag))]
	return ok
}

// check reports whether the checked chain may register the group of tag:
// with nothing kept, any; else the chain must hold a credential from the
// root kept, of the version kept or later, and end with one no older.
func (v *versions) check(tag string, ch *group.CheckedChain) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.entries[v.hash([]byte(tag))]
	if !ok {
		return nil
	}
	if ch.Last().Version < e.Version {
		return errors.New("the group's credential is older than one this forwarder saw")
	}
	for i, root := range ch.Roots {
		k := group.KeyHashOf(root)
		if v.hash([]byte(tag), k[:]) == e.Root && ch.Hubs[i].Version >= e.Version {
			return nil
		}
	}
	return errors.New("the group's credential comes from a root that a later one replaced")
}

// keep remembers the chain's last credential as the group's newest, and
// writes the table when it changed.
func (v *versions) keep(tag string, ch *group.CheckedChain) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	t := v.hash([]byte(tag))
	k := group.KeyHashOf(ch.Roots[len(ch.Roots)-1])
	next := versionEntry{Version: ch.Last().Version, Root: v.hash([]byte(tag), k[:])}
	if e, ok := v.entries[t]; ok && e.Version == next.Version && e.Root == next.Root {
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
