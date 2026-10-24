// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
)

// oldKeysFile lists, on the member that upgraded a legacy group, the
// computers that may still hold the group's old CA keys: those it has not
// yet met since, with a hello that no longer says they hold them.
const oldKeysFile = "oldkeys.json"

// upgrade upgrades a legacy group, on a member that holds its keys
// (docs/design.md, "Upgrading a group a computer created"): it makes a new
// root with path length 1 and names it in a root record that the old group
// CA key signs; under the new root it revokes the old group CA and iPhone
// CA keys and every shortcut's token, keeping every listed device, signs a
// device record for every device, and becomes the group's root with a new
// iPhone CA. The other key holders delete their copies of the old keys
// when the records reach them.
func (s *Service) upgrade() error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	switch {
	case id == nil || nd == nil:
		return s.errNoGroup()
	case !id.Legacy():
		return errors.New("this group already has a root; cbb upgrade is only for groups made before roots and admins")
	case id.GroupCA.Key == nil:
		return errors.New("this member holds no keys of the group; run cbb upgrade on a Linux or Windows member")
	}
	now := s.cfg.now()
	root, err := group.NewRootCA(now)
	if err != nil {
		return err
	}
	phoneCA, err := group.NewPhoneCA(now)
	if err != nil {
		return err
	}
	rr, err := s.signRecord(id, group.RecordBody{Type: group.RecordRoot, Root: root.Cert.Raw})
	if err != nil {
		return err
	}
	oldCA := group.KeyHashOf(id.GroupCA.Cert)
	var oldPhoneCA *group.KeyHash
	if id.PhoneCA != nil {
		k := group.KeyHashOf(id.PhoneCA.Cert)
		oldPhoneCA = &k
	}
	// The identity goes first, so the root record does not make this
	// member delete the keys it signs with.
	s.mu.Lock()
	next, err := s.id.Upgraded(root, []*x509.Certificate{root.Cert}, *phoneCA, now)
	if err == nil {
		err = s.setIdentityLocked(next)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.addRecords("", []group.Record{rr})
	s.recMu.Lock()
	roots := s.records.Roots()
	devs := s.records.Devices()
	s.recMu.Unlock()
	if len(roots) != 1 || !roots[0].Equal(root.Cert) {
		return errors.New("the records do not lead to the new root; another member may have upgraded the group at the same time, see cbb status")
	}
	nd.SendRecords([]group.Record{rr})

	revoke := group.RecordBody{Type: group.RecordRevoke, Keys: []group.KeyHash{oldCA}}
	if oldPhoneCA != nil {
		revoke.Keys = append(revoke.Keys, *oldPhoneCA)
	}
	bodies := []group.RecordBody{}
	var pending []string
	listedSelf := false
	for _, d := range devs {
		if d.Role == group.RoleShortcut {
			revoke.Keys = append(revoke.Keys, d.Key)
			continue
		}
		revoke.Keep = append(revoke.Keep, d.Key)
		key := d.Key
		bodies = append(bodies, group.RecordBody{Type: group.RecordDevice, Device: d.ID, Name: d.Name, Role: d.Role, OS: d.OS, Key: &key})
		switch {
		case d.ID == id.ID:
			listedSelf = true
		case keyHolder(d.Role, d.OS):
			pending = append(pending, string(d.ID))
		}
	}
	if !listedSelf {
		key := group.KeyHashOf(id.Cert)
		revoke.Keep = append(revoke.Keep, key)
		bodies = append(bodies, group.RecordBody{Type: group.RecordDevice, Device: id.ID, Name: s.cfg.Name, Role: group.RoleFull, OS: s.cfg.OS, Key: &key})
	}
	rs := make([]group.Record, 0, len(bodies)+1)
	for _, body := range append([]group.RecordBody{revoke}, bodies...) {
		r, err := s.signRecord(next, body)
		if err != nil {
			return err
		}
		rs = append(rs, r)
	}
	if err := s.saveOldKeys(pending); err != nil {
		s.logf("cbb: saving the members that may hold the old keys: %v", err)
	}
	s.publish(nd, rs...)
	s.noteOldKeys(nd.Peers())
	s.logf("cbb: upgraded the group: this device is its root, the old CA keys are revoked, and the group has a new iPhone CA")
	return nil
}

// oldKeys returns the devices that may still hold the old CA keys of an
// upgraded group, as this member knows them.
func (s *Service) oldKeys() []string {
	data, err := os.ReadFile(filepath.Join(s.cfg.StateDir, oldKeysFile))
	if err != nil {
		return nil
	}
	var ids []string
	if json.Unmarshal(data, &ids) != nil {
		return nil
	}
	return ids
}

func (s *Service) saveOldKeys(ids []string) error {
	path := filepath.Join(s.cfg.StateDir, oldKeysFile)
	if len(ids) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(data, '\n'), 0o600)
}

// noteOldKeys drops from the list of devices that may hold the old keys
// those whose hello no longer says they do.
func (s *Service) noteOldKeys(peers []node.Peer) {
	s.oldKeysMu.Lock()
	defer s.oldKeysMu.Unlock()
	ids := s.oldKeys()
	if len(ids) == 0 {
		return
	}
	left := slices.DeleteFunc(slices.Clone(ids), func(id string) bool {
		for _, p := range peers {
			if string(p.ID) == id && !p.OldKeys {
				s.logf("cbb: %s deleted its copies of the group's old CA keys", id)
				return true
			}
		}
		return false
	})
	if len(left) != len(ids) {
		if err := s.saveOldKeys(left); err != nil {
			s.logf("cbb: saving the members that may hold the old keys: %v", err)
		}
	}
}

// holdsOldKeys reports whether a device may still hold the old CA keys of
// the group: its hello says so, or it has not shown this member otherwise
// since this member upgraded the group.
func (s *Service) holdsOldKeys(dev group.DeviceID, peers map[group.DeviceID]node.Peer) bool {
	if p, ok := peers[dev]; ok {
		return p.OldKeys
	}
	s.oldKeysMu.Lock()
	defer s.oldKeysMu.Unlock()
	return slices.Contains(s.oldKeys(), string(dev))
}

// peersOf returns the connected peers by device ID.
func peersOf(nd *node.Node) map[group.DeviceID]node.Peer {
	out := map[group.DeviceID]node.Peer{}
	for _, p := range nd.Peers() {
		out[p.ID] = p
	}
	return out
}

func errOldKeys(name string) error {
	return fmt.Errorf("%s may still hold the group's old CA keys from before cbb upgrade; start it so that it deletes them, then remove it", name)
}
