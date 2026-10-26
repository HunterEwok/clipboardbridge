// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/HunterEwok/clipboardbridge/internal/attest"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
)

// attestRoots are the roots attestations must lead to; attest.GoogleRoots
// when nil, as everywhere but in tests.
var attestRoots [][]byte

// evidenceReceived checks the attestation a peer sent of its member key
// and, on the group's root, records what it proves in the peer's device
// record when that differs from what the record says (docs/protocol.md,
// section 17, "Evidence"). Other members ignore it.
func (s *Service) evidenceReceived(peer group.DeviceID, chain []*x509.Certificate, e node.Evidence) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || !id.IsRoot() || len(chain) == 0 {
		return nil
	}
	if e.Format != node.EvidenceAndroid || e.Key != node.EvidenceMember {
		return nil // from a newer version
	}
	tag := group.Tag(id.GroupCA.Cert)
	if e.GroupTag != "" && e.GroupTag != tag {
		return errors.New("an attestation made for another group")
	}
	challenge, err := attest.Challenge(e.GroupTag, nil, e.Salt)
	if err != nil {
		return err
	}
	res, err := attest.CheckAndroid(e.Chain, chain[0].RawSubjectPublicKeyInfo, challenge, attest.Policy{Roots: attestRoots})
	if err != nil {
		return err
	}
	leaf := sha256.Sum256(e.Chain[0])
	proof := hex.EncodeToString(leaf[:])
	s.listMu.Lock()
	defer s.listMu.Unlock()
	rec := s.deviceRecord(peer)
	switch {
	case rec == nil || rec.Key != group.KeyHashOf(chain[0]):
		return nil // not listed yet; it sends the evidence again when it next connects
	case rec.Store == res.Store && rec.Kind == res.Kind:
		return nil
	}
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: rec.ID, Name: rec.Name, Role: rec.Role,
		OS: rec.OS, Key: &rec.Key, Admin: rec.AdminKey, Store: res.Store, Kind: res.Kind, Proof: proof})
	if err != nil {
		return fmt.Errorf("recording what its attestation proves: %w", err)
	}
	s.publish(nd, r)
	why := ""
	if res.Why != "" {
		why = ": " + res.Why
	}
	s.logf("cbb: the attestation of %s (%s) shows its keys %s (%s)%s", rec.Name, rec.ID, res.Store, res.Kind, why)
	return nil
}
