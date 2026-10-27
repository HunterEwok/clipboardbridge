// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// credentialStore is the node's view of the group's server credentials
// (docs/protocol.md, section 18).
type credentialStore struct{ s *Service }

func (c credentialStore) All() []group.Credential {
	c.s.recMu.Lock()
	defer c.s.recMu.Unlock()
	if c.s.creds == nil {
		return nil
	}
	return c.s.creds.All()
}

func (c credentialStore) Add(from group.DeviceID, cs []group.Credential) []group.Credential {
	return c.s.addCredentials(from, cs)
}

// pathLocked returns the roots of the group's path, the group CA first.
// s.recMu is held.
func (s *Service) pathLocked() []*x509.Certificate {
	return append([]*x509.Certificate{s.creds.GroupCA()}, s.records.Roots()...)
}

// loadCredentials reads the group's credentials; a file that cannot be
// read leaves the set empty, since the peers give them again.
func (s *Service) loadCredentials(id *group.Identity, recs *group.Records) *group.Credentials {
	roots := append([]*x509.Certificate{id.GroupCA.Cert}, recs.Roots()...)
	creds, err := group.LoadCredentials(s.cfg.StateDir, roots)
	if err != nil {
		s.logf("cbb: reading the server credentials: %v", err)
		return group.NewCredentials(id.GroupCA.Cert)
	}
	return creds
}

// addCredentials adds the valid credentials among cs, saves them, and
// returns those that were new.
func (s *Service) addCredentials(from group.DeviceID, cs []group.Credential) []group.Credential {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.creds == nil || s.records == nil {
		return nil
	}
	fresh, errs := s.creds.Add(s.pathLocked(), cs)
	for _, err := range errs {
		s.logf("cbb: dropped a server credential from %s: %v", orThis(from), err)
	}
	if len(fresh) > 0 {
		if err := s.creds.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the server credentials: %v", err)
		}
	}
	return fresh
}

// refreshCredential signs a new hubs' credential on the group's root when
// the one it keeps lists other keys than the records say, or is due for
// renewal (group.Stale), and sends it to the peers.
func (s *Service) refreshCredential() {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || !id.IsRoot() {
		return
	}
	ca := id.RootCA()
	now := s.cfg.now()
	s.recMu.Lock()
	if s.creds == nil || s.records == nil {
		s.recMu.Unlock()
		return
	}
	roots := s.pathLocked()
	if !roots[len(roots)-1].Equal(ca.Cert) {
		// The records do not lead to this root yet.
		s.recMu.Unlock()
		return
	}
	want := s.records.CredentialLists()
	_, cur, _ := s.creds.Current(roots)
	stale := group.Stale(cur, want, s.records.KnownKey, now)
	prev := s.creds.MaxVersion()
	s.recMu.Unlock()
	if !stale {
		return
	}
	c, err := group.SignHubs(group.Tag(id.GroupCA.Cert), want, group.NextVersion(prev, now), now, ca.Key)
	if err != nil {
		s.logf("cbb: signing the hubs' credential: %v", err)
		return
	}
	if fresh := s.addCredentials("", []group.Credential{c}); len(fresh) > 0 && nd != nil {
		nd.SendCredentials(fresh)
	}
}

// linkCredential signs, on the admin that takes the group over, the link
// that hands it to the new root with this admin's key, when the old root's
// hubs' credential names this admin an heir, and sends it to the peers.
func (s *Service) linkCredential(admin *group.CA, root *x509.Certificate) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return
	}
	l, err := group.SignLink(group.Tag(id.GroupCA.Cert), root, admin.Key)
	if err != nil {
		s.logf("cbb: signing the link to the new root: %v", err)
		return
	}
	if fresh := s.addCredentials("", []group.Credential{l}); len(fresh) > 0 && nd != nil {
		nd.SendCredentials(fresh)
	}
}

// hubCredentials is what the hub registers with on its forwarder when the
// group's credentials list it: the chain from the group CA to the current
// root. It returns nil otherwise, and the hub registers with its member
// certificate and the records.
func (s *Service) hubCredentials() []group.Credential {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil {
		return nil
	}
	s.recMu.Lock()
	if s.creds == nil || s.records == nil {
		s.recMu.Unlock()
		return nil
	}
	roots := s.pathLocked()
	chain := s.creds.Chain(roots)
	_, last, ok := s.creds.Current(roots)
	s.recMu.Unlock()
	if chain == nil || !ok || !s.cfg.now().Before(last.Expires()) || !slices.Contains(last.Hubs, group.KeyHashOf(id.Cert)) {
		return nil
	}
	return chain
}

// hubCert is the certificate the hub registers with when it has a
// credential: one of its member key that names no device.
func (s *Service) hubCert() (tls.Certificate, error) {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil {
		return tls.Certificate{}, errors.New("this device is in no group")
	}
	return id.HubCertificate()
}
