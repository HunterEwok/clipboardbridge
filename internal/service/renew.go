// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// renewEvery is how often a member checks whether certificates are due for
// renewal: its own, if it holds the CA keys, and those of the connected
// members. The renewal periods are months long, so twice a day is plenty.
const renewEvery = 12 * time.Hour

// renewLoop renews certificates when the group starts and every renewEvery
// after, until ctx is done.
func (s *Service) renewLoop(ctx context.Context) {
	t := time.NewTicker(renewEvery)
	defer t.Stop()
	for {
		s.renew(s.cfg.now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// renew renews this member's own certificates if they are due and it holds
// the CA keys, then sends renewed certificates to the connected members
// whose certificates are due.
func (s *Service) renew(now time.Time) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	if id == nil || nd == nil {
		s.mu.Unlock()
		return
	}
	next, changed, err := id.Renew(now)
	if err == nil && changed {
		err = s.setIdentityLocked(next)
	}
	s.mu.Unlock()
	switch {
	case err != nil:
		s.logf("cbb: renewing the certificates: %v", err)
	case changed:
		s.logf("cbb: renewed this member's certificates; the member certificate is valid until %s",
			next.Cert.NotAfter.UTC().Format(time.DateOnly))
	}
	nd.RenewPeers()
}

// certRenewed keeps a member certificate that another member renewed for
// this one, from issuer when an admin phone sent its admin CA.
func (s *Service) certRenewed(der, issuer []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil {
		return errors.New("this device is in no group")
	}
	// A new root may renew before this member has acted on its root
	// record.
	if err := s.adoptRootsLocked(); err != nil {
		return err
	}
	next, err := s.id.WithCertFrom(der, issuer)
	if err != nil {
		return err
	}
	// A certificate the records refuse, as from a removed admin, would
	// cut this member off.
	chain := []*x509.Certificate{next.Cert}
	if next.Issuer != nil {
		chain = append(chain, next.Issuer)
	}
	if err := s.allow(next.ID, chain); err != nil {
		return err
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	s.logf("cbb: got a renewed member certificate, valid until %s", next.Cert.NotAfter.UTC().Format(time.DateOnly))
	return nil
}

// withAdminKey gives a computer of a phone group the admin key that its
// hello offers, so that the root phone can make it an admin
// (docs/protocol.md, section 10). Without one it carries on as it is.
func (s *Service) withAdminKey(id *group.Identity) *group.Identity {
	if !id.PhoneGroup() || id.AdminKey != nil {
		return id
	}
	next, err := id.WithAdminKey()
	if err == nil {
		err = next.Save(s.cfg.StateDir)
	}
	if err != nil {
		s.logf("cbb: making the admin key: %v", err)
		return id
	}
	return next
}

// becomeAdmin keeps the admin CA that the root phone sent for this
// computer's admin key: from then on it admits and removes devices and
// renews certificates with it.
func (s *Service) becomeAdmin(der []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil {
		return errors.New("this device is in no group")
	}
	if s.id.AdminCA != nil && bytes.Equal(s.id.AdminCA.Raw, der) {
		return nil
	}
	if err := s.adoptRootsLocked(); err != nil {
		return err
	}
	next, err := s.id.WithAdminCA(der, s.cfg.now())
	if err != nil {
		return err
	}
	// An admin CA the records refuse, as from a root that handed the
	// group over, would make records nobody takes.
	if err := s.allow(next.ID, []*x509.Certificate{next.AdminCA}); err != nil {
		return err
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	s.logf("cbb: this computer is now an admin of the group: it can admit and remove devices")
	return nil
}

// setIdentityLocked saves a renewed identity and starts using it: new member
// connections and the iPhone port present its certificates.
func (s *Service) setIdentityLocked(next *group.Identity) error {
	if err := next.Save(s.cfg.StateDir); err != nil {
		return err
	}
	s.id = next
	s.nd.SetIdentity(next)
	return nil
}
