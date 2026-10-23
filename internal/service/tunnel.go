// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// The tunnel keys travel inside the member protocol (docs/protocol.md,
// section 11): every member offers its WireGuard public key in its hello,
// the group's hub admits it and answers with its own key, the member's
// preshared key and its addresses, and the member keeps that offer. Since
// it happens only inside member TLS, a device gets into the tunnel only
// after it met the hub as a member, and only with the key that member sent.

// loadTunnel reads the tunnel state for the group of id, with a new key if
// there is none. Without it the member offers no tunnel key and keeps no
// offer: it syncs at home only.
func (s *Service) loadTunnel(id *group.Identity) *tunnel.State {
	st, err := tunnel.LoadState(s.cfg.StateDir)
	if err == nil && st.ForGroup(group.Tag(id.GroupCA.Cert)) {
		err = st.Save(s.cfg.StateDir)
	}
	if err != nil {
		s.logf("cbb: the tunnel for sync away from home is off: %v", err)
		return nil
	}
	return st
}

// tunnelKey returns this member's WireGuard public key for its hello; nil
// when the tunnel state could not be read.
func tunnelKey(st *tunnel.State) []byte {
	if st == nil {
		return nil
	}
	k := st.Key.Public()
	return k[:]
}

// tunnelKeyOffered admits the tunnel key a peer offered, if this member is
// the group's hub, and returns the offer for the peer.
func (s *Service) tunnelKeyOffered(peer group.DeviceID, chain []*x509.Certificate, key []byte) *node.TunnelOffer {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil || !st.IsHub {
		return nil
	}
	var pub tunnel.Key
	if len(key) != len(pub) {
		s.logf("cbb: %s offered a tunnel key of %d bytes", peer, len(key))
		return nil
	}
	copy(pub[:], key)
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	m, changed, err := st.Admit(string(peer), pub, ders)
	if err != nil {
		s.logf("cbb: admitting the tunnel key of %s: %v", peer, err)
		return nil
	}
	if changed {
		if err := st.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the tunnel state: %v", err)
			return nil
		}
		s.logf("cbb: %s can reach this hub away from home", peer)
	}
	hub := st.Key.Public()
	o := &node.TunnelOffer{HubKey: hub[:], PSK: m.PresharedKey[:]}
	for _, ep := range st.Endpoints {
		o.Endpoints = append(o.Endpoints, ep.String())
	}
	return o
}

// tunnelOffered keeps the offer of the group's hub for this member's key.
func (s *Service) tunnelOffered(from group.DeviceID, o node.TunnelOffer) error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil {
		return errors.New("the tunnel is off on this device")
	}
	if st.IsHub {
		return errors.New("this device is the hub itself; the group has two hubs")
	}
	h := tunnel.HubLink{Device: string(from)}
	if len(o.HubKey) != len(h.PublicKey) || len(o.PSK) != len(h.PresharedKey) {
		return errors.New("the keys are not 32 bytes")
	}
	copy(h.PublicKey[:], o.HubKey)
	copy(h.PresharedKey[:], o.PSK)
	for _, e := range o.Endpoints {
		ep, err := netip.ParseAddrPort(e)
		if err != nil {
			return fmt.Errorf("a bad endpoint: %w", err)
		}
		h.Endpoints = append(h.Endpoints, ep)
	}
	old := st.ToHub
	changed, err := st.SetHub(h)
	if err != nil || !changed {
		return err
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		return fmt.Errorf("saving the tunnel state: %w", err)
	}
	if old == nil || old.Device != h.Device {
		s.logf("cbb: %s is the group's hub for sync away from home", from)
	}
	return nil
}

// pruneTunnel forgets, on the hub, the members the records now refuse.
func (s *Service) pruneTunnel() {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil || len(st.Members) == 0 {
		return
	}
	gone := st.Prune(func(m tunnel.Member) bool {
		chain := make([]*x509.Certificate, 0, len(m.Chain))
		for _, der := range m.Chain {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return false
			}
			chain = append(chain, c)
		}
		return s.allow(group.DeviceID(m.Device), chain) == nil
	})
	if len(gone) == 0 {
		return
	}
	for _, d := range gone {
		s.logf("cbb: %s was removed from the group; the hub drops its tunnel", d)
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		s.logf("cbb: saving the tunnel state: %v", err)
	}
}
