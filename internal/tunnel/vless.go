// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

// VLESS is what a client needs to reach the hub's forwarder inside VLESS
// with REALITY, for networks that block WireGuard (docs/design.md, "Blocked
// networks"): the forwarder's VLESS address and REALITY key, the site whose
// name the TLS handshake carries, and the group's VLESS user ID. The hub
// learns all but the ID when it registers with the forwarder and gives it
// to its clients with its offer (docs/protocol.md, section 11). Package
// vless runs it.
type VLESS struct {
	Endpoint   netip.AddrPort `json:"endpoint"`    // the forwarder's VLESS port, TCP
	PublicKey  []byte         `json:"public_key"`  // the forwarder's REALITY key, X25519
	ShortID    string         `json:"short_id"`    // REALITY's short ID, hex
	ServerName string         `json:"server_name"` // the site the handshake names
	ID         string         `json:"id"`          // the group's VLESS user ID, a UUID
}

// Check refuses a link that cannot work.
func (v *VLESS) Check() error {
	switch {
	case !v.Endpoint.IsValid() || v.Endpoint.Port() == 0:
		return errors.New("tunnel: vless: the forwarder's VLESS address is missing")
	case len(v.PublicKey) != 32:
		return errors.New("tunnel: vless: the forwarder's REALITY key is not 32 bytes")
	case !shortIDPattern.MatchString(v.ShortID):
		return fmt.Errorf("tunnel: vless: %q is not a REALITY short ID", v.ShortID)
	}
	if err := CheckServerName(v.ServerName); err != nil {
		return err
	}
	return CheckVLESSID(v.ID)
}

// Equal tells whether v and w are the same link; nil is none.
func (v *VLESS) Equal(w *VLESS) bool {
	if v == nil || w == nil {
		return v == w
	}
	return v.Endpoint == w.Endpoint && string(v.PublicKey) == string(w.PublicKey) &&
		v.ShortID == w.ShortID && v.ServerName == w.ServerName && v.ID == w.ID
}

var (
	shortIDPattern    = regexp.MustCompile(`^([0-9a-f]{2}){1,8}$`)
	serverNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	vlessIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// CheckServerName refuses what is not a site's name, such as
// www.example.com.
func CheckServerName(name string) error {
	if !serverNamePattern.MatchString(name) {
		return fmt.Errorf("tunnel: vless: %q is not a site's name, such as www.example.com", name)
	}
	return nil
}

// NewVLESSID returns a new random VLESS user ID for a group.
func NewVLESSID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// CheckVLESSID refuses what is not a user ID NewVLESSID would make.
func CheckVLESSID(id string) error {
	if !vlessIDPattern.MatchString(id) {
		return fmt.Errorf("tunnel: vless: %q is not a VLESS user ID", id)
	}
	return nil
}
