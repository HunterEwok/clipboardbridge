// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package invite is the remote invitation: what a device that shares no
// network with the group needs to join it through the hub's tunnel
// (docs/design.md, "Joining from another network"; docs/protocol.md,
// section 12). It travels only as a QR code or a file, never typed, and is a
// secret until it is used.
package invite

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// prefix starts an invitation's text: the URI of a QR code, and the one
// line of a .cbbinvite file. The rest is a fragment, which a browser never
// sends anywhere.
const prefix = "clipboardbridge://invite#"

// Ext is the file name extension of an invitation file.
const Ext = ".cbbinvite"

// MaxLifetime is the longest an invitation may be valid; DefaultLifetime
// is how long it is unless the admin asks otherwise.
const (
	MaxLifetime     = 24 * time.Hour
	DefaultLifetime = time.Hour
)

// Invitation is everything a device needs to join through the hub.
type Invitation struct {
	Group     string           // the group's tag
	Hub       string           // the hub's device ID
	HubKey    tunnel.Key       // the hub's WireGuard public key
	Endpoints []netip.AddrPort // where the hub's UDP port is reached
	GuestKey  tunnel.Key       // the one-time WireGuard private key of the guest tunnel
	GuestPSK  tunnel.Key       // its preshared key
	Secret    []byte           // the pairing secret, in place of a code
	Expires   time.Time
	// Obfuscation is the hub's AmneziaWG settings; nil for plain
	// WireGuard.
	Obfuscation *tunnel.Obfuscation
}

// wire is the JSON of an invitation, with short names for a small QR code.
type wire struct {
	V         int      `json:"v"`
	Group     string   `json:"g"`
	Hub       string   `json:"h"`
	HubKey    []byte   `json:"hk"`
	Endpoints []string `json:"ep"`
	GuestKey  []byte   `json:"k"`
	GuestPSK  []byte   `json:"psk"`
	Secret    []byte   `json:"s"`
	Expires   int64    `json:"exp"` // Unix seconds

	Obfuscation *tunnel.Obfuscation `json:"o,omitempty"`
}

// String returns the invitation's text.
func (in *Invitation) String() string {
	w := wire{V: 1, Group: in.Group, Hub: in.Hub, HubKey: in.HubKey[:], GuestKey: in.GuestKey[:],
		GuestPSK: in.GuestPSK[:], Secret: in.Secret, Expires: in.Expires.Unix(), Obfuscation: in.Obfuscation}
	for _, ep := range in.Endpoints {
		w.Endpoints = append(w.Endpoints, ep.String())
	}
	data, err := json.Marshal(w)
	if err != nil {
		panic(err) // it has nothing that cannot be marshaled
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data)
}

// Parse reads an invitation's text, such as a file's content, and checks
// it; surrounding white space is ignored. It does not check the expiry.
func Parse(text string) (*Invitation, error) {
	text = strings.TrimSpace(text)
	enc, ok := strings.CutPrefix(text, prefix)
	if !ok {
		return nil, errors.New("invite: this is not a clipboardbridge invitation")
	}
	data, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, errors.New("invite: the invitation is damaged")
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, errors.New("invite: the invitation is damaged")
	}
	if w.V != 1 {
		return nil, fmt.Errorf("invite: an invitation of version %d; update clipboardbridge", w.V)
	}
	in := &Invitation{Group: w.Group, Hub: w.Hub, Secret: w.Secret, Expires: time.Unix(w.Expires, 0), Obfuscation: w.Obfuscation}
	for _, k := range []struct {
		dst *tunnel.Key
		src []byte
	}{{&in.HubKey, w.HubKey}, {&in.GuestKey, w.GuestKey}, {&in.GuestPSK, w.GuestPSK}} {
		if len(k.src) != len(k.dst) {
			return nil, errors.New("invite: the invitation is damaged")
		}
		copy(k.dst[:], k.src)
	}
	for _, e := range w.Endpoints {
		ep, err := netip.ParseAddrPort(e)
		if err != nil {
			return nil, errors.New("invite: the invitation is damaged")
		}
		in.Endpoints = append(in.Endpoints, ep)
	}
	if err := in.check(); err != nil {
		return nil, err
	}
	return in, nil
}

func (in *Invitation) check() error {
	if _, err := tunnel.Addr(in.Hub); err != nil {
		return errors.New("invite: the invitation names no hub")
	}
	switch {
	case in.Group == "":
		return errors.New("invite: the invitation names no group")
	case len(in.Endpoints) == 0 || len(in.Endpoints) > 8:
		return errors.New("invite: the invitation has no hub address, or too many")
	case len(in.Secret) < pair.MinSecret:
		return errors.New("invite: the invitation's secret is too short")
	case in.HubKey.IsZero() || in.GuestKey.IsZero() || in.GuestPSK.IsZero():
		return errors.New("invite: the invitation lacks a key")
	}
	if o := in.Obfuscation; o != nil {
		if err := o.Check(); err != nil {
			return errors.New("invite: the invitation's obfuscation settings are damaged")
		}
	}
	return nil
}
