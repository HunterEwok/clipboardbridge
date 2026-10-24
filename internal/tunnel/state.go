// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
)

// StateFile holds a member's tunnel state, next to its identity.
const StateFile = "tunnel.json"

const (
	maxMembers   = 256 // clients a hub keeps
	maxEndpoints = 8   // addresses of the hub a client keeps
)

// MarshalText encodes the key in standard base64, as WireGuard does.
func (k Key) MarshalText() ([]byte, error) {
	return base64.StdEncoding.AppendEncode(nil, k[:]), nil
}

// UnmarshalText decodes a key in standard base64.
func (k *Key) UnmarshalText(b []byte) error {
	var buf [33]byte // room for what 44 characters may decode to
	if len(b) != base64.StdEncoding.EncodedLen(len(k)) {
		return errors.New("tunnel: a key is not 32 bytes in base64")
	}
	n, err := base64.StdEncoding.Decode(buf[:], b)
	if err != nil || n != len(k) {
		return errors.New("tunnel: a key is not 32 bytes in base64")
	}
	copy(k[:], buf[:n])
	return nil
}

// State is a member's tunnel state: its own WireGuard key, the hub it
// reaches away from home, and, on the hub, its clients. The member learns
// all of it inside the member protocol's TLS (docs/protocol.md, section 11).
type State struct {
	Key Key // this device's private key; it never leaves the device

	// Group is the tag of the group the rest belongs to; ForGroup clears
	// the rest when the device is in another group.
	Group string

	// ToHub is the hub this device reaches away from home; nil until a
	// hub offered its tunnel.
	ToHub *HubLink

	// IsHub tells whether this member is the group's hub, which admits
	// the other members' keys. Endpoints are the hub's addresses that it
	// gives its clients, and ListenPort the UDP port it listens on (0 for
	// Port).
	IsHub      bool
	Endpoints  []netip.AddrPort
	ListenPort int
	Members    []Member

	// Obfuscation, on the hub, is the group's AmneziaWG settings, which
	// it gives its clients; nil for plain WireGuard.
	Obfuscation *Obfuscation

	// Forwarder is where the hub registers for the clients that cannot
	// reach it directly; nil without one.
	Forwarder *ForwarderLink

	// Relay is where this device meets the others of its group away from
	// home when the group has no hub: a blind relay the user runs; nil
	// without one. A device with a relay is neither a hub nor a client of
	// one.
	Relay *RelayLink

	// KeysInFile records that the user agreed to sync away from home
	// although this device keeps its keys in files, not in hardware
	// (docs/design.md, "Turning it on, step by step").
	KeysInFile bool
}

// ForwarderLink is a hub's forwarder: its address, for UDP and TCP, and the
// pin of its key.
type ForwarderLink struct {
	Endpoint netip.AddrPort
	Pin      string
}

// RelayLink is a device's blind relay: its address, for UDP and TCP, and
// the pin of its key.
type RelayLink struct {
	Endpoint netip.AddrPort
	Pin      string
}

// HubEndpoints returns the addresses the hub gives its clients: its own,
// then the forwarder's, which clients try last.
func (s *State) HubEndpoints() []netip.AddrPort {
	eps := slices.Clone(s.Endpoints)
	if f := s.Forwarder; f != nil && !slices.Contains(eps, f.Endpoint) {
		eps = append(eps, f.Endpoint)
	}
	return eps
}

// HubLink is what a client keeps of its hub.
type HubLink struct {
	Device       string
	PublicKey    Key
	PresharedKey Key
	Endpoints    []netip.AddrPort
	Obfuscation  *Obfuscation // nil for plain WireGuard
}

// Member is a client as its hub keeps it: its WireGuard key, its own
// preshared key, and the certificate chain it presented when it sent the
// key, so that the hub drops it when the group's records revoke it.
type Member struct {
	Device       string
	PublicKey    Key
	PresharedKey Key
	Chain        [][]byte // DER, the member certificate first
}

type stateFile struct {
	Version    int              `json:"v"`
	Key        Key              `json:"key"`
	Group      string           `json:"group,omitempty"`
	ToHub      *hubFile         `json:"to_hub,omitempty"`
	IsHub      bool             `json:"is_hub,omitempty"`
	Endpoints  []netip.AddrPort `json:"endpoints,omitempty"`
	ListenPort int              `json:"listen_port,omitempty"`
	Members    []memberFile     `json:"members,omitempty"`
	KeysInFile bool             `json:"keys_in_file,omitempty"`
	Forwarder  *forwarderFile   `json:"forwarder,omitempty"`
	Relay      *forwarderFile   `json:"relay,omitempty"`
	// Obfuscation is the hub's AmneziaWG settings.
	Obfuscation *Obfuscation `json:"obfuscation,omitempty"`
}

type forwarderFile struct {
	Endpoint netip.AddrPort `json:"endpoint"`
	Pin      string         `json:"key"`
}

type hubFile struct {
	Device       string           `json:"device"`
	PublicKey    Key              `json:"key"`
	PresharedKey Key              `json:"psk"`
	Endpoints    []netip.AddrPort `json:"endpoints,omitempty"`
	Obfuscation  *Obfuscation     `json:"obfuscation,omitempty"`
}

type memberFile struct {
	Device       string   `json:"device"`
	PublicKey    Key      `json:"key"`
	PresharedKey Key      `json:"psk"`
	Chain        [][]byte `json:"chain"`
}

// NewState returns a state with a new private key.
func NewState() (*State, error) {
	k, err := NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("tunnel: making the key: %w", err)
	}
	return &State{Key: k}, nil
}

// LoadState reads the state in dir. Without a state file it makes one with
// a new key.
func LoadState(dir string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		s, err := NewState()
		if err != nil {
			return nil, err
		}
		return s, s.Save(dir)
	}
	if err != nil {
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", StateFile, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: unknown version %d", StateFile, f.Version)
	}
	s := &State{Key: f.Key, Group: f.Group, IsHub: f.IsHub, Endpoints: f.Endpoints, ListenPort: f.ListenPort, KeysInFile: f.KeysInFile,
		Obfuscation: f.Obfuscation}
	if f.ToHub != nil {
		s.ToHub = &HubLink{Device: f.ToHub.Device, PublicKey: f.ToHub.PublicKey, PresharedKey: f.ToHub.PresharedKey, Endpoints: f.ToHub.Endpoints,
			Obfuscation: f.ToHub.Obfuscation}
	}
	for _, c := range f.Members {
		s.Members = append(s.Members, Member(c))
	}
	if f.Forwarder != nil {
		s.Forwarder = &ForwarderLink{Endpoint: f.Forwarder.Endpoint, Pin: f.Forwarder.Pin}
	}
	if f.Relay != nil {
		s.Relay = &RelayLink{Endpoint: f.Relay.Endpoint, Pin: f.Relay.Pin}
	}
	if err := s.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", StateFile, err)
	}
	return s, nil
}

// Save writes the state to dir, readable only by its owner.
func (s *State) Save(dir string) error {
	f := stateFile{Version: 1, Key: s.Key, Group: s.Group, IsHub: s.IsHub, Endpoints: s.Endpoints, ListenPort: s.ListenPort, KeysInFile: s.KeysInFile,
		Obfuscation: s.Obfuscation}
	if h := s.ToHub; h != nil {
		f.ToHub = &hubFile{Device: h.Device, PublicKey: h.PublicKey, PresharedKey: h.PresharedKey, Endpoints: h.Endpoints,
			Obfuscation: h.Obfuscation}
	}
	for _, c := range s.Members {
		f.Members = append(f.Members, memberFile(c))
	}
	if fw := s.Forwarder; fw != nil {
		f.Forwarder = &forwarderFile{Endpoint: fw.Endpoint, Pin: fw.Pin}
	}
	if r := s.Relay; r != nil {
		f.Relay = &forwarderFile{Endpoint: r.Endpoint, Pin: r.Pin}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, StateFile), append(data, '\n'), 0o600)
}

// check refuses a state that would break the tunnel's rules.
func (s *State) check() error {
	if s.Key.IsZero() {
		return errors.New("no private key")
	}
	if len(s.HubEndpoints()) > maxEndpoints {
		return errors.New("too many endpoints")
	}
	if fw := s.Forwarder; fw != nil && (!fw.Endpoint.IsValid() || fw.Endpoint.Port() == 0 || fw.Pin == "") {
		return errors.New("a bad forwarder")
	}
	if r := s.Relay; r != nil {
		if !r.Endpoint.IsValid() || r.Endpoint.Port() == 0 || r.Pin == "" {
			return errors.New("a bad relay")
		}
		if s.IsHub || s.ToHub != nil {
			return errors.New("a device with a relay is neither a hub nor a hub's client")
		}
	}
	if o := s.Obfuscation; o != nil {
		if !s.IsHub {
			return errors.New("obfuscation settings on a device that is not the hub")
		}
		if err := o.Check(); err != nil {
			return err
		}
	}
	if s.ListenPort < 0 || s.ListenPort > 65535 {
		return fmt.Errorf("a bad listen port %d", s.ListenPort)
	}
	if h := s.ToHub; h != nil {
		if err := h.check(); err != nil {
			return err
		}
		if h.PublicKey == s.Key.Public() {
			return errors.New("the hub has this device's key")
		}
	}
	if len(s.Members) > maxMembers {
		return errors.New("too many clients")
	}
	devices := make(map[string]bool, len(s.Members))
	for _, c := range s.Members {
		if devices[c.Device] {
			return fmt.Errorf("the client %s is there twice", c.Device)
		}
		devices[c.Device] = true
		if len(c.Chain) == 0 {
			return fmt.Errorf("the client %s has no certificate", c.Device)
		}
	}
	_, err := s.peers()
	return err
}

func (h *HubLink) check() error {
	if _, err := Addr(h.Device); err != nil {
		return err
	}
	switch {
	case h.PublicKey.IsZero():
		return errors.New("the hub has no key")
	case h.PresharedKey.IsZero():
		return errors.New("the hub gave no preshared key")
	case len(h.Endpoints) > maxEndpoints:
		return errors.New("the hub gave too many endpoints")
	}
	for _, ep := range h.Endpoints {
		if !ep.IsValid() || ep.Port() == 0 {
			return fmt.Errorf("the hub gave a bad endpoint %v", ep)
		}
	}
	if o := h.Obfuscation; o != nil {
		if err := o.Check(); err != nil {
			return err
		}
	}
	return nil
}

// ForGroup keeps the key and forgets the rest when it belongs to another
// group than the one tagged group. changed tells whether the state must be
// saved.
func (s *State) ForGroup(group string) (changed bool) {
	if s.Group == group {
		return false
	}
	*s = State{Key: s.Key, Group: group}
	return true
}

// Peers returns the hub's clients as its WireGuard peers.
func (s *State) Peers() []Peer {
	peers, _ := s.peers()
	return peers
}

func (s *State) peers() ([]Peer, error) {
	peers := make([]Peer, 0, len(s.Members))
	for _, c := range s.Members {
		a, err := Addr(c.Device)
		if err != nil {
			return nil, err
		}
		peers = append(peers, Peer{PublicKey: c.PublicKey, PresharedKey: c.PresharedKey, Addr: a})
	}
	if err := checkPeers(peers, netip.Addr{}); err != nil {
		return nil, err
	}
	for _, p := range peers {
		if p.PublicKey == s.Key.Public() {
			return nil, errors.New("tunnel: a client has the hub's key")
		}
	}
	return peers, nil
}

// Admit adds or updates the client device with the WireGuard key it sent
// and the certificate chain it presented, and returns the client as the
// hub keeps it. A client that keeps its key keeps its preshared key; a new
// key gets a new one. changed tells whether the state must be saved.
func (s *State) Admit(device string, pub Key, chain [][]byte) (c Member, changed bool, err error) {
	if _, err := Addr(device); err != nil {
		return Member{}, false, err
	}
	if len(chain) == 0 {
		return Member{}, false, errors.New("tunnel: a client without a certificate")
	}
	if pub.IsZero() || pub == s.Key.Public() {
		return Member{}, false, errors.New("tunnel: a client offered no key or the hub's own")
	}
	i := slices.IndexFunc(s.Members, func(c Member) bool { return c.Device == device })
	for j, o := range s.Members {
		if j != i && o.PublicKey == pub {
			return Member{}, false, fmt.Errorf("tunnel: %s offered the key of %s", device, o.Device)
		}
	}
	if i >= 0 {
		c := &s.Members[i]
		if c.PublicKey == pub && slices.EqualFunc(c.Chain, chain, bytes.Equal) {
			return *c, false, nil
		}
		if c.PublicKey != pub {
			psk, err := NewPresharedKey()
			if err != nil {
				return Member{}, false, err
			}
			c.PublicKey, c.PresharedKey = pub, psk
		}
		c.Chain = chain
		return *c, true, nil
	}
	if len(s.Members) >= maxMembers {
		return Member{}, false, errors.New("tunnel: the hub has too many clients")
	}
	psk, err := NewPresharedKey()
	if err != nil {
		return Member{}, false, err
	}
	c = Member{Device: device, PublicKey: pub, PresharedKey: psk, Chain: chain}
	s.Members = append(s.Members, c)
	return c, true, nil
}

// Prune forgets the clients keep refuses and returns their devices.
func (s *State) Prune(keep func(Member) bool) []string {
	var gone []string
	s.Members = slices.DeleteFunc(s.Members, func(c Member) bool {
		if keep(c) {
			return false
		}
		gone = append(gone, c.Device)
		return true
	})
	return gone
}

// SetHub keeps the hub that offered its tunnel. changed tells whether the
// state must be saved.
func (s *State) SetHub(h HubLink) (changed bool, err error) {
	if err := h.check(); err != nil {
		return false, fmt.Errorf("tunnel: %w", err)
	}
	if h.PublicKey == s.Key.Public() {
		return false, errors.New("tunnel: the hub offered this device's own key")
	}
	if o := s.ToHub; o != nil && o.Device == h.Device && o.PublicKey == h.PublicKey &&
		o.PresharedKey == h.PresharedKey && slices.Equal(o.Endpoints, h.Endpoints) && o.Obfuscation.Equal(h.Obfuscation) {
		return false, nil
	}
	h.Endpoints = slices.Clone(h.Endpoints)
	s.ToHub = &h
	return true, nil
}
