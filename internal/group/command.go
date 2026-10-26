// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The types of commands (docs/protocol.md, section 15): CommandMode sets
// the sync mode of one member; CommandHub makes the receiver, a computer
// that is an admin, the group's hub for sync away from home in place of the
// sender, with the sender's clients (section 11, "Moving the hub").
const (
	CommandMode = "mode"
	CommandHub  = "hub"
)

// MaxHubClients bounds the clients a hub command hands over, as many as a
// hub keeps.
const MaxHubClients = 256

// maxCommandBody bounds a command's body: a hub command carries the keys of
// up to MaxHubClients clients.
const maxCommandBody = 64 << 10

// The limits of a command's times: it expires at most CommandLifetime after
// it was signed, and its time may be at most CommandAhead ahead of the
// receiver's clock.
const (
	CommandLifetime = 30 * time.Second
	CommandAhead    = 60 * time.Second
)

// A CommandBody is what a command orders: an admin's order for one member,
// signed like a record and never stored. A Command is signed the same way
// as a Record and has its form.
type CommandBody struct {
	V         int       `json:"v"`
	Type      string    `json:"type"`
	Group     string    `json:"group"`
	By        DeviceID  `json:"by"`
	To        DeviceID  `json:"to"`
	ID        string    `json:"id"` // 128 random bits in hex, for the receiver's replay cache
	TimeMS    int64     `json:"time_ms"`
	ExpiresMS int64     `json:"expires_ms"`
	Mode      string    `json:"mode,omitempty"` // mode: own, shared, receive or send
	Hub       *HubOrder `json:"hub,omitempty"`  // hub: how the receiver is the hub
}

// A HubOrder is what a hub command tells the new hub: where its clients
// reach it away from home (a forwarder, its own addresses, or both) and the
// clients of the old hub, each with the tunnel key and the preshared key it
// has, so that they move without meeting the new hub first.
type HubOrder struct {
	Forwarder *HubForwarder `json:"forwarder,omitempty"`
	Endpoints []string      `json:"endpoints,omitempty"` // "ip:port" or "[ipv6]:port"
	Clients   []HubClient   `json:"clients,omitempty"`
}

// HubForwarder is the forwarder of a hub command: its address and the pin
// of its key, as cbb global hub -forwarder and -forwarder-key take them.
type HubForwarder struct {
	Endpoint string `json:"endpoint"`
	Key      string `json:"key"`
}

// HubClient is a client the old hub hands over: its device, its WireGuard
// public key and its preshared key, 32 bytes each.
type HubClient struct {
	Device DeviceID `json:"device"`
	Key    []byte   `json:"key"`
	PSK    []byte   `json:"psk"`
}

// NewCommandID returns a random command ID.
func NewCommandID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SignCommand signs a command with key, a root's key (chain empty) or an
// admin CA key (chain holds the admin CA certificate).
func SignCommand(body CommandBody, key *ecdsa.PrivateKey, chain ...*x509.Certificate) (Record, error) {
	body.V = recordVersion
	if err := body.check(); err != nil {
		return Record{}, err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return Record{}, err
	}
	sum := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return Record{}, err
	}
	r := Record{Body: data, Sig: sig}
	for _, c := range chain {
		r.Chain = append(r.Chain, c.Raw)
	}
	return r, nil
}

func (b *CommandBody) check() error {
	switch {
	case b.V != recordVersion:
		return fmt.Errorf("group: unknown command version %d", b.V)
	case len(b.ID) != 32:
		return errors.New("group: a command has no valid ID")
	}
	if _, err := hex.DecodeString(b.ID); err != nil {
		return errors.New("group: a command has no valid ID")
	}
	switch b.Type {
	case CommandMode:
		if b.Mode == "" || b.Hub != nil {
			return errors.New("group: a mode command names no mode")
		}
	case CommandHub:
		if b.Hub == nil || b.Mode != "" {
			return errors.New("group: a hub command has no order")
		}
		if err := b.Hub.check(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("group: unknown command type %q", b.Type)
	}
	if _, err := ParseDeviceID(string(b.To)); err != nil {
		return err
	}
	if b.ExpiresMS <= b.TimeMS || b.ExpiresMS-b.TimeMS > CommandLifetime.Milliseconds() {
		return errors.New("group: a command's lifetime is not valid")
	}
	return nil
}

// VerifyCommand checks a command for the member self at the time now: its
// signer is an admin of the group now (a root on the path, or an admin CA
// under one that is neither revoked nor frozen), it is for self in this
// group, it has not expired, and it was not signed in the future. The
// caller keeps the replay cache.
func (s *Records) VerifyCommand(c Record, self DeviceID, now time.Time) (CommandBody, error) {
	var body CommandBody
	if len(c.Body) > maxCommandBody {
		return body, errors.New("group: the command is too large")
	}
	if err := json.Unmarshal(c.Body, &body); err != nil {
		return body, fmt.Errorf("group: a command: %w", err)
	}
	if err := body.check(); err != nil {
		return body, err
	}
	if body.Group != s.tag {
		return body, errors.New("group: the command is for another group")
	}
	if body.To != self {
		return body, errors.New("group: the command is for another device")
	}
	signer, anchor, err := s.signerOf(c)
	if err != nil {
		return body, err
	}
	if !s.onPath()[anchor] || s.Revoked(signer) || s.Frozen(signer) || !s.fromRoot(&signedRecord{signer: signer, anchor: anchor}) {
		return body, errors.New("group: the command's signer is not an admin of the group")
	}
	ms := now.UnixMilli()
	switch {
	case body.ExpiresMS <= ms:
		return body, errors.New("group: the command expired; check the clocks of both devices")
	case body.TimeMS > ms+CommandAhead.Milliseconds():
		return body, errors.New("group: the command was signed in the future; check the clocks of both devices")
	}
	return body, nil
}

func (o *HubOrder) check() error {
	switch {
	case o.Forwarder == nil && len(o.Endpoints) == 0:
		return errors.New("group: a hub command gives no forwarder and no address")
	case len(o.Endpoints) > 8:
		return errors.New("group: a hub command gives too many addresses")
	case len(o.Clients) > MaxHubClients:
		return errors.New("group: a hub command hands over too many clients")
	case o.Forwarder != nil && (o.Forwarder.Endpoint == "" || o.Forwarder.Key == ""):
		return errors.New("group: a hub command's forwarder has no address or key")
	}
	seen := make(map[DeviceID]bool, len(o.Clients))
	for _, c := range o.Clients {
		if _, err := ParseDeviceID(string(c.Device)); err != nil {
			return err
		}
		if seen[c.Device] {
			return fmt.Errorf("group: a hub command hands over %s twice", c.Device)
		}
		seen[c.Device] = true
		if len(c.Key) != 32 || len(c.PSK) != 32 {
			return fmt.Errorf("group: a hub command's keys for %s are not 32 bytes", c.Device)
		}
	}
	return nil
}
