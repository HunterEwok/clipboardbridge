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

// CommandMode is the type of a command that sets the sync mode of one
// member (docs/protocol.md, section 15).
const CommandMode = "mode"

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
	V         int      `json:"v"`
	Type      string   `json:"type"`
	Group     string   `json:"group"`
	By        DeviceID `json:"by"`
	To        DeviceID `json:"to"`
	ID        string   `json:"id"` // 128 random bits in hex, for the receiver's replay cache
	TimeMS    int64    `json:"time_ms"`
	ExpiresMS int64    `json:"expires_ms"`
	Mode      string   `json:"mode,omitempty"` // mode: own, shared, receive or send
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
	case b.Type != CommandMode:
		return fmt.Errorf("group: unknown command type %q", b.Type)
	case b.Mode == "":
		return errors.New("group: a mode command names no mode")
	case len(b.ID) != 32:
		return errors.New("group: a command has no valid ID")
	}
	if _, err := hex.DecodeString(b.ID); err != nil {
		return errors.New("group: a command has no valid ID")
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
	if len(c.Body) > maxRecordBody {
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
