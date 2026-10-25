// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package pair admits a new computer to a group with a six-digit code.
//
// An admin opens a pairing window: the group's root, a member the root (a
// computer or a phone) made an admin, or a key holder of a legacy group. The
// window has a code, valid for five minutes, one attempt at a time, closed
// after a success or the third failed attempt. The new device connects to the member's port
// over TLS 1.3 with the ALPN protocol clipboardbridge-pair/1 and presents a
// self-signed certificate for the key it will keep. Neither side can check
// the other's certificate yet; instead both run the CPace
// password-authenticated key exchange with the code, bound to this TLS
// session by an exporter and to both certificates. A device that does not
// know the code gets one guess per attempt and nothing to test guesses
// offline with, and a relay between two TLS sessions makes the exchange
// fail. Once both sides have confirmed the key, the member sends, over the
// same TLS session, a member certificate for the new device's key, the group
// CA and, to a Linux device, the keys of both CAs.
//
// The exchange, in frames of a 4-byte big-endian length and JSON:
//
//	joiner → member  {"msg": Ya, "ad": ADa}   CPace initiator
//	member → joiner  {"msg": Yb, "ad": ADb}   CPace responder, or {"error": code}
//	joiner → member  {"tag": Ta}               key confirmation, joiner first
//	member → joiner  {"tag": Tb, "welcome": …} or {"error": code}
//	joiner → member  {"ok": true}             or {"error": code}: stored or not
//
// The member checks the joiner's tag before it sends its own, so a device
// that guessed wrong learns only that it failed. Errors travel as short
// codes, never as text, so a peer that has not proved it knows the code
// cannot put words in front of the user.
//
// Sending the welcome is the point of no return: from then on the device
// holds a certificate, and, if it is a Linux member, the CA keys. The window
// records the device and closes, whether or not the device confirms that it
// stored its identity.
package pair

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// Protocol is the ALPN protocol of pairing connections.
const Protocol = "clipboardbridge-pair/1"

const (
	exporterLabel = "EXPERIMENTAL-clipboardbridge-pair-v1"
	channelPrefix = "clipboardbridge pair v1\x00"

	// Lifetime is how long a pairing window stays open, counting the time
	// the machine sleeps. An attempt that has started may finish after it.
	Lifetime = 5 * time.Minute
	// MaxFailures is the number of failed attempts that closes a window.
	MaxFailures = 3
	// MinSecret is the length in bytes of the shortest secret a remote
	// invitation may carry in place of a code: 128 bits.
	MinSecret = 16

	attemptTimeout = 30 * time.Second
	// firstTimeout is how long the joiner has for its first message once
	// it holds the window's one attempt: a device that only connects holds
	// it no longer than that.
	firstTimeout = 10 * time.Second
	// maxIdle is how many attempts from one address may end before they
	// count (without the joiner getting the member's CPace message); the
	// window refuses that address afterwards, as busy.
	maxIdle       = 5
	refuseTimeout = 10 * time.Second
	maxFrame      = 64 << 10
	maxNameLen    = 64
)

// Errors a pairing ends with.
var (
	ErrWrongCode = errors.New("pair: wrong code")
	ErrClosed    = errors.New("pair: the pairing window is closed")
	ErrBusy      = errors.New("pair: another device is pairing; try again in a minute")
	ErrExpired   = errors.New("pair: the pairing window expired")
	ErrTooMany   = errors.New("pair: three failed attempts; the pairing window is closed")
	ErrRefused   = errors.New("pair: the other device refused the pairing")
	ErrDeclined  = errors.New("pair: the admin did not confirm the device")
	ErrTaken     = errors.New("pair: a device with this device ID is in the group already; join with a new ID")
)

// spentError is an attempt that failed after the joiner sent its
// confirmation tag: the other side could check a guess of the code with it.
type spentError struct{ err error }

func (e *spentError) Error() string { return e.err.Error() }
func (e *spentError) Unwrap() error { return e.err }

// Spent reports whether a failed Join used up the code: the joiner sent its
// confirmation tag, so whoever answered could check a guess of the code.
// The joiner must not try the same code anywhere else then.
func Spent(err error) bool {
	var s *spentError
	return errors.As(err, &s)
}

// errorCodes are the errors that travel in frames, by their codes.
var errorCodes = map[string]error{
	"wrong-code": ErrWrongCode,
	"closed":     ErrClosed,
	"busy":       ErrBusy,
	"expired":    ErrExpired,
	"too-many":   ErrTooMany,
	"declined":   ErrDeclined,
	"taken":      ErrTaken,
}

// codeOf returns the code that tells the peer about err.
func codeOf(err error) string {
	for code, e := range errorCodes {
		if errors.Is(err, e) {
			return code
		}
	}
	return "refused"
}

// errorOf returns the error a code from the peer stands for. Anything
// unknown is ErrRefused: the peer's own words are never shown.
func errorOf(code string) error {
	if err, ok := errorCodes[code]; ok {
		return err
	}
	return ErrRefused
}

// NewCode returns a random six-digit code.
func NewCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err) // crypto/rand does not fail
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// NormalizeCode returns the code a user typed without spaces and dashes, or
// an error if it is not six digits.
func NormalizeCode(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, s)
	if len(s) != 6 || strings.Trim(s, "0123456789") != "" {
		return "", errors.New("pair: the code is six digits")
	}
	return s, nil
}

// Info describes the device that joins.
type Info struct {
	Name string `json:"name"` // shown in cbb status
	OS   string `json:"os"`   // group.OSLinux, OSWindows or OSMacOS; a lite member also OSNone
	// Role is RoleLite for a lite member, which never holds CA keys;
	// empty for a full computer.
	Role string `json:"role,omitempty"`
}

// RoleLite is the Info role of a lite member.
const RoleLite = "lite"

func (i Info) check() error {
	switch {
	case i.OS == group.OSLinux || i.OS == group.OSWindows || i.OS == group.OSMacOS:
	case i.OS == group.OSNone && i.Role == RoleLite:
	default:
		return fmt.Errorf("pair: unknown operating system %q", i.OS)
	}
	if i.Role != "" && i.Role != RoleLite {
		return fmt.Errorf("pair: unknown device role %q", i.Role)
	}
	if i.Name == "" || len(i.Name) > maxNameLen || !utf8.ValidString(i.Name) {
		return errors.New("pair: the device name must be 1 to 64 bytes of UTF-8")
	}
	for _, r := range i.Name {
		if !unicode.IsPrint(r) {
			return errors.New("pair: the device name has a control character")
		}
	}
	return nil
}

// holdsKeys reports whether the device gets the CA keys in a group a
// computer created: a Linux or Windows computer does.
func (i Info) holdsKeys() bool {
	return i.Role != RoleLite && (i.OS == group.OSLinux || i.OS == group.OSWindows)
}

// memberAD is the member's CPace associated data.
type memberAD struct {
	Device group.DeviceID `json:"device"`
	Group  string         `json:"group"` // group.Tag of the group CA
}

// Welcome is what a new device receives after a successful exchange.
type Welcome struct {
	Cert    []byte `json:"cert"`             // the new member certificate, DER
	Issuer  []byte `json:"issuer,omitempty"` // the admin CA that issued it, DER; absent when a root did
	GroupCA []byte `json:"group_ca"`         // DER: the group's first root, which names it
	// Roots are the roots that took a phone group over from GroupCA, in
	// order, DER; absent when it was never handed over.
	Roots [][]byte `json:"roots,omitempty"`
	// Records are the records that lead to Roots (group.PathRecords), by
	// which the new device checks that Roots are the group's and not ones
	// the admitting admin made up; absent with Roots.
	Records    []group.Record `json:"records,omitempty"`
	GroupCAKey []byte         `json:"group_ca_key,omitempty"`
	PhoneCA    []byte         `json:"phone_ca,omitempty"`
	PhoneCAKey []byte         `json:"phone_ca_key,omitempty"`
}

// frame is every message of the exchange; each uses some of the fields.
type frame struct {
	Msg     []byte   `json:"msg,omitempty"`
	AD      []byte   `json:"ad,omitempty"`
	Tag     []byte   `json:"tag,omitempty"`
	Welcome *Welcome `json:"welcome,omitempty"`
	Error   string   `json:"error,omitempty"` // a code from errorCodes, or "refused"
	OK      bool     `json:"ok,omitempty"`
}

func writeFrame(w io.Writer, f *frame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return errors.New("pair: frame too large")
	}
	buf := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(data)), uint32(len(data)))
	_, err = w.Write(append(buf, data...))
	return err
}

func readFrame(r io.Reader) (*frame, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > maxFrame {
		return nil, errors.New("pair: frame too large")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	var f frame
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("pair: bad frame: %w", err)
	}
	return &f, nil
}

// binding returns the CPace channel identifier and session identifier for
// a TLS session: both certificates, the member's first, and an exporter
// that only the two ends of this session can compute.
func binding(cs tls.ConnectionState, memberCert, joinerCert []byte) (ci, sid []byte, err error) {
	sid, err = cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil, nil, err
	}
	return channelID(memberCert, joinerCert), sid, nil
}

// channelID returns the CPace channel identifier for the two certificates,
// the member's first.
func channelID(memberCert, joinerCert []byte) []byte {
	m, j := sha256.Sum256(memberCert), sha256.Sum256(joinerCert)
	return append(append([]byte(channelPrefix), m[:]...), j[:]...)
}
