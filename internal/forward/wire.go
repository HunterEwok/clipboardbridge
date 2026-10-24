// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/blake2s"
)

// WireGuard's message types and the sizes the forwarder looks at
// (the WireGuard paper, section 5.4).
const (
	msgInitiation = 1
	msgResponse   = 2
	msgCookie     = 3
	msgData       = 4

	initiationSize = 148
	responseSize   = 92
	cookieSize     = 64
	dataMinSize    = 32 // a keepalive: the header and the tag
)

// msgHello is the forwarder's own message, which a hub sends from its
// WireGuard port so that the forwarder learns where that port is reached.
// WireGuard's types use only the first byte, so it never takes this one.
const msgHello = 0x80

// helloSize is a hello's length: the type, the registration's ID, a
// counter and a MAC.
const helloSize = 4 + 8 + 8 + 16

// messageType returns a packet's type, or 0 for something that is neither
// WireGuard's nor a hello: the three bytes after the first are zero in
// every one of them.
func messageType(p []byte) byte {
	if len(p) < 4 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return 0
	}
	switch t := p[0]; {
	case t == msgInitiation && len(p) == initiationSize,
		t == msgResponse && len(p) == responseSize,
		t == msgCookie && len(p) == cookieSize,
		t == msgData && len(p) >= dataMinSize,
		t == msgHello && len(p) == helloSize:
		return t
	}
	return 0
}

// senderIndex returns the index the sender of a handshake message chose
// for its session.
func senderIndex(p []byte) uint32 { return binary.LittleEndian.Uint32(p[4:8]) }

// receiverIndex returns the index the receiver of a message chose: at 8 in
// a response, at 4 in a cookie reply and in data.
func receiverIndex(p []byte) uint32 {
	if p[0] == msgResponse {
		return binary.LittleEndian.Uint32(p[8:12])
	}
	return binary.LittleEndian.Uint32(p[4:8])
}

// mac1Key returns the key of the mac1 field in the handshake messages to
// the holder of the WireGuard public key pub: HASH("mac1----" || pub).
func mac1Key(pub [32]byte) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("mac1----"))
	h.Write(pub[:])
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// hasMac1 tells whether the handshake initiation p is addressed to the
// holder of the public key whose mac1Key is key: its mac1 field, the 16
// bytes before the last 16, is the keyed BLAKE2s of what comes before. It
// proves nothing about the sender: anyone who knows the public key can
// compute it.
func hasMac1(key *[32]byte, p []byte) bool {
	at := len(p) - 32
	h, _ := blake2s.New128(key[:])
	h.Write(p[:at])
	var mac [16]byte
	h.Sum(mac[:0])
	return hmac.Equal(mac[:], p[at:at+16])
}

// hello builds a hub's hello for the registration id: the counter only
// grows, so the forwarder takes a hello only once, and the MAC under the
// key that came with the registration proves the hello is the hub's.
func hello(key *[32]byte, id, counter uint64) []byte {
	p := make([]byte, helloSize)
	p[0] = msgHello
	binary.BigEndian.PutUint64(p[4:12], id)
	binary.BigEndian.PutUint64(p[12:20], counter)
	copy(p[20:], helloMAC(key, p[:20]))
	return p
}

func helloMAC(key *[32]byte, head []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write(head)
	return m.Sum(nil)[:16]
}

// readHello returns the registration and the counter of a hello, which
// the caller checks with checkHello under that registration's key.
func readHello(p []byte) (id, counter uint64) {
	return binary.BigEndian.Uint64(p[4:12]), binary.BigEndian.Uint64(p[12:20])
}

func checkHello(key *[32]byte, p []byte) bool {
	return hmac.Equal(helloMAC(key, p[:20]), p[20:])
}
