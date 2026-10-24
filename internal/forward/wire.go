// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
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

// msgHello starts the forwarder's own message, which a hub sends from its
// WireGuard port so that the forwarder learns where that port is reached.
const msgHello = 0x80

// helloSize is a hello's length before its mask: the type, the
// registration's ID, a counter and a MAC. On the wire it has the mask's
// nonce in front and up to helloTail random bytes behind, and nothing in it
// stays the same from one hello to the next.
const (
	helloSize = 4 + 8 + 8 + 16
	helloTail = 32
	helloMin  = headerNonceSize + helloSize
)

// messageType returns a plain WireGuard packet's type, or 0 for anything
// else: the three bytes after the first are zero in every message.
func messageType(p []byte) byte {
	if len(p) < 4 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return 0
	}
	switch t := p[0]; {
	case t == msgInitiation && len(p) == initiationSize,
		t == msgResponse && len(p) == responseSize,
		t == msgCookie && len(p) == cookieSize,
		t == msgData && len(p) >= dataMinSize:
		return t
	}
	return 0
}

// senderIndex returns the index the sender of a handshake message chose
// for its session.
func senderIndex(p []byte) uint32 { return binary.LittleEndian.Uint32(p[4:8]) }

// receiverIndex returns the index the receiver of a message of type t
// chose: at 8 in a response, at 4 in a cookie reply and in data.
func receiverIndex(t byte, p []byte) uint32 {
	if t == msgResponse {
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
// key that came with the registration proves the hello is the hub's. The
// whole hello is masked with ChaCha20 under the forwarder's mask key and a
// random nonce, so that the network sees random bytes of a random length.
func hello(mask, key *[32]byte, id, counter uint64) []byte {
	var tail [1]byte
	rand.Read(tail[:])
	p := make([]byte, helloMin+int(tail[0])%helloTail)
	rand.Read(p)
	h := p[headerNonceSize:helloMin]
	h[0], h[1], h[2], h[3] = msgHello, 0, 0, 0
	binary.BigEndian.PutUint64(h[4:12], id)
	binary.BigEndian.PutUint64(h[12:20], counter)
	copy(h[20:], helloMAC(key, h[:20]))
	c, err := chacha20.NewUnauthenticatedCipher(mask[:], p[:headerNonceSize])
	if err != nil {
		panic(err) // the key and the nonce have their sizes
	}
	c.XORKeyStream(h, h)
	return p
}

// openHello takes the mask off p and returns the hello in it, which the
// caller reads with readHello and checks with checkHello; false if p is no
// hello.
func openHello(mask *[32]byte, p []byte) ([]byte, bool) {
	if len(p) < helloMin || len(p) >= helloMin+helloTail {
		return nil, false
	}
	c, err := chacha20.NewUnauthenticatedCipher(mask[:], p[:headerNonceSize])
	if err != nil {
		return nil, false
	}
	h := make([]byte, helloSize)
	c.XORKeyStream(h, p[headerNonceSize:helloMin])
	if h[0] != msgHello || h[1] != 0 || h[2] != 0 || h[3] != 0 {
		return nil, false
	}
	return h, true
}

func helloMAC(key *[32]byte, head []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write(head)
	return m.Sum(nil)[:16]
}

// readHello returns the registration and the counter of a hello.
func readHello(h []byte) (id, counter uint64) {
	return binary.BigEndian.Uint64(h[4:12]), binary.BigEndian.Uint64(h[12:20])
}

func checkHello(key *[32]byte, h []byte) bool {
	return hmac.Equal(helloMAC(key, h[:20]), h[20:])
}
