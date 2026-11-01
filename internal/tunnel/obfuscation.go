// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// Obfuscation is a group's AmneziaWG settings, for networks that block
// WireGuard (docs/design.md, "Blocked networks"). The hub makes them, keeps
// them, and gives them to each client in its offer; both ends must use the
// same ones. They hide what the packets are, not what they carry: the
// security is WireGuard's and the member TLS's, with or without them, so
// they are not a secret the tunnel relies on.
//
// The JSON names are AmneziaWG's own (amneziawg-go's UAPI).
type Obfuscation struct {
	// Junk packets of random bytes before each handshake: JC of them, each
	// JMin to JMax bytes long.
	JC   int `json:"jc"`
	JMin int `json:"jmin"`
	JMax int `json:"jmax"`

	// Random bytes in front of the handshake initiation (S1), the
	// response (S2), the cookie reply (S3) and every data message (S4).
	S1 int `json:"s1"`
	S2 int `json:"s2"`
	S3 int `json:"s3"`
	S4 int `json:"s4"`

	// The ranges each message's type field is drawn from, instead of
	// WireGuard's 1 to 4: H1 for the initiation, H2 the response, H3 the
	// cookie reply, H4 data. They do not overlap.
	H1 Range `json:"h1"`
	H2 Range `json:"h2"`
	H3 Range `json:"h3"`
	H4 Range `json:"h4"`

	// HeaderKey encrypts the rest of each message's header, the session
	// indices among it, with the padding in front as the nonce.
	HeaderKey Key `json:"header_protection_key"`
}

// Range is an inclusive range of a message's type field, [Min, Max].
type Range struct {
	Min uint32
	Max uint32
}

// MarshalText writes r as AmneziaWG does: "min-max".
func (r Range) MarshalText() ([]byte, error) {
	return fmt.Appendf(nil, "%d-%d", r.Min, r.Max), nil
}

// UnmarshalText reads "min-max": two decimal numbers of 32 bits, without
// a sign or a leading zero, the first not above the second. Nothing else
// is taken, so that every implementation reads one text alike.
func (r *Range) UnmarshalText(b []byte) error {
	lo, hi, ok := strings.Cut(string(b), "-")
	min, err1 := parseUint32(lo)
	max, err2 := parseUint32(hi)
	if !ok || err1 != nil || err2 != nil || min > max {
		return fmt.Errorf("tunnel: %q is not a range such as 100-200", b)
	}
	r.Min, r.Max = min, max
	return nil
}

// parseUint32 reads a decimal number of 32 bits in its shortest form.
func parseUint32(s string) (uint32, error) {
	if s == "" || len(s) > 10 || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("not a number")
	}
	var n uint64
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + uint64(c-'0')
	}
	if n > math.MaxUint32 {
		return 0, errors.New("not a number")
	}
	return uint32(n), nil
}

func (r Range) overlaps(o Range) bool { return r.Min <= o.Max && o.Min <= r.Max }

// Contains tells whether v is in r.
func (r Range) Contains(v uint32) bool { return r.Min <= v && v <= r.Max }

// The bounds Check holds the settings to. The junk stays well under the
// smallest MTU on the way, so it is never fragmented, and the padding
// leaves room for the tunnel's MTU in a 1500-byte packet.
const (
	maxJunkCount = 16
	maxJunkSize  = 1000
	maxPadding   = 64
	minPadding   = 16 // at least the header protection's random nonce, 12 bytes
)

// NewObfuscation returns new random settings for a group.
func NewObfuscation() (*Obfuscation, error) {
	o := &Obfuscation{}
	var err error
	num := func(lo, hi int) int {
		if err != nil {
			return lo
		}
		var n *big.Int
		n, err = rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
		if err != nil {
			return lo
		}
		return lo + int(n.Int64())
	}
	o.JC = num(3, 8)
	o.JMin = num(40, 100)
	o.JMax = o.JMin + num(100, 500)
	for {
		o.S1, o.S2, o.S3, o.S4 = num(minPadding, maxPadding), num(minPadding, maxPadding), num(minPadding, 32), num(minPadding, 32)
		if err != nil || o.sizesDiffer() {
			break
		}
	}
	// Each header gets its own quarter of the space above WireGuard's types,
	// in a random order, and a random range inside it.
	quarters := []int{0, 1, 2, 3}
	for i := len(quarters) - 1; i > 0; i-- {
		j := num(0, i)
		quarters[i], quarters[j] = quarters[j], quarters[i]
	}
	ranges := make([]Range, 4)
	for i, q := range quarters {
		lo := uint32(q)<<30 + 16
		width := uint32(1) << num(16, 24)
		start := lo + uint32(num(0, 1<<29))
		ranges[i] = Range{Min: start, Max: start + width - 1}
	}
	o.H1, o.H2, o.H3, o.H4 = ranges[0], ranges[1], ranges[2], ranges[3]
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	if o.HeaderKey, err = NewPresharedKey(); err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	if err := o.Check(); err != nil {
		return nil, err
	}
	return o, nil
}

// sizesDiffer tells whether the three handshake messages still have three
// different sizes once padded, so that their size does not mix them up.
func (o *Obfuscation) sizesDiffer() bool {
	a, b, c := 148+o.S1, 92+o.S2, 64+o.S3
	return a != b && a != c && b != c
}

// Check refuses settings that would not work or that a hub should not
// hand out.
func (o *Obfuscation) Check() error {
	switch {
	case o.JC < 0 || o.JC > maxJunkCount:
		return fmt.Errorf("tunnel: obfuscation: %d junk packets, more than %d", o.JC, maxJunkCount)
	case o.JMin < 0 || o.JMin > o.JMax || o.JMax > maxJunkSize:
		return fmt.Errorf("tunnel: obfuscation: junk of %d to %d bytes", o.JMin, o.JMax)
	case o.HeaderKey.IsZero():
		return errors.New("tunnel: obfuscation: no header protection key")
	case !o.sizesDiffer():
		return errors.New("tunnel: obfuscation: two handshake messages have the same size")
	}
	for i, s := range []int{o.S1, o.S2, o.S3, o.S4} {
		if s < minPadding || s > maxPadding {
			return fmt.Errorf("tunnel: obfuscation: s%d is %d, not %d to %d", i+1, s, minPadding, maxPadding)
		}
	}
	hs := []Range{o.H1, o.H2, o.H3, o.H4}
	for i, h := range hs {
		if h.Min > h.Max || h.Min <= msgData {
			return fmt.Errorf("tunnel: obfuscation: h%d is %d-%d", i+1, h.Min, h.Max)
		}
		for j := i + 1; j < len(hs); j++ {
			if h.overlaps(hs[j]) {
				return fmt.Errorf("tunnel: obfuscation: h%d and h%d overlap", i+1, j+1)
			}
		}
	}
	return nil
}

// msgData is WireGuard's highest message type; the headers stay above it.
const msgData = 4

// ipc is the settings in amneziawg-go's UAPI, to set on a device before
// its peers. Unset, nil, the device speaks plain WireGuard.
func (o *Obfuscation) ipc() string {
	if o == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\n", o.JC, o.JMin, o.JMax, o.S1, o.S2, o.S3, o.S4)
	for i, h := range []Range{o.H1, o.H2, o.H3, o.H4} {
		fmt.Fprintf(&b, "h%d=%d-%d\n", i+1, h.Min, h.Max)
	}
	fmt.Fprintf(&b, "header_protection_key=%s\n", o.HeaderKey.hex())
	return b.String()
}

// Equal tells whether o and p are the same settings; nil is plain
// WireGuard.
func (o *Obfuscation) Equal(p *Obfuscation) bool {
	if o == nil || p == nil {
		return o == p
	}
	return *o == *p
}
