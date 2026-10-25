// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package netid tells networks apart: by an interface's networks and the
// link-layer address of its default gateway, so that a member publishes
// itself only on networks where it met the group before (docs/design.md,
// "Known networks").
package netid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
)

// ID returns the identity of a network: an HMAC under key, so that the
// list of known networks says nothing about them, of the interface's IPv4
// networks (its IPv6 networks when it has none, as ISPs change IPv6
// prefixes) and gw, the link-layer address of its gateway or "".
func ID(key []byte, prefixes []netip.Prefix, gw string) string {
	var four, six []string
	for _, p := range prefixes {
		a := p.Addr().Unmap()
		switch {
		case a.IsLoopback(), a.IsLinkLocalUnicast(), !a.IsValid():
		case a.Is4():
			four = append(four, netip.PrefixFrom(a, p.Bits()).Masked().String())
		default:
			six = append(six, netip.PrefixFrom(a, p.Bits()).Masked().String())
		}
	}
	nets := four
	if len(nets) == 0 {
		nets = six
	}
	if len(nets) == 0 {
		return ""
	}
	slices.Sort(nets)
	nets = slices.Compact(nets)
	m := hmac.New(sha256.New, key)
	for _, n := range nets {
		m.Write([]byte(n))
		m.Write([]byte{0})
	}
	m.Write([]byte(gw))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// Gateways returns the link-layer address of the IPv4 default gateway of
// each interface that has one, by interface index, as lowercase hex
// separated by colons. An interface whose gateway's address is not known
// yet is left out. It is empty where the system does not tell.
func Gateways() map[int]string {
	m, err := gateways()
	if err != nil || m == nil {
		return map[int]string{}
	}
	return m
}
