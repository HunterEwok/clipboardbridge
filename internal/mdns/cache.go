// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// maxEntries bounds the cache, so a flood of records cannot exhaust memory.
// A home group needs a few dozen.
const maxEntries = 1024

// A Peer is a member found by browsing.
type Peer struct {
	ID    string       // the first label of the service instance name
	Port  uint16       // from the SRV record
	TXT   []string     // the strings of the TXT record
	Addrs []netip.Addr // link-local IPv6 addresses carry the interface as zone
}

// TXTValue returns the value of key in a TXT record of key=value strings.
func (p Peer) TXTValue(key string) (string, bool) {
	for _, s := range p.TXT {
		if k, v, ok := strings.Cut(s, "="); ok && strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

type entry struct {
	res      dnsmessage.Resource
	zone     string // the interface a link-local address arrived on
	received time.Time
	expires  time.Time
	refresh  int // refresh queries sent: at 80 and 90 percent of the lifetime
}

// cache keeps the records of other members that browsing found.
type cache struct {
	entries []*entry
}

// relevant reports whether a record concerns clipbridge members: the
// service's PTR records, SRV and TXT records of its instances, and the
// addresses of member host names.
func relevant(r dnsmessage.Resource) bool {
	n := strings.ToLower(r.Header.Name.String())
	switch r.Body.(type) {
	case *dnsmessage.PTRResource:
		return n == ServiceName
	case *dnsmessage.SRVResource, *dnsmessage.TXTResource:
		return strings.HasSuffix(n, "."+ServiceName)
	case *dnsmessage.AResource, *dnsmessage.AAAAResource:
		return strings.HasPrefix(n, "cb-") && strings.HasSuffix(n, ".local.") && strings.Count(n, ".") == 2
	}
	return false
}

// add stores the records of a response that arrived on the interface named
// zone.
func (c *cache) add(msg *dnsmessage.Message, zone string, now time.Time) {
	records := append(slices.Clone(msg.Answers), msg.Additionals...)
	for _, r := range records {
		if !relevant(r) {
			continue
		}
		// A record with the cache-flush bit replaces the others of its
		// name and type that arrived more than a second ago (RFC 6762
		// section 10.2).
		if r.Header.Class&cacheFlush != 0 {
			for _, e := range c.entries {
				if sameRRSet(e.res, r) && now.Sub(e.received) > time.Second && e.expires.After(now.Add(time.Second)) {
					e.expires = now.Add(time.Second)
				}
			}
		}
		ttl := time.Duration(r.Header.TTL) * time.Second
		if r.Header.TTL == 0 {
			ttl = time.Second // a goodbye
		}
		e := &entry{res: r, received: now, expires: now.Add(ttl)}
		if _, ok := r.Body.(*dnsmessage.AAAAResource); ok {
			e.zone = zone
		}
		if i := slices.IndexFunc(c.entries, func(o *entry) bool { return sameRecord(o.res, r) && o.zone == e.zone }); i >= 0 {
			c.entries[i] = e
			continue
		}
		c.entries = append(c.entries, e)
	}
	if len(c.entries) > maxEntries {
		slices.SortFunc(c.entries, func(a, b *entry) int { return b.received.Compare(a.received) })
		c.entries = c.entries[:maxEntries]
	}
}

func sameRRSet(a, b dnsmessage.Resource) bool {
	return strings.EqualFold(a.Header.Name.String(), b.Header.Name.String()) &&
		a.Header.Class&^cacheFlush == b.Header.Class&^cacheFlush &&
		typeOf(a) == typeOf(b)
}

func typeOf(r dnsmessage.Resource) dnsmessage.Type {
	switch b := r.Body.(type) {
	case *dnsmessage.PTRResource:
		return dnsmessage.TypePTR
	case *dnsmessage.SRVResource:
		return dnsmessage.TypeSRV
	case *dnsmessage.TXTResource:
		return dnsmessage.TypeTXT
	case *dnsmessage.AResource:
		return dnsmessage.TypeA
	case *dnsmessage.AAAAResource:
		return dnsmessage.TypeAAAA
	case *dnsmessage.UnknownResource:
		return b.Type
	}
	return 0
}

// expire removes the records whose lifetime has ended.
func (c *cache) expire(now time.Time) {
	c.entries = slices.DeleteFunc(c.entries, func(e *entry) bool { return !now.Before(e.expires) })
}

// refresh returns the questions to ask so that the records of known members
// do not expire while the members are still there: at 80 and 90 percent of
// a record's lifetime, as RFC 6762 section 5.2 suggests.
func (c *cache) refresh(now time.Time) []dnsmessage.Question {
	var qs []dnsmessage.Question
	for _, e := range c.entries {
		life := e.expires.Sub(e.received)
		if e.res.Header.TTL == 0 || e.refresh >= 2 {
			continue
		}
		due := e.received.Add(life * time.Duration(8+e.refresh) / 10)
		if now.Before(due) {
			continue
		}
		e.refresh++
		q := dnsmessage.Question{Name: e.res.Header.Name, Type: typeOf(e.res), Class: classIN}
		if !slices.ContainsFunc(qs, func(o dnsmessage.Question) bool {
			return o.Type == q.Type && strings.EqualFold(o.Name.String(), q.Name.String())
		}) {
			qs = append(qs, q)
		}
	}
	return qs
}

// peers returns the members in the cache, except self, sorted by ID.
func (c *cache) peers(self string, now time.Time) []Peer {
	var out []Peer
	for _, e := range c.entries {
		ptr, ok := e.res.Body.(*dnsmessage.PTRResource)
		if !ok || !now.Before(e.expires) {
			continue
		}
		instance := strings.ToLower(ptr.PTR.String())
		id, rest, _ := strings.Cut(instance, ".")
		if rest != ServiceName || id == "" || id == strings.ToLower(self) {
			continue
		}
		if slices.ContainsFunc(out, func(p Peer) bool { return p.ID == id }) {
			continue
		}
		p := Peer{ID: id}
		var target string
		for _, f := range c.entries {
			if !now.Before(f.expires) || !strings.EqualFold(f.res.Header.Name.String(), instance) {
				continue
			}
			switch b := f.res.Body.(type) {
			case *dnsmessage.SRVResource:
				p.Port, target = b.Port, strings.ToLower(b.Target.String())
			case *dnsmessage.TXTResource:
				p.TXT = slices.Clone(b.TXT)
			}
		}
		if target == "" {
			continue
		}
		for _, f := range c.entries {
			if !now.Before(f.expires) || !strings.EqualFold(f.res.Header.Name.String(), target) {
				continue
			}
			var a netip.Addr
			switch b := f.res.Body.(type) {
			case *dnsmessage.AResource:
				a = netip.AddrFrom4(b.A)
			case *dnsmessage.AAAAResource:
				a = netip.AddrFrom16(b.AAAA)
				if a.IsLinkLocalUnicast() {
					a = a.WithZone(f.zone)
				}
			default:
				continue
			}
			if Published(a) && !slices.Contains(p.Addrs, a) {
				p.Addrs = append(p.Addrs, a)
			}
		}
		slices.SortFunc(p.Addrs, func(x, y netip.Addr) int { return x.Compare(y) })
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Peer) int { return strings.Compare(a.ID, b.ID) })
	return out
}
