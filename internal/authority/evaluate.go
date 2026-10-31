// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sort"

	"github.com/HunterEwok/clipboardbridge/internal/strict"
)

// Input is what the evaluation takes (docs/records-v2.md, "The state").
type Input struct {
	// GroupCA is the group's first root; its tag is Group.
	GroupCA *x509.Certificate
	Group   string
	Records []Record
	// NowMS is the member's clock, which counts sleep and does not jump,
	// and FirstSeen the time on that clock when the member first held
	// each claim, by record ID; a claim missing from it was first held
	// now.
	NowMS     int64
	FirstSeen map[Hash]int64
}

// rec is a verified record with what the evaluation finds about it.
type rec struct {
	*Signed
	issuer Hash // the root that issued the admin CA; zero for a root's own record
	label  label
}

type label int

const (
	unlabelled label = iota
	in
	out
	undecided
)

// Evaluate turns a record set into the group's state. It drops records
// that do not verify, and depends only on the set, never on its order.
func Evaluate(input Input) (*State, error) {
	if input.GroupCA == nil {
		return nil, errors.New("authority: no group CA")
	}
	e := newEvaluation(input)
	path, cuts := []Hash{KeyHashOf(input.GroupCA)}, map[Hash]int64{}
	var ep *epoch
	var earlier []Claim // the claims of the roots before the current one
	for {
		ep = e.epoch(path, cuts)
		next, cut := ep.decideClaims(input.NowMS, input.FirstSeen)
		if next == nil {
			break
		}
		earlier = append(earlier, ep.claims...)
		cuts[path[len(path)-1]] = cut
		path = append(path, *next)
	}
	ep.claims = append(earlier, ep.claims...)
	return ep.state(), nil
}

// evaluation holds the verified records of a set.
type evaluation struct {
	roots   map[Hash]*x509.Certificate // every root the group may have
	bySig   map[Hash][]*rec            // records by signer
	devices map[string][]*rec          // device records by device ID
}

func newEvaluation(input Input) *evaluation {
	e := &evaluation{roots: map[Hash]*x509.Certificate{KeyHashOf(input.GroupCA): input.GroupCA}, bySig: map[Hash][]*rec{}, devices: map[string][]*rec{}}
	// The new roots of claims are the only other roots a record may be
	// signed under; a claim itself is signed by an admin CA.
	for _, r := range input.Records {
		if len(r.Chain) != 1 {
			continue
		}
		if b, err := ParseBody(r.Body); err == nil && b.Type == TypeClaim {
			if c, err := x509.ParseCertificate(b.Root); err == nil && checkRoot(c) == nil {
				e.roots[KeyHashOf(c)] = c
			}
		}
	}
	rootKey := func(h Hash) crypto.PublicKey {
		if c := e.roots[h]; c != nil {
			return c.PublicKey
		}
		return nil
	}
	seen := map[Hash]bool{}
	for _, r := range input.Records {
		s, err := Verify(r, rootKey)
		if err != nil || s.Body.Group != input.Group || seen[s.ID] {
			continue
		}
		x := &rec{Signed: s}
		if s.AdminCA != nil {
			issuer, ok := e.issuerOf(s.AdminCA)
			if !ok {
				continue
			}
			x.issuer = issuer
		}
		seen[s.ID] = true
		e.bySig[s.Body.Signer] = append(e.bySig[s.Body.Signer], x)
		if s.Body.Type == TypeDevice {
			e.devices[s.Body.Device] = append(e.devices[s.Body.Device], x)
		}
	}
	return e
}

// issuerOf finds the root that issued an admin CA.
func (e *evaluation) issuerOf(c *x509.Certificate) (Hash, bool) {
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return Hash{}, false
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return Hash{}, false
	}
	for h, root := range e.roots {
		if c.CheckSignatureFrom(root) == nil {
			return h, true
		}
	}
	return Hash{}, false
}

// checkRoot checks a claim's new root: self-signed, a CA with path
// length 1 and a P-256 key.
func checkRoot(c *x509.Certificate) error {
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 1 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("authority: a new root is not a CA with path length 1")
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return errors.New("authority: a new root's key is not a P-256 key")
	}
	if c.CheckSignatureFrom(c) != nil {
		return errors.New("authority: a new root is not self-signed")
	}
	return nil
}

// epoch is the evaluation under one path of roots.
type epoch struct {
	e      *evaluation
	path   []Hash
	onPath map[Hash]int // position on the path
	cuts   map[Hash]int64
	cur    Hash

	voided  map[Hash]bool
	counted map[Hash]bool // records whose chain is whole, before any fork, not voided
	forked  map[Hash]int64

	admins    map[Hash]*rec // each admin key's newest root record naming it
	revoked   map[Hash]bool
	frozen    map[Hash]bool
	conflicts []Conflict
	claims    []Claim
	stopFull  bool
	pending   *Hash // the claimant of a pending claim
}

func (e *evaluation) epoch(path []Hash, cuts map[Hash]int64) *epoch {
	ep := &epoch{e: e, path: path, onPath: map[Hash]int{}, cuts: cuts, cur: path[len(path)-1], forked: map[Hash]int64{}}
	for i, h := range path {
		ep.onPath[h] = i
	}
	ep.voided = ep.voids()
	ep.counted = map[Hash]bool{}
	for signer, rs := range e.bySig {
		ep.chain(signer, rs)
	}
	ep.findAdmins()
	ep.label()
	ep.collect()
	return ep
}

// rootRecord reports whether r is a root's own record that counts in this
// epoch: its root is on the path and it is within that root's cut.
func (ep *epoch) rootRecord(r *rec) bool {
	if r.AdminCA != nil || !ep.counted[r.ID] {
		return false
	}
	if _, ok := ep.onPath[r.Body.Signer]; !ok {
		return false
	}
	if cut, ok := ep.cuts[r.Body.Signer]; ok && r.Body.Seq > cut {
		return false
	}
	return true
}

// voids returns the records the current root's resolve records name. A
// resolve counts here when its own chain is whole, whatever forks it has,
// so the root can end two histories of its own.
func (ep *epoch) voids() map[Hash]bool {
	v := map[Hash]bool{}
	byID := map[Hash]*rec{}
	for _, r := range ep.e.bySig[ep.cur] {
		byID[r.ID] = r
	}
	for _, r := range ep.e.bySig[ep.cur] {
		if r.AdminCA != nil || r.Body.Type != TypeResolve || !whole(r, byID) {
			continue
		}
		for _, id := range r.Body.Records {
			v[id] = true
		}
	}
	return v
}

// whole reports whether r's prev chain down to seq 1 is held, each step
// one seq lower.
func whole(r *rec, byID map[Hash]*rec) bool {
	for steps := 0; r.Body.Seq > 1; steps++ {
		p := byID[*r.Body.Prev]
		if p == nil || p.Body.Seq != r.Body.Seq-1 || steps > MaxSeq {
			return false
		}
		r = p
	}
	return true
}

// chain finds which of one signer's records count: whole chains, not on a
// branch that a resolve voided, below the lowest seq with two records.
func (ep *epoch) chain(signer Hash, rs []*rec) {
	byID, bySeq := map[Hash]*rec{}, map[int64][]*rec{}
	for _, r := range rs {
		byID[r.ID] = r
		bySeq[r.Body.Seq] = append(bySeq[r.Body.Seq], r)
	}
	// A voided record with a sibling ends its branch.
	dead := func(r *rec) bool {
		for {
			if ep.voided[r.ID] && len(bySeq[r.Body.Seq]) > 1 {
				return true
			}
			if r.Body.Seq == 1 {
				return false
			}
			r = byID[*r.Body.Prev]
		}
	}
	live := map[int64][]*rec{}
	for _, r := range rs {
		if whole(r, byID) && !dead(r) {
			live[r.Body.Seq] = append(live[r.Body.Seq], r)
		}
	}
	fork := int64(MaxSeq + 1)
	for seq, l := range live {
		if len(l) > 1 && seq < fork {
			fork = seq
		}
	}
	if fork <= MaxSeq {
		ep.forked[signer] = fork
	}
	for seq, l := range live {
		for _, r := range l {
			if seq < fork && !ep.voided[r.ID] {
				ep.counted[r.ID] = true
			}
		}
	}
}

// newer reports whether root record a is newer than b: a later root on the
// path, then a higher seq.
func (ep *epoch) newer(a, b *rec) bool {
	if pa, pb := ep.onPath[a.Body.Signer], ep.onPath[b.Body.Signer]; pa != pb {
		return pa > pb
	}
	return a.Body.Seq > b.Body.Seq
}

// findAdmins finds the admin keys: the admin of a device record a root on
// the path signed, with the powers of the newest such record.
func (ep *epoch) findAdmins() {
	ep.admins = map[Hash]*rec{}
	for _, rs := range ep.e.devices {
		for _, r := range rs {
			if r.Body.Admin == nil || !ep.rootRecord(r) {
				continue
			}
			if old := ep.admins[*r.Body.Admin]; old == nil || ep.newer(r, old) {
				ep.admins[*r.Body.Admin] = r
			}
		}
	}
}

func (ep *epoch) has(admin Hash, power string) bool {
	r := ep.admins[admin]
	if r == nil {
		return false
	}
	i := sort.SearchStrings(r.Body.Powers, power)
	return i < len(r.Body.Powers) && r.Body.Powers[i] == power
}

// isAdmin reports whether k is an admin key or the member key of a device
// whose newest root record names one: what only remove-admins removes.
func (ep *epoch) isAdmin(k Hash) bool {
	if ep.admins[k] != nil {
		return true
	}
	for _, r := range ep.admins {
		if *r.Body.Key == k {
			return true
		}
	}
	return false
}

// isRoot reports whether k is a root key or the member key of the root's
// own device, which nobody removes.
func (ep *epoch) isRoot(k Hash) bool {
	if ep.e.roots[k] != nil {
		return true
	}
	if d := ep.rootDevice(); d != nil && *d.Body.Key == k {
		return true
	}
	return false
}

// rootDevice returns the current root's newest device record with
// holds_root.
func (ep *epoch) rootDevice() *rec {
	var best *rec
	for _, r := range ep.e.bySig[ep.cur] {
		if r.Body.Type == TypeDevice && r.Body.HoldsRoot && ep.rootRecord(r) && (best == nil || r.Body.Seq > best.Body.Seq) {
			best = r
		}
	}
	return best
}

// permitted reports whether an admin may sign r (docs/records-v2.md, "Who
// signs what").
func (ep *epoch) permitted(r *rec) bool {
	a := r.Body.Signer
	if _, ok := ep.onPath[r.issuer]; !ok || ep.admins[a] == nil {
		return false
	}
	b := &r.Body
	switch b.Type {
	case TypeDevice:
		return ep.has(a, PowerAdmit) && b.Admin == nil && !b.HoldsRoot && b.Role != "phone" && b.Role != "watch"
	case TypeRevoke:
		for _, k := range b.Keys {
			switch {
			case ep.isRoot(k):
				return false
			case ep.isAdmin(k) && !ep.has(a, PowerRemoveAdmins):
				return false
			case !ep.isAdmin(k) && !ep.has(a, PowerRemove):
				return false
			}
		}
		return true
	case TypeFreeze:
		if !ep.has(a, PowerFreeze) {
			return false
		}
		for _, k := range b.Keys {
			if ep.admins[k] == nil || ep.has(k, PowerRemoveAdmins) {
				return false
			}
		}
		return true
	case TypeThaw:
		return ep.has(a, PowerThaw) && ep.has(a, PowerRemoveAdmins)
	case TypeClaim:
		return ep.has(a, PowerTakeover) && r.issuer == ep.cur
	}
	return false
}

// seenOf returns a record's seen entry for k, 0 when it names none.
func seenOf(b *Body, k Hash) int64 {
	for _, s := range b.Seen {
		if s.Key == k {
			return s.Seq
		}
	}
	return 0
}

// cuts reports whether a, a revoke or freeze, cuts off b: it names b's
// signer and saw fewer of its records than b's seq.
func cutsOff(a, b *rec) bool {
	if a.Body.Signer == b.Body.Signer || a.Body.Type != TypeRevoke && a.Body.Type != TypeFreeze {
		return false
	}
	i := sort.Search(len(a.Body.Keys), func(i int) bool { return a.Body.Keys[i].String() >= b.Body.Signer.String() })
	return i < len(a.Body.Keys) && a.Body.Keys[i] == b.Body.Signer && seenOf(&a.Body, b.Body.Signer) < b.Body.Seq
}

// label gives every admin record its label: the grounded labelling of the
// attacks of removals, freezes and thaws (docs/records-v2.md, "Which admin
// records count").
func (ep *epoch) label() {
	var adminRecs, rootActs []*rec
	thawedByRoot := map[Hash]bool{}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			switch {
			case ep.rootRecord(r):
				if r.Body.Type == TypeThaw {
					for _, id := range r.Body.Records {
						thawedByRoot[id] = true
					}
				}
			case r.AdminCA != nil && ep.counted[r.ID]:
				r.label = unlabelled
				if !ep.permitted(r) {
					r.label = out
				}
				adminRecs = append(adminRecs, r)
			}
		}
	}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if ep.rootRecord(r) && (r.Body.Type == TypeRevoke || r.Body.Type == TypeFreeze && !thawedByRoot[r.ID]) {
				rootActs = append(rootActs, r)
			}
		}
	}
	// A root's removal or freeze puts what it cuts off out for good, and
	// a root's thaw puts out the admin freezes it names.
	for _, b := range adminRecs {
		if b.Body.Type == TypeFreeze && thawedByRoot[b.ID] {
			b.label = out
		}
		for _, a := range rootActs {
			if cutsOff(a, b) {
				b.label = out
			}
		}
	}
	attackers := map[*rec][]*rec{}
	for _, b := range adminRecs {
		for _, a := range adminRecs {
			if a.label == out {
				continue
			}
			// An admin's removal of a claimant does not cut its claim:
			// decideClaims sees it as a dispute.
			if cutsOff(a, b) && b.Body.Type != TypeClaim || a.Body.Type == TypeThaw && b.Body.Type == TypeFreeze && contains(a.Body.Records, b.ID) {
				attackers[b] = append(attackers[b], a)
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, b := range adminRecs {
			if b.label != unlabelled {
				continue
			}
			all := true
			for _, a := range attackers[b] {
				if a.label == in {
					b.label, changed = out, true
					break
				}
				if a.label != out {
					all = false
				}
			}
			if b.label == unlabelled && all {
				b.label, changed = in, true
			}
		}
	}
	var undec []*rec
	for _, b := range adminRecs {
		if b.label == unlabelled {
			b.label = undecided
			if b.Body.Type == TypeRevoke || b.Body.Type == TypeFreeze || b.Body.Type == TypeThaw {
				undec = append(undec, b)
			}
		}
	}
	ep.conflictsOf(undec, attackers)
}

func contains(hs []Hash, h Hash) bool {
	for _, x := range hs {
		if x == h {
			return true
		}
	}
	return false
}

// conflictsOf groups undecided records that attack each other into
// conflicts.
func (ep *epoch) conflictsOf(undec []*rec, attackers map[*rec][]*rec) {
	parent := map[*rec]*rec{}
	find := func(r *rec) *rec {
		for parent[r] != nil && parent[r] != r {
			r = parent[r]
		}
		return r
	}
	for _, r := range undec {
		parent[r] = r
	}
	for _, b := range undec {
		for _, a := range attackers[b] {
			if parent[a] != nil {
				parent[find(a)] = find(b)
			}
		}
	}
	byRoot := map[*rec][]*rec{}
	for _, r := range undec {
		byRoot[find(r)] = append(byRoot[find(r)], r)
	}
	for _, rs := range byRoot {
		c := Conflict{Kind: "admins"}
		signers := map[Hash]bool{}
		for _, r := range rs {
			c.Records = append(c.Records, r.ID)
			signers[r.Body.Signer] = true
		}
		for s := range signers {
			c.Signers = append(c.Signers, s)
		}
		ep.conflicts = append(ep.conflicts, c)
		ep.stopFull = true
	}
}

// counts reports whether r counts: a root's record in this epoch, or an
// admin record that is in.
func (ep *epoch) counts(r *rec) bool {
	return ep.rootRecord(r) || r.AdminCA != nil && r.label == in
}

// collect finds the revoked and frozen keys and the two histories.
func (ep *epoch) collect() {
	ep.revoked, ep.frozen = map[Hash]bool{}, map[Hash]bool{}
	// A root's thaw ends any freeze; an admin's only an admin's, which
	// the labelling already put out.
	thawed := map[Hash]bool{}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.Body.Type == TypeThaw && ep.rootRecord(r) {
				for _, id := range r.Body.Records {
					thawed[id] = true
				}
			}
		}
	}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if !ep.counts(r) {
				continue
			}
			switch r.Body.Type {
			case TypeRevoke:
				for _, k := range r.Body.Keys {
					ep.revoked[k] = true
				}
			case TypeFreeze:
				if !thawed[r.ID] {
					for _, k := range r.Body.Keys {
						ep.frozen[k] = true
					}
				}
			}
		}
	}
	for signer := range ep.forked {
		c := Conflict{Kind: "two_histories", Signers: []Hash{signer}}
		for _, r := range ep.e.bySig[signer] {
			if r.Body.Seq == ep.forked[signer] {
				c.Records = append(c.Records, r.ID)
			}
		}
		ep.conflicts = append(ep.conflicts, c)
		if _, root := ep.onPath[signer]; root {
			ep.stopFull = true
		}
	}
}

// decideClaims looks at the claims under the current root and returns the
// next root and the current root's cut when one takes effect.
func (ep *epoch) decideClaims(now int64, firstSeen map[Hash]int64) (*Hash, int64) {
	delay := int64(DefaultDelay)
	var settings *rec
	for _, r := range ep.e.bySig[ep.cur] {
		if r.Body.Type == TypeSettings && ep.rootRecord(r) && (settings == nil || r.Body.Seq > settings.Body.Seq) {
			settings = r
		}
	}
	if settings != nil && settings.Body.TakeoverDelayMS != nil {
		delay = *settings.Body.TakeoverDelayMS
	}
	cancelled := func(c *rec) bool {
		for _, r := range ep.e.bySig[ep.cur] {
			if !ep.rootRecord(r) {
				continue
			}
			if r.Body.Type == TypeResolve && contains(r.Body.Records, c.ID) || r.Body.Type == TypeRevoke && contains(r.Body.Keys, c.Body.Signer) {
				return true
			}
		}
		return false
	}
	var live []*rec
	for _, rs := range ep.e.bySig {
		for _, c := range rs {
			if c.Body.Type != TypeClaim || c.AdminCA == nil || c.issuer != ep.cur || !ep.counted[c.ID] && !ep.voided[c.ID] {
				continue
			}
			root, _ := x509.ParseCertificate(c.Body.Root)
			cl := Claim{Record: c.ID, Claimant: c.Body.Signer}
			if root != nil {
				cl.Root = KeyHashOf(root)
			}
			switch {
			case root == nil || ep.e.roots[cl.Root] == nil || cl.Root == ep.path[0]:
				cl.State = "void"
			case cancelled(c):
				cl.State = "cancelled"
			case c.label == out:
				cl.State = "void"
			default:
				if _, again := ep.onPath[cl.Root]; again {
					cl.State = "void"
				} else {
					live = append(live, c)
				}
			}
			if cl.State != "" {
				ep.claims = append(ep.claims, cl)
			}
		}
	}
	// An admin's removal or freeze of a claimant that the claimant had
	// seen voids its claim; one the claimant had not seen disputes it,
	// unless its author had seen a record of the claimed root, so wrote it
	// after the handover: that one counts under the new root.
	disputes := map[*rec][]*rec{}
	var kept []*rec
	for _, c := range live {
		void := false
		for _, r := range ep.removals(c.Body.Signer) {
			switch {
			case seenOf(&c.Body, r.Body.Signer) >= r.Body.Seq:
				void = true
			case seenOf(&r.Body, claimRoot(c)) == 0:
				disputes[c] = append(disputes[c], r)
			}
		}
		if void {
			ep.claims = append(ep.claims, Claim{Record: c.ID, Claimant: c.Body.Signer, Root: claimRoot(c), State: "void"})
		} else {
			kept = append(kept, c)
		}
	}
	live = kept
	// One claim at a time: a claim whose author held another live claim
	// counts for nothing.
	var first []*rec
	for _, c := range live {
		later := false
		for _, o := range live {
			if o != c && seenOf(&c.Body, o.Body.Signer) >= o.Body.Seq {
				later = true
			}
		}
		if later {
			ep.claims = append(ep.claims, Claim{Record: c.ID, Claimant: c.Body.Signer, Root: claimRoot(c), State: "void"})
		} else {
			first = append(first, c)
		}
	}
	live = first
	if len(live) > 1 {
		c := Conflict{Kind: "claims"}
		for _, r := range live {
			ep.claims = append(ep.claims, Claim{Record: r.ID, Claimant: r.Body.Signer, Root: claimRoot(r), State: "competing"})
			c.Records = append(c.Records, r.ID)
			c.Signers = append(c.Signers, r.Body.Signer)
		}
		ep.conflicts = append(ep.conflicts, c)
		ep.stopFull = true
		return nil, 0
	}
	if len(live) == 0 {
		return nil, 0
	}
	c := live[0]
	cl := Claim{Record: c.ID, Claimant: c.Body.Signer, Root: claimRoot(c)}
	if ds := disputes[c]; len(ds) > 0 {
		cl.State = "disputed"
		ep.claims = append(ep.claims, cl)
		conflict := Conflict{Kind: "claims", Records: []Hash{c.ID}, Signers: []Hash{c.Body.Signer}}
		for _, r := range ds {
			conflict.Records = append(conflict.Records, r.ID)
			if !contains(conflict.Signers, r.Body.Signer) {
				conflict.Signers = append(conflict.Signers, r.Body.Signer)
			}
		}
		ep.conflicts = append(ep.conflicts, conflict)
		ep.stopFull = true
		return nil, 0
	}
	seen, ok := firstSeen[c.ID]
	if !ok || seen > now {
		seen = now
	}
	if c.label != in || ep.rootFrozen(c.Body.Signer) || now-seen < delay {
		cl.State = "pending"
		if left := delay - (now - seen); left > 0 {
			cl.LeftMS = left
		}
		ep.claims = append(ep.claims, cl)
		ep.pending = &c.Body.Signer
		return nil, 0
	}
	cl.State = "effective"
	ep.claims = append(ep.claims, cl)
	next := cl.Root
	return &next, seenOf(&c.Body, ep.cur)
}

// removals returns the admin removals and freezes that count and name
// the admin key k or the member key of its device.
func (ep *epoch) removals(k Hash) []*rec {
	keys := []Hash{k}
	if d := ep.admins[k]; d != nil {
		keys = append(keys, *d.Body.Key)
	}
	var out []*rec
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.AdminCA == nil || r.label != in || r.Body.Type != TypeRevoke && r.Body.Type != TypeFreeze {
				continue
			}
			for _, key := range keys {
				if contains(r.Body.Keys, key) {
					out = append(out, r)
					break
				}
			}
		}
	}
	return out
}

// rootFrozen reports whether a root's freeze, not thawed by a root, names
// k: the root holding a claim back.
func (ep *epoch) rootFrozen(k Hash) bool {
	if !ep.frozen[k] {
		return false
	}
	thawed := map[Hash]bool{}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.Body.Type == TypeThaw && ep.rootRecord(r) {
				for _, id := range r.Body.Records {
					thawed[id] = true
				}
			}
		}
	}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.Body.Type == TypeFreeze && ep.rootRecord(r) && !thawed[r.ID] && contains(r.Body.Keys, k) {
				return true
			}
		}
	}
	return false
}

func claimRoot(r *rec) Hash {
	c, err := x509.ParseCertificate(r.Body.Root)
	if err != nil {
		return Hash{}
	}
	return KeyHashOf(c)
}

// State is the group's state (docs/records-v2.md, "The state").
type State struct {
	Roots       []Hash     `json:"roots"`
	RootDevice  string     `json:"root_device,omitempty"`
	Devices     []Device   `json:"devices,omitempty"`
	Revoked     []Hash     `json:"revoked,omitempty"`
	Claims      []Claim    `json:"claims,omitempty"`
	Conflicts   []Conflict `json:"conflicts,omitempty"`
	Stop        string     `json:"stop"`
	NoSecretsTo []string   `json:"no_secrets_to,omitempty"`
	NothingTo   []string   `json:"nothing_to,omitempty"`
}

// Device is one device of the state.
type Device struct {
	Device   string   `json:"device"`
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	OS       string   `json:"os,omitempty"`
	Keys     []Hash   `json:"keys"`
	Store    string   `json:"store,omitempty"`
	Kind     string   `json:"kind,omitempty"`
	Proof    string   `json:"proof,omitempty"`
	Admin    *Hash    `json:"admin,omitempty"`
	Powers   []string `json:"powers,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Frozen   bool     `json:"frozen,omitempty"`
}

// Claim is a claim of the state.
type Claim struct {
	Record   Hash   `json:"record"`
	Claimant Hash   `json:"claimant"`
	Root     Hash   `json:"root"`
	State    string `json:"state"`
	LeftMS   int64  `json:"left_ms,omitempty"`
}

// Conflict is a conflict of the state.
type Conflict struct {
	Kind    string `json:"kind"`
	Records []Hash `json:"records"`
	Signers []Hash `json:"signers"`
}

// state builds the State of the last epoch.
func (ep *epoch) state() *State {
	s := &State{Roots: ep.path, Stop: "none"}
	if d := ep.rootDevice(); d != nil && !ep.revoked[*d.Body.Key] {
		s.RootDevice = d.Body.Device
	}
	forkedAdmin := false
	for signer := range ep.forked {
		if _, root := ep.onPath[signer]; !root {
			forkedAdmin = true
		}
	}
	for id, rs := range ep.e.devices {
		if d, ok := ep.device(id, rs); ok {
			s.Devices = append(s.Devices, d)
		}
		// The devices that an admin with two histories alone admitted
		// get nothing.
		alone := len(rs) > 0
		for _, r := range rs {
			if _, f := ep.forked[r.Body.Signer]; !f || r.AdminCA == nil {
				alone = false
			}
		}
		if alone {
			s.NothingTo = append(s.NothingTo, id)
		}
		if ep.pending != nil {
			for _, r := range rs {
				if r.Body.Admin != nil && *r.Body.Admin == *ep.pending && ep.rootRecord(r) {
					s.NoSecretsTo = append(s.NoSecretsTo, id)
					break
				}
			}
		}
	}
	sort.Slice(s.Devices, func(i, j int) bool { return s.Devices[i].Device < s.Devices[j].Device })
	sort.Strings(s.NothingTo)
	sort.Strings(s.NoSecretsTo)
	for k := range ep.revoked {
		s.Revoked = append(s.Revoked, k)
	}
	sortHashes(s.Revoked)
	s.Claims = ep.claims
	sort.Slice(s.Claims, func(i, j int) bool { return s.Claims[i].Record.String() < s.Claims[j].Record.String() })
	s.Conflicts = ep.conflicts
	for i := range s.Conflicts {
		sortHashes(s.Conflicts[i].Records)
		sortHashes(s.Conflicts[i].Signers)
	}
	sort.Slice(s.Conflicts, func(i, j int) bool {
		return s.Conflicts[i].Records[0].String() < s.Conflicts[j].Records[0].String()
	})
	switch {
	case ep.stopFull:
		s.Stop = "full"
	case forkedAdmin:
		s.Stop = "secrets"
	}
	return s
}

func sortHashes(hs []Hash) {
	sort.Slice(hs, func(i, j int) bool { return hs[i].String() < hs[j].String() })
}

// device builds one device of the state from its counting records.
func (ep *epoch) device(id string, rs []*rec) (Device, bool) {
	var counting []*rec
	keys := map[Hash]bool{}
	for _, r := range rs {
		if ep.counts(r) && !ep.revoked[*r.Body.Key] {
			counting = append(counting, r)
			keys[*r.Body.Key] = true
		}
	}
	if len(counting) == 0 {
		return Device{}, false
	}
	// The newest record: a root's beats an admin's, a later root's an
	// earlier one's, then the higher seq; among admins the larger signer.
	sort.Slice(counting, func(i, j int) bool {
		a, b := counting[i], counting[j]
		ra, rb := a.AdminCA == nil, b.AdminCA == nil
		switch {
		case ra != rb:
			return ra
		case ra:
			return ep.newer(a, b)
		case a.Body.Signer != b.Body.Signer:
			return a.Body.Signer.String() > b.Body.Signer.String()
		}
		return a.Body.Seq > b.Body.Seq
	})
	n := counting[0].Body
	d := Device{Device: id, Name: n.Name, Role: n.Role, OS: n.OS, Store: n.Store, Kind: n.Kind, Proof: n.Proof}
	for k := range keys {
		d.Keys = append(d.Keys, k)
	}
	sortHashes(d.Keys)
	if n.Admin != nil && counting[0].AdminCA == nil && !ep.revoked[*n.Admin] && ep.admins[*n.Admin] == counting[0] {
		a := *n.Admin
		d.Admin, d.Powers, d.Commands, d.Frozen = &a, n.Powers, n.Commands, ep.frozen[a]
	}
	return d, true
}

// Encode returns the state as canonical JSON, the bytes the vectors
// compare.
func (s *State) Encode() ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return strict.Canonicalize(raw)
}

// Equal reports whether two states are the same bytes.
func (s *State) Equal(o *State) bool {
	a, err1 := s.Encode()
	b, err2 := o.Encode()
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}
