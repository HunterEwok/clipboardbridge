// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package hlc implements a hybrid logical clock (Kulkarni et al., 2014).
//
// A hybrid timestamp is the wall time in milliseconds plus a logical counter.
// Timestamps from one clock always grow, and a received timestamp moves the
// clock forward, so a copy made after another copy was seen always sorts
// after it, even when the wall clocks of the devices differ.
//
// A timestamp is never refused for being ahead: members would disagree about
// where to draw the line, and the group could split. The only bound is
// MaxWall, the same on every member. A clock far ahead moves every member's
// hybrid clock forward with it. Events that depend on each other stay in
// order; while the hybrid clocks are ahead of real time, copies made
// independently are ordered by the logical counter until real time catches
// up. Nothing measures durations with this clock.
package hlc

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxWall is the largest wall time a timestamp may carry: the last
// millisecond of the year 9999.
const MaxWall = 253402300799999

// markStep is how far ahead of the clock the saved mark is set.
const markStep = 10_000 // milliseconds

// Timestamp is a point on the hybrid clock. The zero Timestamp sorts before
// every other one.
type Timestamp struct {
	Wall    int64  // milliseconds since the Unix epoch, at most MaxWall
	Logical uint32 // orders events within the same millisecond
}

// Compare returns -1, 0 or +1 when t is before, equal to or after u.
func (t Timestamp) Compare(u Timestamp) int {
	switch {
	case t.Wall < u.Wall:
		return -1
	case t.Wall > u.Wall:
		return 1
	case t.Logical < u.Logical:
		return -1
	case t.Logical > u.Logical:
		return 1
	}
	return 0
}

// IsZero reports whether t is the zero Timestamp.
func (t Timestamp) IsZero() bool { return t == Timestamp{} }

// Valid reports whether t's wall time lies between 0 and MaxWall.
func (t Timestamp) Valid() bool { return t.Wall >= 0 && t.Wall <= MaxWall }

// String formats t as "wall.logical", for example "1761024000000.3".
func (t Timestamp) String() string {
	return strconv.FormatInt(t.Wall, 10) + "." + strconv.FormatUint(uint64(t.Logical), 10)
}

// MarshalText implements encoding.TextMarshaler.
func (t Timestamp) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler; it accepts exactly the
// format of String, with a wall time of at most MaxWall.
func (t *Timestamp) UnmarshalText(b []byte) error {
	wall, logical, ok := strings.Cut(string(b), ".")
	if !ok || !digits(wall) || !digits(logical) {
		return fmt.Errorf("hlc: timestamp %q is not wall.logical", b)
	}
	w, err := strconv.ParseInt(wall, 10, 64)
	if err != nil || w > MaxWall {
		return fmt.Errorf("hlc: bad wall time in %q", b)
	}
	l, err := strconv.ParseUint(logical, 10, 32)
	if err != nil {
		return fmt.Errorf("hlc: bad logical counter in %q", b)
	}
	*t = Timestamp{Wall: w, Logical: uint32(l)}
	return nil
}

// digits reports whether s is a non-empty run of ASCII digits.
func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Clock is a hybrid logical clock. It is safe for concurrent use.
type Clock struct {
	mu   sync.Mutex
	now  func() time.Time
	last Timestamp
	mark Timestamp             // the last mark saved
	save func(Timestamp) error // nil when nothing is saved
}

// NewClock returns a clock that reads the wall time from now (time.Now if nil)
// and never goes back before floor.
//
// When the clock reaches the last mark it saved, it calls save with a new
// mark 10 seconds further ahead, so a restart that passes the saved mark as
// the floor never issues a timestamp below one issued before, even after a
// crash. A device that boots with its clock far behind, such as a Raspberry Pi
// without a real-time clock, still stamps its copies after the earlier ones.
// If save fails, the mark stays where it was and the next timestamp tries
// again; the caller reports the error. save runs with the clock locked; it
// may be nil.
func NewClock(now func() time.Time, floor Timestamp, save func(Timestamp) error) *Clock {
	if now == nil {
		now = time.Now
	}
	return &Clock{now: now, last: floor, mark: floor, save: save}
}

// Now returns a timestamp for a local event. It is greater than every
// timestamp returned or observed before, until MaxWall.
func (c *Clock) Now() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	pt := min(c.now().UnixMilli(), MaxWall)
	if pt > c.last.Wall {
		c.last = Timestamp{Wall: pt}
	} else {
		c.tick()
	}
	c.keepMark()
	return c.last
}

// MaxAhead is how far a received timestamp may be ahead of this clock: one
// further ahead is refused (Ahead), so that no member can move the group's
// clocks to MaxWall for good (docs/protocol.md, section 5).
const MaxAhead = 7 * 24 * time.Hour

// plausible is a wall time before which this clock does not trust itself to
// refuse timestamps for being ahead: a device without a real-time clock
// that has not set its time yet (2026-01-01).
const plausible = 1767225600000

// Ahead reports whether remote is more than MaxAhead ahead of this clock:
// of its wall time or the latest timestamp it issued or observed, whichever
// is later. A clock that reads before 2026 refuses nothing.
func (c *Clock) Ahead(remote Timestamp) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ref := max(c.now().UnixMilli(), c.last.Wall)
	return ref >= plausible && remote.Wall > ref+MaxAhead.Milliseconds()
}

// Last returns the latest timestamp the clock has issued or observed.
func (c *Clock) Last() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// Observe moves the clock past a timestamp received from another device.
// Timestamps outside the valid range are ignored.
func (c *Clock) Observe(remote Timestamp) {
	if !remote.Valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pt := min(c.now().UnixMilli(), MaxWall)
	wall := max(c.last.Wall, remote.Wall, pt)
	switch {
	case wall == c.last.Wall && wall == remote.Wall:
		c.last.Logical = max(c.last.Logical, remote.Logical)
		c.tick()
	case wall == c.last.Wall:
		c.tick()
	case wall == remote.Wall:
		c.last = remote
		c.tick()
	default:
		c.last = Timestamp{Wall: wall}
	}
	c.keepMark()
}

// tick advances the logical counter, moving to the next millisecond in the
// practically impossible case that the counter is exhausted, and stopping at
// MaxWall.
func (c *Clock) tick() {
	switch {
	case c.last.Logical < math.MaxUint32:
		c.last.Logical++
	case c.last.Wall < MaxWall:
		c.last = Timestamp{Wall: c.last.Wall + 1}
	}
}

// keepMark saves a new mark when the clock reaches the saved one. Near
// MaxWall, where the wall time cannot move a full step ahead, the mark
// advances the logical counter instead, and stops once nothing higher exists.
func (c *Clock) keepMark() {
	if c.save == nil || c.last.Compare(c.mark) < 0 {
		return
	}
	next := Timestamp{Wall: c.last.Wall + markStep}
	if c.last.Wall > MaxWall-markStep {
		next = Timestamp{Wall: MaxWall, Logical: uint32(min(uint64(c.last.Logical)+markStep, math.MaxUint32))}
	}
	if next.Compare(c.mark) <= 0 {
		return // saturated: nothing higher can be issued
	}
	if c.save(next) == nil {
		c.mark = next
	}
}
