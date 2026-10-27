// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package hlc

import (
	"math"
	"sync"
	"testing"
	"time"
)

// fakeTime is a wall clock that tests move by hand.
type fakeTime struct{ ms int64 }

func (f *fakeTime) now() time.Time { return time.UnixMilli(f.ms) }

func TestCompare(t *testing.T) {
	a := Timestamp{Wall: 10, Logical: 0}
	b := Timestamp{Wall: 10, Logical: 1}
	c := Timestamp{Wall: 11, Logical: 0}
	for _, tt := range []struct {
		x, y Timestamp
		want int
	}{
		{a, a, 0}, {a, b, -1}, {b, a, 1}, {b, c, -1}, {c, b, 1}, {Timestamp{}, a, -1},
	} {
		if got := tt.x.Compare(tt.y); got != tt.want {
			t.Errorf("%v.Compare(%v) = %d, want %d", tt.x, tt.y, got, tt.want)
		}
	}
}

func TestNowGrows(t *testing.T) {
	ft := &fakeTime{ms: 1000}
	c := NewClock(ft.now, Timestamp{}, nil)
	t1 := c.Now()
	t2 := c.Now() // same millisecond
	ft.ms = 900   // the wall clock steps back
	t3 := c.Now()
	ft.ms = 2000
	t4 := c.Now()
	want := []Timestamp{{1000, 0}, {1000, 1}, {1000, 2}, {2000, 0}}
	for i, got := range []Timestamp{t1, t2, t3, t4} {
		if got != want[i] {
			t.Errorf("Now() #%d = %v, want %v", i+1, got, want[i])
		}
	}
	if c.Last() != t4 {
		t.Errorf("Last() = %v, want %v", c.Last(), t4)
	}
}

func TestFloor(t *testing.T) {
	// A device that boots with its clock decades behind keeps stamping after
	// the mark it saved before the restart.
	ft := &fakeTime{ms: 5}
	saved := Timestamp{Wall: 1_761_024_000_000, Logical: 7}
	c := NewClock(ft.now, saved, nil)
	if got := c.Now(); got.Compare(saved) <= 0 {
		t.Errorf("Now() = %v, want after the floor %v", got, saved)
	}
	remote := Timestamp{Wall: saved.Wall + 10_000}
	c.Observe(remote)
	if got := c.Now(); got.Compare(remote) <= 0 {
		t.Errorf("Now() = %v, want after the observed %v", got, remote)
	}
}

func TestFloorAfterClockAhead(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	day := 24 * time.Hour
	for _, tt := range []struct {
		name  string
		mark  Timestamp
		now   time.Time
		reset bool
	}{
		{"behind", Timestamp{Wall: now.Add(-day).UnixMilli(), Logical: 3}, now, false},
		{"6 days ahead", Timestamp{Wall: now.Add(6 * day).UnixMilli()}, now, false},
		{"a year ahead", Timestamp{Wall: now.Add(365 * day).UnixMilli()}, now, true},
		// A board without a real-time clock keeps its mark.
		{"clock in 1970", Timestamp{Wall: now.UnixMilli()}, time.UnixMilli(5), false},
	} {
		got, reset := Floor(tt.mark, tt.now)
		want := tt.mark
		if tt.reset {
			want = Timestamp{}
		}
		if reset != tt.reset || got != want {
			t.Errorf("%s: Floor = %v, %v; want %v, %v", tt.name, got, reset, want, tt.reset)
		}
	}
}

func TestMarkIsSavedAhead(t *testing.T) {
	ft := &fakeTime{ms: 1_000_000}
	var saved []Timestamp
	c := NewClock(ft.now, Timestamp{}, func(m Timestamp) error { saved = append(saved, m); return nil })
	first := c.Now()
	if len(saved) != 1 || saved[0].Compare(first) <= 0 {
		t.Fatalf("saved marks %v after the first timestamp %v; want one mark ahead of it", saved, first)
	}
	// Timestamps below the mark need no save.
	ft.ms += 5_000
	c.Now()
	c.Observe(Timestamp{Wall: ft.ms + 1})
	if len(saved) != 1 {
		t.Errorf("saved %d marks while below the mark, want 1", len(saved))
	}
	// Reaching the mark saves a new one before the timestamp is returned.
	ft.ms = saved[0].Wall
	ts := c.Now()
	if len(saved) != 2 || saved[1].Compare(ts) <= 0 {
		t.Errorf("marks %v after %v; want a second mark ahead of it", saved, ts)
	}
	// After a crash, the saved mark as the floor is above everything issued.
	restarted := NewClock(ft.now, saved[len(saved)-1], nil)
	if got := restarted.Now(); got.Compare(ts) <= 0 {
		t.Errorf("after a restart Now() = %v, not after %v", got, ts)
	}
	// An observed jump far ahead is saved at once too.
	c.Observe(Timestamp{Wall: ft.ms + 3_600_000})
	if last := saved[len(saved)-1]; last.Compare(c.Last()) <= 0 {
		t.Errorf("the mark %v is not ahead of an observed jump to %v", last, c.Last())
	}
}

func TestMarkAtTheEndOfTime(t *testing.T) {
	ft := &fakeTime{ms: 1_000}
	var saved []Timestamp
	c := NewClock(ft.now, Timestamp{}, func(m Timestamp) error { saved = append(saved, m); return nil })
	c.Observe(Timestamp{Wall: MaxWall})
	var issued Timestamp
	for range 1000 {
		issued = c.Now()
	}
	if len(saved) > 3 {
		t.Errorf("%d marks saved for 1000 timestamps at MaxWall, want a few", len(saved))
	}
	for _, m := range saved {
		if !m.Valid() {
			t.Errorf("saved an invalid mark %v", m)
		}
	}
	restarted := NewClock(ft.now, saved[len(saved)-1], nil)
	if got := restarted.Now(); got.Compare(issued) <= 0 || !got.Valid() {
		t.Errorf("after a restart at MaxWall, Now() = %v, want a valid timestamp after %v", got, issued)
	}
}

func TestMarkSaveFailureIsRetried(t *testing.T) {
	ft := &fakeTime{ms: 1_000_000}
	fail := true
	var saved []Timestamp
	c := NewClock(ft.now, Timestamp{}, func(m Timestamp) error {
		if fail {
			return errDisk
		}
		saved = append(saved, m)
		return nil
	})
	c.Now()
	fail = false
	issued := c.Now() // the failed save is tried again
	if len(saved) != 1 || saved[0].Compare(issued) <= 0 {
		t.Errorf("after a failed save, marks %v; want one retried mark ahead of %v", saved, issued)
	}
}

type diskError struct{}

func (diskError) Error() string { return "disk full" }

var errDisk error = diskError{}

func TestObserve(t *testing.T) {
	tests := []struct {
		name   string
		last   Timestamp
		wall   int64
		remote Timestamp
		want   Timestamp
	}{
		{name: "wall clock ahead of both", last: Timestamp{100, 5}, wall: 300, remote: Timestamp{200, 9}, want: Timestamp{300, 0}},
		{name: "remote ahead", last: Timestamp{100, 5}, wall: 150, remote: Timestamp{200, 9}, want: Timestamp{200, 10}},
		{name: "local ahead", last: Timestamp{300, 5}, wall: 150, remote: Timestamp{200, 9}, want: Timestamp{300, 6}},
		{name: "same wall, remote counter higher", last: Timestamp{300, 5}, wall: 150, remote: Timestamp{300, 9}, want: Timestamp{300, 10}},
		{name: "same wall, local counter higher", last: Timestamp{300, 12}, wall: 150, remote: Timestamp{300, 9}, want: Timestamp{300, 13}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTime{ms: tt.wall}
			c := NewClock(ft.now, tt.last, nil)
			c.Observe(tt.remote)
			if c.last != tt.want {
				t.Errorf("after Observe(%v): clock = %v, want %v", tt.remote, c.last, tt.want)
			}
			if next := c.Now(); next.Compare(tt.remote) <= 0 || next.Compare(tt.want) <= 0 {
				t.Errorf("Now() after Observe = %v, want after %v and %v", next, tt.remote, tt.want)
			}
		})
	}
}

func TestObserveNeverRefuses(t *testing.T) {
	// A clock years ahead is wrong, but refusing it would let members disagree
	// about what to accept. The local clock follows it, and order is kept.
	ft := &fakeTime{ms: 1_000_000_000}
	c := NewClock(ft.now, Timestamp{}, nil)
	far := Timestamp{Wall: ft.ms + (10 * 365 * 24 * time.Hour).Milliseconds(), Logical: 3}
	c.Observe(far)
	if got := c.Now(); got.Compare(far) <= 0 {
		t.Errorf("Now() = %v, want after %v", got, far)
	}
}

func TestMaxWall(t *testing.T) {
	ft := &fakeTime{ms: 1_000}
	c := NewClock(ft.now, Timestamp{}, nil)
	before := c.Now()
	c.Observe(Timestamp{Wall: MaxWall + 1}) // invalid: ignored
	c.Observe(Timestamp{Wall: -5})          // invalid: ignored
	if c.Last().Compare(before) != 0 {
		t.Errorf("an invalid timestamp moved the clock to %v", c.Last())
	}
	// At the very end the clock saturates instead of wrapping around.
	c.Observe(Timestamp{Wall: MaxWall, Logical: math.MaxUint32})
	if got := c.Now(); got != (Timestamp{Wall: MaxWall, Logical: math.MaxUint32}) || !got.Valid() {
		t.Errorf("Now() at the end of time = %v", got)
	}
	ft.ms = math.MaxInt64 // a wall clock beyond the bound is clamped
	if got := NewClock(ft.now, Timestamp{}, nil).Now(); got.Wall != MaxWall {
		t.Errorf("Now() with a wall clock past MaxWall = %v", got)
	}
}

func TestLogicalOverflow(t *testing.T) {
	ft := &fakeTime{ms: 50}
	c := NewClock(ft.now, Timestamp{Wall: 50, Logical: math.MaxUint32}, nil)
	if got, want := c.Now(), (Timestamp{Wall: 51}); got != want {
		t.Errorf("Now() = %v, want %v", got, want)
	}
}

func TestTextRoundTrip(t *testing.T) {
	for _, ts := range []Timestamp{{}, {1761024000000, 3}, {1, math.MaxUint32}, {MaxWall, 0}} {
		b, err := ts.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var got Timestamp
		if err := got.UnmarshalText(b); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", b, err)
		}
		if got != ts {
			t.Errorf("round trip of %v gave %v", ts, got)
		}
	}
	for _, bad := range []string{"", "1", "a.b", "-1.0", "1.-1", "+1.0", "1.+1", " 1.0", "1.0 ", "1.4294967296",
		"1.2.3", "9223372036854775808.0", "253402300800000.0", ".1", "1."} {
		var ts Timestamp
		if err := ts.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("UnmarshalText(%q) = %v, want an error", bad, ts)
		}
	}
}

func TestConcurrentNowIsStrictlyIncreasing(t *testing.T) {
	c := NewClock(nil, Timestamp{}, func(Timestamp) error { return nil })
	const workers, perWorker = 8, 500
	results := make(chan Timestamp, workers*perWorker)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				results <- c.Now()
			}
		}()
	}
	wg.Wait()
	close(results)
	seen := make(map[Timestamp]bool)
	for ts := range results {
		if seen[ts] {
			t.Fatalf("timestamp %v returned twice", ts)
		}
		seen[ts] = true
	}
}
