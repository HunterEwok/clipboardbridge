// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package benchtime

import (
	"testing"
	"time"
)

func TestParseClock(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"":                     0,
		"3h":                   3 * time.Hour,
		"-1h30m":               -90 * time.Minute,
		"2026-10-27T13:00:00Z": time.Hour,
	} {
		if got, err := parseClock(in, now); err != nil || got != want {
			t.Errorf("parseClock(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseClock("tomorrow", now); err == nil {
		t.Error("a clock that is neither a duration nor a time was taken")
	}
}

func TestScale(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !Enabled() {
		if D(time.Hour) != time.Hour || !Years(now, 2).Equal(now.AddDate(2, 0, 0)) || Enabled() {
			t.Error("the release build changes times")
		}
		return
	}
	if Scale == 1 {
		return
	}
	if D(Scale*time.Second) != time.Second || !Years(now, 1).Equal(now.Add(365*24*time.Hour/Scale)) || !Enabled() {
		t.Error("the time-scaled build does not scale")
	}
}
