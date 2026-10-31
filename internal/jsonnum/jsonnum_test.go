// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package jsonnum

import "testing"

func TestIntegersOnly(t *testing.T) {
	for s, ok := range map[string]bool{
		`{"a":0,"b":-1,"c":[12,9223372036854775807]}`: true,
		`{"a":"-0 1.5 1e3","b":"\"-0","-0":1}`:        true,
		`{"a":-0}`:                                    false,
		`{"a":1.0}`:                                   false,
		`{"a":1e3}`:                                   false,
		`{"a":01}`:                                    false,
		`{"a":-}`:                                     false,
		`{"a":9223372036854775808}`:                   false,
	} {
		if got := IntegersOnly([]byte(s)) == nil; got != ok {
			t.Errorf("%s: %v, want %v", s, got, ok)
		}
	}
}
