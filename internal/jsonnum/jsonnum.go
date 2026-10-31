// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package jsonnum holds the one form of a JSON number that every member
// reads alike (docs/protocol.md, Conventions, "Signed bodies"): an integer
// written -?[1-9][0-9]*|0 in the range of an int64. Readers differ on the
// rest: Go takes "-0" for 0, serde_json for a float.
package jsonnum

import (
	"errors"
	"strconv"
)

// Integer reads the integer that starts at b[i] and returns the index after
// it. "-0", a leading zero, a fraction, an exponent and a number out of the
// range of an int64 are refused.
func Integer(b []byte, i int) (int, error) {
	start := i
	if i < len(b) && b[i] == '-' {
		i++
	}
	digits := i
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	switch {
	case i == digits:
		return 0, errors.New("a number has no digits")
	case b[digits] == '0' && i > digits+1:
		return 0, errors.New("a number has a leading zero")
	case b[digits] == '0' && digits > start:
		return 0, errors.New("a number is a negative zero")
	case i < len(b) && (b[i] == '.' || b[i] == 'e' || b[i] == 'E'):
		return 0, errors.New("a number is not an integer")
	}
	if _, err := strconv.ParseInt(string(b[start:i]), 10, 64); err != nil {
		return 0, errors.New("a number is out of range")
	}
	return i, nil
}

// IntegersOnly checks that every number in b, outside its strings, is an
// Integer, so the member protocol's frames and manifests pass it first,
// members a reader does not know included. It only scans: whether b is
// JSON is for the decoder.
func IntegersOnly(b []byte) error {
	for i := 0; i < len(b); {
		switch c := b[i]; {
		case c == '"':
			for i++; i < len(b) && b[i] != '"'; i++ {
				if b[i] == '\\' {
					i++
				}
			}
			i++
		case c == '-' || c >= '0' && c <= '9':
			end, err := Integer(b, i)
			if err != nil {
				return err
			}
			i = end
		default:
			i++
		}
	}
	return nil
}
