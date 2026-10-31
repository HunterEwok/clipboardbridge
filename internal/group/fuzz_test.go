// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/strict"
)

// fuzzSeeds adds the bodies of a section of strict-generated.json, valid
// and not, as the seed corpus of a fuzz target.
func fuzzSeeds(f *testing.F, section string) {
	data, err := os.ReadFile("../../testdata/interop/strict-generated.json")
	if err != nil {
		f.Fatal(err)
	}
	var v map[string][]genVector
	if err := json.Unmarshal(data, &v); err != nil {
		f.Fatal(err)
	}
	for _, c := range v[section] {
		if c.Pad == 0 {
			f.Add(c.Body)
		}
	}
}

// FuzzRecordBody reads record bodies as they come from other members: a
// body it takes is in the strict form, within the size limit, and reads
// the same again.
func FuzzRecordBody(f *testing.F) {
	fuzzSeeds(f, "records")
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := parseRecordBody(data)
		if err != nil {
			return
		}
		if len(data) > maxRecordBody {
			t.Fatalf("took a body of %d bytes", len(data))
		}
		if err := strict.Check(data, "v", "type", "group", "time_ms"); err != nil {
			t.Fatalf("took a body not in the strict form: %v", err)
		}
		again, err := parseRecordBody(bytes.Clone(data))
		if err != nil {
			t.Fatalf("took a body once only: %v", err)
		}
		if !recordBodiesEqual(b, again) {
			t.Fatal("read a body two ways")
		}
	})
}

func recordBodiesEqual(a, b RecordBody) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// FuzzCommand reads command bodies as a member receives them.
func FuzzCommand(f *testing.F) {
	fuzzSeeds(f, "commands")
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := parseCommandBody(data); err != nil {
			return
		}
		if err := strict.Check(data, "v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"); err != nil {
			t.Fatalf("took a command not in the strict form: %v", err)
		}
	})
}
