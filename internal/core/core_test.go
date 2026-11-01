// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package core

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
)

// TestVectors evaluates every case of testdata/interop/v2-records.json in
// the linked core, which must give its state byte for byte, as Go's
// internal/authority does.
func TestVectors(t *testing.T) {
	if !linked {
		t.Skip("the core is not linked (go test -tags cbbcore)")
	}
	data, err := os.ReadFile("../../testdata/interop/v2-records.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		var name, state string
		if err := json.Unmarshal(c["name"], &name); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(c["state"], &state); err != nil {
			t.Fatal(err)
		}
		req, err := json.Marshal(map[string]any{"abi": ABI, "op": "evaluate", "args": c})
		if err != nil {
			t.Fatal(err)
		}
		answer, err := Call(req)
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"abi":1,"ok":` + state + `}`; string(answer) != want {
			t.Fatalf("%s:\n got %s\nwant %s", name, answer, want)
		}
	}
}

// TestDo asks the version, and sees a refusal come back as a *Refusal.
func TestDo(t *testing.T) {
	v, err := CoreVersion()
	if !linked {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("without the core: %v", err)
		}
		return
	}
	if err != nil || v.ABI != ABI || v.Core == "" {
		t.Fatalf("version %+v, %v", v, err)
	}
	var r *Refusal
	err = Do("no such op", nil, nil)
	if !errors.As(err, &r) || r.Name != "op" {
		t.Fatalf("an unknown op: %v", err)
	}
	if empty, err := Call(nil); err != nil || len(empty) == 0 {
		t.Fatalf("an empty request: %q, %v", empty, err)
	}
}

// TestConcurrent calls the core from many goroutines at once, as the
// service's connections do.
func TestConcurrent(t *testing.T) {
	if !linked {
		t.Skip("the core is not linked")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if v, err := CoreVersion(); err != nil || v.ABI != ABI {
					errs <- errors.Join(errors.New("a version call failed"), err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
