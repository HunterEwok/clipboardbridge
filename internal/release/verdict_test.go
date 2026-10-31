// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestVerdicts writes Go's verdict on the release files of a corpus of
// tools/difffuzz (docs/differential.md); internal/group writes the other
// kinds'. It runs when CBB_VERDICTS names the corpus and writes to
// CBB_VERDICTS_OUT; without them it reads a corpus of its own.
func TestVerdicts(t *testing.T) {
	in, out := os.Getenv("CBB_VERDICTS"), os.Getenv("CBB_VERDICTS_OUT")
	if in == "" {
		in = t.TempDir() + "/corpus.jsonl"
		out = in + ".out"
		corpus := `{"kind":"keys","body":"e30="}` + "\n" + `{"kind":"record","body":"e30="}` + "\n"
		if err := os.WriteFile(in, []byte(corpus), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var c struct {
			Kind string `json:"kind"`
			Body []byte `json:"body"`
		}
		if err := json.Unmarshal(line, &c); err != nil {
			t.Fatalf("case %d: %v", i+1, err)
		}
		var err error
		switch {
		case c.Kind != TypeKeys && c.Kind != TypeRelease && c.Kind != TypeChannel && c.Kind != TypeStatus:
			b.WriteString("skip\n")
			continue
		case len(c.Body) > MaxBody:
			err = fmt.Errorf("too large")
		case c.Kind == TypeKeys:
			_, err = decodeKeys(c.Body)
		case c.Kind == TypeRelease:
			_, err = decodeRelease(c.Body)
		case c.Kind == TypeChannel:
			_, err = decodeChannel(c.Body)
		default:
			_, err = decodeStatus(c.Body)
		}
		if err != nil {
			b.WriteString("refused\n")
		} else {
			b.WriteString("taken\n")
		}
	}
	if err := os.WriteFile(out, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CBB_VERDICTS") == "" && b.String() != "refused\nskip\n" {
		t.Errorf("verdicts %q", strings.TrimSpace(b.String()))
	}
}
