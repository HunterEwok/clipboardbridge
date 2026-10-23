// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "service.log")
	l, err := openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }
	fmt.Fprintf(l, "one\ntwo\n")
	l.Close()
	data, _ := os.ReadFile(path)
	if want := "2026-10-23 12:00:00 one\n2026-10-23 12:00:00 two\n"; string(data) != want {
		t.Errorf("the log holds %q, want %q", data, want)
	}

	// A full log moves aside, and the new one starts empty.
	l, err = openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	line := strings.Repeat("x", 1000) + "\n"
	for l.size < maxLog {
		l.Write([]byte(line))
	}
	l.Write([]byte("after\n"))
	old, err := os.Stat(path + ".1")
	if err != nil || old.Size() < maxLog {
		t.Fatalf("the old log: %v, %v", old, err)
	}
	if data, _ := os.ReadFile(path); !strings.HasSuffix(string(data), "after\n") || len(data) > 100 {
		t.Errorf("the new log holds %d bytes", len(data))
	}
}
