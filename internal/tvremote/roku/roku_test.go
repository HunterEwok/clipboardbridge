// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package roku

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestType(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	off := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if off {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/query/device-info":
			w.Write([]byte(`<?xml version="1.0"?><device-info><user-device-name>Living room</user-device-name></device-info>`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/keypress/"):
			keys = append(keys, strings.TrimPrefix(r.URL.EscapedPath(), "/keypress/"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(strings.TrimPrefix(srv.URL, "http://"), nil)
	name, err := c.Name(context.Background())
	if err != nil || name != "Living room" {
		t.Fatalf("Name: %q, %v", name, err)
	}
	if err := c.Type(context.Background(), "a é/\r\nb"); err != nil {
		t.Fatal(err)
	}
	want := []string{"Lit_a", "Lit_%20", "Lit_%C3%A9", "Lit_%2F", "Enter", "Lit_b"}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys %q, want %q", keys, want)
	}
	mu.Lock()
	off = true
	mu.Unlock()
	if err := c.Type(context.Background(), "x"); !errors.Is(err, ErrOff) {
		t.Fatalf("Type with ECP off: %v", err)
	}
	if _, err := c.Name(context.Background()); !errors.Is(err, ErrOff) {
		t.Fatalf("Name with ECP off: %v", err)
	}
}
