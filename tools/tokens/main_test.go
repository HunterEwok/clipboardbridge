// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokensFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", tokensFile))
	if err != nil {
		t.Fatal(err)
	}
	swift, kotlin, err := generate(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(swift), "static let terminal = Palette(") {
		t.Errorf("no terminal palette in\n%s", swift)
	}
	if !strings.Contains(string(kotlin), "val terminal = Palette(") || !strings.Contains(string(kotlin), "accent = Color(0xFF3DFF8A),") {
		t.Errorf("no terminal palette in\n%s", kotlin)
	}
}

func TestContrast(t *testing.T) {
	if r, _ := contrast("#000000", "#FFFFFF"); r < 20.9 || r > 21.1 {
		t.Errorf("black on white is %.2f:1, want 21:1", r)
	}
	low := Palette{Background: "#000000", Surface: "#000000", Text: "#333333", TextDim: "#FFFFFF", Accent: "#FFFFFF", OnAccent: "#000000", Danger: "#FFFFFF", Grid: "#000000"}
	if err := checkContrast("low", low); err == nil || !strings.Contains(err.Error(), "text has a contrast") {
		t.Errorf("low contrast passed: %v", err)
	}
	if _, _, err := generate([]byte(`{"themes":{"terminal":{}},"radius":{},"spacing":{}}`)); err == nil {
		t.Error("a file without all themes passed")
	}
	if _, _, err := generate([]byte(`{"themes":{},"extra":1}`)); err == nil {
		t.Error("an unknown field passed")
	}
}
