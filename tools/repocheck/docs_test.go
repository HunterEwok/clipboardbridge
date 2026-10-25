// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
)

func TestCheckDocs(t *testing.T) {
	files := map[string][]byte{
		"README.md":        []byte("# Read me\n"),
		"docs/design.md":   []byte("# Design\n\n## The iPhone button\n\n## Sync away from home (planned)\n\n## Notes\n\n## Notes\n\n```sh\n# not a heading\n```\n"),
		"lite/src/main.rs": []byte("fn main() {}\n"),
	}
	tests := []struct {
		name, file, content string
		want                []string
	}{
		{name: "a file", file: "docs/a.md", content: "[d](design.md) [r](../README.md) [l](../lite/src/main.rs)\n"},
		{name: "a directory", file: "README.md", content: "[core](lite/src)\n"},
		{name: "web and mail links", file: "README.md", content: "[w](https://example.org/x.md) [m](mailto:a@example.org)\n"},
		{name: "anchors", file: "docs/a.md", content: "[a](design.md#the-iphone-button) [b](design.md#sync-away-from-home-planned) [c](design.md#notes-1)\n"},
		{name: "an anchor in the same file", file: "docs/design.md", content: "# Design\n\n## Build\n\nSee [build](#build).\n"},
		{
			name: "a missing file", file: "docs/a.md", content: "ok\n[x](missing.md)\n",
			want: []string{"docs/a.md:2: link to missing.md, which is not in the repository"},
		},
		{
			name: "a missing anchor", file: "docs/a.md", content: "[x](design.md#roadmap)\n",
			want: []string{"docs/a.md:1: link to design.md#roadmap: docs/design.md has no heading for #roadmap"},
		},
		{
			name: "a heading inside code", file: "docs/a.md", content: "[x](design.md#not-a-heading)\n",
			want: []string{"has no heading for #not-a-heading"},
		},
		{
			name: "the old name", file: "docs/a.md", content: "Run clipbridge join.\n",
			want: []string{"docs/a.md:1: the old name clipbridge"},
		},
		{name: "the old name in the changelog", file: "CHANGELOG.md", content: "clipbridge is now clipboardbridge.\n"},
		{name: "the old name in code", file: "docs/a.md", content: "```sh\nrm -rf /var/lib/clipbridge\n```\n"},
		{name: "not Markdown", file: "a.sh", content: "# [x](missing.md) clipbridge\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			all := map[string][]byte{tt.file: []byte(tt.content)}
			for k, v := range files {
				if _, ok := all[k]; !ok {
					all[k] = v
				}
			}
			got := checkDocs(tt.file, []byte(tt.content), all)
			if len(got) != len(tt.want) {
				t.Fatalf("checkDocs() = %q, want %d problems containing %q", got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], w)
				}
			}
		})
	}
}

func TestSlug(t *testing.T) {
	for heading, want := range map[string]string{
		"Sync away from home (planned)":         "sync-away-from-home-planned",
		"9. The phone as the root":              "9-the-phone-as-the-root",
		"The holder of `clipboardbridge.local`": "the-holder-of-clipboardbridgelocal",
		"Android: the clipboard without taps":   "android-the-clipboard-without-taps",
		"Mac → Linux":                           "mac--linux",
	} {
		if got := slug(heading); got != want {
			t.Errorf("slug(%q) = %q, want %q", heading, got, want)
		}
	}
}

func TestCheckCommands(t *testing.T) {
	files := map[string][]byte{
		"cmd/cbb/main.go":       []byte("switch cmd {\n\tcase \"copy\":\n\tcase \"away\":\n}\n"),
		"lite/src/main.rs":      []byte("match c {\n    \"watch\" => cmd_watch(&g, rest),\n    \"run\" => cmd_run(&g, rest),\n}\n"),
		"docs/reference/cli.md": []byte("`cbb copy` sends. `cbb watch` is not lite.\n\n## The lite member\n\n`cbb run` runs.\n\n## Other\n"),
	}
	got := checkCommands(files)
	want := []string{"cbb away", "cbb watch"}
	if len(got) != len(want) {
		t.Fatalf("checkCommands() = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], "the command "+w+" ") {
			t.Errorf("problem %d = %q, want it to name %q", i, got[i], w)
		}
	}
}
