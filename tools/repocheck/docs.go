// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// The documentation rules:
//
//   - a relative link in a Markdown file names a file or directory of the
//     repository, and its #anchor, if any, a heading of that file;
//   - the project's old name does not come back, outside the changelog;
//   - every command of cbb, the full and the lite member, is in docs/cli.md,
//     the lite member's in its section.

var (
	mdLink    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	mdHeading = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*\s*$`)
	oldName   = regexp.MustCompile(`(?i)\bclipbridge\b`)
	goCommand = regexp.MustCompile(`(?m)^\s*case "([a-z]+)"`)
	rsCommand = regexp.MustCompile(`(?m)^\s*"([a-z]+)" => cmd_`)
)

// checkDocs checks the rules above in one file; files maps every checked
// path to its content.
func checkDocs(name string, data []byte, files map[string][]byte) []string {
	if !strings.HasSuffix(name, ".md") {
		return nil
	}
	var problems []string
	inCode := false
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCode = !inCode
			continue
		}
		if inCode {
			continue
		}
		if name != "CHANGELOG.md" && oldName.MatchString(line) {
			problems = append(problems, fmt.Sprintf("%s:%d: the old name clipbridge; the project is clipboardbridge and its command cbb", name, i+1))
		}
		for _, m := range mdLink.FindAllStringSubmatch(line, -1) {
			if p := checkLink(name, m[1], files); p != "" {
				problems = append(problems, fmt.Sprintf("%s:%d: %s", name, i+1, p))
			}
		}
	}
	return problems
}

// checkLink returns what is wrong with one link target in the file name, or
// "" when it is fine or not a relative link.
func checkLink(name, target string, files map[string][]byte) string {
	if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
		return ""
	}
	file, anchor, _ := strings.Cut(target, "#")
	if file == "" {
		file = name
	} else {
		file = path.Clean(path.Join(path.Dir(name), file))
	}
	data, ok := files[file]
	if !ok {
		if !isDir(file, files) {
			return fmt.Sprintf("link to %s, which is not in the repository", target)
		}
		return ""
	}
	if anchor == "" || !strings.HasSuffix(file, ".md") {
		return ""
	}
	if !anchors(data)[anchor] {
		return fmt.Sprintf("link to %s: %s has no heading for #%s", target, file, anchor)
	}
	return ""
}

// isDir reports whether some checked file lies below dir.
func isDir(dir string, files map[string][]byte) bool {
	for f := range files {
		if strings.HasPrefix(f, dir+"/") {
			return true
		}
	}
	return false
}

// anchors returns the anchors GitHub makes for the headings of a Markdown
// file: lower case, spaces as hyphens, punctuation dropped, and -1, -2 for
// repeated headings.
func anchors(data []byte) map[string]bool {
	seen := make(map[string]int)
	out := make(map[string]bool)
	inCode := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCode = !inCode
			continue
		}
		m := mdHeading.FindStringSubmatch(line)
		if inCode || m == nil {
			continue
		}
		a := slug(m[1])
		if n := seen[a]; n > 0 {
			out[fmt.Sprintf("%s-%d", a, n)] = true
		} else {
			out[a] = true
		}
		seen[a]++
	}
	return out
}

// slug turns a heading into its GitHub anchor.
func slug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// liteSection is the heading of the lite member's commands in docs/cli.md.
const liteSection = "## The lite member"

// checkCommands reports the commands of cbb that docs/cli.md does not name:
// the full member's anywhere, the lite member's in its section.
func checkCommands(files map[string][]byte) []string {
	ref, ok := files["docs/cli.md"]
	if !ok {
		return nil
	}
	var problems []string
	lite := ""
	if _, after, ok := strings.Cut(string(ref), "\n"+liteSection+"\n"); ok {
		lite, _, _ = strings.Cut(after, "\n## ")
	}
	for _, c := range []struct {
		source, doc string
		re          *regexp.Regexp
	}{
		{"cmd/cbb/main.go", string(ref), goCommand},
		{"lite/src/main.rs", lite, rsCommand},
	} {
		src, ok := files[c.source]
		if !ok {
			continue
		}
		for _, m := range c.re.FindAllStringSubmatch(string(src), -1) {
			if !strings.Contains(c.doc, "`cbb "+m[1]) {
				problems = append(problems, fmt.Sprintf("docs/cli.md:1: the command cbb %s (%s) is not described", m[1], c.source))
			}
		}
	}
	return problems
}
