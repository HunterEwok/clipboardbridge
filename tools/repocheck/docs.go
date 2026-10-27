// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// The documentation rules:
//
//   - a relative link in a Markdown file names a file or directory of the
//     repository, and its #anchor, if any, a heading of that file;
//   - the project's old name does not come back, outside the changelog;
//   - every command of cbb, the full and the lite member, is in docs/reference/cli.md,
//     the lite member's in its section;
//   - every environment variable that the code, the installers or the units
//     read (CBB_*) is in docs/reference/config.md;
//   - every page below docs/ is reached from docs/README.md, the index;
//   - no page outside the changelog calls something "planned for" a version
//     that is released already (the newest version in CHANGELOG.md).

var (
	mdLink    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	mdHeading = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*\s*$`)
	oldName   = regexp.MustCompile(`(?i)\bclipbridge\b`)
	goCommand = regexp.MustCompile(`(?m)^\s*case "([a-z]+)"`)
	rsCommand = regexp.MustCompile(`(?m)^\s*"([a-z]+)" => cmd_`)
	// envQuoted is a variable's name as a string in Go, Rust, Swift and
	// Kotlin; envShell is one that a shell script, a systemd unit or
	// PowerShell reads.
	envQuoted  = regexp.MustCompile(`"(CBB_[A-Z0-9_]+)"`)
	envShell   = regexp.MustCompile(`(?:\$\{?|\$env:|Environment=)(CBB_[A-Z0-9_]+)`)
	mdPageRef  = regexp.MustCompile(`\]\(([^)#\s]+\.md)(?:#[^)]*)?\)`)
	plannedFor = regexp.MustCompile(`(?i)\bplanned for (\d+)\.(\d+)\b`)
	released   = regexp.MustCompile(`(?m)^## \[(\d+)\.(\d+)\.\d+\]`)
)

// notEnv are the CBB_ names in the code that are not environment variables.
var notEnv = map[string]bool{
	"CBB_SELECTION": true, // the X11 property the desktop connector reads a selection into
}

// configRef is the reference page of the environment variables.
const configRef = "docs/reference/config.md"

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

// liteSection is the heading of the lite member's commands in docs/reference/cli.md.
const liteSection = "## The lite member"

// checkCommands reports the commands of cbb that docs/reference/cli.md does not name:
// the full member's anywhere, the lite member's in its section.
func checkCommands(files map[string][]byte) []string {
	ref, ok := files["docs/reference/cli.md"]
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
				problems = append(problems, fmt.Sprintf("docs/reference/cli.md:1: the command cbb %s (%s) is not described", m[1], c.source))
			}
		}
	}
	return problems
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// envFile reports how a file names environment variables: as strings in
// code, or as a shell script, a systemd unit or PowerShell reads them; nil
// for other files.
func envFile(name string) *regexp.Regexp {
	switch path.Ext(name) {
	case ".go", ".rs", ".swift", ".kt":
		return envQuoted
	case ".sh", ".ps1", ".service":
		return envShell
	}
	return nil
}

// envVars returns the CBB_ environment variables that the files read, each
// with the first file that reads it.
func envVars(files map[string][]byte) map[string]string {
	vars := make(map[string]string)
	for _, name := range sortedKeys(files) {
		re := envFile(name)
		// repocheck's own tests name variables that do not exist.
		if re == nil || thirdPartyDir(name) != "" || strings.HasPrefix(name, "tools/repocheck/") {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(string(files[name]), -1) {
			if _, ok := vars[m[1]]; !ok && !notEnv[m[1]] {
				vars[m[1]] = name
			}
		}
	}
	return vars
}

// checkEnv reports the environment variables that docs/reference/config.md
// does not describe.
func checkEnv(files map[string][]byte) []string {
	ref, ok := files[configRef]
	if !ok {
		return nil
	}
	vars := envVars(files)
	var problems []string
	for _, v := range sortedKeys(vars) {
		if !strings.Contains(string(ref), "`"+v+"`") {
			problems = append(problems, fmt.Sprintf("%s:1: the environment variable %s (%s) is not described", configRef, v, vars[v]))
		}
	}
	return problems
}

// checkIndex reports the pages below docs/ that docs/README.md does not
// reach: by a link of its own, or by a link of the index page of a
// directory it links to, such as docs/decisions/README.md.
func checkIndex(files map[string][]byte) []string {
	if _, ok := files["docs/README.md"]; !ok {
		return nil
	}
	reached := map[string]bool{"docs/README.md": true}
	queue := []string{"docs/README.md"}
	for len(queue) > 0 {
		from := queue[0]
		queue = queue[1:]
		for _, m := range mdPageRef.FindAllStringSubmatch(string(files[from]), -1) {
			to := path.Clean(path.Join(path.Dir(from), m[1]))
			if reached[to] || !strings.HasPrefix(to, "docs/") {
				continue
			}
			reached[to] = true
			if path.Base(to) == "README.md" {
				queue = append(queue, to)
			}
		}
	}
	var problems []string
	for _, name := range sortedKeys(files) {
		if strings.HasPrefix(name, "docs/") && strings.HasSuffix(name, ".md") && !reached[name] {
			problems = append(problems, fmt.Sprintf("%s:1: not reached from docs/README.md, the index", name))
		}
	}
	return problems
}

// newestRelease returns the major and minor version of the newest release
// in CHANGELOG.md, or false when it names none.
func newestRelease(files map[string][]byte) (major, minor int, ok bool) {
	m := released.FindSubmatch(files["CHANGELOG.md"])
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(string(m[1]))
	minor, _ = strconv.Atoi(string(m[2]))
	return major, minor, true
}

// checkPlanned reports the Markdown lines that call something planned for a
// version that is out already: it is built, moved to a later version, or
// dropped, and the line should say which.
func checkPlanned(files map[string][]byte) []string {
	major, minor, ok := newestRelease(files)
	if !ok {
		return nil
	}
	var problems []string
	for _, name := range sortedKeys(files) {
		if !strings.HasSuffix(name, ".md") || name == "CHANGELOG.md" {
			continue
		}
		for i, line := range strings.Split(string(files[name]), "\n") {
			for _, m := range plannedFor.FindAllStringSubmatch(line, -1) {
				ma, _ := strconv.Atoi(m[1])
				mi, _ := strconv.Atoi(m[2])
				if ma < major || ma == major && mi <= minor {
					problems = append(problems, fmt.Sprintf("%s:%d: %q, but %d.%d is released; say whether it is built, moved or dropped", name, i+1, m[0], ma, mi))
				}
			}
		}
	}
	return problems
}
