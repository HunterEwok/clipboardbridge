// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The test functions of each language, by the files they live in and how
// they are declared.
var testFuncs = []struct {
	lang  string
	file  func(name string) bool
	re    *regexp.Regexp
	byDir bool // Go names a test within its package, the others within the language
}{
	{"Go", func(n string) bool { return strings.HasSuffix(n, "_test.go") },
		regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark|Example)\w*)\(`), true},
	{"Rust", func(n string) bool { return strings.HasSuffix(n, ".rs") },
		regexp.MustCompile(`#\[test\]\s*(?:#\[[^\]]*\]\s*)*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)`), false},
	{"Swift", func(n string) bool { return strings.HasSuffix(n, ".swift") && strings.Contains(n, "/Tests/") },
		regexp.MustCompile(`(?m)^\s*(?:@Test(?:\([^)]*\))?\s+)?func\s+(test\w+|\w+)\s*\(\)\s*(?:async\s+)?(?:throws\s+)?\{`), false},
	{"Kotlin", func(n string) bool { return strings.HasSuffix(n, ".kt") && strings.Contains(n, "/src/test/") },
		regexp.MustCompile("@Test\\s+fun\\s+(`[^`]+`|\\w+)"), false},
}

// testNames returns the test functions in the files, as "language
// [directory] name" keys, with the file of each.
func testNames(files map[string][]byte) map[string]string {
	out := map[string]string{}
	for name, data := range files {
		for _, l := range testFuncs {
			if !l.file(name) {
				continue
			}
			for _, m := range l.re.FindAllSubmatch(data, -1) {
				fn := string(m[1])
				if l.lang == "Swift" && !strings.HasPrefix(fn, "test") && !strings.Contains(string(m[0]), "@Test") {
					continue
				}
				key := l.lang + " " + fn
				if l.byDir {
					key = l.lang + " " + path.Dir(name) + " " + fn
				}
				out[key] = name
			}
		}
	}
	return out
}

// checkTestsKept reports every test function that the commit base has and
// the files do not: a change keeps every test, and one that replaces a
// test keeps its name (CONTRIBUTING.md, "Tests").
func checkTestsKept(base string, files map[string][]byte) ([]string, error) {
	list, err := git("ls-tree", "-r", "-z", "--name-only", base)
	if err != nil {
		return nil, err
	}
	old := map[string][]byte{}
	for _, name := range strings.Split(list, "\x00") {
		matches := false
		for _, l := range testFuncs {
			matches = matches || (name != "" && l.file(name))
		}
		if !matches {
			continue
		}
		data, err := git("show", base+":"+name)
		if err != nil {
			return nil, err
		}
		old[name] = []byte(data)
	}
	had, have := testNames(old), testNames(files)
	var problems []string
	for key, file := range had {
		if _, ok := have[key]; !ok {
			f := strings.Fields(key)
			problems = append(problems, fmt.Sprintf("%s: the %s test %s is gone; keep it, or keep its name for the test that replaces it", file, f[0], f[len(f)-1]))
		}
	}
	sort.Strings(problems)
	return problems, nil
}
