// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command repocheck enforces the repository rules that the Go tools do not
// check:
//
//   - every tracked text file is in English: no Cyrillic letters;
//   - every Go file, except generated code, starts with the license header.
//
// Run it anywhere inside the repository:
//
//	go run ./tools/repocheck
package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unicode"
)

const spdxLine = "// SPDX-License-Identifier: AGPL-3.0-only"

var copyrightLine = regexp.MustCompile(`^// Copyright \(C\) \d{4}(-\d{4})? HunterEwok$`)

func main() {
	problems, checked, err := checkRepo()
	if err != nil {
		fmt.Fprintln(os.Stderr, "repocheck:", err)
		os.Exit(1)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "repocheck: %d problem(s) in %d file(s) checked\n", len(problems), checked)
		os.Exit(1)
	}
}

// checkRepo checks the repository that contains the current directory and
// returns the problems and the number of files checked.
func checkRepo() (problems []string, checked int, err error) {
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, 0, err
	}
	if err := os.Chdir(strings.TrimSpace(top)); err != nil {
		return nil, 0, err
	}
	// Tracked files and new files that are not ignored, so a local run also
	// checks files that are not committed yet.
	out, err := git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--deduplicate")
	if err != nil {
		return nil, 0, err
	}
	for _, name := range strings.Split(out, "\x00") {
		if name == "" {
			continue
		}
		data, ok, err := readEntry(name)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if !ok {
			continue
		}
		checked++
		problems = append(problems, check(name, data)...)
	}
	return problems, checked, nil
}

// readEntry returns the content to check for one listed path: the file, or
// the target path of a symbolic link. It reports false for entries that have
// no content of their own: a deletion not committed yet, a submodule or a
// directory.
func readEntry(name string) ([]byte, bool, error) {
	fi, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(name)
		return []byte(target), err == nil, err
	case !fi.Mode().IsRegular():
		return nil, false, nil
	}
	data, err := os.ReadFile(name)
	return data, err == nil, err
}

// git runs a git command and returns its standard output.
func git(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// check returns the rule violations in one file.
func check(name string, data []byte) []string {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil // a binary file
	}
	var problems []string
	for i, line := range strings.Split(string(data), "\n") {
		if r, ok := firstCyrillic(line); ok {
			problems = append(problems, fmt.Sprintf("%s:%d: Cyrillic letter %q; the repository is in English only", name, i+1, r))
		}
	}
	if strings.HasSuffix(name, ".go") && !isGenerated(data) && !hasHeader(data) {
		problems = append(problems, fmt.Sprintf("%s:1: missing license header; start the file with\n\t%s\n\t// Copyright (C) <year> HunterEwok", name, spdxLine))
	}
	return problems
}

func firstCyrillic(s string) (rune, bool) {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return r, true
		}
	}
	return 0, false
}

// isGenerated reports whether a Go file carries the generated-code marker
// before its package clause, as https://go.dev/s/generatedcode defines it.
func isGenerated(data []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "", data, parser.PackageClauseOnly|parser.ParseComments)
	return err == nil && ast.IsGenerated(f)
}

func hasHeader(data []byte) bool {
	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 2 {
		return false
	}
	return strings.TrimSuffix(lines[0], "\r") == spdxLine &&
		copyrightLine.MatchString(strings.TrimSuffix(lines[1], "\r"))
}
