// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Report collects the cases of one run, prints each as it ends, and writes
// JUnit XML for GitHub's test summary and a plain text copy.
type Report struct {
	suite string
	out   io.Writer
	debug bool
	start time.Time

	mu    sync.Mutex
	cases []Case
}

// Case is one test case's result.
type Case struct {
	Name     string
	Duration time.Duration
	Skipped  string // why, when the case did not run
	Failure  string // the user-facing reason, empty when it passed
	Details  string // the commands' output behind a failure
}

func NewReport(suite string, out io.Writer, debug bool) *Report {
	return &Report{suite: suite, out: out, debug: debug, start: time.Now()}
}

// Do runs one case and records it. f returns nil when the case passed.
func (r *Report) Do(name string, f func() error) error {
	start := time.Now()
	err := f()
	c := Case{Name: name, Duration: time.Since(start)}
	if err != nil {
		c.Failure = err.Error()
		var re interface{ Details() string }
		if errors.As(err, &re) {
			c.Details = re.Details()
		}
	}
	r.add(c)
	return err
}

// Skip records a case that did not run.
func (r *Report) Skip(name, why string) { r.add(Case{Name: name, Skipped: why}) }

func (r *Report) add(c Case) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cases = append(r.cases, c)
	switch {
	case c.Skipped != "":
		fmt.Fprintf(r.out, "SKIP %s: %s\n", c.Name, c.Skipped)
	case c.Failure != "":
		fmt.Fprintf(r.out, "FAIL %s (%.1fs): %s\n", c.Name, c.Duration.Seconds(), c.Failure)
		if r.debug && c.Details != "" {
			fmt.Fprintf(r.out, "     %s\n", strings.ReplaceAll(strings.TrimSpace(c.Details), "\n", "\n     "))
		}
	default:
		fmt.Fprintf(r.out, "PASS %s (%.1fs)\n", c.Name, c.Duration.Seconds())
	}
}

// Failed counts the failed cases.
func (r *Report) Failed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.cases {
		if c.Failure != "" {
			n++
		}
	}
	return n
}

type junitSuites struct {
	XMLName xml.Name   `xml:"testsuites"`
	Suites  []junitRun `xml:"testsuite"`
}

type junitRun struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     float64     `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Class   string        `xml:"classname,attr"`
	Time    float64       `xml:"time,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
	Skipped *junitFailure `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// Write writes report.xml and report.txt into dir.
func (r *Report) Write(dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	run := junitRun{Name: "bench/" + r.suite, Tests: len(r.cases), Time: time.Since(r.start).Seconds()}
	var txt strings.Builder
	fmt.Fprintf(&txt, "bench %s, %s\n\n", r.suite, r.start.UTC().Format(time.RFC3339))
	for _, c := range r.cases {
		jc := junitCase{Name: c.Name, Class: "bench." + r.suite, Time: c.Duration.Seconds()}
		switch {
		case c.Skipped != "":
			run.Skipped++
			jc.Skipped = &junitFailure{Message: c.Skipped}
			fmt.Fprintf(&txt, "SKIP %s: %s\n", c.Name, c.Skipped)
		case c.Failure != "":
			run.Failures++
			jc.Failure = &junitFailure{Message: c.Failure, Text: c.Details}
			fmt.Fprintf(&txt, "FAIL %s: %s\n%s\n", c.Name, c.Failure, c.Details)
		default:
			fmt.Fprintf(&txt, "PASS %s (%.1fs)\n", c.Name, c.Duration.Seconds())
		}
		run.Cases = append(run.Cases, jc)
	}
	b, err := xml.MarshalIndent(junitSuites{Suites: []junitRun{run}}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.xml"), append([]byte(xml.Header), b...), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.txt"), []byte(txt.String()), 0o600)
}
