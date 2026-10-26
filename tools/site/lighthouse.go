// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// lighthousePages are the pages CI measures: the start page left to right
// and right to left, and the two other pages.
var lighthousePages = []string{"/en/", "/ar/", "/en/download.html", "/ru/privacy.html"}

// lighthouseMin is the lowest median score each category may have; below
// it, a category in lighthouseFail fails the check and any other only
// warns.
var (
	lighthouseMin  = map[string]float64{"performance": 0.9, "accessibility": 0.95, "seo": 0.9, "best-practices": 0.9}
	lighthouseFail = map[string]bool{"performance": true, "accessibility": true, "seo": true}
)

// lighthouse serves dir on the loopback address and runs Lighthouse (bin,
// from site/package.json) runs times on each of lighthousePages, keeping
// every report in reports. The median of each page's runs counts, as
// Lighthouse advises for its run-to-run variance.
func lighthouse(dir, bin, reports string, runs int) error {
	if runs < 1 {
		return errors.New("lighthouse: runs must be at least 1")
	}
	if _, err := os.Stat(filepath.Join(dir, "en", "index.html")); err != nil {
		return fmt.Errorf("lighthouse: the site is not built: %w", err)
	}
	if err := os.MkdirAll(reports, 0o755); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	go http.Serve(ln, http.FileServer(http.Dir(dir)))
	base := "http://" + ln.Addr().String()

	var failed []string
	for _, page := range lighthousePages {
		scores := map[string][]float64{}
		for run := 1; run <= runs; run++ {
			report := filepath.Join(reports, fmt.Sprintf("%s-%d.json", reportName(page), run))
			cmd := exec.Command(bin, base+page, "--output=json", "--output-path="+report, "--quiet",
				"--only-categories="+strings.Join(slices.Sorted(maps.Keys(lighthouseMin)), ","),
				"--chrome-flags=--headless=new --no-sandbox")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("lighthouse on %s: %w", page, err)
			}
			got, err := readScores(report)
			if err != nil {
				return fmt.Errorf("lighthouse on %s: %w", page, err)
			}
			for c, s := range got {
				scores[c] = append(scores[c], s)
			}
		}
		for _, c := range slices.Sorted(maps.Keys(lighthouseMin)) {
			m := median(scores[c])
			mark := "ok"
			if m < lighthouseMin[c] {
				mark = "warning"
				if lighthouseFail[c] {
					mark = "FAIL"
					failed = append(failed, fmt.Sprintf("%s %s %.2f < %.2f", page, c, m, lighthouseMin[c]))
				}
			}
			fmt.Printf("%-20s %-15s %.2f (runs %v) %s\n", page, c, m, scores[c], mark)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("lighthouse: %s", strings.Join(failed, "; "))
	}
	return nil
}

// readScores reads the category scores of a Lighthouse JSON report; a
// category Lighthouse could not score counts as 0.
func readScores(path string) (map[string]float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r struct {
		Categories map[string]struct {
			Score *float64 `json:"score"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	scores := map[string]float64{}
	for c := range lighthouseMin {
		if s := r.Categories[c].Score; s != nil {
			scores[c] = *s
		} else {
			scores[c] = 0
		}
	}
	return scores, nil
}

// median returns the middle value, or the mean of the two middle ones.
func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Sorted(slices.Values(v))
	if n := len(s); n%2 == 0 {
		return (s[n/2-1] + s[n/2]) / 2
	}
	return s[len(s)/2]
}

// reportName turns a page's path into a file name: "/en/" is "en",
// "/ru/privacy.html" is "ru-privacy".
func reportName(page string) string {
	n := strings.TrimSuffix(strings.Trim(page, "/"), ".html")
	return strings.ReplaceAll(n, "/", "-")
}
