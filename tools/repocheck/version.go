// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// androidVersion is the file with the Android apps' version, which their
// builds and F-Droid read (docs/apps.md, "F-Droid").
const androidVersion = "apps/android/version.properties"

// released matches a release's heading in CHANGELOG.md.
var released = regexp.MustCompile(`(?m)^## \[(\d+)\.(\d+)\.(\d+)\] - `)

// checkAndroidVersion checks that the Android apps' version is the last
// release in CHANGELOG.md and that its versionCode is X*10000 + Y*100 + Z,
// so that the pull request that moves the changes under a new version also
// moves the apps on, and the tag's build is that version.
func checkAndroidVersion(files map[string][]byte) []string {
	data, ok := files[androidVersion]
	if !ok {
		return nil
	}
	props := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			props[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	m := released.FindSubmatch(files["CHANGELOG.md"])
	if m == nil {
		return []string{"CHANGELOG.md: no released version for " + androidVersion + " to follow"}
	}
	var problems []string
	if want := fmt.Sprintf("%s.%s.%s", m[1], m[2], m[3]); props["versionName"] != want {
		problems = append(problems, fmt.Sprintf("%s: versionName is %q, the last release in CHANGELOG.md is %s", androidVersion, props["versionName"], want))
	}
	var n [3]int
	for i := range n {
		n[i], _ = strconv.Atoi(string(m[i+1]))
	}
	if want := strconv.Itoa(n[0]*10000 + n[1]*100 + n[2]); props["versionCode"] != want {
		problems = append(problems, fmt.Sprintf("%s: versionCode is %q, want %s for the last release", androidVersion, props["versionCode"], want))
	}
	return problems
}
