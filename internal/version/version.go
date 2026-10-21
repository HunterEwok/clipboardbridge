// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package version reports which build of clipbridge is running.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the release version. Release builds set it with
//
//	-ldflags "-X github.com/HunterEwok/clipbridge/internal/version.Version=v1.2.3"
//
// Other builds keep "dev", and String uses the module version that the Go
// toolchain records instead: the tag of an installed release, or a
// pseudo-version with the commit for a build from a checkout.
var Version = "dev"

// String describes the build in one line, for example
// "clipbridge v1.2.3 linux/arm/v6".
func String() string {
	var mainVersion, goarm string
	if info, ok := debug.ReadBuildInfo(); ok {
		mainVersion = info.Main.Version
		for _, s := range info.Settings {
			if s.Key == "GOARM" {
				goarm = s.Value
			}
		}
	}
	return describe(Version, mainVersion, runtime.GOOS, runtime.GOARCH, goarm)
}

func describe(version, mainVersion, goos, goarch, goarm string) string {
	if version == "dev" && mainVersion != "" && mainVersion != "(devel)" {
		version = mainVersion
	}
	platform := goos + "/" + goarch
	if goarch == "arm" && goarm != "" {
		// GOARM may carry a float mode, as in "7,softfloat".
		level, _, _ := strings.Cut(goarm, ",")
		platform += "/v" + level
	}
	return "clipbridge " + version + " " + platform
}
