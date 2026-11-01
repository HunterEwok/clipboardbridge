// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package core

// The kinds of signed body CheckBody reads (docs/core-api.md, "Signed
// bodies").
const (
	KindCommand    = "command"
	KindCredential = "credential"
	KindKeys       = "keys"
	KindRelease    = "release"
	KindChannel    = "channel"
	KindStatus     = "attest-status"
	KindManifest   = "manifest"
)

// CheckBody checks a signed body of the kind through the core's
// parse_body when the build links the core, as the release builds do:
// the core then decides alone whether the body is taken, so that every
// program takes the same bodies. checked is false in a build without the
// core, whose caller checks the body with Go's own code, which the tests
// keep the same as the core's. The error is the core's refusal, its
// *Refusal, or a failure to reach the core.
func CheckBody(kind string, body []byte) (checked bool, err error) {
	if !linked {
		return false, nil
	}
	args := map[string]any{"kind": kind, "body": body}
	return true, Do("parse_body", args, nil)
}
