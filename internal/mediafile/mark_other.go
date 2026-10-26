// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !darwin && !windows

package mediafile

// markDownload does nothing: Linux has no mark of a downloaded file.
func markDownload(string) error { return nil }
