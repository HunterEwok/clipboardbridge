// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package atomicfile

// syncDir does nothing on Windows: a directory cannot be flushed there,
// and NTFS journals the rename itself.
func syncDir(string) error { return nil }
