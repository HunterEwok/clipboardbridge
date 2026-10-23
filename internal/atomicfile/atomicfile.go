// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package atomicfile replaces files so that a reader, or a restart after a
// crash or a power cut, sees either the old content or the new one, never a
// mix or an empty file.
package atomicfile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Write replaces the file at path with data. The file gets the mode perm,
// whatever the mode of the file it replaces.
//
// The data goes to a temporary file in the same directory, which is flushed
// to disk and then renamed over path; the directory is flushed too, so the
// rename survives a power cut.
func Write(path string, data []byte, perm fs.FileMode) (err error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+name+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	// CreateTemp makes the file with mode 0600; set the final mode before
	// any data is written, so the data is never readable with a wider mode.
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("atomicfile: %s was replaced, but flushing its directory failed: %w", path, err)
	}
	return nil
}
