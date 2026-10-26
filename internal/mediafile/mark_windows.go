// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mediafile

import "os"

// markDownload gives the file the Mark of the Web, the Zone.Identifier
// stream a browser writes, so SmartScreen and Office treat it as from the
// internet (zone 3). A file system without streams, such as FAT, cannot
// hold it; the file is kept unmarked then.
func markDownload(path string) error {
	f, err := os.OpenFile(path+":Zone.Identifier", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil
	}
	_, err = f.WriteString("[ZoneTransfer]\r\nZoneId=3\r\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
