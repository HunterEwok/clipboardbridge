// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"bytes"
	"net/url"
	"path/filepath"
	"strings"
)

// Files on the Linux desktops (design.md, "Images and files"): file
// managers copy a list of file URIs, as text/uri-list (RFC 2483) and
// GNOME's x-special/gnome-copied-files, next to the paths as text. A
// cut is taken as a copy: nothing is ever deleted on the source.
//
// A Flatpak app sees only its own sandbox, so a written list also
// carries a key of the FileTransfer portal, which hands the files into
// the app's sandbox when it pastes. Files a Flatpak app copies are under
// the document portal's /run/user/UID/doc, which the host reads, so a
// read needs no portal.

const (
	uriListType     = "text/uri-list"
	gnomeFilesType  = "x-special/gnome-copied-files"
	portalFilesType = "application/vnd.portal.filetransfer"
	// maxFileList bounds a list of files read from the clipboard.
	maxFileList = 1 << 20
)

// fileTypes are the types of a list of files, the best first.
var fileTypes = []string{uriListType, gnomeFilesType}

// filePaths returns the local paths of a list of files of the type typ;
// none when it holds no file URI of this computer, as a list of links
// from a browser.
func filePaths(typ string, data []byte) []string {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if typ == gnomeFilesType && len(lines) > 0 {
		lines = lines[1:] // "copy" or "cut"
	}
	var paths []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		u, err := url.Parse(l)
		if err != nil || u.Scheme != "file" || (u.Host != "" && u.Host != "localhost") || !filepath.IsAbs(u.Path) {
			continue
		}
		paths = append(paths, filepath.Clean(u.Path))
	}
	return paths
}

// fileURI is the file URI of an absolute path.
func fileURI(path string) string {
	return (&url.URL{Scheme: "file", Path: path}).String()
}

// fileData is what a written list of files holds for each of its types:
// the URIs in both forms, the paths as text, and the portal's key, if any.
func fileData(paths []string, key string) map[string][]byte {
	var list, gnome bytes.Buffer
	gnome.WriteString("copy")
	for _, p := range paths {
		u := fileURI(p)
		list.WriteString(u + "\r\n")
		gnome.WriteString("\n" + u)
	}
	data := map[string][]byte{uriListType: list.Bytes(), gnomeFilesType: gnome.Bytes()}
	if key != "" {
		data[portalFilesType] = []byte(key)
	}
	return data
}
