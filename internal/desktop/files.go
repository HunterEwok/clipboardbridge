// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
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

const (
	docsBus      = "org.freedesktop.portal.Documents"
	docsPath     = dbus.ObjectPath("/org/freedesktop/portal/documents")
	fileTransfer = "org.freedesktop.portal.FileTransfer"
	// transferCall bounds a call to the portal, which should answer at
	// once.
	transferCall = 2 * time.Second
)

// transfers offers written files to Flatpak apps through the FileTransfer
// portal: one transfer for the clipboard's files, stopped when the
// clipboard changes.
type transfers struct {
	logf func(string, ...any)
	mu   sync.Mutex
	conn *dbus.Conn // nil until the first write of files
	none bool       // the session has no portal: do not ask again
	key  string     // the transfer of the clipboard's files
}

// connect returns the session bus, dialed at first use.
func (t *transfers) connect() *dbus.Conn {
	if t.conn == nil && !t.none {
		conn, err := dbus.ConnectSessionBus()
		if err != nil {
			t.none = true
			return nil
		}
		t.conn = conn
	}
	return t.conn
}

// start stops the transfer of the clipboard's last files, if any, and
// starts one for paths; it returns its key, or "" when the session has
// no FileTransfer portal.
func (t *transfers) start(paths []string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
	conn := t.connect()
	if conn == nil {
		return ""
	}
	key, err := startTransfer(conn, paths)
	if err != nil {
		t.logf("cbb: the FileTransfer portal: %v; Flatpak apps cannot paste the files", err)
		t.none = true
		return ""
	}
	t.key = key
	return key
}

// stop stops the transfer of the clipboard's files, if any.
func (t *transfers) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
}

func (t *transfers) stopLocked() {
	if t.key != "" && t.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), transferCall)
		t.conn.Object(docsBus, docsPath).CallWithContext(ctx, fileTransfer+".StopTransfer", 0, t.key)
		cancel()
	}
	t.key = ""
}

// close stops the transfer and closes the bus.
func (t *transfers) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

// startTransfer registers paths with the portal for every paste, read
// only, and returns the transfer's key.
func startTransfer(conn *dbus.Conn, paths []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), transferCall)
	defer cancel()
	obj := conn.Object(docsBus, docsPath)
	var key string
	opts := map[string]dbus.Variant{"writable": dbus.MakeVariant(false), "autostop": dbus.MakeVariant(false)}
	if err := obj.CallWithContext(ctx, fileTransfer+".StartTransfer", 0, opts).Store(&key); err != nil {
		return "", fmt.Errorf("StartTransfer: %w", err)
	}
	fds := make([]dbus.UnixFD, 0, len(paths))
	defer func() {
		for _, fd := range fds {
			unix.Close(int(fd))
		}
	}()
	for _, p := range paths {
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return "", err
		}
		fds = append(fds, dbus.UnixFD(fd))
	}
	if err := obj.CallWithContext(ctx, fileTransfer+".AddFiles", 0, key, fds, map[string]dbus.Variant{}).Err; err != nil {
		obj.CallWithContext(ctx, fileTransfer+".StopTransfer", 0, key)
		return "", fmt.Errorf("AddFiles: %w", err)
	}
	return key, nil
}
