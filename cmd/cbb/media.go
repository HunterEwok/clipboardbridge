// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/service"
)

// Images and files on the command line (design.md, "Images and files"):
// cbb copy FILE... sends files and folders, or with -type one image, and
// cbb paste -o DIR saves what the clipboard holds. The command reads and
// writes the files itself, as the user, and streams their bytes over the
// control socket; the service keeps them in its cache.

// mediaType reads the -type of cbb copy: png, jpeg or html, or the type
// itself.
func mediaType(t string) (string, error) {
	switch strings.ToLower(t) {
	case "png", clip.TypePNG:
		return clip.TypePNG, nil
	case "jpeg", "jpg", clip.TypeJPEG:
		return clip.TypeJPEG, nil
	case "html", clip.TypeHTML:
		return clip.TypeHTML, nil
	}
	return "", fmt.Errorf("-type is png, jpeg or html, not %q", t)
}

// mediaPart is a part to send, with the file it comes from.
type mediaPart struct {
	control.Part
	file string // "" for a folder
}

// collect lists the parts of a copy of the files and folders at paths:
// each by its cleaned name, a folder with its tree, links and special
// files left out (it returns how many).
func collect(paths []string) ([]mediaPart, int, error) {
	var parts []mediaPart
	seen := map[string]bool{}
	skipped, names := 0, 0
	add := func(p mediaPart) error {
		if seen[p.Path] {
			return fmt.Errorf("two files would be %q in the copy", p.Path)
		}
		seen[p.Path] = true
		names += len(p.Path)
		switch {
		case len(parts) == clip.MaxParts:
			return fmt.Errorf("a copy has at most %d files and folders", clip.MaxParts)
		case names > clip.MaxPaths:
			return errors.New("the names in the copy are too long together")
		case len(p.Path) > clip.MaxPath:
			return fmt.Errorf("the path %q is too long", p.Path)
		}
		parts = append(parts, p)
		return nil
	}
	for _, arg := range paths {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return nil, 0, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, 0, err
		}
		top := clip.CleanName(filepath.Base(abs))
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return nil, 0, fmt.Errorf("%s is not a file or a folder", arg)
			}
			if err := add(mediaPart{Part: control.Part{Path: top, Size: info.Size()}, file: abs}); err != nil {
				return nil, 0, err
			}
			continue
		}
		err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(abs, p)
			if err != nil {
				return err
			}
			name := top
			if rel != "." {
				var clean []string
				for n := range strings.SplitSeq(filepath.ToSlash(rel), "/") {
					clean = append(clean, clip.CleanName(n))
				}
				name = path.Join(top, path.Join(clean...))
			}
			switch {
			case d.IsDir():
				return add(mediaPart{Part: control.Part{Path: name, Dir: true}})
			case !d.Type().IsRegular():
				skipped++ // links are neither followed nor sent
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return add(mediaPart{Part: control.Part{Path: name, Size: info.Size()}, file: p})
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return parts, skipped, nil
}

// copyMedia sends the files at paths, or with typ the one file as an
// image or HTML, as the clipboard's new content, with text as its plain
// text, if any.
func copyMedia(paths []string, typ, text string, stdout, stderr io.Writer) int {
	var parts []mediaPart
	if typ != "" {
		if len(paths) != 1 {
			fmt.Fprintln(stderr, "cbb: copy -type takes one file")
			return 2
		}
		t, err := mediaType(typ)
		if err != nil {
			fmt.Fprintln(stderr, "cbb:", err)
			return 2
		}
		info, err := os.Stat(paths[0])
		if err != nil {
			return fail(stderr, err)
		}
		if !info.Mode().IsRegular() {
			return fail(stderr, fmt.Errorf("%s is not a file", paths[0]))
		}
		parts = []mediaPart{{Part: control.Part{Type: t, Size: info.Size()}, file: paths[0]}}
	} else {
		var skipped int
		var err error
		if parts, skipped, err = collect(paths); err != nil {
			return fail(stderr, err)
		}
		if skipped > 0 {
			fmt.Fprintf(stderr, "cbb: left out %d links and special files; only files and folders are copied\n", skipped)
		}
	}
	var total int64
	for _, p := range parts {
		total += p.Size
	}
	if total > clip.MaxMedia {
		return fail(stderr, fmt.Errorf("the copy is %s; Clipboard Bridge carries at most 1 GiB", service.SizeText(total)))
	}
	c, err := control.DialFor(control.OpCopyMedia)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if err := sendMedia(c, parts, text); err != nil {
		// The service may have refused the copy midway and said why.
		if m, rerr := c.Receive(); rerr != nil && m != nil {
			return fail(stderr, rerr)
		}
		return fail(stderr, err)
	}
	if _, err := c.Receive(); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Copied %s to the group.\n", describe(parts, total))
	return 0
}

// describe says what a copy holds: an image, a file, or so many files and
// folders, and its size.
func describe(parts []mediaPart, total int64) string {
	files, dirs := 0, 0
	for _, p := range parts {
		switch {
		case p.Type != "":
			return fmt.Sprintf("the %s (%s)", p.Type, service.SizeText(total))
		case p.Dir:
			dirs++
		default:
			files++
		}
	}
	switch {
	case dirs == 0 && files == 1:
		return fmt.Sprintf("%s (%s)", parts[0].Path, service.SizeText(total))
	case dirs == 0:
		return fmt.Sprintf("%d files (%s)", files, service.SizeText(total))
	}
	return fmt.Sprintf("%d files in %d folders (%s)", files, dirs, service.SizeText(total))
}

// sendMedia sends the request, each part and its bytes, and the end.
func sendMedia(c *control.Client, parts []mediaPart, text string) error {
	if err := c.Send(&control.Message{Header: control.Header{Op: control.OpCopyMedia}, Payload: []byte(text)}); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for _, p := range parts {
		if err := c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Part: &p.Part}}); err != nil {
			return err
		}
		if p.Dir {
			continue
		}
		if err := sendFile(c, p, buf); err != nil {
			return err
		}
	}
	return c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Done: true}})
}

// sendFile sends exactly the size the part says of its file.
func sendFile(c *control.Client, p mediaPart, buf []byte) error {
	f, err := os.Open(p.file)
	if err != nil {
		return err
	}
	defer f.Close()
	left := p.Size
	for left > 0 {
		n, err := io.ReadFull(f, buf[:min(int64(len(buf)), left)])
		if n > 0 {
			if err := c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: buf[:n]}); err != nil {
				return err
			}
			left -= int64(n)
		}
		if err != nil && left > 0 {
			return fmt.Errorf("%s changed while it was copied", p.file)
		}
	}
	return nil
}

// pasteMedia saves the images or files of the clipboard in dir: files and
// folders by their names, an image as image.png or image.jpg, HTML as
// clipboard.html. It never replaces a file, and makes nothing executable.
func pasteMedia(dir string, stdout, stderr io.Writer) int {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fail(stderr, fmt.Errorf("%s is not a folder", dir))
	}
	c, err := control.DialFor(control.OpPasteMedia)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPasteMedia}}); err != nil {
		return fail(stderr, err)
	}
	var made []string // to remove when the paste fails
	failed := func(err error) int {
		for i := len(made) - 1; i >= 0; i-- {
			os.Remove(made[i])
		}
		return fail(stderr, err)
	}
	var top []string
	for {
		m, err := c.Receive()
		if err != nil {
			return failed(err)
		}
		if m.Done {
			break
		}
		if m.Part == nil {
			return failed(errors.New("the service sent bytes without their part"))
		}
		name, err := savedName(*m.Part)
		if err != nil {
			return failed(err)
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if !strings.Contains(name, "/") {
			top = append(top, target)
		}
		if m.Part.Dir {
			if err := os.Mkdir(target, 0o755); err != nil {
				return failed(err)
			}
			made = append(made, target)
			continue
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return failed(err)
		}
		made = append(made, target)
		err = receiveFile(c, f, m.Part.Size)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return failed(err)
		}
	}
	for _, t := range top {
		fmt.Fprintln(stdout, t)
	}
	return 0
}

// savedName is where a part goes in the folder: its path, checked again,
// or a name for its type.
func savedName(p control.Part) (string, error) {
	switch p.Type {
	case "":
		return p.Path, clip.CheckPath(p.Path)
	case clip.TypePNG:
		return "image.png", nil
	case clip.TypeJPEG:
		return "image.jpg", nil
	case clip.TypeHTML:
		return "clipboard.html", nil
	}
	return "", fmt.Errorf("the clipboard holds %s, which this cbb does not know", p.Type)
}

// receiveFile writes size bytes of the service's answers to f.
func receiveFile(c *control.Client, f *os.File, size int64) error {
	for got := int64(0); got < size; {
		m, err := c.Receive()
		if err != nil {
			return err
		}
		if m.Part != nil || m.Done || len(m.Payload) == 0 || int64(len(m.Payload)) > size-got {
			return errors.New("the service sent the bytes of a part not as said")
		}
		if _, err := f.Write(m.Payload); err != nil {
			return err
		}
		got += int64(len(m.Payload))
	}
	return nil
}

// cmdConfig shows or changes this device's settings: the largest copy of
// images and files it sends or fetches, at home and away from home.
func cmdConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if fs.Parse(args) != nil {
		return 2
	}
	if n := fs.NArg(); n != 0 && n != 2 {
		fmt.Fprintln(stderr, "usage: cbb config\n       cbb config max-copy|max-copy-away SIZE (such as 200MiB)")
		return 2
	}
	h := control.Header{Op: control.OpConfig, Name: fs.Arg(0), Value: fs.Arg(1)}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	if m.Status == nil || m.Status.Media == nil {
		return fail(stderr, errors.New("this device is in no group; run cbb new here to start one, or cbb pair to join one"))
	}
	fmt.Fprintf(stdout, "max-copy       %s  the largest copy of images and files this device sends or fetches at home\n", service.SizeText(m.Status.Media.MaxCopy))
	fmt.Fprintf(stdout, "max-copy-away  %s  the same away from home\n", service.SizeText(m.Status.Media.MaxCopyAway))
	return 0
}

// writeMedia says in cbb status what is being fetched, or why the last
// copy was not.
func writeMedia(w io.Writer, st *control.Media) {
	switch {
	case st == nil:
	case st.Fetching > 0:
		from := ""
		if st.From != "" {
			from = " from " + st.From
		}
		fmt.Fprintf(w, "Fetching a copy of %s%s: %d%%.\n", service.SizeText(st.Fetching), from, st.Fetched*100/st.Fetching)
	case st.Failed != "":
		fmt.Fprintf(w, "The last copy of images or files was not fetched: %s.\n", st.Failed)
	}
}
