// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/mediafile"
)

// Images and files (design.md, "Images and files"): a Board that is also
// an ImageBoard takes and gives images, and one that is a FileBoard files.
// A copied image or file list goes to the service on a connection of its
// own, as cbb copy sends one, so that its bytes do not hold up the watch;
// a written one comes the same way, as cbb paste -o asks for it, once the
// service has it whole. Received files are saved in a folder of their own
// under Config.Files, which the clipboard then points at.

// MaxImage is the largest image a board reads or writes: the largest copy
// the group carries.
const MaxImage = clip.MaxMedia

// KeepCopies is how long the folder of received files stays after a newer
// copy replaced it, for a paste that is still reading it.
var KeepCopies = 10 * time.Minute

// An Image is clipboard data of an image type: clip.TypePNG or
// clip.TypeJPEG.
type Image struct {
	Type string
	Data []byte
}

// An ImageBoard is a clipboard that takes images. Its Current and Next
// return an Item with Image set when the clipboard holds an image and no
// text.
type ImageBoard interface {
	// WriteImage puts an image into the clipboard, with text, if not
	// empty, as its plain-text alternative.
	WriteImage(img Image, text string) error
}

// A FileBoard is a clipboard that takes files. Its Current and Next return
// an Item with Files set, to their absolute paths, when the clipboard
// holds files, as a file manager copies them.
type FileBoard interface {
	// WriteFiles puts files into the clipboard, as copied in a file
	// manager.
	WriteFiles(paths []string) error
}

// sendMedia reports a copied image or files to the service, until ctx is
// done.
func sendMedia(ctx context.Context, socket string, it Item, logf func(string, ...any)) error {
	var parts []mediafile.Part
	var text string
	if it.Image != nil {
		if len(it.Text) <= clip.MaxAltText {
			text = it.Text
		}
		parts = []mediafile.Part{{Part: control.Part{Type: it.Image.Type, Size: int64(len(it.Image.Data))}}}
	} else {
		var skipped int
		var err error
		if parts, skipped, err = mediafile.Collect(it.Files); err != nil {
			return err
		}
		if skipped > 0 {
			logf("cbb: left out %d links and special files of a copy; only files and folders are synced", skipped)
		}
		if size := mediafile.Size(parts); size > clip.MaxMedia {
			return fmt.Errorf("the copy is %d bytes; the group carries at most 1 GiB", size)
		}
	}
	c, err := control.Dial(socket)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if it.Image != nil {
		err = sendImage(c, *it.Image, text, parts[0])
	} else {
		err = mediafile.Send(c, control.OpCopiedMedia, parts, "")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// The service may have refused the copy midway and said why.
	if _, rerr := c.Receive(); rerr != nil {
		return rerr
	}
	return err
}

// sendImage sends an image from memory, as mediafile.Send sends files.
func sendImage(c *control.Client, img Image, text string, p mediafile.Part) error {
	err := c.Send(&control.Message{Header: control.Header{Op: control.OpCopiedMedia}, Payload: []byte(text)})
	if err == nil {
		err = c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Part: &p.Part}})
	}
	for b := img.Data; err == nil && len(b) > 0; {
		n := min(len(b), 1<<20)
		err = c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: b[:n]})
		b = b[n:]
	}
	if err == nil {
		err = c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Done: true}})
	}
	return err
}

// media is a copy fetched from the service: an image or the paths of
// saved files, and its plain-text alternative.
type media struct {
	image *Image
	files []string
	text  string
}

// fetchMedia asks the service for the clipboard's copy: of an image, the
// PNG if it has one, else the JPEG; files are saved in a new folder of
// copies, if any.
func fetchMedia(ctx context.Context, socket string, copies *copies) (media, error) {
	c, err := control.Dial(socket)
	if err != nil {
		return media{}, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPasteMedia}})
	if err != nil {
		return media{}, err
	}
	got := media{text: string(m.Payload)}
	first, err := c.Receive()
	if err != nil {
		return media{}, err
	}
	if first.Part != nil && (first.Part.Path != "" || first.Part.Dir) {
		if copies == nil {
			return media{}, errors.New("this clipboard takes no files")
		}
		dir, err := copies.fresh()
		if err != nil {
			return media{}, err
		}
		got.files, err = mediafile.Save(&peeked{first: first, c: c}, dir)
		if err != nil {
			copies.drop(dir)
			return media{}, err
		}
		return got, nil
	}
	got.image, err = receiveImage(c, first)
	return got, err
}

// receiveImage collects the image parts that follow paste-media's first
// answer, starting with m, and picks the best.
func receiveImage(c *control.Client, m *control.Message) (*Image, error) {
	var imgs []Image
	var size int64
	for {
		switch {
		case m.Done:
			for _, typ := range []string{clip.TypePNG, clip.TypeJPEG} {
				for _, img := range imgs {
					if img.Type == typ {
						return &img, nil
					}
				}
			}
			return nil, errors.New("the copy holds no image")
		case m.Part != nil:
			if size += m.Part.Size; size > MaxImage {
				return nil, fmt.Errorf("the copy is larger than %d bytes", MaxImage)
			}
			imgs = append(imgs, Image{Type: m.Part.Type, Data: make([]byte, 0, m.Part.Size)})
		case len(imgs) > 0:
			last := &imgs[len(imgs)-1]
			if len(last.Data)+len(m.Payload) > cap(last.Data) {
				return nil, errors.New("the service sent more bytes than a part has")
			}
			last.Data = append(last.Data, m.Payload...)
		default:
			return nil, errors.New("the service sent bytes before a part")
		}
		var err error
		if m, err = c.Receive(); err != nil {
			return nil, err
		}
	}
}

// peeked gives a message already received, then the client's.
type peeked struct {
	first *control.Message
	c     *control.Client
}

func (p *peeked) Receive() (*control.Message, error) {
	if m := p.first; m != nil {
		p.first = nil
		return m, nil
	}
	return p.c.Receive()
}

// copies keeps the folders of received files: one for each copy, readable
// only by the user, the older ones removed KeepCopies after a newer one
// came, and all of them when the connector starts.
type copies struct {
	root string
	mu   sync.Mutex
	cur  string
}

// newCopies returns the folders under root, emptied; nil for no root.
func newCopies(root string, logf func(string, ...any)) *copies {
	if root == "" {
		return nil
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
			logf("cbb: removing old received files: %v", err)
		}
	}
	return &copies{root: root}
}

// fresh makes the folder for a new copy.
func (c *copies) fresh() (string, error) {
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(c.root, "copy-")
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	old := c.cur
	c.cur = dir
	c.mu.Unlock()
	if old != "" {
		time.AfterFunc(KeepCopies, func() { os.RemoveAll(old) })
	}
	return dir, nil
}

// drop removes the folder of a copy that did not arrive.
func (c *copies) drop(dir string) {
	c.mu.Lock()
	if c.cur == dir {
		c.cur = ""
	}
	c.mu.Unlock()
	os.RemoveAll(dir)
}
