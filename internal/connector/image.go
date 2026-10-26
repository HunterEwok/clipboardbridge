// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"context"
	"errors"
	"fmt"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// Images (design.md, "Images and files"): a Board that is also an
// ImageBoard takes and gives images. A copied image goes to the service on
// a connection of its own, as cbb copy -type sends one, so that its bytes
// do not hold up the watch; a written one comes the same way, as cbb paste
// -o asks for it, once the service has it whole.

// MaxImage is the largest image a board reads or writes: the largest copy
// the group carries.
const MaxImage = clip.MaxMedia

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

// sendImage reports a copied image to the service, with the item's text
// as its plain-text alternative.
func sendImage(socket string, it Item) error {
	text := it.Text
	if len(text) > clip.MaxAltText {
		text = ""
	}
	c, err := control.Dial(socket)
	if err != nil {
		return err
	}
	defer c.Close()
	img := it.Image
	err = c.Send(&control.Message{Header: control.Header{Op: control.OpCopiedMedia}, Payload: []byte(text)})
	if err == nil {
		err = c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Part: &control.Part{Type: img.Type, Size: int64(len(img.Data))}}})
	}
	for b := img.Data; err == nil && len(b) > 0; {
		n := min(len(b), 1<<20)
		err = c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: b[:n]})
		b = b[n:]
	}
	if err == nil {
		err = c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Done: true}})
	}
	// The service may have refused the image midway and said why.
	if _, rerr := c.Receive(); rerr != nil {
		return rerr
	}
	return err
}

// fetchImage asks the service for the image of the clipboard's copy: the
// PNG if it has one, else the JPEG.
func fetchImage(ctx context.Context, socket string) (Image, string, error) {
	c, err := control.Dial(socket)
	if err != nil {
		return Image{}, "", err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPasteMedia}})
	if err != nil {
		return Image{}, "", err
	}
	text := string(m.Payload)
	var imgs []Image
	var size int64
	for {
		m, err := c.Receive()
		if err != nil {
			return Image{}, "", err
		}
		switch {
		case m.Done:
			for _, typ := range []string{clip.TypePNG, clip.TypeJPEG} {
				for _, img := range imgs {
					if img.Type == typ {
						return img, text, nil
					}
				}
			}
			return Image{}, "", errors.New("the copy holds no image")
		case m.Part != nil:
			if size += m.Part.Size; size > MaxImage {
				return Image{}, "", fmt.Errorf("the copy is larger than %d bytes", MaxImage)
			}
			imgs = append(imgs, Image{Type: m.Part.Type, Data: make([]byte, 0, m.Part.Size)})
		case len(imgs) > 0:
			last := &imgs[len(imgs)-1]
			if len(last.Data)+len(m.Payload) > cap(last.Data) {
				return Image{}, "", errors.New("the service sent more bytes than a part has")
			}
			last.Data = append(last.Data, m.Payload...)
		default:
			return Image{}, "", errors.New("the service sent bytes before a part")
		}
	}
}
