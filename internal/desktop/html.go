// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// htmlText is the formatted text of a clipboard's text/html: UTF-8, or
// UTF-16 with a byte order mark, as some programs on X11 still give it.
// A UTF-8 byte order mark and trailing NULs go.
func htmlText(data []byte) string {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order = binary.LittleEndian
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order = binary.BigEndian
	}
	if order != nil {
		u := make([]uint16, (len(data)-2)/2)
		for i := range u {
			u[i] = order.Uint16(data[2+2*i:])
		}
		data = []byte(string(utf16.Decode(u)))
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	return string(bytes.TrimRight(data, "\x00"))
}
