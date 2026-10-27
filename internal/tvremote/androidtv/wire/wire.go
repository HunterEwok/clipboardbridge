// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package wire is the framing and the protobuf fields of the Android TV
// Remote v2 protocol: each message after its length as a varint. It is
// apart so that the fake TV of the tests speaks it too.
package wire

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protowire"
)

// maxMessage is the longest message taken from a TV: a text field's value
// and an app's name fit in it many times over.
const maxMessage = 64 << 10

// Write writes one message after its length.
func Write(w io.Writer, m []byte) error {
	_, err := w.Write(protowire.AppendBytes(nil, m))
	return err
}

// Read reads one message.
func Read(r *bufio.Reader) ([]byte, error) {
	var n uint64
	for shift := 0; ; shift += 7 {
		if shift > 63 {
			return nil, errors.New("a message's length is too long a number")
		}
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		n |= uint64(b&0x7f) << shift
		if b < 0x80 {
			break
		}
	}
	if n > maxMessage {
		return nil, fmt.Errorf("a message of %d bytes, more than %d", n, maxMessage)
	}
	m := make([]byte, n)
	_, err := io.ReadFull(r, m)
	return m, err
}

// field is one field of a message: a number, and its value as a varint or
// as bytes (a string or a message).
type field struct {
	num    protowire.Number
	varint uint64
	bytes  []byte
}

// fields parses a message's fields; fixed-size ones are skipped.
func fields(m []byte) ([]field, error) {
	var out []field
	for len(m) > 0 {
		num, typ, n := protowire.ConsumeTag(m)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		m = m[n:]
		f := field{num: num}
		switch typ {
		case protowire.VarintType:
			f.varint, n = protowire.ConsumeVarint(m)
		case protowire.BytesType:
			f.bytes, n = protowire.ConsumeBytes(m)
		default:
			n = protowire.ConsumeFieldValue(num, typ, m)
		}
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		m = m[n:]
		out = append(out, f)
	}
	return out, nil
}

// Message is a parsed message.
type Message []field

func Parse(m []byte) (Message, error) {
	f, err := fields(m)
	return Message(f), err
}

// Has reports whether the message has field num.
func (m Message) Has(num protowire.Number) bool {
	for _, f := range m {
		if f.num == num {
			return true
		}
	}
	return false
}

// Int is field num as a number, 0 if it is missing.
func (m Message) Int(num protowire.Number) uint64 {
	for _, f := range m {
		if f.num == num {
			return f.varint
		}
	}
	return 0
}

// Sub is field num as a message: empty if it is missing, nil with an
// error if it does not parse.
func (m Message) Sub(num protowire.Number) (Message, error) {
	for _, f := range m {
		if f.num == num {
			return Parse(f.bytes)
		}
	}
	return Message{}, nil
}

// Str is field num as a string.
func (m Message) Str(num protowire.Number) string {
	for _, f := range m {
		if f.num == num {
			return string(f.bytes)
		}
	}
	return ""
}

// Builder writes a message's fields.
type Builder []byte

func (b Builder) Int(num protowire.Number, v uint64) Builder {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func (b Builder) Bytes(num protowire.Number, v []byte) Builder {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func (b Builder) Str(num protowire.Number, v string) Builder {
	return b.Bytes(num, []byte(v))
}

func (b Builder) Sub(num protowire.Number, v Builder) Builder {
	return b.Bytes(num, v)
}

// New starts a message.
func New() Builder { return nil }
