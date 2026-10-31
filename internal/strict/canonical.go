// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package strict

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// CheckCanonical checks that b is a signed body in the strict form and in
// its canonical form (docs/records-v2.md, "Canonical form of signed
// bodies"): no whitespace outside strings, the members of every object in
// bytewise order of their names, and in strings only the escapes \", \\
// and \u00XX, in lower-case hex, for a character below U+0020. So b is
// the bytes Canonicalize gives for what it holds. Each name in required
// must be a member of the object.
func CheckCanonical(b []byte, required ...string) error {
	if err := Check(b, required...); err != nil {
		return err
	}
	c := canonChecker{b: b}
	if err := c.value(); err != nil {
		return fmt.Errorf("a signed body is not in its canonical form: %w", err)
	}
	if c.i != len(b) {
		return errors.New("a signed body is not in its canonical form: it has more after its object")
	}
	return nil
}

// canonChecker walks a body that Check has already taken, so it only
// looks at what the canonical form adds.
type canonChecker struct {
	b []byte
	i int
}

func (c *canonChecker) value() error {
	if c.i >= len(c.b) {
		return errors.New("it ends early")
	}
	switch c.b[c.i] {
	case '{':
		return c.object()
	case '[':
		return c.array()
	case '"':
		_, err := c.str()
		return err
	case 't':
		c.i += len("true")
	case 'f':
		c.i += len("false")
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		c.i++
		for c.i < len(c.b) && c.b[c.i] >= '0' && c.b[c.i] <= '9' {
			c.i++
		}
	default:
		return fmt.Errorf("whitespace or %q where a value starts", c.b[c.i])
	}
	return nil
}

func (c *canonChecker) object() error {
	c.i++ // {
	if c.i < len(c.b) && c.b[c.i] == '}' {
		c.i++
		return nil
	}
	var last []byte
	for first := true; ; first = false {
		if c.i >= len(c.b) || c.b[c.i] != '"' {
			return errors.New("whitespace before a member name")
		}
		name, err := c.str()
		if err != nil {
			return err
		}
		if !first && bytes.Compare(last, name) >= 0 {
			return fmt.Errorf("the member %s is out of order", name)
		}
		last = name
		if c.i >= len(c.b) || c.b[c.i] != ':' {
			return errors.New("whitespace after a member name")
		}
		c.i++
		if err := c.value(); err != nil {
			return err
		}
		if c.i >= len(c.b) {
			return errors.New("it ends early")
		}
		switch c.b[c.i] {
		case ',':
			c.i++
		case '}':
			c.i++
			return nil
		default:
			return errors.New("whitespace in an object")
		}
	}
}

func (c *canonChecker) array() error {
	c.i++ // [
	if c.i < len(c.b) && c.b[c.i] == ']' {
		c.i++
		return nil
	}
	for {
		if err := c.value(); err != nil {
			return err
		}
		if c.i >= len(c.b) {
			return errors.New("it ends early")
		}
		switch c.b[c.i] {
		case ',':
			c.i++
		case ']':
			c.i++
			return nil
		default:
			return errors.New("whitespace in an array")
		}
	}
}

// str reads a string at c.i and returns its raw bytes between the quotes.
func (c *canonChecker) str() ([]byte, error) {
	c.i++ // "
	start := c.i
	for c.i < len(c.b) {
		switch ch := c.b[c.i]; ch {
		case '"':
			s := c.b[start:c.i]
			c.i++
			return s, nil
		case '\\':
			if c.i+1 >= len(c.b) {
				return nil, errors.New("it ends early")
			}
			switch c.b[c.i+1] {
			case '"', '\\':
				c.i += 2
			case 'u':
				if c.i+6 > len(c.b) {
					return nil, errors.New("it ends early")
				}
				h := string(c.b[c.i+2 : c.i+6])
				v, err := strconv.ParseUint(h, 16, 16)
				if err != nil || v >= 0x20 || h != fmt.Sprintf("%04x", v) {
					return nil, errors.New("a string has an escape the canonical form writes otherwise")
				}
				c.i += 6
			default:
				return nil, errors.New("a string has an escape the canonical form writes otherwise")
			}
		default:
			c.i++
		}
	}
	return nil, errors.New("it ends early")
}

// Canonicalize returns the canonical form of b, a body in the strict
// form: what a signer signs after it has built the body with any JSON
// encoder.
func Canonicalize(b []byte) ([]byte, error) {
	if err := Check(b); err != nil {
		return nil, err
	}
	r := canonReader{b: b}
	var out bytes.Buffer
	r.space()
	if err := r.value(&out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// canonReader reads a body that Check has taken and writes it again in
// the canonical form.
type canonReader struct {
	b []byte
	i int
}

func (r *canonReader) space() {
	for r.i < len(r.b) && (r.b[r.i] == ' ' || r.b[r.i] == '\t' || r.b[r.i] == '\n' || r.b[r.i] == '\r') {
		r.i++
	}
}

func (r *canonReader) value(out *bytes.Buffer) error {
	r.space()
	switch c := r.b[r.i]; {
	case c == '{':
		return r.object(out)
	case c == '[':
		r.i++
		out.WriteByte('[')
		r.space()
		if r.b[r.i] == ']' {
			r.i++
			out.WriteByte(']')
			return nil
		}
		for {
			if err := r.value(out); err != nil {
				return err
			}
			r.space()
			if r.b[r.i] == ']' {
				r.i++
				out.WriteByte(']')
				return nil
			}
			r.i++ // ,
			out.WriteByte(',')
		}
	case c == '"':
		s, err := r.str()
		if err != nil {
			return err
		}
		writeString(out, s)
	default:
		start := r.i
		for r.i < len(r.b) && r.b[r.i] != ',' && r.b[r.i] != '}' && r.b[r.i] != ']' &&
			r.b[r.i] != ' ' && r.b[r.i] != '\t' && r.b[r.i] != '\n' && r.b[r.i] != '\r' {
			r.i++
		}
		out.Write(r.b[start:r.i])
	}
	return nil
}

func (r *canonReader) object(out *bytes.Buffer) error {
	r.i++ // {
	type member struct {
		name string
		val  []byte
	}
	var members []member
	r.space()
	if r.b[r.i] != '}' {
		for {
			r.space()
			name, err := r.str()
			if err != nil {
				return err
			}
			r.space()
			r.i++ // :
			var v bytes.Buffer
			if err := r.value(&v); err != nil {
				return err
			}
			members = append(members, member{name, v.Bytes()})
			r.space()
			if r.b[r.i] == '}' {
				break
			}
			r.i++ // ,
		}
	}
	r.i++ // }
	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
	out.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		writeString(out, m.name)
		out.WriteByte(':')
		out.Write(m.val)
	}
	out.WriteByte('}')
	return nil
}

// str reads a string at r.i and returns its value.
func (r *canonReader) str() (string, error) {
	r.i++ // "
	var s []byte
	for {
		c := r.b[r.i]
		switch {
		case c == '"':
			r.i++
			return string(s), nil
		case c != '\\':
			s = append(s, c)
			r.i++
			continue
		}
		r.i++
		switch e := r.b[r.i]; e {
		case '"', '\\', '/':
			s = append(s, e)
			r.i++
		case 'b':
			s, r.i = append(s, '\b'), r.i+1
		case 'f':
			s, r.i = append(s, '\f'), r.i+1
		case 'n':
			s, r.i = append(s, '\n'), r.i+1
		case 'r':
			s, r.i = append(s, '\r'), r.i+1
		case 't':
			s, r.i = append(s, '\t'), r.i+1
		case 'u':
			v, _ := strconv.ParseUint(string(r.b[r.i+1:r.i+5]), 16, 16)
			r.i += 5
			ru := rune(v)
			if utf16.IsSurrogate(ru) {
				low, _ := strconv.ParseUint(string(r.b[r.i+2:r.i+6]), 16, 16)
				r.i += 6
				ru = utf16.DecodeRune(ru, rune(low))
			}
			s = utf8.AppendRune(s, ru)
		}
	}
}

// writeString writes s as a string in the canonical form.
func writeString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c < 0x20:
			fmt.Fprintf(out, "\\u%04x", c)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
}
