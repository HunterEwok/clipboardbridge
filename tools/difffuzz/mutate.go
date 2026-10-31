// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
)

// A mutator changes bodies: bytes at random, and, in a body that is JSON,
// its members' names, values, order and form.
type mutator struct{ r *rand.Rand }

// mutate returns one change of b.
func (m mutator) mutate(b []byte) []byte {
	if m.r.IntN(4) > 0 {
		if mem, ok := members(b); ok {
			return m.object(mem, 0).bytes()
		}
	}
	return m.raw(b)
}

// The bytes that the parsers treat specially.
var specialBytes = []byte{'"', '\\', '{', '}', '[', ']', ',', ':', ' ', '\t', '\r', '\n', 0, '0', '-', '+', '.', 'e', 'u', 0x7f, 0x80, 0xbf, 0xc0, 0xe2, 0xed, 0xef, 0xf0, 0xf4, 0xff}

// Short strings that make JSON mean something else where they go in.
var specialStrings = []string{`\u0000`, `\ud800`, `\udc00`, `\"`, `\\`, `,"v":1`, `,"type":"x"`, `":`, "\xef\xbb\xbf", "\xc0\x80", "\xed\xa0\x80", `null`, `1e3`, `-0`}

func (m mutator) raw(b []byte) []byte {
	out := append([]byte{}, b...)
	if len(out) == 0 {
		return []byte{specialBytes[m.r.IntN(len(specialBytes))]}
	}
	at := m.r.IntN(len(out) + 1)
	switch m.r.IntN(7) {
	case 0: // flip a bit
		i := m.r.IntN(len(out))
		out[i] ^= byte(1 << m.r.IntN(8))
	case 1: // a special byte in place of one
		out[m.r.IntN(len(out))] = specialBytes[m.r.IntN(len(specialBytes))]
	case 2: // a special byte more
		out = append(out[:at], append([]byte{specialBytes[m.r.IntN(len(specialBytes))]}, out[at:]...)...)
	case 3: // a special string more
		out = append(out[:at], append([]byte(specialStrings[m.r.IntN(len(specialStrings))]), out[at:]...)...)
	case 4: // cut a run
		end := min(len(out), at+1+m.r.IntN(8))
		if at < end {
			out = append(out[:at], out[end:]...)
		}
	case 5: // a run twice
		end := min(len(out), at+1+m.r.IntN(16))
		run := append([]byte{}, out[at:end]...)
		out = append(out[:end], append(run, out[end:]...)...)
	default: // cut the end, or add to it
		if m.r.IntN(2) == 0 {
			out = out[:at]
		} else {
			out = append(out, specialBytes[m.r.IntN(len(specialBytes))])
		}
	}
	return out
}

// A member is one member of an object, as written.
type member struct {
	name  string // raw, with its quotes
	value []byte // raw JSON
}

type object []member

func (o object) bytes() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, mem := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(mem.name)
		b.WriteByte(':')
		b.Write(mem.value)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// members splits a JSON object into its members, keeping how each is
// written; false when b is no JSON object.
func members(b []byte) (object, bool) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, false
	}
	var o object
	for d.More() {
		start := d.InputOffset()
		if _, err := d.Token(); err != nil {
			return nil, false
		}
		rawName := strings.TrimLeft(string(b[start:d.InputOffset()]), " \t\r\n,")
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, false
		}
		o = append(o, member{name: rawName, value: append([]byte{}, v...)})
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if d.More() {
		return nil, false
	}
	return o, true
}

// elements splits a JSON array into its elements.
func elements(b []byte) ([][]byte, bool) {
	var l []json.RawMessage
	if json.Unmarshal(b, &l) != nil {
		return nil, false
	}
	out := make([][]byte, len(l))
	for i, e := range l {
		out[i] = append([]byte{}, e...)
	}
	return out, true
}

func (m mutator) object(o object, depth int) object {
	o = append(object{}, o...)
	if len(o) == 0 {
		return append(o, member{`"later"`, []byte(`""`)})
	}
	i := m.r.IntN(len(o))
	switch m.r.IntN(10) {
	case 0: // the member twice, with another value the second time
		o = append(o, member{o[i].name, m.value(o[i].name, o[i].value, depth)})
	case 1: // without it
		o = append(o[:i], o[i+1:]...)
	case 2: // in another place
		j := m.r.IntN(len(o))
		o[i], o[j] = o[j], o[i]
	case 3: // its name written otherwise
		o[i].name = m.name(o[i].name)
	case 4: // a member no table names
		o = append(o, member{[]string{`"later"`, `"x"`, `"V"`, `"type2"`, `"_"`, `"a_b_0"`, `"` + strings.Repeat("n", 65) + `"`}[m.r.IntN(7)], m.anyValue()})
	case 5: // white space around it
		ws := []string{" ", "\t", "\r\n", "\n ", "\u00a0", "\xef\xbb\xbf"}[m.r.IntN(6)]
		if m.r.IntN(2) == 0 {
			o[i].name = ws + o[i].name
		} else {
			o[i].value = append([]byte(ws), o[i].value...)
		}
	default: // another value
		o[i].value = m.value(o[i].name, o[i].value, depth)
	}
	return o
}

// name returns a member's name written in another way: the same name for
// a reader that undoes escapes, or one close to it.
func (m mutator) name(raw string) string {
	n, err := strconv.Unquote(raw)
	if err != nil || n == "" {
		return raw
	}
	switch m.r.IntN(5) {
	case 0:
		return `"` + strings.ToUpper(n) + `"`
	case 1:
		return `"` + escapeAll(n[:1]) + n[1:] + `"`
	case 2:
		return `"` + n + ` "`
	case 3:
		return `"` + n + `\u0000"`
	default:
		return `"` + n[:len(n)-1] + `"`
	}
}

func escapeAll(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0xffff {
			b.WriteString(strconv.QuoteToASCII(string(r))[1:13])
			continue
		}
		b.WriteString(`\u` + strconv.FormatInt(int64(r)+0x10000, 16)[1:])
	}
	return b.String()
}

var (
	reHex    = regexp.MustCompile(`^[0-9a-f]+$`)
	reBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

// The integers at the edges of the readers' types.
var edgeInts = []string{"0", "-0", "1", "-1", "2", "255", "256", "65535", "65536", "2147483647", "2147483648", "-2147483649",
	"4294967295", "4294967296", "9007199254740991", "9007199254740992", "9007199254740993", "-9007199254740993",
	"9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "18446744073709551615",
	"18446744073709551616", "1e3", "1E3", "1.0", "0.5", "01", "+1", "1e400", "-1e400", "0x10", "1_0"}

// Strings that readers of names and hex read in their own ways.
var edgeStrings = []string{"", " ", "a", "A", `\u0000`, `\u0041`, `\/`, `\ud800`, `\udbff\udfff`, `\ud83d\ude00`, "\u202e", "\u200b",
	"\u2028", "e\u0301", "\u00e9", "\U0001F600", `\n`, `\t`, "\x7f", "\xff", "\xc0\x80", "\xf4\x90\x80\x80", `\u202e`, `\uFEFF`,
	strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("a", 256), strings.Repeat("\u00e9", 64), " x", "x "}

// The sizes at which the readers' limits are.
var edgeSizes = []int{63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192, 8193, 16384, 65536}

func (m mutator) anyValue() []byte {
	switch m.r.IntN(8) {
	case 0:
		return []byte(edgeInts[m.r.IntN(len(edgeInts))])
	case 1:
		return []byte(`"` + edgeStrings[m.r.IntN(len(edgeStrings))] + `"`)
	default:
		return []byte([]string{"true", "false", "null", "[]", "{}", `[""]`, `"1"`, `[1]`, `{"a":1}`, `[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]`}[m.r.IntN(10)])
	}
}

// value returns another value for a member, of the kind its value has.
func (m mutator) value(name string, v []byte, depth int) []byte {
	if m.r.IntN(8) == 0 {
		return m.anyValue()
	}
	v = bytes.TrimSpace(v)
	switch {
	case len(v) > 0 && v[0] == '{' && depth < 4:
		if o, ok := members(v); ok {
			return m.object(o, depth+1).bytes()
		}
	case len(v) > 0 && v[0] == '[' && depth < 4:
		if l, ok := elements(v); ok {
			return m.array(name, l, depth+1)
		}
	case len(v) > 0 && v[0] == '"':
		return m.str(name, v)
	case bytes.Equal(v, []byte("true")) || bytes.Equal(v, []byte("false")):
		return []byte([]string{"true", "false", "1", "0", `"true"`}[m.r.IntN(5)])
	case len(v) > 0:
		return m.number(v)
	}
	return m.anyValue()
}

func (m mutator) array(name string, l [][]byte, depth int) []byte {
	l = append([][]byte{}, l...)
	switch {
	case len(l) == 0 || m.r.IntN(5) == 0:
		if len(l) > 0 {
			l = append(l, l[m.r.IntN(len(l))])
		} else {
			l = append(l, m.anyValue())
		}
	case m.r.IntN(4) == 0:
		i := m.r.IntN(len(l))
		l = append(l[:i], l[i+1:]...)
	case m.r.IntN(4) == 0:
		// Many of them, up to a limit.
		n := edgeSizes[m.r.IntN(8)]
		for len(l) < n {
			l = append(l, l[len(l)%max(1, len(l))])
		}
	default:
		i := m.r.IntN(len(l))
		l[i] = m.value(name, l[i], depth)
	}
	return append(append([]byte("["), bytes.Join(l, []byte(","))...), ']')
}

func (m mutator) number(v []byte) []byte {
	n, err := strconv.ParseInt(string(v), 10, 64)
	switch {
	case err == nil && m.r.IntN(2) == 0:
		d := []int64{-1, 1, -n, 1000, -1000}[m.r.IntN(5)]
		return []byte(strconv.FormatInt(n+d, 10))
	case err == nil && m.r.IntN(3) == 0:
		s := string(v)
		return []byte([]string{s + ".0", s + "e0", "0" + s, "-" + s, s + " ", `"` + s + `"`}[m.r.IntN(6)])
	default:
		return []byte(edgeInts[m.r.IntN(len(edgeInts))])
	}
}

func (m mutator) str(name string, v []byte) []byte {
	s, err := strconv.Unquote(string(v))
	if err != nil {
		// Escapes Go's strconv does not read: change the bytes.
		return m.raw(v)
	}
	inner := string(v[1 : len(v)-1])
	switch m.r.IntN(9) {
	case 0:
		return []byte(`"` + edgeStrings[m.r.IntN(len(edgeStrings))] + `"`)
	case 1: // the same string, one of its characters escaped
		if s == "" {
			return v
		}
		return []byte(`"` + escapeAll(s[:1]) + strconv.Quote(s[1:])[1:])
	case 2: // longer, to the edge of a limit
		n := edgeSizes[m.r.IntN(len(edgeSizes))]
		return []byte(`"` + inner + strings.Repeat("a", max(0, n-len(s))) + `"`)
	case 3: // a character more or less
		if s != "" && m.r.IntN(2) == 0 {
			return []byte(strconv.Quote(s[:len(s)-1]))
		}
		return []byte(`"` + inner + []string{"a", "0", "=", "A", " ", `\u0000`, "\u00e9", "\xff"}[m.r.IntN(8)] + `"`)
	case 4: // hex in capitals, base64 in another alphabet or padding
		switch {
		case reHex.MatchString(s):
			return []byte(`"` + strings.ToUpper(s) + `"`)
		case reBase64.MatchString(s):
			t := []string{strings.TrimRight(s, "="), s + "=", strings.NewReplacer("+", "-", "/", "_").Replace(s), s[:len(s)/2] + "\\n" + s[len(s)/2:], s + "AAAA"}[m.r.IntN(5)]
			return []byte(`"` + t + `"`)
		}
		return []byte(`"` + strings.ToUpper(inner) + `"`)
	case 5: // a name's control and direction characters
		ctl := []string{"\u202e", "\u200f", "\u2066", "\u0007", `\u001b`, "\u0085", "\u00ad", "\ufeff", "\U000e0041", `\r`}[m.r.IntN(10)]
		at := 0
		if s != "" {
			at = len(inner) / 2
		}
		return []byte(`"` + inner[:at] + ctl + inner[at:] + `"`)
	case 6:
		return m.number([]byte("0"))
	default: // a byte of it changed
		if len(inner) == 0 {
			return []byte(`"a"`)
		}
		b := []byte(inner)
		const alphabet = "0aAzZ9+/=-_. \\\"\x00\xff"
		b[m.r.IntN(len(b))] = alphabet[m.r.IntN(len(alphabet))]
		return []byte(`"` + string(b) + `"`)
	}
}
