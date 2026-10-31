// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package strict

import (
	"bytes"
	"testing"
)

func TestCanonical(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{`{}`, `{}`},
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{` { "a" : [ 1 , true , false , "x" ] } `, `{"a":[1,true,false,"x"]}`},
		{`{"a":"\/\b\f\n\r\t"}`, `{"a":"/\u0008\u000c\u000a\u000d\u0009"}`},
		{`{"a":"\u00e9\u20ac\ud83d\ude00"}`, "{\"a\":\"é€\U0001F600\"}"},
		{`{"a":"\u001F\"\\"}`, `{"a":"\u001f\"\\"}`},
		{`{"a":{"z":0,"y":-1},"_":"","0":1}`, `{"0":1,"_":"","a":{"y":-1,"z":0}}`},
		{`{"ab":1,"a":2,"b":3}`, `{"a":2,"ab":1,"b":3}`},
		{`{"a":[{"c":1,"b":2},[]]}`, `{"a":[{"b":2,"c":1},[]]}`},
	} {
		got, err := Canonicalize([]byte(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s: got %s, want %s", tc.in, got, tc.want)
		}
		if err := CheckCanonical(got); err != nil {
			t.Errorf("%s: the canonical form %s is refused: %v", tc.in, got, err)
		}
		if same := tc.in == tc.want; same != (CheckCanonical([]byte(tc.in)) == nil) {
			t.Errorf("%s: CheckCanonical says %v, want %v", tc.in, !same, same)
		}
	}
}

func TestCheckCanonicalRefuses(t *testing.T) {
	for _, in := range []string{
		`{"b":1,"a":2}`,
		`{"a":1,"a":2}`,
		`{ "a":1}`,
		`{"a" :1}`,
		`{"a": 1}`,
		`{"a":1 }`,
		`{"a":[1, 2]}`,
		`{"a":"\/"}`,
		`{"a":"\n"}`,
		`{"a":"\u0041"}`,
		`{"a":"\u001F"}`,
		`{"a":"\u00e9"}`,
		`{"a":"\ud83d\ude00"}`,
		"{\"a\":1}\n",
		`{"a":null}`,
		`{"a":1.0}`,
	} {
		if err := CheckCanonical([]byte(in)); err == nil {
			t.Errorf("%s is taken", in)
		}
	}
}

// FuzzCanonical checks that CheckCanonical takes exactly the bodies that
// Canonicalize leaves as they are, and that Canonicalize gives a body
// CheckCanonical takes, holding the same members.
func FuzzCanonical(f *testing.F) {
	for _, s := range []string{`{}`, `{"b":1,"a":[2,"\n"]}`, `{"a":"\u00e9\ud83d\ude00"}`, `{"a":{"c":true,"b":false}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if Check(b) != nil {
			return
		}
		c, err := Canonicalize(b)
		if err != nil {
			t.Fatalf("Canonicalize %q: %v", b, err)
		}
		if err := CheckCanonical(c); err != nil {
			t.Fatalf("the canonical form %q of %q is refused: %v", c, b, err)
		}
		if again, _ := Canonicalize(c); !bytes.Equal(again, c) {
			t.Fatalf("Canonicalize is not stable on %q: %q", c, again)
		}
		if (CheckCanonical(b) == nil) != bytes.Equal(b, c) {
			t.Fatalf("CheckCanonical(%q) and Canonicalize %q disagree", b, c)
		}
	})
}
