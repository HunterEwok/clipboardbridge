// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestCFHTML(t *testing.T) {
	// A block as a browser writes it: offsets of 10 digits, a NUL at the end.
	doc := "<html>\r\n<body>\r\n<!--StartFragment--><b>caf\u00e9 \U0001F600</b><!--EndFragment-->\r\n</body>\r\n</html>"
	const header = "Version:0.9\r\nStartHTML:%010d\r\nEndHTML:%010d\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n"
	n := len(fmt.Sprintf(header, 0, 0, 0, 0))
	block := fmt.Sprintf(header, n, n+len(doc), n+strings.Index(doc, "<b>"), n+strings.Index(doc, "<!--End")) + doc + "\x00"
	if got, err := parseCFHTML([]byte(block)); err != nil || got != doc {
		t.Errorf("parse = %q, %v", got, err)
	}
	// One that names only its fragment, as some programs write it.
	block = fmt.Sprintf("Version:0.9\r\nStartHTML:-1\r\nEndHTML:-1\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n", 0, 0)
	m := len(block)
	block = fmt.Sprintf("Version:0.9\r\nStartHTML:-1\r\nEndHTML:-1\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n", m, m+8) + "<i>x</i>"
	if got, err := parseCFHTML([]byte(block)); err != nil || got != "<i>x</i>" {
		t.Errorf("parse of a fragment = %q, %v", got, err)
	}

	// Ours round-trip, with fragment offsets around the fragment.
	for _, html := range []string{"<p>Hello, <i>world</i></p>", doc} {
		b := string(makeCFHTML(html))
		got, err := parseCFHTML([]byte(b))
		if err != nil || !strings.Contains(got, html) {
			t.Errorf("round trip of %q = %q, %v", html, got, err)
		}
		field := func(name string) int {
			i := strings.Index(b, name+":") + len(name) + 1
			v, err := strconv.Atoi(b[i : i+10])
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		frag := b[field("StartFragment"):field("EndFragment")]
		if frag == "" || !strings.Contains(html, frag) {
			t.Errorf("the fragment of %q is %q", html, frag)
		}
	}
	if _, err := parseCFHTML([]byte("Version:0.9\r\nStartHTML:0000000999\r\nEndHTML:0000001000\r\n<p>x</p>")); err == nil {
		t.Error("offsets outside the block were taken")
	}
}
