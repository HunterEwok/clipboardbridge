// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Windows' clipboard format for formatted text, "HTML Format" (CF_HTML),
// is UTF-8 with a header of byte offsets: where the document starts and
// ends, and where the fragment that was copied does, between the comments
// <!--StartFragment--> and <!--EndFragment-->.

const (
	startFragment = "<!--StartFragment-->"
	endFragment   = "<!--EndFragment-->"
)

// parseCFHTML returns the document of a CF_HTML block, or its fragment
// when the block names no document.
func parseCFHTML(data []byte) (string, error) {
	s := strings.TrimRight(string(data), "\x00")
	offsets := map[string]int{}
	rest := s
	for {
		line, after, ok := strings.Cut(rest, "\n")
		key, value, isField := strings.Cut(strings.TrimSuffix(line, "\r"), ":")
		if !ok || !isField || strings.HasPrefix(line, "<") {
			break
		}
		if n, err := strconv.Atoi(value); err == nil && (strings.HasPrefix(key, "Start") || strings.HasPrefix(key, "End")) {
			offsets[key] = n
		}
		rest = after
	}
	for _, pair := range [][2]string{{"StartHTML", "EndHTML"}, {"StartFragment", "EndFragment"}} {
		start, okStart := offsets[pair[0]]
		end, okEnd := offsets[pair[1]]
		if okStart && okEnd && start >= 0 && start <= end && end <= len(s) {
			return s[start:end], nil
		}
	}
	return "", errors.New("pasteboard: an HTML Format block without valid offsets")
}

// makeCFHTML makes the CF_HTML block of formatted text: the text as the
// document, with fragment comments around all of its body when it has
// none of its own.
func makeCFHTML(html string) []byte {
	if !strings.Contains(html, startFragment) || !strings.Contains(html, endFragment) {
		html = "<html><body>\r\n" + startFragment + html + endFragment + "\r\n</body></html>"
	}
	const header = "Version:0.9\r\nStartHTML:%010d\r\nEndHTML:%010d\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n"
	n := len(fmt.Sprintf(header, 0, 0, 0, 0))
	startF := n + strings.Index(html, startFragment) + len(startFragment)
	endF := n + strings.LastIndex(html, endFragment)
	return []byte(fmt.Sprintf(header, n, n+len(html), startF, endF) + html)
}
