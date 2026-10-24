// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// maxText is the largest text the group carries (clip.MaxText).
const maxText = 1 << 20

// textCase is one class of text of the matrix (docs/testbench.md,
// section 6) that every member sends to every other one.
type textCase struct {
	id, name string
	text     func(run, from string) string
}

var textCases = []textCase{
	{"C1", "ascii", func(run, from string) string { return "cbb-bench " + run + " ascii from " + from }},
	// Cyrillic, an emoji with a skin tone, a combining accent, Hebrew and
	// Arabic (right to left), Japanese.
	{"C2", "unicode", func(run, from string) string {
		return "cbb-bench " + run + " " + from + " \u041f\u0440\u0438\u0432\u0435\u0442 \U0001F44B\U0001F3FD e\u0301 \u05e9\u05dc\u05d5\u05dd \u0645\u0631\u062d\u0628\u0627 \u65e5\u672c\u8a9e"
	}},
	// Line endings must arrive as sent; the text ends without one, since
	// some clipboards add a newline at the end.
	{"C3", "lines", func(run, from string) string {
		return "cbb-bench " + run + " " + from + "\r\nCRLF line\nLF line\n\ttabbed\ntrailing spaces   \nend"
	}},
	{"C4", "whitespace", func(run, from string) string {
		// Only spaces and tabs, the bits of the sender's name and the
		// run, so that each text differs.
		var b strings.Builder
		for _, c := range []byte(from + " " + run) {
			for i := 7; i >= 0; i-- {
				b.WriteByte(" \t"[c>>i&1])
			}
		}
		return b.String()
	}},
}

// Full makes a group as smoke does and runs the sync matrix of
// docs/testbench.md, section 6 (C1 to C5, C7, C8), then kills each
// member's service (F1).
func Full(ctx context.Context, r *Report, devices []*Device, timeout time.Duration) {
	g := formGroup(ctx, r, "full", devices)
	if g == nil {
		return
	}
	defer g.end(ctx, r)

	for _, tc := range textCases {
		for _, from := range g.members {
			text := tc.text(g.run, from.Name)
			prefix := fmt.Sprintf("full/%s-%s/", tc.id, tc.name)
			if r.Do(prefix+from.Name+"/copy", func() error { return Copy(ctx, from, text) }) != nil {
				continue
			}
			spread(ctx, r, prefix, g.members, from, text, timeout)
		}
	}
	emptyText(ctx, r, g, timeout)
	sizeLimit(ctx, r, g, timeout)
	burst(ctx, r, g, timeout)
	race(ctx, r, g, timeout)
	killService(ctx, r, g, timeout)
}

// emptyText (C4): an empty text is refused by cbb copy and changes no
// clipboard.
func emptyText(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	before := fmt.Sprintf("cbb-bench %s before the empty text", g.run)
	if r.Do("full/C4-empty/setup", func() error { return Copy(ctx, g.hub, before) }) != nil {
		return
	}
	spread(ctx, r, "full/C4-empty/setup/", g.members, g.hub, before, timeout)
	r.Do("full/C4-empty/refused", func() error {
		_, err := Run(ctx, g.hub, cbbCmd(g.hub)+" copy", "")
		if err == nil {
			return errors.New("cbb copy took an empty text")
		}
		return nil
	})
	time.Sleep(2 * time.Second)
	for _, d := range g.members {
		r.Do("full/C4-empty/kept/"+d.Name, func() error { return arrives(ctx, d, before, timeout) })
	}
}

// sizeLimit (C5): a text of exactly the limit arrives everywhere; one byte
// more is refused with a message that names the limit, and changes no
// clipboard.
func sizeLimit(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	head := fmt.Sprintf("cbb-bench %s size limit\n", g.run)
	limit := head + strings.Repeat("0123456789abcdef", maxText/16)[:maxText-len(head)]
	if r.Do("full/C5-size/limit/copy", func() error {
		_, err := Run(ctx, g.hub, cbbCmd(g.hub)+" copy", limit)
		return err
	}) == nil {
		spread(ctx, r, "full/C5-size/limit/", g.members, g.hub, limit, 2*timeout)
	}
	r.Do("full/C5-size/over/refused", func() error {
		_, err := Run(ctx, g.hub, cbbCmd(g.hub)+" copy", limit+"x")
		var re *RunError
		switch {
		case err == nil:
			return errors.New("cbb copy took a text one byte over the limit")
		case !errors.As(err, &re):
			return err
		case !strings.Contains(re.Output, "larger than") && !strings.Contains(re.Output, "too large") && !strings.Contains(re.Output, "limit"):
			return fmt.Errorf("cbb copy refused the text without naming the limit: %q", firstLine(re.Output))
		}
		return nil
	})
}

// burst (C7): ten copies within a second on one member; the last one wins
// everywhere.
func burst(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	text := func(i int) string { return fmt.Sprintf("cbb-bench %s burst %d", g.run, i) }
	var script strings.Builder
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&script, "printf '%%s' %s | %s copy || exit 1; ", shellQuote(text(i)), cbbCmd(g.hub))
	}
	if r.Do("full/C7-burst/copy", func() error {
		start := time.Now()
		if _, err := Run(ctx, g.hub, script.String(), ""); err != nil {
			return err
		}
		if took := time.Since(start); took > 3*time.Second {
			return fmt.Errorf("ten copies took %v, not about a second", took.Round(100*time.Millisecond))
		}
		return nil
	}) != nil {
		return
	}
	for _, d := range g.members {
		r.Do("full/C7-burst/last/"+d.Name, func() error { return arrives(ctx, d, text(10), timeout) })
	}
}

// race (C8): two members copy at the same moment; every member ends on the
// same one of the two texts.
func race(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	if len(g.members) < 3 {
		r.Skip("full/C8-race", "needs three members")
		return
	}
	a, b := g.members[1], g.members[2]
	ta := fmt.Sprintf("cbb-bench %s race from %s", g.run, a.Name)
	tb := fmt.Sprintf("cbb-bench %s race from %s", g.run, b.Name)
	var wg sync.WaitGroup
	for _, c := range []struct {
		d    *Device
		text string
	}{{a, ta}, {b, tb}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Do("full/C8-race/copy/"+c.d.Name, func() error { return Copy(ctx, c.d, c.text) })
		}()
	}
	wg.Wait()
	r.Do("full/C8-race/agree", func() error {
		return eventually(ctx, 2*timeout, func() error {
			var first string
			for i, d := range g.members {
				got, err := Paste(ctx, d)
				if err != nil {
					return err
				}
				got = strings.TrimRight(got, "\r\n")
				if got != ta && got != tb {
					return fmt.Errorf("%s has %s, neither text", d.Name, describe(got))
				}
				if i == 0 {
					first = got
				} else if got != first {
					return fmt.Errorf("%s has %s, %s has %s", g.members[0].Name, describe(first), d.Name, describe(got))
				}
			}
			return nil
		})
	})
}

// killService (F1): each member's service is killed with SIGKILL; its
// service manager starts it again, and it gets the next text.
func killService(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	for _, d := range g.members {
		kill := killCmd(d)
		if kill == "" {
			r.Skip("full/F1-kill/"+d.Name, "the bench cannot kill this device's service without the owner's password")
			continue
		}
		if r.Do("full/F1-kill/"+d.Name+"/kill", func() error {
			_, err := Run(ctx, d, kill, "")
			return err
		}) != nil {
			continue
		}
		if r.Do("full/F1-kill/"+d.Name+"/back", func() error {
			return eventually(ctx, 30*time.Second, func() error {
				tag, err := groupOf(ctx, d)
				if err == nil && tag != g.tag {
					err = fmt.Errorf("%s came back in group %q, not %s", d.Name, tag, g.tag)
				}
				return err
			})
		}) != nil {
			continue
		}
		from := g.hub
		if d == g.hub {
			from = g.members[len(g.members)-1]
		}
		text := fmt.Sprintf("cbb-bench %s after killing %s", g.run, d.Name)
		if r.Do("full/F1-kill/"+d.Name+"/copy", func() error { return Copy(ctx, from, text) }) != nil {
			continue
		}
		r.Do("full/F1-kill/"+d.Name+"/sync", func() error { return arrives(ctx, d, text, 2*timeout) })
	}
}

// killCmd kills the device's service the hard way, or is "" where the
// bench may not.
func killCmd(d *Device) string {
	switch d.OS {
	case "linux", "linux-lite":
		return "sudo -n systemctl kill -s KILL clipboardbridge"
	case "windows":
		return `Get-CimInstance Win32_Service -Filter "Name='clipboardbridge'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`
	}
	return "" // the Mac's service runs as _clipboardbridge
}
