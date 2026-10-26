// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var siteLangs = []string{"en", "ru", "zh", "es", "ar", "sw", "he", "hi"}

func TestChooseLanguage(t *testing.T) {
	for _, tc := range []struct {
		name, picked, country, accept, want string
	}{
		{"nothing known", "", "", "", "en"},
		{"the picked one wins", "es", "RU", "ru", "es"},
		{"an unknown pick is ignored", "de", "RU", "", "ru"},
		{"the country's language", "", "RU", "en-US,en;q=0.9", "ru"},
		{"a country with several, by the browser", "", "IL", "ru-RU,ru;q=0.9,he;q=0.5", "ru"},
		{"a country with several, the first", "", "IL", "fr", "he"},
		{"a country without a language of the site, by the browser", "", "DE", "ru-RU,de;q=0.8", "ru"},
		{"a country without a language of the site", "", "DE", "de-DE", "en"},
		{"Kenya in English", "", "KE", "en-KE,en", "en"},
		{"Kenya in Swahili", "", "KE", "", "sw"},
		{"Hebrew's old code", "", "", "iw", "he"},
		{"India in Hindi", "", "IN", "hi-IN,en;q=0.5", "hi"},
		{"India in English", "", "IN", "en-IN", "en"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := chooseLanguage(siteLangs, tc.picked, tc.country, tc.accept); got != tc.want {
				t.Errorf("chooseLanguage(%q, %q, %q) = %q, want %q", tc.picked, tc.country, tc.accept, got, tc.want)
			}
		})
	}
	// A country whose language the site does not have yet.
	if got := chooseLanguage([]string{"en", "ru"}, "", "CN", ""); got != "en" {
		t.Errorf("China without Chinese = %q, want en", got)
	}
}

func TestBrowserLanguages(t *testing.T) {
	got := browserLanguages("en;q=0.5, ru-RU, zh-Hans-CN;q=0.8, fr;q=0, *;q=0.1, ru;q=0.9, xx;q=bad")
	want := []string{"ru", "zh", "en"}
	if !slices.Equal(got, want) {
		t.Errorf("browserLanguages = %v, want %v", got, want)
	}
}

const geoCSV = `1.0.0.0,1.0.0.255,AU
5.3.0.0,5.3.255.255,RU
5.8.0.0,5.8.0.255,DE
"2a00:1370::","2a00:137f:ffff:ffff:ffff:ffff:ffff:ffff",RU
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US
41.0.0.0,41.0.0.255,TZ
`

func TestGeo(t *testing.T) {
	db, err := readGeo(strings.NewReader(geoCSV))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(db.ranges); n != 3 {
		t.Errorf("kept %d ranges, want only the 3 of known countries", n)
	}
	for addr, want := range map[string]string{
		"5.3.0.0":         "RU",
		"5.3.200.7":       "RU",
		"5.3.255.255":     "RU",
		"5.4.0.0":         "",
		"5.8.0.1":         "",
		"1.0.0.1":         "",
		"41.0.0.9":        "TZ",
		"::ffff:5.3.1.1":  "RU",
		"2a00:1370::1":    "RU",
		"2a00:1380::":     "",
		"2001:4860::8888": "",
		"0.0.0.0":         "",
		"ffff::1":         "",
		"255.255.255.255": "",
		"2a00:137f::ffff": "RU",
		"2a00:136f::ffff": "",
		"41.0.1.0":        "",
		"40.255.255.255":  "",
		"5.2.255.255":     "",
	} {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := db.country(a); got != want {
			t.Errorf("country(%s) = %q, want %q", addr, got, want)
		}
	}
	var none *geoDB
	if got := none.country(netip.MustParseAddr("5.3.0.1")); got != "" {
		t.Errorf("no database gave %q", got)
	}
	for name, bad := range map[string]string{
		"overlap":       "5.3.0.0,5.3.255.255,RU\n5.3.1.0,5.3.1.255,BY\n",
		"backwards":     "5.3.255.255,5.3.0.0,RU\n",
		"mixed":         "5.3.0.0,2a00::,RU\n",
		"short":         "5.3.0.0,RU\n",
		"not addresses": "a,b,RU\n",
		"empty":         "1.0.0.0,1.0.0.255,AU\n",
	} {
		if _, err := readGeo(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: readGeo took it", name)
		}
	}
}

func TestChooser(t *testing.T) {
	db, err := readGeo(strings.NewReader(geoCSV))
	if err != nil {
		t.Fatal(err)
	}
	c := &chooser{langs: siteLangs, proxy: true}
	c.geo.Store(db)
	for _, tc := range []struct {
		name, url, realIP, accept, cookie, want, setCookie string
	}{
		{name: "by country", url: "/", realIP: "5.3.1.1", want: "/ru/"},
		{name: "by browser", url: "/", realIP: "8.8.8.8", accept: "es-MX", want: "/es/"},
		{name: "English", url: "/", realIP: "8.8.8.8", want: "/en/"},
		{name: "no address", url: "/", want: "/en/"},
		{name: "the cookie", url: "/", realIP: "5.3.1.1", cookie: "he", want: "/he/"},
		{name: "a page", url: "/?p=download.html", realIP: "41.0.0.1", want: "/sw/download.html"},
		{name: "not a page", url: "/?p=//evil.example/x.html", realIP: "5.3.1.1", want: "/ru/"},
		{name: "picking", url: "/?lang=ar&p=privacy.html", realIP: "5.3.1.1", want: "/ar/privacy.html", setCookie: "lang=ar"},
		{name: "picking an unknown one", url: "/?lang=xx", realIP: "5.3.1.1", want: "/ru/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			if tc.realIP != "" {
				r.Header.Set("X-Real-IP", tc.realIP)
			}
			if tc.accept != "" {
				r.Header.Set("Accept-Language", tc.accept)
			}
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: langCookie, Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			c.ServeHTTP(w, r)
			if w.Code != http.StatusFound || w.Header().Get("Location") != tc.want {
				t.Errorf("got %d to %q, want 302 to %q", w.Code, w.Header().Get("Location"), tc.want)
			}
			if got := w.Header().Get("Set-Cookie"); !strings.HasPrefix(got, tc.setCookie) || (tc.setCookie == "") != (got == "") {
				t.Errorf("Set-Cookie %q, want %q", got, tc.setCookie)
			}
		})
	}
}

// TestSite checks the real site: every page renders in every language and
// every translation is complete, as CI's "site check" does.
func TestSite(t *testing.T) {
	if err := check("../../site"); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := build("../../site", out); err != nil {
		t.Fatal(err)
	}
	langs, err := loadLanguages("../../site")
	if err != nil {
		t.Fatal(err)
	}
	ld := regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)
	for _, l := range langs {
		for _, p := range append(slices.Clone(pages), errorPages...) {
			data, err := os.ReadFile(filepath.Join(out, l.Code, p+".html"))
			if err != nil {
				t.Fatal(err)
			}
			html := string(data)
			if !strings.Contains(html, `lang="`+l.Tag+`"`) {
				t.Errorf("%s/%s.html: no lang=%q", l.Code, p, l.Tag)
			}
			if n := strings.Count(html, "<h1"); n != 1 {
				t.Errorf("%s/%s.html: %d h1, want 1", l.Code, p, n)
			}
			isError := slices.Contains(errorPages, p)
			if strings.Contains(html, `name="robots" content="noindex"`) != isError {
				t.Errorf("%s/%s.html: noindex should be on the error pages only", l.Code, p)
			}
			if !isError && !strings.Contains(html, `rel="canonical" href="https://cbb.tools/`+l.Code+`/`) {
				t.Errorf("%s/%s.html: no canonical link", l.Code, p)
			}
			for _, m := range ld.FindAllStringSubmatch(html, -1) {
				var v map[string]any
				if err := json.Unmarshal([]byte(m[1]), &v); err != nil || v["@context"] != "https://schema.org" {
					t.Errorf("%s/%s.html: bad JSON-LD %.80q: %v", l.Code, p, m[1], err)
				}
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "sitemap.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var sm struct {
		URLs []struct {
			Loc   string `xml:"loc"`
			Links []struct {
				Lang string `xml:"hreflang,attr"`
			} `xml:"link"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(data, &sm); err != nil {
		t.Fatal(err)
	}
	if len(sm.URLs) != len(pages)*len(langs) || len(sm.URLs[0].Links) != len(langs) {
		t.Errorf("sitemap: %d pages, want %d, each with %d languages", len(sm.URLs), len(pages)*len(langs), len(langs))
	}
	if _, err := os.Stat(filepath.Join(out, "robots.txt")); err != nil {
		t.Error(err)
	}
}

func TestTranslate(t *testing.T) {
	ru := Language{Code: "ru", texts: map[string]string{"Run %s now": "<b>%s</b> & %s"}}
	tr := &translator{lang: ru, used: map[string]bool{}, missing: map[string]bool{}}
	if _, err := tr.t("Run %s now", "x"); err == nil {
		t.Error("a translation with another number of placeholders was taken")
	}
	ru.texts["Run %s now"] = "<i>%s</i> jetzt"
	got, err := tr.t("Run %s now", "<a>")
	if err != nil || got != "&lt;i&gt;&lt;a&gt;&lt;/i&gt; jetzt" {
		t.Errorf("t = %q, %v", got, err)
	}
	if got, _ := tr.t("Missing"); got != "Missing" || !tr.missing["Missing"] {
		t.Errorf("a missing text gave %q and was not recorded", got)
	}
}
