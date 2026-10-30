// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"encoding/xml"
	"io"
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

// TestChooserNewLanguage checks that a language whose pages arrive after the
// chooser started can be picked at once: on cbb.tools the chooser may start
// before every page has been copied.
func TestChooserNewLanguage(t *testing.T) {
	dir := t.TempDir()
	addLang := func(code string) {
		if err := os.MkdirAll(filepath.Join(dir, code), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, code, "index.html"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	addLang("en")
	c := &chooser{dir: dir, langs: siteLanguages(dir)}
	pick := func() string {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("GET", "/?lang=ru", nil))
		return w.Header().Get("Location")
	}
	if got := pick(); got != "/en/" {
		t.Fatalf("before ru: %q, want /en/", got)
	}
	addLang("ru")
	if got := pick(); got != "/ru/" {
		t.Errorf("after ru: %q, want /ru/", got)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if got := pick(); got != "/en/" {
		t.Errorf("without the directory: %q, want what the start found, /en/", got)
	}
}

// TestSite checks the real site: every page renders in every language and
// every translation is complete, as CI's "site check" does.
func TestSite(t *testing.T) {
	if err := check("../../site", false, io.Discard); err != nil {
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
	ds, err := loadDocs("../../site")
	if err != nil {
		t.Fatal(err)
	}
	// The documentation's pages are listed in the languages they are
	// translated into, English always.
	want := len(pages) * len(langs)
	for _, f := range ds.files {
		want++ // English
		for _, l := range langs[1:] {
			if data, _ := ds.translation(l.Code, f); data != nil || f == indexFile {
				want++
			}
		}
	}
	if len(sm.URLs) != want || len(sm.URLs[0].Links) != len(langs) {
		t.Errorf("sitemap: %d pages, want %d, the site's each with %d languages", len(sm.URLs), want, len(langs))
	}
	checkLinks(t, out)
	for _, name := range []string{"robots.txt", "soon.html", ".well-known/security.txt", "site.webmanifest", "en/index.html.gz"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Error(err)
		}
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

// served are the paths nginx answers without a file in the build: the
// language chooser, the visit counter, the revocation mirror.
var served = regexp.MustCompile(`^/(\?.*)?$|^/count(\.js)?$|^/attest/`)

// checkLinks fails for every link of a built page to a page or file of the
// site that the build did not write.
func checkLinks(t *testing.T, out string) {
	t.Helper()
	attr := regexp.MustCompile(`(?:href|src|srcset)="([^"]+)"`)
	err := filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range attr.FindAllStringSubmatch(string(data), -1) {
			link := strings.ReplaceAll(m[1], "&amp;", "&")
			if strings.Contains(link, "://") || strings.HasPrefix(link, "#") || strings.HasPrefix(link, "mailto:") || served.MatchString(link) {
				continue
			}
			link, _, _ = strings.Cut(link, "#")
			target := filepath.Join(filepath.Dir(p), filepath.FromSlash(link))
			if strings.HasPrefix(link, "/") {
				target = filepath.Join(out, filepath.FromSlash(link))
			}
			if strings.HasSuffix(link, "/") {
				target = filepath.Join(target, "index.html")
			}
			if _, err := os.Stat(target); err != nil {
				rel, _ := filepath.Rel(out, p)
				t.Errorf("%s: link to %s, which the build did not write", rel, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLatestRelease(t *testing.T) {
	dir := t.TempDir()
	site := filepath.Join(dir, "site")
	if err := os.Mkdir(site, 0o755); err != nil {
		t.Fatal(err)
	}
	// A checkout on Windows has CRLF line ends.
	log := "# Changelog\r\n\r\n## [Unreleased]\r\n\r\n## [1.2.3] - 2026-01-02\r\n\r\n## [1.2.2] - 2025-12-01\r\n"
	if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := latestRelease(site)
	if err != nil || r != (Release{Version: "1.2.3", Date: "2026-01-02"}) {
		t.Errorf("latestRelease = %+v, %v", r, err)
	}
}

func TestMedian(t *testing.T) {
	for _, c := range []struct {
		in   []float64
		want float64
	}{{nil, 0}, {[]float64{0.65, 1, 0.98}, 0.98}, {[]float64{0.9, 1}, 0.95}} {
		if got := median(c.in); got != c.want {
			t.Errorf("median(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	if got := reportName("/ru/privacy.html"); got != "ru-privacy" {
		t.Errorf("reportName = %q", got)
	}
}

// TestGzipStatic: Lighthouse gets the .gz that build wrote, as readers do
// from nginx, and the plain file when it takes no gzip or none was written.
func TestGzipStatic(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "en"), 0o755); err != nil {
		t.Fatal(err)
	}
	page := []byte("<!doctype html><title>x</title>")
	gz, err := gzipped(page)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"en/index.html": page, "en/index.html.gz": gz, "plain.txt": []byte("plain")} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(gzipStatic(dir))
	defer srv.Close()
	get := func(path string, gzip bool) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if gzip {
			req.Header.Set("Accept-Encoding", "gzip")
		}
		// A transport that asks for gzip only when told to, and leaves it so.
		resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := get("/en/", true); r.Header.Get("Content-Encoding") != "gzip" || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || r.ContentLength != int64(len(gz)) {
		t.Errorf("/en/ with gzip: %v %v %d", r.Header.Get("Content-Encoding"), r.Header.Get("Content-Type"), r.ContentLength)
	}
	if r := get("/en/", false); r.Header.Get("Content-Encoding") != "" || r.ContentLength != int64(len(page)) {
		t.Errorf("/en/ without gzip: %v %d", r.Header.Get("Content-Encoding"), r.ContentLength)
	}
	if r := get("/plain.txt", true); r.Header.Get("Content-Encoding") != "" || r.StatusCode != 200 {
		t.Errorf("/plain.txt: %v %d", r.Header.Get("Content-Encoding"), r.StatusCode)
	}
}

// A picture of the documentation is put inline on a board, without its own
// style and size, and a table is wrapped so that it can scroll on its own.
func TestBoards(t *testing.T) {
	ds := &docSet{images: map[string][]byte{
		"a.svg": []byte("<!-- note -->\n<svg xmlns=\"x\" width=\"720\" height=\"250\" viewBox=\"0 0 720 250\">\n<style>.a{}</style>\n<rect width=\"150\" height=\"64\"/><path d=\"M0 0\"/></svg>\n"),
	}}
	l := linker{ds: ds, lang: "en"}
	got := l.boards(`<p><img src="/docs/images/a.svg" alt="A"></p><table><tr><td>1</td></tr></table>`)
	for _, want := range []string{
		`<div class="frame diagram">`,
		`<svg xmlns="x" viewBox="0 0 720 250">`,
		`<rect width="150" height="64"/>`,
		`<path pathLength="1" d="M0 0"/>`,
		`<div class="tablewrap"><table><tr><td>1</td></tr></table></div>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("boards() lacks %q in %s", want, got)
		}
	}
	for _, bad := range []string{"<style", "note", "<img"} {
		if strings.Contains(got, bad) {
			t.Errorf("boards() keeps %q in %s", bad, got)
		}
	}
}
