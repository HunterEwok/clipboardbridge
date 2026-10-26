// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// pages are the site's pages, each site/templates/<page>.html inside
// layout.html.
var pages = []string{"index", "download", "privacy"}

// errorPages are the pages nginx shows for an error, in the visitor's
// language (site/deploy/nginx.conf); search engines and the sitemap leave
// them out.
var errorPages = []string{"404", "50x"}

// siteURL is where the site is published, for the links that must be
// absolute: canonical, hreflang, Open Graph, the sitemap.
const siteURL = "https://cbb.tools"

// faq are the questions on the home page, in English, also given to search
// engines as a FAQPage. An answer is plain text: no links.
var faq = []struct{ Q, A string }{
	{"Is it free?", "Yes. Clipboard Bridge is free software: no price, no subscription, no ads."},
	{"Can anyone else read what I copy?", "No. Your devices talk only to each other, and always encrypted. Away from home a server may pass the traffic on, but it cannot read it."},
	{"Do I need a computer?", "No. A group of phones only works too. A computer that is often on makes sync away from home simpler."},
	{"Does it work away from home?", "Yes. Your devices reach the group through its hub, a computer of yours or a phone while its app is open, over an encrypted tunnel. For now this takes a port forward on your router or a small server of your own."},
	{"Why does the iPhone need a gesture?", "iOS does not let apps read the clipboard in the background. You send a copy with the Action button or a double tap on the back of the phone."},
	{"Are my passwords synced?", "What password managers mark as secret is not synced automatically."},
	{"Where is the iPhone app?", "It comes with TestFlight, which is not open yet. Until then an iPhone joins with a shortcut, and a computer holds the group."},
}

// Language is one language of the site.
type Language struct {
	Code string // the directory and the code in links: "en", "zh"
	Name string // its own name, for the language menu
	Tag  string // the html lang attribute: "zh-Hans"
	RTL  bool   // written right to left
	// texts maps each English text to its translation; nil for English.
	texts map[string]string
}

// Meta keys of a translation file: they describe the language and are not
// texts of a page.
const (
	metaName = "@name" // the language's own name
	metaTag  = "@lang" // its html lang attribute, when not its code
	metaDir  = "@dir"  // "rtl" for a language written right to left
)

// english is the language the pages are written in.
var english = Language{Code: "en", Name: "English", Tag: "en"}

// loadLanguages returns English and every language of site/l10n, in the
// order of their codes after English.
func loadLanguages(root string) ([]Language, error) {
	langs := []Language{english}
	files, err := filepath.Glob(filepath.Join(root, "l10n", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var texts map[string]string
		if err := json.Unmarshal(data, &texts); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		code := strings.TrimSuffix(filepath.Base(f), ".json")
		l := Language{Code: code, Name: texts[metaName], Tag: texts[metaTag], RTL: texts[metaDir] == "rtl", texts: texts}
		if l.Name == "" {
			return nil, fmt.Errorf("%s: no %q", f, metaName)
		}
		if l.Tag == "" {
			l.Tag = code
		}
		langs = append(langs, l)
	}
	return langs, nil
}

// page is what a page's template sees.
type page struct {
	Lang  Language
	Langs []Language
	Page  string // the page's file name, "download.html"
	Path  string // its path in links: "download.html", "" for the home page
	Error bool   // an error page: not to be indexed
}

// URL returns the absolute address of this page in lang.
func (p page) URL(lang Language) string {
	return siteURL + "/" + lang.Code + "/" + p.Path
}

// pagePath returns the path of a page in links.
func pagePath(name string) string {
	if name == "index" {
		return ""
	}
	return name + ".html"
}

// translator turns the pages' English texts into one language and records
// what it was asked for and what it lacked.
type translator struct {
	lang    Language
	used    map[string]bool
	missing map[string]bool
}

// placeholder is where a text takes an argument: a link, a command.
var placeholder = regexp.MustCompile(`%s`)

// t translates text and puts args into its placeholders, in order. The
// text is escaped; an argument is escaped too unless it is already HTML,
// such as what link and code return.
func (tr *translator) t(text string, args ...any) (template.HTML, error) {
	tr.used[text] = true
	out := text
	if tr.lang.texts != nil {
		if s, ok := tr.lang.texts[text]; ok && s != "" {
			out = s
		} else {
			tr.missing[text] = true
		}
	}
	n := len(placeholder.FindAllStringIndex(out, -1))
	if n != len(args) {
		return "", fmt.Errorf("%s: %q has %d placeholders for %d arguments", tr.lang.Code, out, n, len(args))
	}
	i := 0
	escaped := placeholder.ReplaceAllStringFunc(template.HTMLEscapeString(out), func(string) string {
		i++
		return html(args[i-1])
	})
	return template.HTML(escaped), nil
}

// html returns v as HTML: as it is when it is HTML already, escaped
// otherwise.
func html(v any) string {
	if h, ok := v.(template.HTML); ok {
		return string(h)
	}
	return template.HTMLEscapeString(fmt.Sprint(v))
}

// funcs are the functions the pages use besides t.
var funcs = template.FuncMap{
	"t":    func(string, ...any) template.HTML { return "" }, // replaced per language
	"list": func(v ...any) []any { return v },
	"code": func(s string) template.HTML {
		return template.HTML("<code>" + template.HTMLEscapeString(s) + "</code>")
	},
	"link": func(href string, text any) template.HTML {
		return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + html(text) + `</a>`)
	},
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, errors.New("dict: odd number of arguments")
		}
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[fmt.Sprint(kv[i])] = plain(kv[i+1])
		}
		return m, nil
	},
	// jsonld writes v as the JSON of a <script type="application/ld+json">;
	// json.Marshal escapes <, > and &, so it cannot close the element.
	"jsonld": func(v any) (template.JS, error) {
		b, err := json.Marshal(v)
		return template.JS(b), err
	},
}

// plain returns v as plain text when it is translated HTML without markup,
// for JSON-LD; anything else stays as it is.
func plain(v any) any {
	if h, ok := v.(template.HTML); ok {
		return stdhtml.UnescapeString(string(h))
	}
	return v
}

// qa is a question of the FAQ in one language.
type qa struct{ Q, A template.HTML }

// faqIn translates the FAQ.
func faqIn(tr *translator) ([]qa, error) {
	var out []qa
	for _, f := range faq {
		q, err := tr.t(f.Q)
		if err != nil {
			return nil, err
		}
		a, err := tr.t(f.A)
		if err != nil {
			return nil, err
		}
		out = append(out, qa{q, a})
	}
	return out, nil
}

// faqLD is the FAQ as a schema.org FAQPage.
func faqLD(items []qa) map[string]any {
	var qs []any
	for _, it := range items {
		qs = append(qs, map[string]any{
			"@type":          "Question",
			"name":           plain(it.Q),
			"acceptedAnswer": map[string]any{"@type": "Answer", "text": plain(it.A)},
		})
	}
	return map[string]any{"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": qs}
}

// render renders every page in every language and returns them by path
// below the output directory, with the translators to check.
func render(root string) (map[string][]byte, []*translator, error) {
	langs, err := loadLanguages(root)
	if err != nil {
		return nil, nil, err
	}
	out := map[string][]byte{}
	var trs []*translator
	for _, lang := range langs {
		tr := &translator{lang: lang, used: map[string]bool{}, missing: map[string]bool{}}
		trs = append(trs, tr)
		items, err := faqIn(tr)
		if err != nil {
			return nil, nil, err
		}
		perLang := template.FuncMap{
			"t":     tr.t,
			"faq":   func() []qa { return items },
			"faqld": func() map[string]any { return faqLD(items) },
		}
		for _, name := range append(slices.Clone(pages), errorPages...) {
			tmpl, err := template.New("layout.html").Funcs(funcs).Funcs(perLang).ParseFiles(
				filepath.Join(root, "templates", "layout.html"),
				filepath.Join(root, "templates", name+".html"))
			if err != nil {
				return nil, nil, err
			}
			var b bytes.Buffer
			p := page{Lang: lang, Langs: langs, Page: name + ".html", Path: pagePath(name), Error: slices.Contains(errorPages, name)}
			if err := tmpl.Execute(&b, p); err != nil {
				return nil, nil, fmt.Errorf("%s/%s.html: %w", lang.Code, name, err)
			}
			out[lang.Code+"/"+name+".html"] = b.Bytes()
		}
	}
	// Without the language chooser, "/" falls back to English.
	out["index.html"] = []byte(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=en/"><title>Clipboard Bridge</title><a href="en/">Clipboard Bridge</a>` + "\n")
	out["sitemap.xml"] = sitemap(langs)
	out["robots.txt"] = []byte("User-agent: *\n" +
		"# \"/\" only redirects; \"/?lang=\" sets a cookie.\n" +
		"Disallow: /?\n" +
		"Sitemap: " + siteURL + "/sitemap.xml\n")
	return out, trs, nil
}

// sitemap lists every page in every language, each with its translations
// (hreflang), for search engines.
func sitemap(langs []Language) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n")
	for _, name := range pages {
		p := page{Path: pagePath(name)}
		for _, l := range langs {
			fmt.Fprintf(&b, "<url><loc>%s</loc>", p.URL(l))
			for _, alt := range langs {
				fmt.Fprintf(&b, `<xhtml:link rel="alternate" hreflang="%s" href="%s"/>`, alt.Tag, p.URL(alt))
			}
			b.WriteString("</url>\n")
		}
	}
	b.WriteString("</urlset>\n")
	return b.Bytes()
}

// check renders the site and reports every missing, unused or broken
// translation.
func check(root string) error {
	_, trs, err := render(root)
	if err != nil {
		return err
	}
	used := trs[0].used // English asks for every text
	var problems []string
	for _, tr := range trs[1:] {
		for _, text := range sortedKeys(tr.missing) {
			problems = append(problems, fmt.Sprintf("l10n/%s.json: no translation of %q", tr.lang.Code, text))
		}
		for _, text := range sortedKeys(tr.lang.texts) {
			if !used[text] && !strings.HasPrefix(text, "@") {
				problems = append(problems, fmt.Sprintf("l10n/%s.json: %q is on no page", tr.lang.Code, text))
			}
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

// build writes the site to dir: the pages and site/static.
func build(root, dir string) error {
	if err := check(root); err != nil {
		return err
	}
	files, _, err := render(root)
	if err != nil {
		return err
	}
	static := filepath.Join(root, "static")
	err = filepath.WalkDir(static, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(static, p)
		files["static/"+filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(files) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
