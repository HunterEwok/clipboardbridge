// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
		for _, name := range pages {
			tmpl, err := template.New("layout.html").Funcs(funcs).Funcs(template.FuncMap{"t": tr.t}).ParseFiles(
				filepath.Join(root, "templates", "layout.html"),
				filepath.Join(root, "templates", name+".html"))
			if err != nil {
				return nil, nil, err
			}
			var b bytes.Buffer
			if err := tmpl.Execute(&b, page{Lang: lang, Langs: langs, Page: name + ".html"}); err != nil {
				return nil, nil, fmt.Errorf("%s/%s.html: %w", lang.Code, name, err)
			}
			out[lang.Code+"/"+name+".html"] = b.Bytes()
		}
	}
	// Without the language chooser, "/" falls back to English.
	out["index.html"] = []byte(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=en/"><title>Clipboard Bridge</title><a href="en/">Clipboard Bridge</a>` + "\n")
	return out, trs, nil
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
