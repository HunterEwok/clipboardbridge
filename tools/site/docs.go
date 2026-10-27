// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

// The documentation at /docs/: every Markdown page below docs/ and the few
// pages elsewhere in the repository it links to (extraDocs), in English, as
// they read on GitHub. A link to another published page leads to its page
// here, a link to any other file of the repository to that file on GitHub,
// and docs/images is copied as it is. The headings get GitHub's anchors, so
// the links that tools/repocheck checks keep working.

// repoURL is where a file of the repository is shown on GitHub.
const repoURL = "https://github.com/HunterEwok/clipboardbridge/blob/main/"

// extraDocs are the pages outside docs/ that the documentation publishes,
// with their names below /docs/.
var extraDocs = map[string]string{
	"CONTRIBUTING.md":            "contributing.html",
	"SECURITY.md":                "security.html",
	"CHANGELOG.md":               "changelog.html",
	"lite/README.md":             "lite.html",
	"packaging/docker/README.md": "docker.html",
}

// docPage returns the page below /docs/ of a Markdown file of the
// repository, by its path from the repository's root, and false for a file
// the documentation does not publish.
func docPage(file string) (string, bool) {
	if p, ok := extraDocs[file]; ok {
		return p, true
	}
	rest, ok := strings.CutPrefix(file, "docs/")
	if !ok || path.Ext(rest) != ".md" {
		return "", false
	}
	if path.Base(rest) == "README.md" {
		return path.Join(path.Dir(rest), "index.html"), true
	}
	return strings.TrimSuffix(rest, ".md") + ".html", true
}

// docURL is a page's address in links.
func docURL(page string) string {
	if page == "index.html" {
		return "/docs/"
	}
	return "/docs/" + strings.TrimSuffix(page, "index.html")
}

// doc is what doc.html sees.
type doc struct {
	Title       string
	Description string
	Path        string // the page's address: "/docs/protocol.html"
	Source      string // the Markdown file's path in the repository
	Body        template.HTML
}

// URL returns the page's absolute address.
func (d doc) URL() string { return siteURL + d.Path }

// githubIDs gives the headings the anchors GitHub gives them: lower case,
// spaces as hyphens, other punctuation dropped, -1, -2 for a repeat.
type githubIDs struct{ seen map[string]int }

func (g *githubIDs) Generate(value []byte, _ ast.NodeKind) []byte {
	var b strings.Builder
	for _, r := range strings.ToLower(string(value)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	id := b.String()
	if n := g.seen[id]; n > 0 {
		g.seen[id]++
		id = fmt.Sprintf("%s-%d", id, n)
	} else {
		g.seen[id] = 1
	}
	return []byte(id)
}

func (g *githubIDs) Put(value []byte) { g.seen[string(value)]++ }

// markdown renders the documentation: GitHub's tables, strikethrough and
// autolinks, no raw HTML, and no alignment attributes, which the site's
// Content-Security-Policy would block as inline styles.
var markdown = goldmark.New(
	goldmark.WithExtensions(
		extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignNone)),
		extension.Strikethrough,
		extension.Linkify,
	),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
)

// rewriteLink turns the destination of a link in file into its address on
// the site or on GitHub; an address with a scheme or an anchor alone stays.
func rewriteLink(file, dest string, published map[string]bool) string {
	if dest == "" || strings.HasPrefix(dest, "#") || strings.Contains(dest, ":") {
		return dest
	}
	target, frag, _ := strings.Cut(dest, "#")
	if frag != "" {
		frag = "#" + frag
	}
	target = path.Join(path.Dir(file), target)
	if published[target] {
		page, _ := docPage(target)
		return docURL(page) + frag
	}
	if rest, ok := strings.CutPrefix(target, "docs/images/"); ok {
		return "/docs/images/" + rest
	}
	return repoURL + target + frag
}

// renderDoc renders one Markdown file of the repository into its page.
func renderDoc(tmpl *template.Template, file string, src []byte, published map[string]bool) ([]byte, error) {
	ctx := parser.NewContext(parser.WithIDs(&githubIDs{seen: map[string]int{}}))
	root := markdown.Parser().Parse(text.NewReader(src), parser.WithContext(ctx))
	page, _ := docPage(file)
	d := doc{Path: docURL(page), Source: file}
	err := ast.Walk(root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Link:
			n.Destination = []byte(rewriteLink(file, string(n.Destination), published))
		case *ast.Image:
			n.Destination = []byte(rewriteLink(file, string(n.Destination), published))
		case *ast.Heading:
			if n.Level == 1 && d.Title == "" {
				d.Title = plainText(n, src)
			}
		case *ast.Paragraph:
			if d.Description == "" && d.Title != "" {
				d.Description = describe(plainText(n, src))
			}
		}
		return ast.WalkContinue, nil
	})
	if err != nil {
		return nil, err
	}
	if d.Title == "" {
		return nil, fmt.Errorf("%s: no title (# heading)", file)
	}
	var body bytes.Buffer
	if err := markdown.Renderer().Render(&body, src, root); err != nil {
		return nil, err
	}
	d.Body = template.HTML(body.String())
	var out bytes.Buffer
	if err := tmpl.Execute(&out, d); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return out.Bytes(), nil
}

// plainText returns the text of n without its markup.
func plainText(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch c := c.(type) {
		case *ast.Text:
			b.Write(c.Segment.Value(src))
			if c.SoftLineBreak() || c.HardLineBreak() {
				b.WriteByte(' ')
			}
		case *ast.String:
			b.Write(c.Value)
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}

// describe cuts a page's first paragraph to a description for search
// engines: at most 160 characters, ending at a word.
func describe(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:157])
		if i := strings.LastIndex(s, " "); i > 0 {
			s = s[:i]
		}
		s += "…"
	}
	return s
}

// docFiles returns the Markdown files the documentation publishes, by
// their paths from the repository's root.
func docFiles(repo string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(filepath.Join(repo, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".md" {
			return err
		}
		rel, err := filepath.Rel(repo, p)
		files = append(files, filepath.ToSlash(rel))
		return err
	})
	if err != nil {
		return nil, err
	}
	return append(files, sortedKeys(extraDocs)...), nil
}

// renderDocs renders the documentation and returns its files by path below
// the output directory, and the pages' addresses for the sitemap.
func renderDocs(root string, asset template.FuncMap) (map[string][]byte, []string, error) {
	repo := filepath.Join(root, "..")
	files, err := docFiles(repo)
	if err != nil {
		return nil, nil, err
	}
	published := make(map[string]bool, len(files))
	for _, f := range files {
		published[f] = true
	}
	tmpl, err := template.New("doc.html").Funcs(asset).ParseFiles(filepath.Join(root, "templates", "doc.html"))
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string][]byte)
	var urls []string
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(f)))
		if err != nil {
			return nil, nil, err
		}
		page, _ := docPage(f)
		if out["docs/"+page], err = renderDoc(tmpl, f, src, published); err != nil {
			return nil, nil, err
		}
		urls = append(urls, siteURL+docURL(page))
	}
	images := filepath.Join(repo, "docs", "images")
	err = filepath.WalkDir(images, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		out["docs/images/"+d.Name()] = data
		return err
	})
	return out, urls, err
}
