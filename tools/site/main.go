// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command site builds the project's website from site/ and serves the one
// part of it that is not a static file: the choice of language at "/".
//
//	site build [-out DIR]     write the site, one directory per language
//	site check                fail if a page or a translation is broken
//	site serve [-dir DIR] [-geo FILE] [-addr ADDR] [-proxy] [-preview]
//	site lighthouse [-dir DIR] [-runs N]   measure the built site (CI)
//
// The pages are site/templates, written in English; each other language is
// site/l10n/<language>.json, which maps every English text to its
// translation. build writes DIR/<language>/<page>.html and the files of
// site/static, and check fails when a language lacks a text, keeps one no
// page uses, or a page does not render.
//
// serve answers "/" with a redirect to the visitor's language (lang.go) and
// "/?lang=xx&p=page.html" by remembering a language the visitor picked;
// with -preview it also serves the built files. On cbb.tools
// nginx serves the files and passes only "/" to it, from the loopback
// address, which is what -proxy trusts for the visitor's address
// (site/deploy).
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		out := fs.String("out", "site/out", "the directory to write the site to")
		fs.Parse(os.Args[2:])
		err = build("site", *out)
	case "check":
		err = check("site")
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		dir := fs.String("dir", "site/out", "the built site")
		preview := fs.Bool("preview", false, "serve the site's files too, not only \"/\"")
		geo := fs.String("geo", "", "DB-IP's country CSV, plain or gzipped, to pick the language by country")
		addr := fs.String("addr", "127.0.0.1:8780", "the address to listen on")
		proxy := fs.Bool("proxy", false, "take the visitor's address from X-Real-IP, set by nginx")
		fs.Parse(os.Args[2:])
		err = serve(*addr, *dir, *geo, *proxy, *preview)
	case "lighthouse":
		fs := flag.NewFlagSet("lighthouse", flag.ExitOnError)
		dir := fs.String("dir", "site/out", "the built site")
		bin := fs.String("bin", "site/node_modules/.bin/lighthouse", "Lighthouse, installed by npm ci in site")
		reports := fs.String("reports", "site/out-lighthouse", "the directory to keep the reports in")
		runs := fs.Int("runs", 3, "the runs on each page; the median counts")
		fs.Parse(os.Args[2:])
		err = lighthouse(*dir, *bin, *reports, *runs)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "site:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: site build [-out DIR] | site check | site serve [-dir DIR] [-geo FILE] [-addr ADDR] [-proxy] [-preview] | site lighthouse [-dir DIR] [-runs N]")
	os.Exit(2)
}
