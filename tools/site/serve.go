// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"sync/atomic"
	"syscall"
	"time"
)

// langCookie keeps the language a visitor picked, and nothing else.
const langCookie = "lang"

// pageFiles are the pages the language menu may send a visitor back to.
var pageFiles = func() []string {
	var files []string
	for _, p := range pages {
		files = append(files, p+".html")
	}
	return files
}()

// docPageName is a page of the documentation the language menu may send a
// visitor back to; its characters cannot make an address other than the
// site's own.
var docPageName = regexp.MustCompile(`^docs/(guide/[a-z0-9-]+\.html)?$`)

// chooser answers "/" with a redirect to a language of the site. It logs
// no visitor: their address is used for the country and then forgotten.
type chooser struct {
	// dir is the built site, read again on every request: a language
	// whose pages arrive after the start is offered at once. langs is
	// what the start found, and all there is without dir.
	dir   string
	langs []string
	geo   atomic.Pointer[geoDB]
	proxy bool // trust X-Real-IP
}

// languages returns the site's languages now: the directories of dir with
// an index.html, or what the start found if dir can't be read.
func (c *chooser) languages() []string {
	if c.dir == "" {
		return c.langs
	}
	if langs := siteLanguages(c.dir); slices.Contains(langs, "en") {
		return langs
	}
	return c.langs
}

// siteLanguages returns the directories of dir with an index.html.
func siteLanguages(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var langs []string
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "index.html")); e.IsDir() && err == nil {
			langs = append(langs, e.Name())
		}
	}
	return langs
}

func (c *chooser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie, Accept-Language")
	q := r.URL.Query()
	// The redirect is built from the site's own names only, never from
	// what the request says.
	page := ""
	if p := q.Get("p"); slices.Contains(pageFiles, p) || docPageName.MatchString(p) {
		page = p
	}
	langs := c.languages()
	if i := slices.Index(langs, q.Get("lang")); i >= 0 {
		picked := langs[i]
		http.SetCookie(w, &http.Cookie{
			Name: langCookie, Value: picked, Path: "/", MaxAge: 365 * 24 * 3600,
			Secure: r.TLS != nil || c.proxy, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/"+picked+"/"+page, http.StatusFound)
		return
	}
	var picked string
	if ck, err := r.Cookie(langCookie); err == nil {
		picked = ck.Value
	}
	var country string
	if addr, ok := c.visitor(r); ok {
		country = c.geo.Load().country(addr)
	}
	lang := chooseLanguage(langs, picked, country, r.Header.Get("Accept-Language"))
	http.Redirect(w, r, "/"+lang+"/"+page, http.StatusFound)
}

// visitor returns the visitor's address: nginx's X-Real-IP behind it, the
// connection's otherwise.
func (c *chooser) visitor(r *http.Request) (netip.Addr, bool) {
	if c.proxy {
		a, err := netip.ParseAddr(r.Header.Get("X-Real-IP"))
		return a, err == nil
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	return ap.Addr(), err == nil
}

// serve runs the language chooser for the site built in dir, whose
// languages are its directories with an index.html; with preview it serves
// the site's files too.
func serve(addr, dir, geo string, proxy, preview bool) error {
	if _, err := os.ReadDir(dir); err != nil {
		return err
	}
	c := &chooser{dir: dir, langs: siteLanguages(dir), proxy: proxy}
	if !slices.Contains(c.langs, "en") {
		return errors.New(dir + ": no en/index.html; is it the built site?")
	}
	if geo != "" {
		// Without the database the browser's language decides; the
		// timer that fetches it reloads the chooser.
		if db, err := loadGeo(geo); err != nil {
			log.Printf("no country database, choosing by the browser's language: %v", err)
		} else {
			c.geo.Store(db)
		}
		// The database is replaced every month; SIGHUP reads it again,
		// and a broken one keeps the last.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				db, err := loadGeo(geo)
				if err != nil {
					log.Printf("keeping the last country database: %v", err)
					continue
				}
				c.geo.Store(db)
				log.Printf("read the country database again")
			}
		}()
	}
	mux := http.NewServeMux()
	mux.Handle("/{$}", c)
	if preview {
		mux.Handle("/", http.FileServer(http.Dir(dir)))
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("serving on %s, languages %v", ln.Addr(), c.langs)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(os.Stderr, "", 0)}
	return srv.Serve(ln)
}
