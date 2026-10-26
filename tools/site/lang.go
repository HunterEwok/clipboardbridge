// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// countryLanguages lists, for each country where one of the site's
// languages is the most likely one, the site's languages spoken there, the
// most likely first. A country that is not here, or whose languages the
// site does not have, gets the browser's language or English.
var countryLanguages = map[string][]string{
	// Russian.
	"RU": {"ru"}, "BY": {"ru"}, "KZ": {"ru"}, "KG": {"ru"}, "TJ": {"ru"}, "UZ": {"ru"}, "TM": {"ru"},
	// Chinese.
	"CN": {"zh"}, "TW": {"zh"}, "HK": {"zh", "en"}, "MO": {"zh"}, "SG": {"en", "zh"},
	// Spanish.
	"ES": {"es"}, "MX": {"es"}, "AR": {"es"}, "CO": {"es"}, "PE": {"es"}, "VE": {"es"}, "CL": {"es"},
	"EC": {"es"}, "GT": {"es"}, "CU": {"es"}, "BO": {"es"}, "DO": {"es"}, "HN": {"es"}, "PY": {"es"},
	"SV": {"es"}, "NI": {"es"}, "CR": {"es"}, "PA": {"es"}, "UY": {"es"}, "GQ": {"es"}, "PR": {"es", "en"},
	// Arabic.
	"SA": {"ar"}, "AE": {"ar", "en"}, "EG": {"ar"}, "IQ": {"ar"}, "JO": {"ar"}, "KW": {"ar"}, "LB": {"ar"},
	"LY": {"ar"}, "MA": {"ar"}, "OM": {"ar"}, "QA": {"ar"}, "SY": {"ar"}, "TN": {"ar"}, "YE": {"ar"},
	"BH": {"ar"}, "DZ": {"ar"}, "SD": {"ar"}, "PS": {"ar"}, "MR": {"ar"},
	// Hebrew, and the other languages many people there read.
	"IL": {"he", "ar", "ru", "en"},
	// Swahili.
	"TZ": {"sw"}, "KE": {"sw", "en"}, "UG": {"en", "sw"},
}

// chooseLanguage picks the language of the site for a visitor: the one
// they picked before (picked, from the cookie), else their country's most
// likely one, which the browser's languages (acceptLanguage) decide between
// where a country has several, else the browser's own, else English. have
// is the site's languages.
func chooseLanguage(have []string, picked, country, acceptLanguage string) string {
	if i := slices.Index(have, picked); i >= 0 {
		return have[i]
	}
	browser := browserLanguages(acceptLanguage)
	var local []string
	for _, l := range countryLanguages[country] {
		if slices.Contains(have, l) {
			local = append(local, l)
		}
	}
	for _, l := range browser {
		if slices.Contains(local, l) {
			return l
		}
	}
	if len(local) > 0 {
		return local[0]
	}
	for _, l := range browser {
		if slices.Contains(have, l) {
			return l
		}
	}
	return "en"
}

// browserLanguages returns the primary languages of an Accept-Language
// header ("ru-RU,ru;q=0.9,en;q=0.8" gives ru, en) in the order of their
// weights, leaving out the ones with weight 0.
func browserLanguages(header string) []string {
	type weighted struct {
		lang string
		q    float64
	}
	var ls []weighted
	for _, part := range strings.Split(header, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if _, err := fmt.Sscan(v, &q); err != nil {
				continue
			}
		}
		primary, _, _ := strings.Cut(strings.ToLower(tag), "-")
		if primary == "" || primary == "*" || q <= 0 {
			continue
		}
		// Hebrew's old code.
		if primary == "iw" {
			primary = "he"
		}
		ls = append(ls, weighted{primary, q})
	}
	slices.SortStableFunc(ls, func(a, b weighted) int {
		switch {
		case a.q > b.q:
			return -1
		case a.q < b.q:
			return 1
		}
		return 0
	})
	var out []string
	for _, l := range ls {
		if !slices.Contains(out, l.lang) {
			out = append(out, l.lang)
		}
	}
	return out
}

// geoRange is a range of addresses in one country.
type geoRange struct {
	first, last netip.Addr
	country     string
}

// geoDB finds the country of an address. It keeps only the countries of
// countryLanguages: every other address is in no country it knows.
type geoDB struct {
	ranges []geoRange // sorted, not overlapping
}

// loadGeo reads DB-IP's "IP to Country Lite" CSV (first,last,country per
// line), gzipped when its name ends in .gz.
func loadGeo(name string) (*geoDB, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = bufio.NewReader(f)
	if strings.HasSuffix(name, ".gz") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		r = zr
	}
	db, err := readGeo(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return db, nil
}

func readGeo(r io.Reader) (*geoDB, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	db := &geoDB{}
	for line := 1; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 3 {
			return nil, fmt.Errorf("line %d: %d fields, want 3", line, len(rec))
		}
		if _, ok := countryLanguages[rec[2]]; !ok {
			continue
		}
		first, err1 := netip.ParseAddr(rec[0])
		last, err2 := netip.ParseAddr(rec[1])
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if first.Is4() != last.Is4() || last.Less(first) {
			return nil, fmt.Errorf("line %d: %s-%s is not a range", line, first, last)
		}
		db.ranges = append(db.ranges, geoRange{first, last, rec[2]})
	}
	slices.SortFunc(db.ranges, func(a, b geoRange) int { return a.first.Compare(b.first) })
	for i := 1; i < len(db.ranges); i++ {
		if !db.ranges[i-1].last.Less(db.ranges[i].first) {
			return nil, fmt.Errorf("ranges %s-%s and %s-%s overlap", db.ranges[i-1].first, db.ranges[i-1].last, db.ranges[i].first, db.ranges[i].last)
		}
	}
	if len(db.ranges) == 0 {
		return nil, errors.New("no address of a known country")
	}
	return db, nil
}

// country returns the country of addr, or "" when it is in none the
// database keeps.
func (db *geoDB) country(addr netip.Addr) string {
	if db == nil {
		return ""
	}
	addr = addr.Unmap()
	i, _ := slices.BinarySearchFunc(db.ranges, addr, func(r geoRange, a netip.Addr) int {
		switch {
		case r.last.Less(a):
			return -1
		case a.Less(r.first):
			return 1
		}
		return 0
	})
	if i < len(db.ranges) && !addr.Less(db.ranges[i].first) && !db.ranges[i].last.Less(addr) {
		return db.ranges[i].country
	}
	return ""
}
