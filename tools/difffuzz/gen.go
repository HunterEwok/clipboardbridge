// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A Case is one line of the corpus.
type Case struct {
	Kind    string   `json:"kind"`
	Body    []byte   `json:"body,omitempty"`
	CA      []byte   `json:"ca,omitempty"`
	Records []Record `json:"records,omitempty"`
	Keys    [][]byte `json:"keys,omitempty"`
}

// A Record is a signed record as the interop vectors and the member
// protocol carry it.
type Record struct {
	Body  []byte   `json:"body"`
	Sig   []byte   `json:"sig"`
	Chain [][]byte `json:"chain,omitempty"`
}

// A vector is a body of strict-generated.json or strict-files.json.
type vector struct {
	Body  []byte `json:"body"`
	Pad   int    `json:"pad"`
	PadAt int    `json:"pad_at"`
	Kind  string `json:"kind"`
}

func (v vector) full() []byte {
	if v.Pad == 0 {
		return v.Body
	}
	b := append([]byte{}, v.Body[:v.PadAt]...)
	b = append(b, bytes.Repeat([]byte("a"), v.Pad)...)
	return append(b, v.Body[v.PadAt:]...)
}

// A setSource is a record set of the interop vectors.
type setSource struct {
	name    string
	ca      []byte
	records []Record
}

// seeds reads the bodies the corpus starts from, by kind.
func seeds(dir string) ([]Case, error) {
	var out []Case
	read := func(file string, sections map[string]string) error {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return err
		}
		var v map[string][]vector
		if err := json.Unmarshal(data, &v); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		names := make([]string, 0, len(sections))
		for s := range sections {
			names = append(names, s)
		}
		sort.Strings(names)
		for _, s := range names {
			if len(v[s]) == 0 {
				return fmt.Errorf("%s: no %s", file, s)
			}
			for _, c := range v[s] {
				kind := sections[s]
				if kind == "" {
					kind = c.Kind
				}
				out = append(out, Case{Kind: kind, Body: c.full()})
			}
		}
		return nil
	}
	if err := read("strict-generated.json", map[string]string{"records": "record", "commands": "command", "manifests": "manifest"}); err != nil {
		return nil, err
	}
	if err := read("strict-files.json", map[string]string{"credentials": "credential", "releases": ""}); err != nil {
		return nil, err
	}
	return out, nil
}

// setSources reads every record set of the interop vectors: a file with a
// group_ca and records, or a list of such cases. The records of a set's
// "later" go with it, so the set holds both.
func setSources(dir string) ([]setSource, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	type raw struct {
		Name    string   `json:"name"`
		GroupCA []byte   `json:"group_ca"`
		Records []Record `json:"records"`
		Later   []Record `json:"later"`
	}
	var out []setSource
	add := func(name string, r raw) {
		if len(r.GroupCA) == 0 || len(r.Records) == 0 {
			return
		}
		out = append(out, setSource{name: name, ca: r.GroupCA, records: append(r.Records, r.Later...)})
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		base := strings.TrimSuffix(filepath.Base(f), ".json")
		var one raw
		if json.Unmarshal(data, &one) == nil {
			add(base, one)
		}
		var many struct {
			Cases []raw `json:"cases"`
		}
		if json.Unmarshal(data, &many) == nil {
			for _, c := range many.Cases {
				add(base+"/"+c.Name, c)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no record sets", dir)
	}
	return out, nil
}

// keysOf returns every key hash the records' bodies name, sorted: the keys
// whose state a set's verdict reports.
func keysOf(rs []Record) [][]byte {
	seen := map[string]bool{}
	for _, r := range rs {
		var b struct {
			Key   []byte   `json:"key"`
			Admin []byte   `json:"admin"`
			Keys  [][]byte `json:"keys"`
			Keep  [][]byte `json:"keep"`
		}
		if json.Unmarshal(r.Body, &b) != nil {
			continue
		}
		for _, k := range append(append([][]byte{b.Key, b.Admin}, b.Keys...), b.Keep...) {
			if len(k) == 32 {
				seen[string(k)] = true
			}
		}
	}
	out := make([][]byte, 0, len(seen))
	for k := range seen {
		out = append(out, []byte(k))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// maxSeed is the size of the largest body the corpus changes.
const maxSeed = 9 << 10

// generate returns the corpus: every seed body as it is, n changed bodies
// and sets record sets, from the seed.
func generate(dir string, seed uint64, n, sets int) ([]Case, error) {
	base, err := seeds(dir)
	if err != nil {
		return nil, err
	}
	srcs, err := setSources(dir)
	if err != nil {
		return nil, err
	}
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	m := mutator{r: r}
	out := append([]Case{}, base...)
	seen := map[string]bool{}
	for _, c := range base {
		seen[c.Kind+"\x00"+string(c.Body)] = true
	}
	// Each kind as often as the others, from its bodies of a few
	// kilobytes at most: the long ones are in the corpus as they are.
	byKind := map[string][]Case{}
	var kinds []string
	for _, c := range base {
		if len(c.Body) > maxSeed {
			continue
		}
		if byKind[c.Kind] == nil {
			kinds = append(kinds, c.Kind)
		}
		byKind[c.Kind] = append(byKind[c.Kind], c)
	}
	for tries := 0; len(out) < len(base)+n && tries < 4*n; tries++ {
		l := byKind[kinds[r.IntN(len(kinds))]]
		c := l[r.IntN(len(l))]
		body := c.Body
		for k := 1 + r.IntN(3); k > 0; k-- {
			body = m.mutate(body)
		}
		key := c.Kind + "\x00" + string(body)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Case{Kind: c.Kind, Body: body})
	}
	for _, s := range srcs {
		out = append(out, Case{Kind: "set", CA: s.ca, Records: s.records, Keys: keysOf(s.records)})
	}
	for i := 0; i < sets; i++ {
		s := srcs[r.IntN(len(srcs))]
		out = append(out, m.set(s))
	}
	return out, nil
}

// set returns a changed copy of a record set: some of its records, in
// another order, some twice, some with their chain or signature changed.
func (m mutator) set(s setSource) Case {
	keep := []float64{1, 1, 0.9, 0.7, 0.5}[m.r.IntN(5)]
	var rs []Record
	for _, rec := range s.records {
		if m.r.Float64() < keep {
			rs = append(rs, rec)
		}
	}
	m.r.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
	if len(rs) > 0 && m.r.IntN(4) == 0 {
		rs = append(rs, rs[m.r.IntN(len(rs))])
	}
	if len(rs) > 0 && m.r.IntN(6) == 0 {
		i := m.r.IntN(len(rs))
		c := rs[i]
		switch m.r.IntN(4) {
		case 0:
			c.Chain = nil
		case 1:
			c.Sig = flip(m.r, c.Sig)
		case 2:
			c.Body = flip(m.r, c.Body)
		default:
			// Another record's signature.
			c.Sig = rs[m.r.IntN(len(rs))].Sig
		}
		rs[i] = c
	}
	return Case{Kind: "set", CA: s.ca, Records: rs, Keys: keysOf(s.records)}
}

func flip(r *rand.Rand, b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := append([]byte{}, b...)
	out[r.IntN(len(out))] ^= byte(1 << r.IntN(8))
	return out
}

// writeCorpus writes the cases one to a line.
func writeCorpus(path string, cases []Case) error {
	f := os.Stdout
	if path != "" {
		var err error
		if f, err = os.Create(path); err != nil {
			return err
		}
		defer f.Close()
	}
	w := bufio.NewWriter(f)
	for _, c := range cases {
		line, err := json.Marshal(c)
		if err != nil {
			return err
		}
		w.Write(line)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// readCorpus reads a corpus that writeCorpus wrote.
func readCorpus(path string) ([]Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Case
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var c Case
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		out = append(out, c)
	}
	return out, nil
}

var b64 = base64.StdEncoding

// fuzzTargets names the cargo fuzz target of each kind of body.
var fuzzTargets = map[string]string{
	"record": "record_body", "command": "command", "credential": "credential", "manifest": "wire",
	"keys": "release", "release": "release", "channel": "release",
}

// writeSeeds writes every seed body to out/<target>/<n>.
func writeSeeds(dir, out string) error {
	base, err := seeds(dir)
	if err != nil {
		return err
	}
	n := map[string]int{}
	for _, c := range base {
		t := fuzzTargets[c.Kind]
		if t == "" || len(c.Body) > maxSeed {
			continue
		}
		if err := os.MkdirAll(filepath.Join(out, t), 0o755); err != nil {
			return err
		}
		n[t]++
		if err := os.WriteFile(filepath.Join(out, t, fmt.Sprint(n[t])), c.Body, 0o644); err != nil {
			return err
		}
	}
	return nil
}
