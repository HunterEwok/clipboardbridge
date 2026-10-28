// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/release"
)

// fakeGitHub plays the gh commands publish and renew run, with each
// release's files in a directory.
type fakeGitHub struct {
	t        *testing.T
	dir      string
	drafts   map[string]bool
	latest   string
	attested bool
	edits    [][]string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{t: t, dir: t.TempDir(), drafts: map[string]bool{}, attested: true}
	prev := gh
	gh = g.run
	t.Cleanup(func() { gh = prev })
	return g
}

// draft makes a draft release of the archives, as the release workflow does.
func (g *fakeGitHub) draft(tag string) {
	archives(g.t, g.release(tag))
	g.drafts[tag] = true
}

func (g *fakeGitHub) release(tag string) string {
	d := filepath.Join(g.dir, tag)
	os.MkdirAll(d, 0o755)
	return d
}

// argAfter returns the value after name in args.
func argAfter(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func copyFile(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, data, 0o644)
}

func (g *fakeGitHub) run(args ...string) ([]byte, error) {
	switch {
	case args[0] == "release" && args[1] == "view" && strings.HasPrefix(args[2], "v"):
		draft, ok := g.drafts[args[2]]
		if !ok {
			return nil, errors.New("release not found")
		}
		return json.Marshal(map[string]any{"isDraft": draft,
			"body": "notes\n\n```\nghcr.io/hunterewok/clipboardbridge@sha256:" + strings.Repeat("ab", 32) + "\n```\n"})
	case args[0] == "release" && args[1] == "view":
		if g.latest == "" {
			return nil, errors.New("release not found")
		}
		return json.Marshal(map[string]string{"tagName": g.latest})
	case args[0] == "release" && args[1] == "download" && strings.HasPrefix(args[2], "v"):
		entries, _ := os.ReadDir(g.release(args[2]))
		for _, e := range entries {
			if err := copyFile(filepath.Join(g.release(args[2]), e.Name()), filepath.Join(argAfter(args, "--dir"), e.Name())); err != nil {
				return nil, err
			}
		}
		return nil, nil
	case args[0] == "release" && args[1] == "download":
		name := argAfter(args, "--pattern")
		if g.latest == "" {
			return nil, errors.New("release not found")
		}
		if err := copyFile(filepath.Join(g.release(g.latest), name), filepath.Join(argAfter(args, "--dir"), name)); err != nil {
			return nil, fmt.Errorf("no assets match the file pattern")
		}
		return nil, nil
	case args[0] == "attestation":
		if !g.attested {
			return nil, errors.New("verification failed")
		}
		return nil, nil
	case args[0] == "release" && args[1] == "upload":
		if !g.drafts[args[2]] && g.latest != args[2] {
			g.t.Errorf("uploaded to %s, neither a draft nor the latest", args[2])
		}
		for _, a := range args[3:] {
			if strings.HasSuffix(a, ".json") {
				if err := copyFile(a, filepath.Join(g.release(args[2]), filepath.Base(a))); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	case args[0] == "release" && args[1] == "edit":
		g.edits = append(g.edits, args)
		g.drafts[args[2]] = false
		if !strings.Contains(args[2], "-") {
			g.latest = args[2]
		}
		return nil, nil
	}
	g.t.Fatalf("unexpected gh %v", args)
	return nil, nil
}

func (g *fakeGitHub) file(tag, name string, body any) {
	g.t.Helper()
	f, err := readFile(filepath.Join(g.release(tag), name))
	if err != nil {
		g.t.Fatal(err)
	}
	if err := json.Unmarshal(f.Body, body); err != nil {
		g.t.Fatal(err)
	}
}

// TestPublish publishes releases and renews the channel as the maintainer
// does, with keys in files and a GitHub in a directory.
func TestPublish(t *testing.T) {
	g := newFakeGitHub(t)
	keysDir := t.TempDir()
	root1, root1Pub := newKey(t, keysDir, "root-1")
	_, root2Pub := newKey(t, keysDir, "root-2")
	rk, _ := newKey(t, keysDir, "release")
	roots := [][]byte{must(readPublic(root1Pub)), must(readPublic(root2Pub))}
	prevRoots, prevAsk, prevNow := pinnedRoots, ask, now
	pinnedRoots = func() [][]byte { return roots }
	answer := true
	ask = func(string) bool { return answer }
	clock := time.Now()
	now = func() time.Time { return clock }
	t.Cleanup(func() { pinnedRoots, ask, now = prevRoots, prevAsk, prevNow })
	keyFlags := []string{"-root", "file:" + root1, "-release-key", "file:" + rk}
	pub := func(extra ...string) error { return publish(append(append([]string{}, keyFlags...), extra...)) }
	renewNow := func() error { return renew(keyFlags) }
	var k release.Keys
	var c release.Channel
	var r release.Release

	// The first signed release: a root signs keys.json.
	g.draft("v0.6.0")
	if err := pub("-version", "0.6.0", "-min-from", "0.5.0"); err != nil {
		t.Fatal(err)
	}
	if g.drafts["v0.6.0"] || g.latest != "v0.6.0" {
		t.Fatalf("v0.6.0 is not published: %+v", g)
	}
	g.file("v0.6.0", "keys.json", &k)
	g.file("v0.6.0", "stable.json", &c)
	g.file("v0.6.0", "release.json", &r)
	if k.Seq != 1 || c.Seq != 1 || c.Release != "0.6.0" || r.MinFrom != "0.5.0" || r.Docker == nil || len(r.Files) != 3 {
		t.Fatalf("keys %+v, channel %+v, release %+v", k, c, r)
	}
	call(t, verify, g.release("v0.6.0"))

	// Renewed within keys.json's margin: only stable.json changes.
	clock = clock.Add(20 * 24 * time.Hour)
	if err := renewNow(); err != nil {
		t.Fatal(err)
	}
	g.file("v0.6.0", "keys.json", &k)
	g.file("v0.6.0", "stable.json", &c)
	if k.Seq != 1 || c.Seq != 2 || c.Release != "0.6.0" {
		t.Fatalf("after renew: keys %d, channel %+v", k.Seq, c)
	}
	// Past the margin, a root signs keys.json again.
	clock = clock.Add(30 * 24 * time.Hour)
	if err := renewNow(); err != nil {
		t.Fatal(err)
	}
	g.file("v0.6.0", "keys.json", &k)
	g.file("v0.6.0", "stable.json", &c)
	if k.Seq != 2 || len(k.Keys) != 1 || c.Seq != 3 {
		t.Fatalf("after the second renew: keys %+v, channel %d", k, c.Seq)
	}
	call(t, verify, g.release("v0.6.0"))

	// The next release carries keys.json on and raises the channel.
	g.draft("v0.6.1")
	if err := pub("-version", "v0.6.1"); err != nil {
		t.Fatal(err)
	}
	g.file("v0.6.1", "keys.json", &k)
	g.file("v0.6.1", "stable.json", &c)
	if k.Seq != 2 || c.Seq != 4 || c.Release != "0.6.1" || g.latest != "v0.6.1" {
		t.Fatalf("v0.6.1: keys %d, channel %+v", k.Seq, c)
	}
	call(t, verify, g.release("v0.6.1"))

	// A pre-release gets no channel file; answering no leaves a draft.
	g.draft("v0.7.0-rc.1")
	answer = false
	if err := pub("-version", "0.7.0-rc.1", "-docker", "none"); err != nil {
		t.Fatal(err)
	}
	if !g.drafts["v0.7.0-rc.1"] {
		t.Error("published without a yes")
	}
	if _, err := os.Stat(filepath.Join(g.release("v0.7.0-rc.1"), "stable.json")); err == nil {
		t.Error("a pre-release got stable.json")
	}
	r = release.Release{}
	g.file("v0.7.0-rc.1", "release.json", &r)
	if r.Docker != nil {
		t.Errorf("-docker none left %+v", r.Docker)
	}

	// Refused: a published release, a file without the attestation.
	if pub("-version", "0.6.1") == nil {
		t.Error("signed a published release")
	}
	g.draft("v0.6.2")
	g.attested = false
	if pub("-version", "0.6.2") == nil {
		t.Error("signed a file without its attestation")
	}
	if _, err := os.Stat(filepath.Join(g.release("v0.6.2"), "release.json")); err == nil {
		t.Error("uploaded after a failed attestation")
	}
}

// TestPublishKeepsTheSequence: a keys.json that no longer checks out is
// replaced by one numbered above it.
func TestPublishKeepsTheSequence(t *testing.T) {
	g := newFakeGitHub(t)
	keysDir := t.TempDir()
	root1, root1Pub := newKey(t, keysDir, "root-1")
	other, _ := newKey(t, keysDir, "other")
	rk, rkPub := newKey(t, keysDir, "release")
	prevRoots, prevAsk := pinnedRoots, ask
	pinnedRoots = func() [][]byte { return [][]byte{must(readPublic(root1Pub))} }
	ask = func(string) bool { return true }
	t.Cleanup(func() { pinnedRoots, ask = prevRoots, prevAsk })

	// The latest release's keys.json is signed by a key that is no root.
	g.draft("v0.5.9")
	g.drafts["v0.5.9"], g.latest = false, "v0.5.9"
	kb := write(t, filepath.Join(keysDir, "keys.body"), call(t, keys, "-seq", "7", "release="+rkPub))
	write(t, filepath.Join(g.release("v0.5.9"), "keys.json"), call(t, sign, "-key", "file:"+other, kb))

	g.draft("v0.6.0")
	if err := publish([]string{"-root", "file:" + root1, "-release-key", "file:" + rk, "-version", "0.6.0"}); err != nil {
		t.Fatal(err)
	}
	var k release.Keys
	g.file("v0.6.0", "keys.json", &k)
	if k.Seq != 8 {
		t.Errorf("keys.json is %d, not 8", k.Seq)
	}
}
