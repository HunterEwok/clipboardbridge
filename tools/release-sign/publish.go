// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/release"
)

// The steps of publish and renew reach GitHub through the gh command, ask
// on the terminal and check under the pinned roots; variables for the
// tests.
var (
	gh  = func(args ...string) ([]byte, error) { return run(append([]string{"gh"}, args...), nil) }
	ask = func(question string) bool {
		fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.EqualFold(strings.TrimSpace(line), "y")
	}
	pinnedRoots = func() [][]byte { return release.Roots }
)

// keysMargin is how long keys.json must still be valid for a release to
// carry it on; a shorter one is signed again by a root.
const keysMargin = 45 * 24 * time.Hour

const defaultRepo = "HunterEwok/clipboardbridge"

// The image the release workflow's docker job pushes; it adds the digest
// to the draft's notes.
var dockerRE = regexp.MustCompile(`ghcr\.io/hunterewok/clipboardbridge@sha256:[0-9a-f]{64}`)

// signing are the flags publish and renew share.
type signing struct {
	repo, root, releaseKey string
	status                 []string
	newKeys                bool
}

func (s *signing) flags(fs *flag.FlagSet) {
	home, _ := os.UserHomeDir()
	fs.StringVar(&s.repo, "repo", defaultRepo, "the repository")
	fs.StringVar(&s.root, "root", "piv:82", "the root key that signs keys.json when it is signed again")
	fs.StringVar(&s.releaseKey, "release-key", "se:"+filepath.Join(home, ".config", "cbb-release", "release.se"), "the release key")
	fs.BoolVar(&s.newKeys, "new-keys", false, "sign keys.json again even when it is valid for long enough")
	fs.Func("status", "NAME=KEY.pem of a key that signs attest-status.json, added to keys.json (repeatable)", func(v string) error {
		s.status = append(s.status, v)
		return nil
	})
}

// publish signs a release the workflow left as a draft and publishes it:
// docs/maintaining.md, "Signed releases".
func publish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	var s signing
	s.flags(fs)
	version := fs.String("version", "", "the release's version, as in its tag without the v")
	minFrom := fs.String("min-from", "", "the lowest version that may update to this one directly")
	docker := fs.String("docker", "", "the image as NAME@sha256:DIGEST; by default from the draft's notes, none for no image")
	dirFlag := fs.String("dir", "", "where the files go; a new directory by default")
	noPublish := fs.Bool("no-publish", false, "upload the signed files and leave the release a draft")
	fs.Parse(args)
	v := strings.TrimPrefix(*version, "v")
	if v == "" || fs.NArg() != 0 {
		return errors.New("publish needs -version X.Y.Z and nothing else")
	}
	tag := "v" + v
	pre := strings.Contains(v, "-")

	var view struct {
		IsDraft bool   `json:"isDraft"`
		Body    string `json:"body"`
	}
	out, err := gh("release", "view", tag, "--repo", s.repo, "--json", "isDraft,body")
	if err != nil {
		return fmt.Errorf("the release %s: %w", tag, err)
	}
	if err := json.Unmarshal(out, &view); err != nil {
		return err
	}
	if !view.IsDraft {
		return fmt.Errorf("%s is published already, and a published release takes no more files", tag)
	}
	switch *docker {
	case "":
		*docker = dockerRE.FindString(view.Body)
		if *docker == "" {
			return errors.New("the draft's notes name no Docker image yet: wait for the release workflow's docker job, or pass -docker none")
		}
	case "none":
		*docker = ""
	}

	dir := *dirFlag
	if dir == "" {
		if dir, err = os.MkdirTemp("", "cbb-"+tag+"-"); err != nil {
			return err
		}
	}
	step("downloading %s's files into %s", tag, dir)
	if _, err := gh("release", "download", tag, "--repo", s.repo, "--dir", dir, "--clobber"); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			// From an earlier run; signed again below.
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
			continue
		}
		step("checking the build attestation of %s", name)
		if _, err := gh("attestation", "verify", filepath.Join(dir, name), "--repo", s.repo,
			"--source-ref", "refs/tags/"+tag, "--signer-workflow", s.repo+"/.github/workflows/release.yml"); err != nil {
			return fmt.Errorf("%s was not built by the release workflow from %s: %w", name, tag, err)
		}
	}

	prev, err := latestFiles(s.repo, "keys.json", "stable.json")
	if err != nil {
		return err
	}
	rs, err := signer(s.releaseKey)
	if err != nil {
		return err
	}
	keysFile, err := s.keysFor(prev["keys.json"], rs)
	if err != nil {
		return err
	}

	r, err := buildManifest(dir, v, stableChannel, *minFrom, *docker)
	if err != nil {
		return err
	}
	step("signing release.json with the release key")
	rel, err := signWith(rs, r)
	if err != nil {
		return err
	}
	files := map[string]release.File{"keys.json": keysFile, "release.json": rel}
	if !pre {
		// A pre-release stays out of the channel, as it stays out of
		// releases/latest.
		ch, err := s.channelFor(prev["stable.json"], rel, rs)
		if err != nil {
			return err
		}
		files[stableChannel+".json"] = ch
	}
	if err := checkSigned(files, dir); err != nil {
		return fmt.Errorf("the signed files do not check out, nothing was uploaded: %w", err)
	}
	if err := upload(s.repo, tag, dir, files); err != nil {
		return err
	}
	if *noPublish {
		step("%s is signed and still a draft: publish it on GitHub, or run publish again", tag)
		return nil
	}
	if !ask(fmt.Sprintf("Publish %s now? Once published, its files cannot change.", tag)) {
		step("%s is signed and still a draft", tag)
		return nil
	}
	edit := []string{"release", "edit", tag, "--repo", s.repo, "--draft=false"}
	if !pre {
		edit = append(edit, "--latest")
	}
	if _, err := gh(edit...); err != nil {
		return err
	}
	step("%s is published; the published workflow updates the Homebrew tap", tag)
	return nil
}

// renew signs stable.json of the latest release again, and keys.json when
// it is near its expiry, and replaces them in that release, so that a
// release older than 30 days still installs.
func renew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	var s signing
	s.flags(fs)
	fs.Parse(args)
	if fs.NArg() != 0 {
		return errors.New("renew takes only flags")
	}
	out, err := gh("release", "view", "--repo", s.repo, "--json", "tagName")
	if err != nil {
		return err
	}
	var view struct {
		TagName string `json:"tagName"`
	}
	if err := json.Unmarshal(out, &view); err != nil {
		return err
	}
	prev, err := latestFiles(s.repo, "keys.json", "stable.json", "release.json")
	if err != nil {
		return err
	}
	for _, name := range []string{"stable.json", "release.json"} {
		if _, ok := prev[name]; !ok {
			return fmt.Errorf("the latest release, %s, has no %s; publish it first", view.TagName, name)
		}
	}
	rs, err := signer(s.releaseKey)
	if err != nil {
		return err
	}
	keysFile, err := s.keysFor(prev["keys.json"], rs)
	if err != nil {
		return err
	}
	ch, err := s.channelFor(prev["stable.json"], prev["release.json"], rs)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "cbb-renew-")
	if err != nil {
		return err
	}
	files := map[string]release.File{"keys.json": keysFile, "stable.json": ch, "release.json": prev["release.json"]}
	if err := checkSigned(files, ""); err != nil {
		return fmt.Errorf("the signed files do not check out, nothing was uploaded: %w", err)
	}
	delete(files, "release.json")
	if err := upload(s.repo, view.TagName, dir, files); err != nil {
		return err
	}
	step("%s: stable.json is valid until %s", view.TagName, expiry(ch))
	return nil
}

// stableChannel is the one channel releases go to.
const stableChannel = "stable"

func step(format string, a ...any) { fmt.Fprintf(os.Stderr, "release-sign: "+format+"\n", a...) }

// latestFiles downloads the named files of the latest published release,
// leaving out those it lacks: before the first signed release it has
// none.
func latestFiles(repo string, names ...string) (map[string]release.File, error) {
	dir, err := os.MkdirTemp("", "cbb-latest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	files := map[string]release.File{}
	for _, name := range names {
		// One at a time: gh fails when a pattern matches nothing.
		if _, err := gh("release", "download", "--repo", repo, "--dir", dir, "--pattern", name); err != nil {
			step("the latest release has no %s", name)
			continue
		}
		f, err := readFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files[name] = f
	}
	return files, nil
}

// keysFor returns the keys.json a release carries: the latest one while it
// is valid for long enough and certifies the release key, otherwise a new
// one from a root, with the latest one's keys and a sequence number above
// its own.
func (s *signing) keysFor(prev release.File, rs crypto.Signer) (release.File, error) {
	spki, err := x509.MarshalPKIXPublicKey(rs.Public())
	if err != nil {
		return release.File{}, err
	}
	var k release.Keys
	have := prev.Body != nil
	if have {
		if k, err = release.VerifyKeys(prev, pinnedRoots(), now(), release.Seen{}); err != nil {
			step("the latest keys.json does not check out (%v); a root signs a new one", err)
			have = false
			// Its keys are dropped, but the new one's number stays above
			// its own, which devices may have seen.
			k = release.Keys{}
			json.Unmarshal(prev.Body, &k)
		}
	}
	if !have {
		k.Keys = nil
	}
	certified := false
	for _, key := range k.Keys {
		certified = certified || (key.Use != release.UseStatus && bytes.Equal(key.Key, spki))
	}
	left := time.Duration(k.ExpiresMS-now().UnixMilli()) * time.Millisecond
	if have && certified && left >= keysMargin && !s.newKeys && len(s.status) == 0 {
		step("keys.json %d is valid until %s; the release carries it", k.Seq, time.UnixMilli(k.ExpiresMS).UTC().Format(time.DateOnly))
		return prev, nil
	}
	next := release.Keys{V: 1, Type: release.TypeKeys, Seq: k.Seq + 1, TimeMS: now().UnixMilli()}
	next.ExpiresMS = next.TimeMS + 90*24*time.Hour.Milliseconds()
	next.Keys = k.Keys
	if !certified {
		next.Keys = append(next.Keys, release.Key{Key: spki, Name: "release " + time.UnixMilli(next.TimeMS).UTC().Format("2006-01")})
	}
	for _, arg := range s.status {
		name, path, ok := strings.Cut(arg, "=")
		if !ok {
			return release.File{}, fmt.Errorf("%q is not NAME=KEY.pem", arg)
		}
		key, err := readPublic(path)
		if err != nil {
			return release.File{}, err
		}
		next.Keys = append(next.Keys, release.Key{Key: key, Name: name, Use: release.UseStatus})
	}
	root, err := signer(s.root)
	if err != nil {
		return release.File{}, fmt.Errorf("the root key, to sign keys.json %d: %w", next.Seq, err)
	}
	step("signing keys.json %d with the root key: enter the YubiKey's PIN, then touch it", next.Seq)
	return signWith(root, next)
}

// channelFor signs a channel file naming rel, its sequence number above the
// latest one's.
func (s *signing) channelFor(prev, rel release.File, rs crypto.Signer) (release.File, error) {
	var last release.Channel
	if prev.Body != nil {
		if err := json.Unmarshal(prev.Body, &last); err != nil {
			return release.File{}, fmt.Errorf("the latest stable.json: %w", err)
		}
	}
	var r release.Release
	if err := json.Unmarshal(rel.Body, &r); err != nil {
		return release.File{}, err
	}
	h := rel.Hash()
	c := release.Channel{V: 1, Type: release.TypeChannel, Channel: r.Channel, Seq: last.Seq + 1, TimeMS: now().UnixMilli(),
		Release: r.Version, ReleaseSHA256: hex.EncodeToString(h[:])}
	c.ExpiresMS = c.TimeMS + 30*24*time.Hour.Milliseconds()
	step("signing %s.json %d with the release key", c.Channel, c.Seq)
	return signWith(rs, c)
}

// signWith signs body; a hardware key is handed the exact bytes it signs.
func signWith(s crypto.Signer, body any) (release.File, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return release.File{}, err
	}
	if t, ok := s.(*tool); ok {
		t.data = data
	}
	return release.Sign(json.RawMessage(data), s)
}

// checkSigned checks the files as a device would, under the pinned roots,
// and the release's files in dir unless dir is "".
func checkSigned(files map[string]release.File, dir string) error {
	var (
		r   release.Release
		err error
	)
	if ch, ok := files[stableChannel+".json"]; ok {
		r, _, err = release.Check(files["keys.json"], ch, files["release.json"], pinnedRoots(), stableChannel, now(), release.Seen{})
	} else {
		r, _, err = release.CheckPinned(files["keys.json"], files["release.json"], pinnedRoots(), now(), release.Seen{})
	}
	if err != nil || dir == "" {
		return err
	}
	for _, a := range r.Files {
		data, err := os.ReadFile(filepath.Join(dir, a.Name))
		if err != nil {
			return err
		}
		if err := r.CheckFile(a.Name, data); err != nil {
			return err
		}
	}
	step("%s: keys.json, release.json and %d files check out under the pinned roots", r.Version, len(r.Files))
	return nil
}

// upload writes the files into dir and replaces them in the release.
func upload(repo, tag, dir string, files map[string]release.File) error {
	args := []string{"release", "upload", tag, "--repo", repo, "--clobber"}
	for _, name := range []string{"keys.json", "release.json", stableChannel + ".json"} {
		f, ok := files[name]
		if !ok {
			continue
		}
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			return err
		}
		args = append(args, path)
	}
	step("uploading the signed files to %s", tag)
	_, err := gh(args...)
	return err
}

func expiry(f release.File) string {
	var c release.Channel
	json.Unmarshal(f.Body, &c)
	return time.UnixMilli(c.ExpiresMS).UTC().Format(time.DateOnly)
}
