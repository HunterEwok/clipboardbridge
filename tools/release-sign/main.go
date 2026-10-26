// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command release-sign makes and signs the files that describe a release
// (docs/protocol.md, section 16), on the maintainer's Mac:
//
//	release-sign manifest -version 0.6.0 -channel stable [-min-from 0.5.0] [-docker IMAGE@sha256:...] DIR >release.body
//	release-sign keys -seq 2 [-days 90] [-status NAME=status-key.pem] NAME=release-key.pem... >keys.body
//	release-sign channel -seq 7 [-days 30] release.json >stable.body
//	release-sign sign -key SIGNER BODY >FILE.json
//	release-sign public -key SIGNER >key.pem
//	release-sign verify -roots root-1.pem,root-2.pem [-channel stable] DIR
//	release-sign drill -version 0.6.0 DIR ROOTS.pem
//
// A SIGNER is file:KEY.pem (a P-256 key in a file, for tests and drills),
// piv:SLOT (a key on a YubiKey, through yubico-piv-tool; the root keys) or
// se:KEY (a Secure Enclave key through se.swift beside this file, which
// asks for Touch ID; the release key). drill signs DIR as a release with
// throwaway keys in files and writes their roots to ROOTS.pem, for the
// installers' tests and for drills. docs/maintaining.md, "Signed
// releases", has the whole flow.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) error{
		"manifest": manifest, "keys": keys, "channel": channel,
		"sign": sign, "public": public, "verify": verify, "drill": drill,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "release-sign:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: release-sign manifest|keys|channel|sign|public|verify|drill ... (see the comment in tools/release-sign/main.go)")
	os.Exit(2)
}

var (
	now              = time.Now
	stdout io.Writer = os.Stdout
)

func writeJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(data, '\n'))
	return err
}

// manifest writes the body of release.json for the files in a directory.
func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	version := fs.String("version", "", "the release's version, without the v")
	ch := fs.String("channel", "stable", "the channel")
	minFrom := fs.String("min-from", "", "the lowest version that may update to this one directly")
	docker := fs.String("docker", "", "the image as NAME@sha256:DIGEST")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("manifest needs the directory of the release's files")
	}
	r, err := buildManifest(fs.Arg(0), *version, *ch, *minFrom, *docker)
	if err != nil {
		return err
	}
	return writeJSON(r)
}

func buildManifest(dir, version, ch, minFrom, docker string) (release.Release, error) {
	r := release.Release{V: 1, Type: release.TypeRelease, Version: strings.TrimPrefix(version, "v"), Channel: ch,
		TimeMS: now().UnixMilli(), MinFrom: strings.TrimPrefix(minFrom, "v")}
	if docker != "" {
		image, digest, ok := strings.Cut(docker, "@")
		if !ok {
			return r, errors.New("-docker must be NAME@sha256:DIGEST")
		}
		r.Docker = &release.Docker{Image: image, Digest: digest}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return r, err
	}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return r, err
		}
		a := release.Asset{Name: name, Size: int64(len(data)), SHA256: hexSum(data)}
		if a.Binaries, err = binaries(name, data); err != nil {
			return r, fmt.Errorf("%s: %w", name, err)
		}
		r.Files = append(r.Files, a)
	}
	// Signing the body checks it as every reader will.
	body, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if err := checkBody(body); err != nil {
		return r, err
	}
	return r, nil
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// binaries lists the programs inside an archive: the executable files of
// a tar.gz, the .exe files of a zip.
func binaries(name string, data []byte) ([]release.Binary, error) {
	var out []release.Binary
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg || h.Mode&0o111 == 0 || strings.HasSuffix(h.Name, ".sh") {
				continue
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			out = append(out, release.Binary{Name: h.Name, SHA256: hexSum(b)})
		}
	case strings.HasSuffix(name, ".zip") && !strings.HasPrefix(name, "winget"):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
			out = append(out, release.Binary{Name: f.Name, SHA256: hexSum(b)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// checkBody signs body with a throwaway key, which runs the checks Sign
// makes, without a hardware key.
func checkBody(body []byte) error {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	k, err := ecdsa.GenerateKey(ellipticP256(), randReader)
	if err != nil {
		return err
	}
	_, err = release.Sign(json.RawMessage(body), k)
	return err
}

// keys writes the body of keys.json, certifying the release keys and,
// with -status, the keys that sign attest-status.json.
func keys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	seq := fs.Uint64("seq", 0, "the sequence number, above the last keys.json's")
	days := fs.Int("days", 90, "days until it expires")
	var status []string
	fs.Func("status", "NAME=KEY.pem of a key that signs attest-status.json (repeatable)", func(v string) error {
		status = append(status, v)
		return nil
	})
	fs.Parse(args)
	k := release.Keys{V: 1, Type: release.TypeKeys, Seq: *seq, TimeMS: now().UnixMilli()}
	k.ExpiresMS = k.TimeMS + int64(*days)*24*time.Hour.Milliseconds()
	add := func(arg, use string) error {
		name, path, ok := strings.Cut(arg, "=")
		if !ok {
			return fmt.Errorf("%q is not NAME=KEY.pem", arg)
		}
		spki, err := readPublic(path)
		if err != nil {
			return err
		}
		k.Keys = append(k.Keys, release.Key{Key: spki, Name: name, Use: use})
		return nil
	}
	for _, arg := range fs.Args() {
		if err := add(arg, ""); err != nil {
			return err
		}
	}
	for _, arg := range status {
		if err := add(arg, release.UseStatus); err != nil {
			return err
		}
	}
	return writeJSON(k)
}

// channel writes the body of a channel file that names a signed
// release.json.
func channel(args []string) error {
	fs := flag.NewFlagSet("channel", flag.ExitOnError)
	seq := fs.Uint64("seq", 0, "the sequence number, above the channel's last")
	days := fs.Int("days", 30, "days until it expires")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("channel needs the signed release.json")
	}
	f, err := readFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var r release.Release
	if err := json.Unmarshal(f.Body, &r); err != nil {
		return err
	}
	h := f.Hash()
	c := release.Channel{V: 1, Type: release.TypeChannel, Channel: r.Channel, Seq: *seq, TimeMS: now().UnixMilli(),
		Release: r.Version, ReleaseSHA256: hex.EncodeToString(h[:])}
	c.ExpiresMS = c.TimeMS + int64(*days)*24*time.Hour.Milliseconds()
	return writeJSON(c)
}

func readFile(path string) (release.File, error) {
	var f release.File
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	return f, json.Unmarshal(data, &f)
}

func readPublic(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s holds no PUBLIC KEY", path)
	}
	if _, err := x509.ParsePKIXPublicKey(b.Bytes); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b.Bytes, nil
}

// sign signs a body with a signer and writes the file.
func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	key := fs.String("key", "", "the signer: file:KEY.pem, piv:SLOT or se:KEY")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("sign needs the body")
	}
	body, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return err
	}
	body = compact.Bytes()
	s, err := signer(*key)
	if err != nil {
		return err
	}
	if t, ok := s.(*tool); ok {
		t.data = body
	}
	f, err := release.Sign(json.RawMessage(body), s)
	if err != nil {
		return err
	}
	return writeJSON(f)
}

func public(args []string) error {
	fs := flag.NewFlagSet("public", flag.ExitOnError)
	key := fs.String("key", "", "the signer: file:KEY.pem, piv:SLOT or se:KEY")
	fs.Parse(args)
	s, err := signer(*key)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return err
	}
	return pem.Encode(stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: spki})
}

// verify checks a directory that holds keys.json, the channel file,
// release.json and the files, as a device would.
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rootsFlag := fs.String("roots", "", "the root keys' PEM files, comma-separated")
	ch := fs.String("channel", "stable", "the channel")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("verify needs the directory")
	}
	dir := fs.Arg(0)
	var roots [][]byte
	for _, p := range strings.Split(*rootsFlag, ",") {
		spki, err := readPublic(p)
		if err != nil {
			return err
		}
		roots = append(roots, spki)
	}
	var files [3]release.File
	for i, name := range []string{"keys.json", *ch + ".json", "release.json"} {
		f, err := readFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		files[i] = f
	}
	r, _, err := release.Check(files[0], files[1], files[2], roots, *ch, now(), release.Seen{})
	if err != nil {
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
	fmt.Fprintf(stdout, "%s %s: keys.json, %s.json, release.json and %d files check out\n", r.Version, r.Channel, *ch, len(r.Files))
	return nil
}

// signer returns the key a SIGNER names.
func signer(spec string) (crypto.Signer, error) {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "file":
		data, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		b, _ := pem.Decode(data)
		if b == nil {
			return nil, fmt.Errorf("%s holds no PEM key", arg)
		}
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			if ec, err2 := x509.ParseECPrivateKey(b.Bytes); err2 == nil {
				return ec, nil
			}
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s is not a signing key", arg)
		}
		return s, nil
	case "piv":
		return newTool([]string{"yubico-piv-tool", "-a", "read-certificate", "-s", arg, "-K", "PEM"},
			[]string{"yubico-piv-tool", "-a", "verify-pin", "-a", "sign", "-s", arg, "-A", "ECCP256", "-H", "SHA256"})
	case "se":
		helper := filepath.Join(sourceDir(), "se.swift")
		return newTool([]string{"swift", helper, "public", arg}, []string{"swift", helper, "sign", arg})
	}
	return nil, fmt.Errorf("unknown signer %q: file:KEY.pem, piv:SLOT or se:KEY", spec)
}

func sourceDir() string {
	if d := os.Getenv("CBB_RELEASE_SIGN_DIR"); d != "" {
		return d
	}
	return filepath.Join("tools", "release-sign")
}

// drill signs the files in dir as a release with new keys in files: two
// roots, whose public keys go to rootsPath, and a release key.
func drill(args []string) error {
	fs := flag.NewFlagSet("drill", flag.ExitOnError)
	version := fs.String("version", "0.0.1", "the release's version")
	fs.Parse(args)
	if fs.NArg() != 2 {
		return errors.New("drill needs the directory and the file for the roots")
	}
	dir, rootsPath := fs.Arg(0), fs.Arg(1)
	var ks [3]*ecdsa.PrivateKey
	var roots []byte
	for i := range ks {
		k, err := ecdsa.GenerateKey(ellipticP256(), randReader)
		if err != nil {
			return err
		}
		ks[i] = k
		if i < 2 {
			spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
			roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})...)
		}
	}
	r, err := buildManifest(dir, *version, "stable", "", "")
	if err != nil {
		return err
	}
	rel, err := release.Sign(r, ks[2])
	if err != nil {
		return err
	}
	spki, _ := x509.MarshalPKIXPublicKey(&ks[2].PublicKey)
	t := now().UnixMilli()
	keysFile, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: t,
		ExpiresMS: t + 90*24*time.Hour.Milliseconds(), Keys: []release.Key{{Key: spki, Name: "drill"}}}, ks[0])
	if err != nil {
		return err
	}
	h := rel.Hash()
	ch, err := release.Sign(release.Channel{V: 1, Type: release.TypeChannel, Channel: "stable", Seq: 1, TimeMS: t,
		ExpiresMS: t + 30*24*time.Hour.Milliseconds(), Release: r.Version, ReleaseSHA256: hex.EncodeToString(h[:])}, ks[2])
	if err != nil {
		return err
	}
	for name, f := range map[string]release.File{"release.json": rel, "keys.json": keysFile, "stable.json": ch} {
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(rootsPath, roots, 0o644)
}
