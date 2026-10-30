// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A strictVector is a body and whether every member takes it: the
// vectors of testdata/interop/strict.json, which the lite member and both
// phone kits read too.
type strictVector struct {
	Name  string `json:"name"`
	Body  []byte `json:"body"`
	Valid bool   `json:"valid"`
}

type strictVectors struct {
	Records   []strictVector `json:"records"`
	Commands  []strictVector `json:"commands"`
	Manifests []strictVector `json:"manifests"`
}

const (
	vecGroup  = "0011223344556677"
	vecDevice = "00112233445566778899aabbccddeeff"
	vecOther  = "ffeeddccbbaa99887766554433221100"
)

var (
	vecHash  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	vecHash2 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
)

// makeStrictVectors returns the vectors; each body is written out as it
// is, so that it can break the rules of JSON.
func makeStrictVectors() strictVectors {
	dev := func(fields string) []byte {
		return []byte(`{"v":1,"type":"device","group":"` + vecGroup + `","time_ms":1700000000000` + fields + `}`)
	}
	good := `,"device":"` + vecDevice + `","name":"Laptop","role":"full","os":"linux","key":"` + vecHash + `"`
	with := func(old, repl string) []byte { return dev(strings.Replace(good, old, repl, 1)) }
	r := func(name string, valid bool, body []byte) strictVector {
		return strictVector{Name: name, Body: body, Valid: valid}
	}
	var v strictVectors
	v.Records = []strictVector{
		r("device", true, dev(good)),
		r("device with spaces and newlines", true, []byte(" {\n\t\"v\": 1, \"type\": \"device\", \"group\": \""+vecGroup+"\", \"time_ms\": 1700000000000"+good+"}\r\n")),
		r("revoke", true, []byte(`{"v":1,"type":"revoke","group":"`+vecGroup+`","time_ms":5,"keys":["`+vecHash+`"],"keep":["`+vecHash2+`"]}`)),
		r("thaw", true, []byte(`{"v":1,"type":"thaw","group":"`+vecGroup+`","time_ms":5,"records":["`+vecHash+`"]}`)),
		r("an unknown member", true, dev(good+`,"later":"x","more":{"a":[1,-2,true,false,"s"]}`)),
		r("an earlier role", true, with(`"role":"full"`, `"role":"linux"`)),
		r("a surrogate pair escaped", true, with(`"Laptop"`, `"Lap\ud83d\ude00"`)),
		r("other escapes", true, with(`"Laptop"`, `"\u00e9\"\\\/"`)),
		r("negative time", true, []byte(`{"v":1,"type":"revoke","group":"`+vecGroup+`","time_ms":-1,"keys":["`+vecHash+`"]}`)),

		r("a member name in upper case", false, with(`"name"`, `"NAME"`)),
		r("a member name in mixed case", false, []byte(`{"v":1,"Type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("a member name escaped", false, with(`"name"`, `"n\u0061me"`)),
		r("a member name with a Kelvin sign", false, with(`"key"`, "\"\u212aey\"")),
		r("a member twice", false, dev(good+`,"type":"revoke"`)),
		r("a member twice with the same value", false, dev(good+`,"name":"Laptop"`)),
		r("a member twice in a nested object", false, dev(good+`,"later":{"a":1,"a":2}`)),
		r("invalid UTF-8", false, with(`"Laptop"`, "\"Lap\xfftop\"")),
		r("overlong UTF-8", false, with(`"Laptop"`, "\"Lap\xc0\xaftop\"")),
		r("a surrogate in UTF-8", false, with(`"Laptop"`, "\"Lap\xed\xa0\x80top\"")),
		r("a lone high surrogate escaped", false, with(`"Laptop"`, `"Lap\ud800top"`)),
		r("a lone low surrogate escaped", false, with(`"Laptop"`, `"Lap\udc00top"`)),
		r("a byte order mark", false, append([]byte("\xef\xbb\xbf"), dev(good)...)),
		r("a raw control character", false, with(`"Laptop"`, "\"Lap\ttop\"")),
		r("an unknown escape", false, with(`"Laptop"`, `"Lap\xtop"`)),
		r("no time", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`"`+good+`}`)),
		r("no version", false, []byte(`{"type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("no group", false, []byte(`{"v":1,"type":"device","time_ms":1`+good+`}`)),
		r("a null", false, with(`"os":"linux"`, `"os":null`)),
		r("a null among unknown members", false, dev(good+`,"later":[null]`)),
		r("a time with a fraction", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":1.0`+good+`}`)),
		r("a time with an exponent", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":1e3`+good+`}`)),
		r("a time with a leading zero", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":01`+good+`}`)),
		r("a time out of range", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":9223372036854775808`+good+`}`)),
		r("a version as a string", false, []byte(`{"v":"1","type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("another version", false, []byte(`{"v":2,"type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("a version that wraps in 32 bits", false, []byte(`{"v":4294967297,"type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("more after the object", false, append(dev(good), []byte(`{}`)...)),
		r("an array", false, []byte(`[`+string(dev(good))+`]`)),
		r("nested too deeply", false, dev(good+`,"later":`+strings.Repeat("[", 17)+strings.Repeat("]", 17))),
		r("a key hash with stray bits", false, with(vecHash, vecHash[:42]+"x=")),
		r("a key hash without padding", false, with(vecHash, strings.TrimRight(vecHash, "="))),
		r("a key hash with a newline", false, with(vecHash, vecHash[:20]+`\n`+vecHash[20:])),
		r("a key hash of 31 bytes", false, with(vecHash, base64.StdEncoding.EncodeToString(make([]byte, 31)))),
		r("an admin hash of 33 bytes", false, dev(good+`,"admin":"`+base64.StdEncoding.EncodeToString(make([]byte, 33))+`"`)),
		r("no key", false, with(`,"key":"`+vecHash+`"`, ``)),
		r("a device ID in upper case", false, with(vecDevice, strings.ToUpper(vecDevice))),
		r("a name of 65 bytes", false, with(`"Laptop"`, `"`+strings.Repeat("a", 65)+`"`)),
		r("a name with a control character", false, with(`"Laptop"`, `"Lap\u0007top"`)),
		r("a name with a C1 control character", false, with(`"Laptop"`, `"Lap\u0085top"`)),
		r("an empty name", false, with(`"Laptop"`, `""`)),
		r("an unknown role", false, with(`"role":"full"`, `"role":"server"`)),
		r("an unknown system", false, with(`"os":"linux"`, `"os":"beos"`)),
		r("an unknown type", false, []byte(`{"v":1,"type":"other","group":"`+vecGroup+`","time_ms":1}`)),
		r("a revoke of nothing", false, []byte(`{"v":1,"type":"revoke","group":"`+vecGroup+`","time_ms":1,"keys":[]}`)),
		r("a root without a certificate", false, []byte(`{"v":1,"type":"root","group":"`+vecGroup+`","time_ms":1,"root":""}`)),
	}
	cmd := func(fields string) []byte {
		return []byte(`{"v":1,"type":"paste-off","group":"` + vecGroup + `","by":"` + vecOther + `","to":"` + vecDevice +
			`","id":"0123456789abcdef0123456789abcdef","time_ms":1000,"expires_ms":20000` + fields + `}`)
	}
	v.Commands = []strictVector{
		r("paste-off", true, cmd("")),
		r("an empty kind and no enter", true, cmd(`,"kind":"","enter":false,"text":"","action":""`)),
		r("mode", true, []byte(`{"v":1,"type":"mode","group":"`+vecGroup+`","by":"`+vecOther+`","to":"`+vecDevice+
			`","id":"0123456789abcdef0123456789abcdef","time_ms":1000,"expires_ms":20000,"mode":"own"}`)),
		r("paste", true, []byte(`{"v":1,"type":"paste","group":"`+vecGroup+`","by":"`+vecOther+`","to":"`+vecDevice+
			`","id":"0123456789abcdef0123456789abcdef","time_ms":1000,"expires_ms":20000,"mode":"paste","kind":"secret","text":"line\none"}`)),
		r("a member name in upper case", false, bytes.Replace(cmd(""), []byte(`"to"`), []byte(`"TO"`), 1)),
		r("a member twice", false, cmd(`,"type":"mode"`)),
		r("no signer", false, bytes.Replace(cmd(""), []byte(`"by":"`+vecOther+`",`), nil, 1)),
		r("no time", false, bytes.Replace(cmd(""), []byte(`"time_ms":1000,`), nil, 1)),
		r("a null mode", false, cmd(`,"mode":null`)),
		r("invalid UTF-8", false, cmd(",\"later\":\"\xff\"")),
		r("an ID in upper case", false, bytes.Replace(cmd(""), []byte("abcdef0123456789abcdef"), []byte("ABCDEF0123456789abcdef"), 1)),
		r("a kind on paste-off", false, cmd(`,"kind":"text"`)),
		r("enter on paste-off", false, cmd(`,"enter":true`)),
	}
	part := func(p string) []byte {
		return []byte(`{"size":3,"parts":[{"path":"d","dir":true` + p + `},{"path":"d/f","size":3,"sha256":"` + vecHash + `"}]}`)
	}
	v.Manifests = []strictVector{
		r("a folder", true, part("")),
		r("a folder with a null hash", true, part(`,"sha256":null`)),
		r("a folder with an empty hash", false, part(`,"sha256":""`)),
		r("a folder with a hash", false, part(`,"sha256":"`+vecHash+`"`)),
		r("a folder with a size", false, part(`,"size":1`)),
	}
	return v
}

// TestStrictVectors checks Go's verdict on testdata/interop/strict.json,
// which go test -update writes.
func TestStrictVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "strict.json")
	if *update {
		b, err := json.MarshalIndent(makeStrictVectors(), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v strictVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Records) == 0 || len(v.Commands) == 0 || len(v.Manifests) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Records {
		_, err := parseRecordBody(c.Body)
		if (err == nil) != c.Valid {
			t.Errorf("record %q: valid %v, got %v", c.Name, c.Valid, err)
		}
	}
	for _, c := range v.Commands {
		_, err := parseCommandBody(c.Body)
		if (err == nil) != c.Valid {
			t.Errorf("command %q: valid %v, got %v", c.Name, c.Valid, err)
		}
	}
	// The manifests are in internal/clip, whose test reads them.
}

// A record whose body breaks the strict form is refused though its
// signature is good: the members that read JSON more loosely would count
// it, the others would not.
func TestRecordsStrictBody(t *testing.T) {
	ca, err := NewGroupCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tag := Tag(ca.Cert)
	sign := func(body string) Record {
		sum := sha256.Sum256([]byte(body))
		sig, err := ca.Key.Sign(rand.Reader, sum[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		return Record{Body: []byte(body), Sig: sig}
	}
	revoke := `"keys":["` + vecHash + `"]`
	for _, body := range []string{
		`{"v":1,"type":"device","group":"` + tag + `","time_ms":1,"type":"revoke",` + revoke + `}`,
		`{"V":1,"TYPE":"revoke","GROUP":"` + tag + `","TIME_MS":1,` + revoke + `}`,
		`{"v":1,"type":"revoke","group":"` + tag + `",` + revoke + `}`,
		`{"v":1,"type":"revoke","group":"` + tag + `","time_ms":1,"by":"\ud800",` + revoke + `}`,
		"{\"v\":1,\"type\":\"revoke\",\"group\":\"" + tag + "\",\"time_ms\":1,\"by\":\"\xff\"," + revoke + "}",
	} {
		s := NewRecords(ca.Cert)
		if ok, err := s.Add(sign(body)); err == nil || ok {
			t.Errorf("%q taken", body)
		}
	}
	s := NewRecords(ca.Cert)
	if ok, err := s.Add(sign(`{"v":1,"type":"revoke","group":"` + tag + `","time_ms":1,` + revoke + `}`)); err != nil || !ok {
		t.Fatalf("a strict record refused: %v", err)
	}
}
