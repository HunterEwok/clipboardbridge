// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type rootMemberCase struct {
	Name       string   `json:"name"`
	Records    []Record `json:"records"`
	RootDevice DeviceID `json:"root_device"`
	RootRole   string   `json:"root_role"`
}

type rootMemberVectors struct {
	GroupCA []byte           `json:"group_ca"`
	Cases   []rootMemberCase `json:"cases"`
}

// rootOf returns the root's own device and the role the devices list
// gives it, as a member that asks whether the root is a computer reads it.
func rootOf(s *Records) (DeviceID, string) {
	root := s.RootDevice()
	for _, d := range s.Devices() {
		if d.ID == root {
			return root, d.Role
		}
	}
	return root, ""
}

// TestGoRootMemberVectors writes (with -update) and checks
// testdata/interop/go-root-member.json: the root's own device when the
// root signed two own device records at the same time, the one with the
// greater record ID, and whether it is a phone or a computer, the same in
// every order of the records, for the phone kits and the lite member to
// agree with.
func TestGoRootMemberVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-root-member.json")
	var v rootMemberVectors
	if *update {
		// New keys until the computer wins both ties, so the file holds a
		// computer root of each role's spelling.
		for try := 0; ; try++ {
			if try == 64 {
				t.Fatal("the computer never won the ties")
			}
			if v = makeRootMemberVectors(t); v.Cases[1].RootRole == RoleFull && v.Cases[3].RootRole == RoleFull {
				break
			}
		}
		data, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v = rootMemberVectors{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) < 4 {
		t.Fatalf("%d cases", len(v.Cases))
	}
	roles := map[string]bool{}
	for _, c := range v.Cases {
		if c.RootDevice == "" || c.RootRole == "" {
			t.Errorf("%s: no root in the file", c.Name)
		}
		roles[c.RootRole] = true
		permute(len(c.Records), func(order []int) {
			s := NewRecords(ca)
			recs := make([]Record, len(order))
			for i, k := range order {
				recs[i] = c.Records[k]
			}
			if _, errs := s.AddAll(recs); len(errs) != 0 {
				t.Fatal(errs)
			}
			if dev, role := rootOf(s); dev != c.RootDevice || role != c.RootRole {
				t.Errorf("%s, order %v: the root is %s, %s; the file has %s, %s", c.Name, order, dev, role, c.RootDevice, c.RootRole)
			}
		})
	}
	if !roles[RoleFull] || !roles[RolePhone] {
		t.Errorf("the cases' roots are %v, want a phone and a computer among them", roles)
	}
}

// makeRootMemberVectors makes the cases of go-root-member.json with new
// keys: two own device records of the root at the same time, and a plain
// computer.
func makeRootMemberVectors(t *testing.T) rootMemberVectors {
	root := newRoot(t)
	g := root.Cert
	own := func(name, role string, dev DeviceID, cert *x509.Certificate) Record {
		key := KeyHashOf(cert)
		r, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 5, By: dev,
			Device: dev, Name: name, Role: role, Key: &key}, root.Key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	a, b := member(t, root), member(t, root)
	devA, devB := DeviceID(a.Subject.CommonName), DeviceID(b.Subject.CommonName)
	plain := deviceRecord(t, g, root, nil, member(t, root), "plain pc", 1)
	v := rootMemberVectors{GroupCA: g.Raw}
	for _, c := range []struct {
		name string
		recs []Record
	}{
		{"two phones at the same time", []Record{own("phone a", RolePhone, devA, a), own("phone b", RolePhone, devB, b), plain}},
		{"a phone and a computer at the same time", []Record{own("phone a", RolePhone, devA, a), own("pc b", RoleFull, devB, b), plain}},
		{"one device as a phone and as a computer at the same time", []Record{own("as a phone", RolePhone, devA, a), own("as a pc", RoleFull, devA, a), plain}},
		{"a computer of an earlier role and a phone at the same time", []Record{own("pc a", roleLinux, devA, a), own("phone b", RolePhone, devB, b), plain}},
	} {
		s := NewRecords(g)
		if _, errs := s.AddAll(c.recs); len(errs) != 0 {
			t.Fatal(errs)
		}
		dev, role := rootOf(s)
		v.Cases = append(v.Cases, rootMemberCase{Name: c.name, Records: c.recs, RootDevice: dev, RootRole: role})
	}
	return v
}
