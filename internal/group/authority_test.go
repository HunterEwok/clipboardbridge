// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type authorityVectors struct {
	GroupCA []byte            `json:"group_ca"`
	Records []Record          `json:"records"`
	Devices []authorityDevice `json:"devices"`
	// Other is the admin CA the computer admin named for the laptop, and
	// OtherRevoked whether the computer admin's revocation of it counts:
	// it does, since only a root's own record makes it an admin key.
	Other        KeyHash `json:"other"`
	OtherRevoked bool    `json:"other_revoked"`
	// Later are the records the root adds after: it removes the computer
	// admin and renames the laptop.
	Later        []Record          `json:"later"`
	DevicesLater []authorityDevice `json:"devices_later"`
}

type authorityDevice struct {
	ID       DeviceID `json:"id"`
	Name     string   `json:"name"`
	Admin    bool     `json:"admin"`
	AdminKey *KeyHash `json:"admin_key,omitempty"`
	Role     string   `json:"role"`
	Store    string   `json:"store"`
}

func authorityDevices(s *Records) []authorityDevice {
	var out []authorityDevice
	for _, d := range s.Devices() {
		out = append(out, authorityDevice{ID: d.ID, Name: d.Name, Admin: d.Admin, AdminKey: d.AdminKey, Role: d.Role, Store: d.Store})
	}
	return out
}

// TestGoAuthorityVectors writes (with -update) and checks
// testdata/interop/go-authority.json: a device is an admin, and an admin
// has its role and store, only by a record a root's own key signed; and a
// removed admin's records no longer decide a device's entry
// (docs/protocol.md, section 10), for the phone kits and the lite member to
// agree with.
func TestGoAuthorityVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-authority.json")
	if *update {
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		pc, phone := pg.a, pg.b
		pcChain := []*x509.Certificate{pc.Cert}
		pcKey, phoneKey := KeyHashOf(pc.Cert), KeyHashOf(phone.Cert)
		pcMember, phoneMember, laptop, ghost := member(t, pc), member(t, phone), member(t, pc), member(t, pc)
		tag := Tag(g)
		bySigner := func(body RecordBody) Record {
			t.Helper()
			r, err := SignRecord(body, pc.Key, pcChain...)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		key := func(c *x509.Certificate) *KeyHash { k := KeyHashOf(c); return &k }
		var other KeyHash
		other[0], other[31] = 0xaa, 0x55
		v := authorityVectors{GroupCA: g.Raw, Records: []Record{
			computerAdminRecord(t, pg, pcMember, "pc", pcKey),
			adminRecord(t, g, pg.root, nil, phoneMember, "phone", phoneKey),
			deviceRecord(t, g, pc, pcChain, laptop, "laptop", 2),
			// The computer admin names its own admin CA for a device of its
			// own, as a phone with its keys in hardware.
			bySigner(RecordBody{Type: RecordDevice, Group: tag, TimeMS: 3, Device: DeviceID(ghost.Subject.CommonName), Name: "ghost",
				Role: RolePhone, OS: OSiOS, Key: key(ghost), Admin: &pcKey, Store: StoreHardware}),
			bySigner(RecordBody{Type: RecordDevice, Group: tag, TimeMS: 4, Device: DeviceID(pcMember.Subject.CommonName), Name: "pc",
				Role: RolePhone, OS: OSiOS, Key: key(pcMember), Admin: &pcKey, Store: StoreHardware}),
			// It names an admin CA for the laptop, then gives the laptop a
			// time no later record passes.
			bySigner(RecordBody{Type: RecordDevice, Group: tag, TimeMS: 5, Device: DeviceID(laptop.Subject.CommonName), Name: "laptop",
				Role: RoleFull, Key: key(laptop), Admin: &other}),
			bySigner(RecordBody{Type: RecordDevice, Group: tag, TimeMS: math.MaxInt64, Device: DeviceID(laptop.Subject.CommonName), Name: "pinned",
				Role: RoleFull, Key: key(laptop)}),
			revokeRecord(t, g, pc, pcChain, []KeyHash{other}, nil),
		}, Other: other}
		s := NewRecords(g)
		if _, errs := s.AddAll(v.Records); len(errs) != 0 {
			t.Fatal(errs)
		}
		v.Devices, v.OtherRevoked = authorityDevices(s), s.Revoked(other)
		removed := []KeyHash{pcKey, KeyHashOf(pcMember)}
		keep := slices.DeleteFunc(s.Staying(pcKey), func(k KeyHash) bool { return slices.Contains(removed, k) })
		v.Later = []Record{
			revokeRecord(t, g, pg.root, nil, removed, keep),
			deviceRecord(t, g, pg.root, nil, laptop, "laptop", t0.UnixMilli()),
		}
		if _, errs := s.AddAll(v.Later); len(errs) != 0 {
			t.Fatal(errs)
		}
		v.DevicesLater = authorityDevices(s)
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
	var v authorityVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) != 0 {
		t.Fatal(errs)
	}
	byName := map[string]authorityDevice{}
	for _, d := range v.Devices {
		byName[d.Name] = d
	}
	// What the file says is what the rules say.
	if d := byName["pc"]; !d.Admin || d.Role != RoleFull || d.Store != StoreFile || d.AdminKey == nil {
		t.Errorf("the computer admin in the file: %+v", d)
	}
	if d := byName["ghost"]; d.Admin || d.AdminKey != nil {
		t.Errorf("a device the computer admin named as an admin in the file: %+v", d)
	}
	if d := byName["pinned"]; d.Admin || d.AdminKey != nil {
		t.Errorf("the laptop in the file: %+v", d)
	}
	if a, b := mustJSON(t, authorityDevices(s)), mustJSON(t, v.Devices); a != b {
		t.Errorf("devices %s, the file has %s", a, b)
	}
	ghost, laptop := byName["ghost"].ID, byName["pinned"].ID
	if s.MayHost(ghost) || s.MayHost(laptop) || slices.Contains(s.HubOrder(), ghost) || slices.Contains(s.HubOrder(), laptop) {
		t.Error("a device a computer admin named as an admin may host")
	}
	if !s.Revoked(v.Other) || !v.OtherRevoked {
		t.Errorf("an admin CA that only a computer admin named is an admin key: revoked %v, the file says %v", s.Revoked(v.Other), v.OtherRevoked)
	}
	if _, errs := s.AddAll(v.Later); len(errs) != 0 {
		t.Fatal(errs)
	}
	if a, b := mustJSON(t, authorityDevices(s)), mustJSON(t, v.DevicesLater); a != b {
		t.Errorf("devices after %s, the file has %s", a, b)
	}
	for _, d := range v.DevicesLater {
		if d.ID == laptop && d.Name != "laptop" {
			t.Errorf("the laptop is %q after the root renamed it", d.Name)
		}
	}
}

// A command signed by a computer's admin CA has the role and store the
// root's record gives that computer, whatever record the admin signed for
// itself.
func TestCommandSignerByRoot(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	pc := pg.a
	pcKey := KeyHashOf(pc.Cert)
	pcMember := member(t, pc)
	s := NewRecords(g)
	mustAdd(t, s, computerAdminRecord(t, pg, pcMember, "pc", pcKey))
	fake := KeyHash{1, 2, 3}
	self, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 2, Device: NewDeviceID(), Name: "0",
		Role: RolePhone, OS: OSiOS, Key: &fake, Admin: &pcKey, Store: StoreHardware}, pc.Key, pc.Cert)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, s, self)
	now := time.Now()
	cmd, err := SignCommand(CommandBody{Type: CommandAction, Group: Tag(g), By: DeviceID(pcMember.Subject.CommonName), To: NewDeviceID(),
		ID: NewCommandID(), TimeMS: now.UnixMilli(), ExpiresMS: now.Add(20 * time.Second).UnixMilli(), Action: "reboot"}, pc.Key, pc.Cert)
	if err != nil {
		t.Fatal(err)
	}
	dev, root, ok := s.CommandSigner(cmd)
	if !ok || root || dev.ID != DeviceID(pcMember.Subject.CommonName) || dev.Role != RoleFull || dev.Store != StoreFile {
		t.Fatalf("the signer: ok %v, root %v, %+v", ok, root, dev)
	}
}
