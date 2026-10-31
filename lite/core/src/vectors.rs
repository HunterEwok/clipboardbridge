// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The cross-implementation test vectors in testdata/interop, which the Go
//! tests write and the phone kit reads too: a lite member must decode,
//! encode and decide what they say as the Go member does.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::certs::{self, Cert, KeyHash};
use crate::clip::Event;
use crate::hlc::Timestamp;
use crate::identity::Identity;
use crate::records::{Record, Records};
use crate::wire::{self, Message};

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/interop").join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

fn cert(v: &Value) -> Cert {
    Cert::parse(&bytes(v)).unwrap()
}

fn records(v: &Value) -> Vec<Record> {
    serde_json::from_value(v.clone()).unwrap()
}

/// The member protocol's frames, timestamps, events and their order
/// (member.json).
#[test]
fn member_frames() {
    let v = vectors("member.json");
    for f in v["frames"].as_array().unwrap() {
        let m: Message = serde_json::from_value(f.clone()).unwrap();
        // Encoding again gives the same JSON.
        assert_eq!(serde_json::to_value(&m).unwrap(), *f, "frame {f}");
        match m.kind.as_str() {
            "hello" => {
                assert!(wire::known_role(&m.role));
                let (h, body) = wire::decode_hello(m.hello.as_ref()).unwrap();
                let want = &f["hello"];
                assert_eq!(h.wall, want["wall_ms"].as_i64().unwrap_or(0));
                assert_eq!(body.name, want["name"].as_str().unwrap_or(""));
                let device = wire::DeviceInfo::of(&body);
                assert_eq!(device.is_empty(), want.get("device").is_none());
                if let Some(d) = want.get("device") {
                    assert_eq!(serde_json::to_value(&device).unwrap(), *d);
                }
                if let Some(c) = h.current {
                    assert_eq!(serde_json::to_value(&c).unwrap(), want["current"]);
                }
            }
            "event" => {
                let ev: Event = serde_json::from_value(m.event.clone().unwrap()).unwrap();
                ev.validate().unwrap();
                assert_eq!(serde_json::to_value(&ev).unwrap(), f["event"]);
            }
            "records" => assert!(!m.records.is_empty()),
            _ => {}
        }
    }
    for t in v["timestamps"].as_array().unwrap() {
        let text = t["text"].as_str().unwrap();
        let got = Timestamp::parse(text);
        assert_eq!(got.is_some(), t["ok"].as_bool().unwrap(), "timestamp {text:?}");
        // Leading zeros parse; what is written again parses the same.
        if let Some(ts) = got {
            assert_eq!(Timestamp::parse(&ts.to_string()), Some(ts));
        }
    }
    for e in v["events"].as_array().unwrap() {
        let valid = serde_json::from_value::<Event>(e["json"].clone()).ok().is_some_and(|ev| ev.validate().is_ok());
        assert_eq!(valid, e["valid"].as_bool().unwrap(), "event {}", e["json"]);
    }
    for o in v["order"].as_array().unwrap() {
        let a: Event = serde_json::from_value(o["a"].clone()).unwrap();
        let b: Event = serde_json::from_value(o["b"].clone()).unwrap();
        assert_eq!(a.later(&b), o["later"].as_bool().unwrap(), "order {o}");
    }
}

/// Which member certificates a peer accepts at which time
/// (member-certs.json).
#[test]
fn member_certs() {
    let v = vectors("member-certs.json");
    let ca = cert(&v["group_ca"]);
    for c in v["cases"].as_array().unwrap() {
        let leaf = cert(&c["cert"]);
        let t = (c["now_ms"].as_i64().unwrap() / 1000).max(ca.not_before);
        let got = certs::verify_member(&[leaf], std::slice::from_ref(&ca), t, certs::Usage::Server)
            .map(|d| d.to_string())
            .unwrap_or_default();
        assert_eq!(got, c["device"].as_str().unwrap(), "{}", c["name"]);
    }
}

/// The pairing's channel identifier, the QR fingerprint and the frames
/// (pairing.json).
#[test]
fn pairing() {
    let v = vectors("pairing.json");
    let (member, joiner) = (bytes(&v["member_cert"]), bytes(&v["joiner_cert"]));
    assert_eq!(certs::hex(&crate::pair::channel_id(&member, &joiner)), v["channel_id"].as_str().unwrap());
    assert_eq!(certs::qr_fingerprint(&joiner), v["fingerprint"].as_str().unwrap());
    let frames = v["frames"].as_array().unwrap();
    // The joiner's first frame, as a lite member writes it, differs only in
    // its role; the member's frames decode.
    crate::pair::check_frames_for_tests(frames);
}

/// The devices list, the revocations and the digest of records the phone
/// kit signed (swift-records.json).
#[test]
fn swift_records() {
    let v = vectors("swift-records.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let (fresh, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(fresh.len(), v["records"].as_array().unwrap().len());
    let ids: Vec<String> = s.devices().into_iter().map(|d| d.id).collect();
    let want: Vec<String> = serde_json::from_value(v["devices"].clone()).unwrap();
    assert_eq!(ids, want);
    for k in v["revoked"].as_array().unwrap() {
        assert!(s.revoked(&bytes(k).try_into().unwrap()));
    }
    assert_eq!(s.digest(), v["digest"].as_str().unwrap());
}

/// Records and a member certificate from an admin CA under the phone's
/// root (swift-admin.json).
#[test]
fn swift_admin() {
    let v = vectors("swift-admin.json");
    let ca = cert(&v["group_ca"]);
    let admin = cert(&v["admin_ca"]);
    let mut s = Records::new(&ca);
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let mut ids: Vec<String> = s.devices().into_iter().map(|d| d.id).collect();
    let mut want: Vec<String> = serde_json::from_value(v["devices"].clone()).unwrap();
    ids.sort();
    want.sort();
    assert_eq!(ids, want);
    assert_eq!(s.digest(), v["digest"].as_str().unwrap());

    let leaf = cert(&v["cert"]);
    let chain = [leaf.clone(), admin.clone()];
    let t = leaf.not_before + 48 * 3600;
    assert_eq!(
        certs::verify_member(&chain, std::slice::from_ref(&ca), t, certs::Usage::Client).unwrap().as_str(),
        v["device"].as_str().unwrap()
    );
    assert!(s.refused(&chain).is_none());
    // Without its admin CA the certificate does not verify.
    assert!(certs::verify_member(&chain[..1], std::slice::from_ref(&ca), t, certs::Usage::Server).is_err());
    // The identity of the device it names holds together, with the key.
    if let Ok(key) = STANDARD.decode(v["key"].as_str().unwrap()) {
        if crate::identity::public_key(&key).is_ok() {
            let id = Identity {
                id: certs::DeviceId::parse(v["device"].as_str().unwrap()).unwrap(),
                key,
                cert: leaf,
                issuer: Some(admin),
                group_ca: ca,
                roots: vec![],
            };
            id.check().unwrap();
        }
    }
}

/// A group handed over to a new root (go-root.json): the roots, the
/// devices list, which chains the records refuse, and the digest.
#[test]
fn go_root() {
    check_roots("go-root.json");
}

/// A legacy group that cbb upgrade gave a root (go-upgrade.json), checked
/// as go-root.json.
#[test]
fn go_upgrade() {
    check_roots("go-upgrade.json");
}

fn check_roots(file: &str) {
    let v = vectors(file);
    let mut s = Records::new(&cert(&v["group_ca"]));
    // In reverse order too: the result does not depend on it.
    let mut rs = records(&v["records"]);
    rs.reverse();
    let (_, errs) = s.add_all(&rs);
    assert!(errs.is_empty(), "{errs:?}");
    let roots: Vec<Vec<u8>> = s.roots().into_iter().map(|c| c.der).collect();
    let want: Vec<Vec<u8>> = v["roots"].as_array().unwrap().iter().map(bytes).collect();
    assert_eq!(roots, want);
    for d in v["devices"].as_array().unwrap() {
        let got = s.devices().into_iter().find(|x| x.id == d["id"].as_str().unwrap()).expect("a listed device");
        assert_eq!(got.name, d["name"].as_str().unwrap());
        assert_eq!(got.admin, d["admin"].as_bool().unwrap(), "{}", got.name);
    }
    assert_eq!(s.devices().len(), v["devices"].as_array().unwrap().len());
    for c in v["chains"].as_array().unwrap() {
        let chain: Vec<Cert> = c["chain"].as_array().unwrap().iter().map(cert).collect();
        assert_eq!(s.refused(&chain).is_some(), c["refused"].as_bool().unwrap(), "{}", c["name"]);
    }
    assert_eq!(s.digest(), v["digest"].as_str().unwrap());
}

/// The order of the group's hubs (go-hubs.json, docs/protocol.md section
/// 11, "Several hubs"), as Go's TestGoHubVectors writes it.
#[test]
fn go_hubs() {
    let v = vectors("go-hubs.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let mut rs = records(&v["records"]);
    rs.reverse();
    let (_, errs) = s.add_all(&rs);
    assert!(errs.is_empty(), "{errs:?}");
    let want: Vec<String> =
        v["hub_order"].as_array().unwrap().iter().map(|d| d.as_str().unwrap().to_string()).collect();
    assert_eq!(want.len(), 4);
    assert_eq!(s.hub_order(), want);
}

/// What a computer's admin CA may do in a phone's group (go-admins.json):
/// it removes a device but neither the admin phone nor the root, nor hands
/// the group over, and nothing it signs after the admin phone removed it
/// counts.
#[test]
fn go_admins() {
    let v = vectors("go-admins.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let mut rs = records(&v["records"]);
    rs.reverse();
    // The record signed under the root the computer admin named is dropped:
    // that root is never known.
    let (_, errs) = s.add_all(&rs);
    assert_eq!(v["dropped"].as_u64(), Some(1));
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(s.roots().is_empty());
    assert!(v["roots"].as_array().is_none_or(|r| r.is_empty()));
    let names: Vec<String> = s.devices().into_iter().map(|d| d.name).collect();
    let want: Vec<String> =
        v["devices"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, want);
    for d in v["devices"].as_array().unwrap() {
        let got = s.devices().into_iter().find(|x| x.id == d["id"].as_str().unwrap()).expect("a listed device");
        assert_eq!(got.admin, d["admin"].as_bool().unwrap(), "{}", got.name);
    }
    for k in v["keys"].as_array().unwrap() {
        let key: KeyHash = bytes(&k["key"]).try_into().unwrap();
        assert_eq!(s.revoked(&key), k["revoked"].as_bool().unwrap(), "{}", k["name"]);
    }
    for c in v["chains"].as_array().unwrap() {
        let chain: Vec<Cert> = c["chain"].as_array().unwrap().iter().map(cert).collect();
        assert_eq!(s.refused(&chain).is_some(), c["refused"].as_bool().unwrap(), "{}", c["name"]);
    }
    assert_eq!(s.digest(), v["digest"].as_str().unwrap());
}

/// One body signed by two signers is two records, and the set says the same
/// whichever came first: the root's removal of an admin phone counts though
/// a computer admin's copy of it came first (go-envelopes.json, as Go's
/// TestEnvelopeVectors writes it).
#[test]
fn go_envelopes() {
    let v = vectors("go-envelopes.json");
    let rs = records(&v["records"]);
    let mut reversed = rs.clone();
    reversed.reverse();
    let only_computer = rs[..3].to_vec();
    for (name, recs) in
        [("as written", &rs), ("reversed", &reversed), ("the computer admin's copy only", &only_computer)]
    {
        let mut s = Records::new(&cert(&v["group_ca"]));
        for r in recs {
            s.add(r).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        for r in recs {
            assert!(!s.add(r).unwrap(), "{name}: a record held already was new again");
        }
        let full = recs.len() == rs.len();
        for k in v["keys"].as_array().unwrap() {
            let key: KeyHash = bytes(&k["key"]).try_into().unwrap();
            assert_eq!(s.revoked(&key), k["revoked"].as_bool().unwrap() && full, "{name}: {}", k["name"]);
        }
        if full {
            assert_eq!(s.len() as u64, v["count"].as_u64().unwrap(), "{name}");
            assert_eq!(s.digest(), v["digest"].as_str().unwrap(), "{name}");
        }
    }
}

/// An admin phone that the root removed signs a root record afterwards, for
/// a root of its own that revokes the group's root and admins: that root is
/// not known, so none of it counts, in any order (go-removed-admin.json, as
/// Go's TestRemovedAdminVectors writes it).
#[test]
fn go_removed_admin() {
    let v = vectors("go-removed-admin.json");
    let rs = records(&v["records"]);
    let mut reversed = rs.clone();
    reversed.reverse();
    for (name, recs) in [("as written", &rs), ("reversed", &reversed)] {
        let mut s = Records::new(&cert(&v["group_ca"]));
        for r in recs {
            let _ = s.add(r);
        }
        assert_eq!(s.roots().len() as u64, v["roots"].as_u64().unwrap(), "{name}");
        for k in v["keys"].as_array().unwrap() {
            let key: KeyHash = bytes(&k["key"]).try_into().unwrap();
            assert_eq!(s.revoked(&key), k["revoked"].as_bool().unwrap(), "{name}: {}", k["name"]);
        }
    }
}

/// A device is an admin, with the role and store of that record, only by a
/// record a root's own key signed, and a removed admin's records no longer
/// decide a device's entry (go-authority.json, as Go's
/// TestGoAuthorityVectors writes it).
#[test]
fn go_authority() {
    let v = vectors("go-authority.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let check = |s: &Records, want: &Value| {
        let got = s.devices();
        let want = want.as_array().unwrap();
        assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(want) {
            assert_eq!(g.id, w["id"].as_str().unwrap());
            assert_eq!(g.name, w["name"].as_str().unwrap());
            assert_eq!(g.admin, w["admin"].as_bool().unwrap(), "{}", g.name);
            assert_eq!(g.admin_key.map(|k| k.to_vec()), w.get("admin_key").map(bytes), "{}", g.name);
            assert_eq!(g.role, w["role"].as_str().unwrap(), "{}", g.name);
            assert_eq!(g.store, w["store"].as_str().unwrap(), "{}", g.name);
        }
    };
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    check(&s, &v["devices"]);
    let other: KeyHash = bytes(&v["other"]).try_into().unwrap();
    assert_eq!(s.revoked(&other), v["other_revoked"].as_bool().unwrap());
    let (_, errs) = s.add_all(&records(&v["later"]));
    assert!(errs.is_empty(), "{errs:?}");
    check(&s, &v["devices_later"]);
}

/// An admin computer freezing another (docs/protocol.md, section 10, rule
/// 4), as Go's TestGoFreezeVectors writes it.
#[test]
fn go_freeze() {
    let v = vectors("go-freeze.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let mut rs = records(&v["records"]);
    rs.reverse();
    let (_, errs) = s.add_all(&rs);
    assert!(errs.is_empty(), "{errs:?}");
    let names: Vec<String> = s.devices().into_iter().map(|d| d.name).collect();
    let want: Vec<String> =
        v["devices"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, want);
    for d in v["devices"].as_array().unwrap() {
        let got = s.devices().into_iter().find(|x| x.id == d["id"].as_str().unwrap()).expect("a listed device");
        assert_eq!(got.admin, d["admin"].as_bool().unwrap(), "{}", got.name);
    }
    for k in v["keys"].as_array().unwrap() {
        let key: KeyHash = bytes(&k["key"]).try_into().unwrap();
        assert_eq!(s.frozen(&key), k["frozen"].as_bool().unwrap(), "{}", k["name"]);
        assert!(!s.revoked(&key), "{}", k["name"]);
    }
    for c in v["chains"].as_array().unwrap() {
        let chain: Vec<Cert> = c["chain"].as_array().unwrap().iter().map(cert).collect();
        assert_eq!(s.refused(&chain).is_some(), c["refused"].as_bool().unwrap(), "{}", c["name"]);
    }
    assert_eq!(s.digest(), v["digest"].as_str().unwrap());
}

/// An admin computer taking over a group whose root is a computer
/// (go-takeover.json): it counts there, but not in a phone's group, not
/// while another admin computer has frozen it, and not once the old root
/// removed it.
#[test]
fn go_takeover() {
    let v = vectors("go-takeover.json");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for c in cases {
        let mut s = Records::new(&cert(&c["group_ca"]));
        let mut rs = records(&c["records"]);
        rs.reverse();
        let (_, errs) = s.add_all(&rs);
        let dropped = c["dropped"].as_u64().unwrap_or(0) as usize;
        assert_eq!(dropped, usize::from(c["name"] == "phone root"), "{}", c["name"]);
        assert_eq!(errs.len(), dropped, "{}: {errs:?}", c["name"]);
        let roots: Vec<Vec<u8>> = s.roots().into_iter().map(|c| c.der).collect();
        let want: Vec<Vec<u8>> = c["roots"].as_array().map(|a| a.iter().map(bytes).collect()).unwrap_or_default();
        assert_eq!(roots, want, "{}", c["name"]);
        for k in c["keys"].as_array().unwrap() {
            let key: KeyHash = bytes(&k["key"]).try_into().unwrap();
            assert_eq!(s.revoked(&key), k["revoked"].as_bool().unwrap(), "{}: {}", c["name"], k["name"]);
        }
        assert_eq!(s.digest(), c["digest"].as_str().unwrap());
    }
}

/// A hello's device keeps only its valid fields.
#[test]
fn device_cleaned() {
    let good = wire::DeviceInfo {
        form: "board".into(),
        os_version: "Raspbian 13".into(),
        version: "0.5.0".into(),
        mac: "dc:a6:32:00:00:01".into(),
    };
    assert_eq!(good.cleaned(), good);
    let bad = wire::DeviceInfo {
        form: "toaster".into(),
        os_version: "9".repeat(33),
        version: "1\n2".into(),
        mac: "DC:A6:32:00:00:01".into(),
    };
    assert!(bad.cleaned().is_empty());
}

/// Commands for one member (docs/protocol.md, section 15), as Go's
/// TestGoCommandVectors writes them: who may send one, and when.
#[test]
fn go_commands() {
    let v = vectors("go-commands.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let me = v["self"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let cs = v["commands"].as_array().unwrap();
    assert_eq!(cs.len(), 15);
    for c in cs {
        let r: Record = serde_json::from_value(c["command"].clone()).unwrap();
        let got = s.verify_command(&r, me, now);
        let name = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{name}: {got:?}");
        if let Ok(b) = got {
            assert_eq!(b.mode, c["mode"].as_str().unwrap_or(""), "{name}");
            if b.kind == "paste" {
                assert!(b.enter && b.paste_kind == "text" && b.text.ends_with("\"done\"\n"), "{name}");
            }
        }
    }
}

/// A lite member's hello names the quick actions that are on there, and
/// leaves the field out when none is.
#[test]
fn hello_actions() {
    let h = crate::clip::Hello { wall: 1, current: None };
    let on = ["reboot".to_string(), "restart".to_string()];
    let m = wire::hello(&h, String::new(), "pi", "linux", &wire::DeviceInfo::default(), None, "own", &on, "file");
    let (_, body) = wire::decode_hello(m.hello.as_ref()).unwrap();
    assert_eq!(body.actions, on);
    let m = wire::hello(&h, String::new(), "pi", "linux", &wire::DeviceInfo::default(), None, "own", &[], "file");
    assert!(m.hello.unwrap().get("actions").is_none());
}

/// Quick action commands (docs/protocol.md, section 15), as Go's
/// TestGoActionVectors writes them: which ones a member takes, and the
/// signer each names, whose kind and keys the member's user may require.
#[test]
fn go_actions() {
    let v = vectors("go-actions.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let me = v["self"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let cs = v["commands"].as_array().unwrap();
    assert_eq!(cs.len(), 6);
    for c in cs {
        let r: Record = serde_json::from_value(c["command"].clone()).unwrap();
        let got = s.verify_command(&r, me, now);
        let name = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{name}: {got:?}");
        let Ok(b) = got else { continue };
        assert_eq!(b.action, c["action"].as_str().unwrap_or(""), "{name}");
        let (d, root) = s.command_signer(&r);
        let want = &c["signer"];
        assert_eq!(root, want["root"].as_bool().unwrap_or(false), "{name}");
        assert_eq!(d.is_some(), want["found"].as_bool().unwrap_or(false), "{name}");
        if let Some(d) = d {
            assert_eq!(d.role, want["role"].as_str().unwrap(), "{name}");
            assert_eq!(d.store, want["store"].as_str().unwrap(), "{name}");
        }
    }
    for (n, ok) in [("lock", true), ("a1-b", true), ("1a", false), ("Lock", false), ("", false), ("a_b", false)] {
        assert_eq!(crate::records::valid_action_name(n), ok, "{n:?}");
    }
    assert!(crate::records::valid_action_name(&"a".repeat(32)) && !crate::records::valid_action_name(&"a".repeat(33)));
}

/// The signed files of a release (docs/protocol.md, section 16), as Go's
/// TestReleaseVectors writes them: which combinations a device takes.
#[test]
fn go_release() {
    use crate::release::{self, File, Seen};
    let v = vectors("go-release.json");
    let roots: Vec<Vec<u8>> = v["roots"].as_array().unwrap().iter().map(bytes).collect();
    let roots: Vec<&[u8]> = roots.iter().map(|r| r.as_slice()).collect();
    let name = v["channel"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 33);
    for c in cases {
        let file = |k: &str| -> File { serde_json::from_value(c[k].clone()).unwrap() };
        let seen: Seen = serde_json::from_value(c["seen"].clone()).unwrap();
        let got = release::check(&file("keys"), &file("channel"), &file("release"), &roots, name, now, &seen);
        let label = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{label}: {:?}", got.as_ref().err().map(|e| e.message()));
        if let Ok((r, next)) = got {
            assert_eq!(r.version, c["version"].as_str().unwrap(), "{label}");
            assert_eq!(next.version, r.version, "{label}");
            assert!(r.direct("0.5.3") && !r.direct("0.3.9"), "{label}");
        }
    }
    use core::cmp::Ordering::*;
    for (a, b, want) in [
        ("0.10.0", "0.9.0", Greater),
        ("0.6.0", "0.6.0", Equal),
        ("0.6.0-rc.1", "0.6.0", Less),
        ("0.6.0-rc.2", "0.6.0-rc.10", Less),
        ("0.6.0-rc.1", "0.5.9", Greater),
        ("v0.6.0", "0.0.0", Less),
        ("0.06.0", "0.0.0", Less),
    ] {
        assert_eq!(release::compare(a, b), want, "{a} {b}");
    }
    for bad in ["0.6", "0.6.0-rc.0", "0.6.0-rc.01", "0.6.0-beta.1", "0.6.0.1", "1234567.0.0"] {
        assert!(release::parse_version(bad).is_none(), "{bad}");
    }
}

/// The server credentials (docs/protocol.md, section 18), as Go's
/// TestGoCredentialVectors writes them: what the records say the
/// credentials list, the signatures and types, and which sets a server
/// takes.
#[test]
fn go_credentials() {
    use crate::credential::{self, Credential, HUBS, MEMBERS, PERIOD, SERVER};
    let v = vectors("go-credentials.json");
    let ca = cert(&v["group_ca"]);
    let mut s = Records::new(&ca);
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let hashes = |k: &str| -> Vec<KeyHash> {
        v["lists"][k].as_array().unwrap().iter().map(|h| bytes(h).try_into().unwrap()).collect()
    };
    let l = credential::lists(&s);
    assert_eq!(l.hubs, hashes("Hubs"));
    assert_eq!(l.admins, hashes("Admins"));
    assert_eq!(l.members, hashes("Members"));

    let cred = |v: &Value| -> Credential { serde_json::from_value(v.clone()).unwrap() };
    let tag = certs::tag(&ca);
    let period = cred(&v["period"]);
    let p = period.open().unwrap();
    assert_eq!((p.kind.as_str(), p.group.as_str()), (PERIOD, tag.as_str()));
    // The group's root signed the period.
    assert_eq!(period.key, ca.spki);
    for c in v["servers"].as_array().unwrap() {
        let c = cred(c);
        let b = c.open().unwrap();
        assert_eq!((b.kind.as_str(), b.group.as_str(), b.tag.as_str()), (SERVER, tag.as_str(), p.tag.as_str()));
        assert!(s.devices().iter().any(|d| d.keys.contains(&c.signer())), "a server key that no member signed");
    }
    let (hubs, members) = (cred(&v["hubs"]), cred(&v["members"]));
    let hb = hubs.open().unwrap();
    assert_eq!((hb.kind.as_str(), hb.group.as_str()), (HUBS, p.tag.as_str()));
    assert_eq!(hubs.key, p.key);
    assert_eq!(credential::pseudonym(&hb.hubs[0]), v["pseudonym"].as_str().unwrap());
    // Padded to 4, 8, 16 or more.
    assert!(hb.hubs.len() >= l.hubs.len() && hb.hubs.len().is_power_of_two() && hb.hubs.len() >= 4);
    assert_eq!(members.open().unwrap().kind, MEMBERS);

    let now = v["now_ms"].as_i64().unwrap();
    let got = credential::check_presented(&[hubs.clone(), members.clone(), period.clone()], now).unwrap();
    assert_eq!(got.tag, p.tag);
    assert!(got.members.is_some() && got.period.is_some());
    assert!(credential::check_presented(std::slice::from_ref(&hubs), p.expires_ms).is_err(), "expired");
    for b in v["bad"].as_array().unwrap() {
        let set: Vec<Credential> = b["set"].as_array().unwrap().iter().map(cred).collect();
        assert!(credential::check_presented(&set, now).is_err(), "{}: taken", b["name"]);
    }
    // A body changed after signing does not verify.
    let mut forged = hubs.clone();
    forged.body[10] ^= 1;
    assert!(forged.open().is_err());
    // Encoding again gives the same JSON as Go's.
    assert_eq!(serde_json::to_value(&hubs).unwrap(), v["hubs"]);
}

/// What a watch's admin key may do (docs/protocol.md, section 10, rule 8),
/// as Go's TestGoWatchVectors writes it: in a phone's group it freezes an
/// admin computer and removes an ordinary device, and nothing more; an
/// admin computer freezes it; in a group whose root is a computer it does
/// not take the group over.
#[test]
fn go_watch() {
    let v = vectors("go-watch.json");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let mut s = Records::new(&cert(&c["group_ca"]));
        let mut rs = records(&c["records"]);
        rs.reverse();
        let (_, errs) = s.add_all(&rs);
        assert_eq!(errs.len(), c["dropped"].as_u64().unwrap_or(0) as usize, "{name}: {errs:?}");
        let got: Vec<(String, String, String, bool)> =
            s.devices().into_iter().map(|d| (d.id, d.name, d.role, d.admin)).collect();
        let want: Vec<(String, String, String, bool)> = c["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["id"].as_str().unwrap().to_string(),
                    d["name"].as_str().unwrap().to_string(),
                    d["role"].as_str().unwrap().to_string(),
                    d["admin"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}");
        for k in c["keys"].as_array().unwrap() {
            let key: KeyHash = bytes(&k["key"]).try_into().unwrap();
            let what = k["name"].as_str().unwrap();
            assert_eq!(s.revoked(&key), k["revoked"].as_bool().unwrap(), "{name}: {what} revoked");
            assert_eq!(s.frozen(&key), k["frozen"].as_bool().unwrap(), "{name}: {what} frozen");
            assert_eq!(s.watch(&key), k["watch"].as_bool().unwrap(), "{name}: {what} watch");
        }
        for ch in c["chains"].as_array().into_iter().flatten() {
            let chain: Vec<Cert> = ch["chain"].as_array().unwrap().iter().map(cert).collect();
            assert_eq!(s.refused(&chain).is_some(), ch["refused"].as_bool().unwrap(), "{name}: {}", ch["name"]);
        }
        assert!(s.roots().is_empty(), "{name}");
        let hubs: Vec<String> = c["hubs"].as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect();
        assert_eq!(s.hub_order(), hubs, "{name}");
        for d in s.devices() {
            if d.role == "watch" {
                assert!(!s.may_host(&d.id), "{name}");
            }
        }
        let me = c["self"].as_str().unwrap_or("");
        let now = c["now_ms"].as_i64().unwrap_or(0);
        for cmd in c["commands"].as_array().into_iter().flatten() {
            let r: Record = serde_json::from_value(cmd["command"].clone()).unwrap();
            let got = s.verify_command(&r, me, now);
            assert_eq!(got.is_ok(), cmd["ok"].as_bool().unwrap(), "{name}: {}: {got:?}", cmd["name"]);
        }
        assert_eq!(s.digest(), c["digest"].as_str().unwrap(), "{name}");
    }
}

/// The strict form of signed bodies (strict.json): the lite member takes
/// exactly the record bodies, commands and manifests the Go member does.
#[test]
fn strict() {
    let v = vectors("strict.json");
    let cases = |kind: &str| {
        v[kind]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["name"].as_str().unwrap().to_string(), bytes(&c["body"]), c["valid"].as_bool().unwrap()))
            .collect::<Vec<_>>()
    };
    for (name, body, valid) in cases("records") {
        let got = crate::records::Body::parse(&body);
        assert_eq!(got.is_ok(), valid, "record {name:?}: {:?}", got.err());
    }
    for (name, body, valid) in cases("commands") {
        let got = crate::records::Command::parse(&body);
        assert_eq!(got.is_ok(), valid, "command {name:?}: {:?}", got.err());
    }
    for (name, body, valid) in cases("manifests") {
        let got = serde_json::from_slice::<crate::media::Manifest>(&body)
            .map_err(|e| e.to_string())
            .and_then(|m| m.validate().map_err(|e| e.to_string()));
        assert_eq!(got.is_ok(), valid, "manifest {name:?}: {:?}", got.err());
    }
}

/// The vectors the tables of docs/protocol.md give (strict-generated.json,
/// as Go's TestStrictGenerated writes it): the lite member takes exactly
/// the bodies the tables take, and says which row it reads otherwise.
#[test]
fn strict_generated() {
    let v = vectors("strict-generated.json");
    let mut wrong = Vec::new();
    for kind in ["records", "commands", "manifests"] {
        let cases = v[kind].as_array().unwrap();
        assert!(!cases.is_empty(), "no {kind}");
        for c in cases {
            let mut body = bytes(&c["body"]);
            if let Some(pad) = c["pad"].as_u64() {
                let at = c["pad_at"].as_u64().unwrap() as usize;
                body.splice(at..at, std::iter::repeat_n(b'a', pad as usize));
            }
            let got = match kind {
                "records" => crate::records::Body::parse(&body).map(|_| ()).map_err(|e| e.to_string()),
                "commands" => crate::records::Command::parse(&body).map(|_| ()).map_err(|e| e.to_string()),
                _ => serde_json::from_slice::<crate::media::Manifest>(&body)
                    .map_err(|e| e.to_string())
                    .and_then(|m| m.validate().map_err(|e| e.to_string())),
            };
            if got.is_ok() != c["valid"].as_bool().unwrap() {
                wrong.push(format!(
                    "{kind} {:?} ({}): valid {}, got {got:?}",
                    c["name"].as_str().unwrap(),
                    c["rule"].as_str().unwrap(),
                    c["valid"]
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{} vectors read otherwise:\n{}", wrong.len(), wrong.join("\n"));
}

/// The timestamps a clock took do not move how far ahead it takes the next
/// one (hlc-ahead.json, as Go's TestAheadVectors writes it).
#[test]
fn hlc_ahead() {
    let v = vectors("hlc-ahead.json");
    assert_eq!(v["max_ahead"].as_i64(), Some(crate::hlc::MAX_AHEAD));
    let now = v["now"].as_i64().unwrap();
    let c = crate::hlc::Clock::new(Box::new(move || now), Timestamp::default(), None);
    for w in v["accepted"].as_array().unwrap() {
        let ts = Timestamp { wall: w.as_i64().unwrap(), logical: 0 };
        assert!(!c.ahead(ts), "{w} refused");
        c.observe(ts);
    }
    let refused = Timestamp { wall: v["refused"].as_i64().unwrap(), logical: 0 };
    assert!(c.ahead(refused), "taken after a chain of timestamps ahead");
}
