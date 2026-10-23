// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The cross-implementation test vectors in testdata/interop, which the Go
//! tests write and the phone kit reads too: a lite member must decode,
//! encode and decide what they say as the Go member does.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::certs::{self, Cert};
use crate::clip::Event;
use crate::hlc::Timestamp;
use crate::identity::Identity;
use crate::records::{Record, Records};
use crate::wire::{self, Message};

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop").join(name);
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
        let got =
            certs::verify_member(&[leaf], std::slice::from_ref(&ca), t).map(|d| d.to_string()).unwrap_or_default();
        assert_eq!(got, c["device"].as_str().unwrap(), "{}", c["name"]);
    }
}

/// The pairing's channel identifier, the QR fingerprint and the frames
/// (pairing.json).
#[test]
fn pairing() {
    let v = vectors("pairing.json");
    let (member, joiner) = (bytes(&v["member_cert"]), bytes(&v["joiner_cert"]));
    assert_eq!(certs::hex(&crate::pair::channel_id_for_tests(&member, &joiner)), v["channel_id"].as_str().unwrap());
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
        certs::verify_member(&chain, std::slice::from_ref(&ca), t).unwrap().as_str(),
        v["device"].as_str().unwrap()
    );
    assert!(s.refused(&chain).is_none());
    // Without its admin CA the certificate does not verify.
    assert!(certs::verify_member(&chain[..1], std::slice::from_ref(&ca), t).is_err());
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
    let v = vectors("go-root.json");
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
