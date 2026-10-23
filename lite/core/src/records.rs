// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's signed records: devices, revocations and root handovers
//! (docs/protocol.md, section 10), as Go's group.Records evaluates them.
//! What the set says depends on the records alone, never on the order in
//! which they arrived.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::certs::{self, Cert, KeyHash, b64, sha256};
use crate::error::{Context, Error, Result};

pub const MAX_RECORDS: usize = 4096;
const MAX_BODY: usize = 8 << 10;
const VERSION: i64 = 1;

/// A signed record: the body's exact bytes, an ECDSA signature over them,
/// and the signer's certificates below the group CA.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Record {
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    #[serde(with = "b64")]
    pub sig: Vec<u8>,
    #[serde(with = "b64::list", default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<Vec<u8>>,
}

impl Record {
    /// The record's ID: SHA-256 over its body.
    pub fn id(&self) -> [u8; 32] {
        sha256(&self.body)
    }

    fn is_root(&self) -> bool {
        serde_json::from_slice::<Body>(&self.body).is_ok_and(|b| b.kind == "root")
    }
}

/// What a record says; the fields depend on its type.
#[derive(Deserialize, Default, Clone)]
struct Body {
    #[serde(default)]
    v: i64,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    time_ms: i64,
    #[serde(default)]
    device: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    role: String,
    #[serde(with = "b64::opt_hash", default)]
    key: Option<KeyHash>,
    #[serde(with = "b64::opt_hash", default)]
    admin: Option<KeyHash>,
    #[serde(with = "b64::hashes", default)]
    keys: Vec<KeyHash>,
    #[serde(with = "b64::hashes", default)]
    keep: Vec<KeyHash>,
    #[serde(with = "b64", default)]
    root: Vec<u8>,
}

impl Body {
    fn check(&self) -> Result<()> {
        if self.v != VERSION {
            return Err(Error::msg(format!("unknown record version {}", self.v)));
        }
        match self.kind.as_str() {
            "device" => {
                certs::DeviceId::parse(&self.device)?;
                if !valid_name(&self.name) {
                    return Err(Error::msg("a device record has no valid name"));
                }
                if !matches!(self.role.as_str(), "linux" | "mac" | "phone" | "lite" | "iphone") {
                    return Err(Error::msg(format!("unknown role {:?} in a device record", self.role)));
                }
                if self.key.is_none() {
                    return Err(Error::msg("a device record names no key"));
                }
            }
            "revoke" => {
                if self.keys.is_empty() {
                    return Err(Error::msg("a revocation record names no key"));
                }
            }
            "root" => {
                if self.root.is_empty() {
                    return Err(Error::msg("a root record has no certificate"));
                }
            }
            t => return Err(Error::msg(format!("unknown record type {t:?}"))),
        }
        Ok(())
    }
}

/// Reports whether s is a device name: 1 to 64 bytes of UTF-8 without
/// control characters.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control)
}

/// A record whose signature was checked.
#[derive(Clone)]
struct Signed {
    record: Record,
    body: Body,
    signer: KeyHash,
    anchor: KeyHash,    // the root it was signed under
    root: Option<Cert>, // the new root of a root record
}

/// An entry of the devices list.
#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub role: String,
    pub key: KeyHash,
    pub admin: bool,
}

/// The set of a group's records. It only grows.
pub struct Records {
    group_ca: Cert,
    tag: String,
    ca_key: KeyHash,
    by_id: BTreeMap<[u8; 32], Signed>,
    roots: BTreeMap<KeyHash, Cert>,
}

impl core::fmt::Debug for Records {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Records({})", self.len())
    }
}

impl Records {
    /// An empty set for the group of group_ca.
    pub fn new(group_ca: &Cert) -> Records {
        let ca_key = group_ca.key_hash();
        Records {
            group_ca: group_ca.clone(),
            tag: certs::tag(group_ca),
            ca_key,
            by_id: BTreeMap::new(),
            roots: BTreeMap::from([(ca_key, group_ca.clone())]),
        }
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Checks a record and adds it; reports whether it was new.
    pub fn add(&mut self, r: &Record) -> Result<bool> {
        let id = r.id();
        if self.by_id.contains_key(&id) {
            return Ok(false);
        }
        if self.by_id.len() >= MAX_RECORDS {
            return Err(Error::msg("too many records"));
        }
        let s = self.verify(r)?;
        if let Some(root) = &s.root {
            self.roots.entry(root.key_hash()).or_insert_with(|| root.clone());
        }
        self.by_id.insert(id, s);
        Ok(true)
    }

    /// Adds the valid records among rs and returns those that were new, and
    /// an error for each one that is not valid. A record signed under a new
    /// root is taken once the record that names that root is in.
    pub fn add_all(&mut self, rs: &[Record]) -> (Vec<Record>, Vec<Error>) {
        let mut fresh = Vec::new();
        let mut pending: Vec<Record> = rs.to_vec();
        loop {
            let mut rest = Vec::new();
            let mut errs = Vec::new();
            let mut rooted = false;
            for r in pending {
                match self.add(&r) {
                    Err(e) => {
                        rest.push(r);
                        errs.push(e);
                    }
                    Ok(true) => {
                        rooted |= r.is_root();
                        fresh.push(r);
                    }
                    Ok(false) => {}
                }
            }
            if !rooted || rest.is_empty() {
                return (fresh, errs);
            }
            pending = rest;
        }
    }

    fn verify(&self, r: &Record) -> Result<Signed> {
        if r.body.len() > MAX_BODY {
            return Err(Error::msg("the record is too large"));
        }
        let body: Body = serde_json::from_slice(&r.body).context("a record does not decode")?;
        body.check()?;
        if body.group != self.tag {
            return Err(Error::msg("the record is for another group"));
        }
        let (signer, anchor) = match r.chain.len() {
            0 => {
                // Signed by a root's own key.
                let k = self
                    .roots
                    .iter()
                    .find(|(_, root)| root.verifies(&r.body, &r.sig))
                    .map(|(k, _)| *k)
                    .ok_or_else(|| Error::msg("the record's signature is not valid"))?;
                (k, k)
            }
            1 => {
                let admin = Cert::parse(&r.chain[0])?;
                let anchor = self
                    .roots
                    .iter()
                    .find(|(_, root)| certs::check_admin_ca(&admin, root).is_ok())
                    .map(|(k, _)| *k)
                    .ok_or_else(|| Error::msg("the signer is not an admin CA of the group"))?;
                if !admin.verifies(&r.body, &r.sig) {
                    return Err(Error::msg("the record's signature is not valid"));
                }
                (admin.key_hash(), anchor)
            }
            _ => return Err(Error::msg("a record's chain is too long")),
        };
        let mut root = None;
        if body.kind == "root" {
            if self.roots[&anchor].path_len != Some(1) {
                return Err(Error::msg("only a group whose root is a phone is handed to a new root"));
            }
            let c = Cert::parse(&body.root)?;
            certs::check_root(&c)?;
            root = Some(c);
        }
        Ok(Signed { record: r.clone(), body, signer, anchor, root })
    }

    /// The roots from the group CA to the current root: from each root, the
    /// root record signed under it that counts and whose new root has the
    /// smallest SHA-256 leads to the next.
    fn path(&self) -> Vec<Cert> {
        let mut path = vec![self.group_ca.clone()];
        let mut on = vec![self.ca_key];
        loop {
            let cur = path.last().unwrap().key_hash();
            let mut next: Option<(&Cert, [u8; 32])> = None;
            for r in self.by_id.values() {
                let Some(root) = &r.root else { continue };
                if r.anchor != cur
                    || on.contains(&root.key_hash())
                    || self.revoked(&r.signer)
                    || !self.signed_by_root(r)
                {
                    continue;
                }
                let sum = sha256(&root.der);
                if next.is_none_or(|(_, best)| sum < best) {
                    next = Some((root, sum));
                }
            }
            match next {
                None => return path,
                Some((root, _)) => {
                    on.push(root.key_hash());
                    path.push(root.clone());
                }
            }
        }
    }

    /// The roots that took the group over from the group CA, in order.
    pub fn roots(&self) -> Vec<Cert> {
        self.path().split_off(1)
    }

    fn signed_by_root(&self, r: &Signed) -> bool {
        r.signer == r.anchor || self.issued(&r.anchor, &r.signer)
    }

    /// Reports whether what issuer certified, the key k, still stands.
    fn issued(&self, issuer: &KeyHash, k: &KeyHash) -> bool {
        !self.revoked(issuer) || self.kept(issuer, k)
    }

    /// Reports whether a key is revoked by any revocation record.
    pub fn revoked(&self, k: &KeyHash) -> bool {
        self.by_id.values().any(|r| r.body.kind == "revoke" && r.body.keys.contains(k))
    }

    /// Reports whether admin is revoked only by records that keep leaf.
    fn kept(&self, admin: &KeyHash, leaf: &KeyHash) -> bool {
        let mut revoked = false;
        for r in self.by_id.values() {
            if r.body.kind != "revoke" || !r.body.keys.contains(admin) {
                continue;
            }
            if !r.body.keep.contains(leaf) {
                return false;
            }
            revoked = true;
        }
        revoked
    }

    fn counts(&self, r: &Signed, on: &[KeyHash]) -> bool {
        on.contains(&r.anchor) && self.signed_by_root(r) && r.body.key.is_some_and(|k| self.issued(&r.signer, &k))
    }

    /// Reports why a member certificate chain (leaf first, then its admin
    /// CA when one issued it), already verified to a root, is refused, or
    /// None.
    pub fn refused(&self, chain: &[Cert]) -> Option<&'static str> {
        let first = chain.first()?;
        let mut leaf = first.key_hash();
        if self.revoked(&leaf) {
            return Some("the device was removed from the group");
        }
        let mut top = first;
        if chain.len() >= 2 {
            let admin = chain[1].key_hash();
            if !self.issued(&admin, &leaf) {
                return Some("the admin that admitted the device was removed");
            }
            top = &chain[1];
            leaf = admin;
        }
        for root in self.path() {
            if top.signed_by(&root) {
                if !self.issued(&root.key_hash(), &leaf) {
                    return Some("the certificate is from a root that handed the group over");
                }
                break;
            }
        }
        None
    }

    /// The devices list: the latest device record that counts for each
    /// device, without revoked keys, sorted by name and then ID.
    pub fn devices(&self) -> Vec<Device> {
        let on: Vec<KeyHash> = self.path().iter().map(Cert::key_hash).collect();
        let mut latest: BTreeMap<&str, &Signed> = BTreeMap::new();
        for r in self.by_id.values() {
            if r.body.kind != "device" || !self.counts(r, &on) {
                continue;
            }
            let newer = latest
                .get(r.body.device.as_str())
                .is_none_or(|cur| (r.body.time_ms, r.record.id()) > (cur.body.time_ms, cur.record.id()));
            if newer {
                latest.insert(&r.body.device, r);
            }
        }
        let mut out: Vec<Device> = latest
            .into_iter()
            .filter(|(_, r)| !self.revoked(&r.body.key.unwrap()))
            .map(|(id, r)| Device {
                id: id.to_string(),
                name: r.body.name.clone(),
                role: r.body.role.clone(),
                key: r.body.key.unwrap(),
                admin: r.body.admin.is_some_and(|a| !self.revoked(&a)),
            })
            .collect();
        out.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        out
    }

    /// Every record, sorted by ID.
    pub fn all(&self) -> Vec<Record> {
        self.by_id.values().map(|r| r.record.clone()).collect()
    }

    /// SHA-256 over the sorted record IDs in base64, as the hello carries
    /// it; "" for an empty set.
    pub fn digest(&self) -> String {
        if self.by_id.is_empty() {
            return String::new();
        }
        let ids: Vec<u8> = self.by_id.keys().flatten().copied().collect();
        base64::engine::general_purpose::STANDARD.encode(sha256(&ids))
    }

    /// The records file's contents: every record, as JSON.
    pub fn to_file(&self) -> Result<Vec<u8>> {
        let mut data = serde_json::to_vec_pretty(&self.all()).context("cannot encode the records")?;
        data.push(b'\n');
        Ok(data)
    }

    /// A set for the group of group_ca from a records file's contents;
    /// records not valid for the group are left out.
    pub fn from_file(data: &[u8], group_ca: &Cert) -> Result<Records> {
        let mut s = Records::new(group_ca);
        let all: Vec<Record> = serde_json::from_slice(data).context("the records do not decode")?;
        s.add_all(&all);
        Ok(s)
    }
}
