// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's signed records: devices, revocations and root handovers
//! (docs/protocol.md, section 10), as Go's group.Records evaluates them.
//! What the set says depends on the records alone, never on the order in
//! which they arrived.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::certs::{self, Cert, KeyHash, b64, sha256};
use crate::error::{Context, Error, Result};

pub const MAX_RECORDS: usize = 4096;
/// The records one admin CA signs at most, so a stolen admin cannot fill
/// the set and shut the others out.
pub const MAX_PER_ADMIN: usize = 1024;
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
    /// The signer's device ID: a root's own device record has by = device.
    #[serde(default)]
    by: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    os: String,
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
    /// freeze: the records of the frozen admins that still count; thaw: the
    /// freeze records it ends. Both are record IDs.
    #[serde(with = "b64::hashes", default)]
    records: Vec<KeyHash>,
}

/// Whether `os` names an operating system that device records know.
pub fn valid_os(os: &str) -> bool {
    matches!(os, "linux" | "windows" | "macos" | "ios" | "android" | "none")
}

/// The role a record names, with the roles of earlier records read as
/// today's.
fn role(r: &str) -> &str {
    match r {
        "linux" | "mac" => "full",
        "iphone" => "shortcut",
        r => r,
    }
}

/// The system a record names, or the one its earlier role implies.
fn os_of(b: &Body) -> &str {
    match (b.os.as_str(), b.role.as_str()) {
        ("", "mac") => "macos",
        ("", "iphone" | "shortcut") => "ios",
        (os, _) => os,
    }
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
                if !matches!(role(&self.role), "full" | "phone" | "lite" | "shortcut") {
                    return Err(Error::msg(format!("unknown role {:?} in a device record", self.role)));
                }
                if !self.os.is_empty() && !valid_os(&self.os) {
                    return Err(Error::msg(format!("unknown system {:?} in a device record", self.os)));
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
            "freeze" => {
                if self.keys.is_empty() {
                    return Err(Error::msg("a freeze record names no admin"));
                }
            }
            "thaw" => {
                if self.records.is_empty() {
                    return Err(Error::msg("a thaw record names no freeze record"));
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
    id: [u8; 32],
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
    /// `full`, `phone`, `lite` or `shortcut`.
    pub role: String,
    /// Its operating system; empty when its record does not tell.
    pub os: String,
    pub key: KeyHash,
    pub admin: bool,
    /// An admin computer another admin froze: no admin, and refused.
    pub frozen: bool,
}

/// The set of a group's records. It only grows.
pub struct Records {
    group_ca: Cert,
    tag: String,
    ca_key: KeyHash,
    by_id: BTreeMap<[u8; 32], Signed>,
    roots: BTreeMap<KeyHash, Cert>,
    /// The records each admin CA signed (MAX_PER_ADMIN).
    per_signer: BTreeMap<KeyHash, usize>,
    /// What the set says about revocations, worked out on first use after a
    /// change.
    ev: RefCell<Option<Eval>>,
}

/// What the set says about revocations (docs/protocol.md, section 10,
/// rules 2 and 3), as Go's group.evaluation.
struct Eval {
    revoked: BTreeSet<KeyHash>,
    /// The records that revoked each key, by record ID.
    revokers: BTreeMap<KeyHash, Vec<[u8; 32]>>,
    phone_admin: BTreeSet<KeyHash>,
    /// The known roots: the group CA and the new roots of the root records
    /// that a known root or an admin phone under one signed.
    roots: BTreeSet<KeyHash>,
    /// The freezes that count, for each frozen admin CA (rule 4), by
    /// record ID.
    freezes: BTreeMap<KeyHash, Vec<[u8; 32]>>,
    /// The device keys of the frozen admins.
    frozen_keys: BTreeSet<KeyHash>,
}

impl Eval {
    fn root_signed(&self, r: &Signed) -> bool {
        r.signer == r.anchor && self.roots.contains(&r.anchor)
    }
}

/// The admin CA key that r, a device record of a phone signed by the own
/// key of one of roots, names; None for any other record.
fn phone_admin_of(r: &Signed, roots: &BTreeSet<KeyHash>) -> Option<KeyHash> {
    let b = &r.body;
    if b.kind != "device" || role(&b.role) != "phone" || r.signer != r.anchor || !roots.contains(&r.signer) {
        return None;
    }
    b.admin
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
            per_signer: BTreeMap::new(),
            ev: RefCell::new(None),
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
        if s.signer != s.anchor {
            let n = self.per_signer.entry(s.signer).or_insert(0);
            if *n >= MAX_PER_ADMIN {
                return Err(Error::msg("too many records from one admin"));
            }
            *n += 1;
        }
        if let Some(root) = &s.root {
            self.roots.entry(root.key_hash()).or_insert_with(|| root.clone());
        }
        self.by_id.insert(id, s);
        *self.ev.get_mut() = None;
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
            // A legacy group CA hands the group to its first root itself,
            // with its own key (cbb upgrade); a root with path length 1 also
            // through its admins.
            let upgrade = anchor == self.ca_key && signer == anchor;
            if self.roots[&anchor].path_len != Some(1) && !upgrade {
                return Err(Error::msg("only a group with a root is handed to a new root"));
            }
            let c = Cert::parse(&body.root)?;
            certs::check_root(&c)?;
            root = Some(c);
        }
        Ok(Signed { record: r.clone(), id: r.id(), body, signer, anchor, root })
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
                    || self.revoked(&r.signer) && !self.upgrade_stands(r)
                    || !self.signed_by_root(r)
                    || !self.may_hand_over(r)
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

    /// Reports whether the root record r, in which a legacy group CA hands
    /// the group to its first root (cbb upgrade), still counts though the
    /// group CA's key is revoked: every record that revokes it was signed
    /// under the root that r names.
    fn upgrade_stands(&self, r: &Signed) -> bool {
        let Some(root) = &r.root else { return false };
        if r.anchor != self.ca_key || r.signer != r.anchor || self.group_ca.path_len != Some(0) {
            return false;
        }
        let root = root.key_hash();
        self.by_id
            .values()
            .filter(|rv| rv.body.kind == "revoke" && rv.body.keys.contains(&r.signer))
            .all(|rv| rv.anchor == root)
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

    /// Reports whether a key is revoked: named by a revocation record that
    /// counts, or an admin or root key named by a revocation from a root or
    /// an admin phone (docs/protocol.md, section 10, rules 2 and 3).
    pub fn revoked(&self, k: &KeyHash) -> bool {
        self.ev().revoked.contains(k)
    }

    /// Reports whether admin is revoked only by records that keep leaf.
    fn kept(&self, admin: &KeyHash, leaf: &KeyHash) -> bool {
        let ev = self.ev();
        let Some(ids) = ev.revokers.get(admin) else { return false };
        ids.iter().all(|id| self.by_id[id].body.keep.contains(leaf))
    }

    /// Whether the signer of a root record may hand the group over: a known
    /// root's own key or an admin phone's admin CA, never a computer's.
    /// Reports whether a key is frozen (docs/protocol.md, section 10, rule
    /// 4): a computer's admin CA that a freeze that counts names, or the
    /// device key of such an admin.
    pub fn frozen(&self, k: &KeyHash) -> bool {
        let ev = self.ev();
        ev.freezes.contains_key(k) || ev.frozen_keys.contains(k)
    }

    /// Reports whether every freeze of r's signer names r, as for the
    /// records of an admin that is not frozen.
    fn kept_by_freezes(&self, ev: &Eval, r: &Signed) -> bool {
        ev.freezes.get(&r.signer).is_none_or(|ids| ids.iter().all(|id| self.by_id[id].body.records.contains(&r.id)))
    }

    fn may_hand_over(&self, r: &Signed) -> bool {
        let ev = self.ev();
        ev.root_signed(r)
            || (ev.phone_admin.contains(&r.signer) && ev.roots.contains(&r.anchor))
            || (ev.roots.contains(&r.anchor) && self.computer_hand_over(r))
    }

    /// Whether r, a root record, was signed by the admin CA of a computer
    /// under its anchor, a root that is a computer itself, and only that
    /// root's own records stop it, as Go's group.Records.computerHandOver.
    fn computer_hand_over(&self, r: &Signed) -> bool {
        if r.root.is_none() || r.signer == r.anchor {
            return false;
        }
        let root = r.anchor;
        let (mut admins, mut revoked, mut thawed) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let mut computer = false;
        for o in self.by_id.values() {
            let b = &o.body;
            if o.signer != root || o.anchor != root {
                continue;
            }
            match b.kind.as_str() {
                "revoke" => revoked.extend(b.keys.iter().copied()),
                "thaw" => thawed.extend(b.records.iter().copied()),
                "device" => {
                    let own = b.device == b.by;
                    if own && role(&b.role) == "phone" {
                        return false;
                    }
                    computer |= own && role(&b.role) == "full";
                    if let Some(a) = b.admin
                        && role(&b.role) != "phone"
                    {
                        admins.insert(a);
                    }
                }
                _ => {}
            }
        }
        if !computer || !admins.contains(&r.signer) || revoked.contains(&r.signer) {
            return false;
        }
        !self.by_id.values().any(|o| {
            o.body.kind == "freeze"
                && o.anchor == root
                && o.body.keys.contains(&r.signer)
                && !thawed.contains(&o.id)
                && (o.signer == root || (admins.contains(&o.signer) && !revoked.contains(&o.signer)))
        })
    }

    fn ev(&self) -> Ref<'_, Eval> {
        if self.ev.borrow().is_none() {
            let ev = self.evaluate();
            *self.ev.borrow_mut() = Some(ev);
        }
        Ref::map(self.ev.borrow(), |e| e.as_ref().unwrap())
    }

    /// Works out the revocations in strata that do not depend on each other
    /// in a circle, as Go's group.Records.eval.
    fn evaluate(&self) -> Eval {
        let mut ev = Eval {
            revoked: BTreeSet::new(),
            revokers: BTreeMap::new(),
            phone_admin: BTreeSet::new(),
            roots: self.known_roots(),
            freezes: BTreeMap::new(),
            frozen_keys: BTreeSet::new(),
        };
        let mut by_root: BTreeMap<KeyHash, Vec<&Signed>> = BTreeMap::new();
        let mut privileged: BTreeSet<KeyHash> = self.roots.keys().copied().collect();
        for r in self.by_id.values() {
            if r.body.kind == "revoke" && ev.root_signed(r) {
                for k in &r.body.keys {
                    by_root.entry(*k).or_default().push(r);
                }
            } else if r.body.kind == "device" {
                if let Some(a) = r.body.admin {
                    privileged.insert(a);
                }
            }
            if r.signer != r.anchor {
                privileged.insert(r.signer);
            }
        }
        let stands_for_roots = |issuer: &KeyHash, k: &KeyHash| {
            by_root.get(issuer).is_none_or(|rs| rs.iter().all(|r| r.body.keep.contains(k)))
        };
        for r in self.by_id.values() {
            if let Some(a) = phone_admin_of(r, &ev.roots) {
                if stands_for_roots(&r.signer, &a) {
                    ev.phone_admin.insert(a);
                }
            }
        }
        let mut disabled = BTreeSet::new();
        for (id, r) in &self.by_id {
            let from_phone = ev.phone_admin.contains(&r.signer) && ev.roots.contains(&r.anchor);
            if r.body.kind != "revoke" || !(ev.root_signed(r) || from_phone) {
                continue;
            }
            for k in &r.body.keys {
                if privileged.contains(k) && (ev.root_signed(r) || !ev.roots.contains(k)) {
                    disabled.insert(*k);
                    ev.revoked.insert(*k);
                    ev.revokers.entry(*k).or_default().push(*id);
                }
            }
        }
        // The device keys of each computer's admin CA, and the freezes that
        // a root or an admin phone ended.
        let mut computers: BTreeMap<KeyHash, Vec<KeyHash>> = BTreeMap::new();
        let mut thawed: BTreeSet<[u8; 32]> = BTreeSet::new();
        for r in self.by_id.values() {
            let b = &r.body;
            if b.kind == "device" && role(&b.role) != "phone" && ev.root_signed(r) {
                if let (Some(a), Some(k)) = (b.admin, b.key) {
                    if !ev.phone_admin.contains(&a) {
                        computers.entry(a).or_default().push(k);
                    }
                }
            } else if b.kind == "thaw"
                && (ev.root_signed(r)
                    || (ev.phone_admin.contains(&r.signer)
                        && ev.roots.contains(&r.anchor)
                        && !disabled.contains(&r.signer)))
            {
                thawed.extend(b.records.iter().copied());
            }
        }
        // A frozen admin's freezes still count, so two admins that freeze
        // each other both stay frozen until the root or an admin phone
        // decides.
        for (id, r) in &self.by_id {
            if r.body.kind != "freeze" || thawed.contains(id) || !ev.roots.contains(&r.anchor) {
                continue;
            }
            if r.signer != r.anchor && (disabled.contains(&r.signer) || !stands_for_roots(&r.anchor, &r.signer)) {
                continue;
            }
            if !r.body.keys.iter().all(|k| computers.contains_key(k)) {
                continue;
            }
            for k in &r.body.keys {
                ev.freezes.entry(*k).or_default().push(*id);
                ev.frozen_keys.extend(computers[k].iter().copied());
            }
        }
        for (id, r) in &self.by_id {
            if r.body.kind != "revoke" || !self.kept_by_freezes(&ev, r) {
                continue;
            }
            let counts = if r.signer == r.anchor {
                ev.roots.contains(&r.anchor)
            } else {
                ev.roots.contains(&r.anchor)
                    && !disabled.contains(&r.signer)
                    && stands_for_roots(&r.anchor, &r.signer)
                    && !r.body.keys.iter().any(|k| {
                        ev.roots.contains(k) || (privileged.contains(k) && !ev.phone_admin.contains(&r.signer))
                    })
            };
            if !counts {
                continue;
            }
            for k in &r.body.keys {
                let ids = ev.revokers.entry(*k).or_default();
                if !ids.contains(id) {
                    ids.push(*id);
                    ev.revoked.insert(*k);
                }
            }
        }
        ev
    }

    /// The roots whose own signatures may count: the group CA and the new
    /// root of every root record that a known root's own key, or an admin
    /// phone under a known root, signed, or that an admin computer signed
    /// under a root that is a computer (computer_hand_over).
    fn known_roots(&self) -> BTreeSet<KeyHash> {
        let mut known = BTreeSet::from([self.ca_key]);
        loop {
            let phones: BTreeSet<KeyHash> = self.by_id.values().filter_map(|r| phone_admin_of(r, &known)).collect();
            let mut grew = false;
            for r in self.by_id.values() {
                let Some(root) = &r.root else { continue };
                if !known.contains(&r.anchor)
                    || (r.signer != r.anchor && !phones.contains(&r.signer) && !self.computer_hand_over(r))
                {
                    continue;
                }
                grew |= known.insert(root.key_hash());
            }
            if !grew {
                return known;
            }
        }
    }

    fn counts(&self, r: &Signed, on: &[KeyHash]) -> bool {
        on.contains(&r.anchor)
            && self.signed_by_root(r)
            && r.body.key.is_some_and(|k| self.issued(&r.signer, &k))
            && self.kept_by_freezes(&self.ev(), r)
    }

    /// Reports whether a device record that counts names the key k.
    fn listed(&self, k: &KeyHash) -> bool {
        let on: Vec<KeyHash> = self.path().iter().map(Cert::key_hash).collect();
        self.by_id.values().any(|r| r.body.kind == "device" && r.body.key == Some(*k) && self.counts(r, &on))
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
        if self.frozen(&leaf) {
            return Some("the device is a frozen admin");
        }
        let mut top = first;
        let path = self.path();
        // The issuer is the certificate that signed the leaf, wherever it is
        // in the chain: a peer may add certificates it does not need.
        if !path.iter().any(|root| first.issued_by(root)) {
            let Some(issuer) = chain[1..].iter().find(|c| first.issued_by(c)) else {
                return Some("the certificate's issuer is not in its chain");
            };
            let admin = issuer.key_hash();
            if !self.issued(&admin, &leaf) {
                return Some("the admin that admitted the device was removed");
            }
            // A frozen admin's certificates hold only for devices the records
            // already list.
            if self.frozen(&admin) && !self.listed(&leaf) {
                return Some("the admin that certified the device is frozen");
            }
            top = issuer;
            leaf = admin;
        }
        for root in path {
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
                role: role(&r.body.role).to_string(),
                os: os_of(&r.body).to_string(),
                key: r.body.key.unwrap(),
                admin: r.body.admin.is_some_and(|a| !self.revoked(&a) && !self.frozen(&a)),
                frozen: self.frozen(&r.body.key.unwrap()) || r.body.admin.is_some_and(|a| self.frozen(&a)),
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
