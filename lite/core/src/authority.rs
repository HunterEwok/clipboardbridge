// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's authority records of version 2 (docs/records-v2.md): the
//! record, its closed canonical body, its signature, and the one rule that
//! turns a set of records into the group's state, as Go's
//! internal/authority. Both are checked on testdata/interop/v2-records.json.
//! What the set says depends on the records alone, never on the order in
//! which they arrived.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::certs::{self, Cert, b64, sha256};
use crate::error::{Error, Result};
use crate::strict;

/// The largest record body a member takes (8 KiB).
pub const MAX_BODY: usize = 8 << 10;

/// The one signature algorithm of version 2: ECDSA P-256 with SHA-256, DER.
pub const ALG_ES256: &str = "es256";

/// How many records of a later version a state lists.
pub const MAX_NEWER: usize = 16;
/// The largest seq a signer gives a record.
pub const MAX_SEQ: i64 = (1 << 31) - 1;
/// The longest takeover delay the root may set (7 days), in milliseconds.
pub const MAX_DELAY: i64 = 7 * 24 * 3600 * 1000;
/// The takeover delay without a settings record (72 hours).
pub const DEFAULT_DELAY: i64 = 72 * 3600 * 1000;

pub const TYPE_DEVICE: &str = "device";
pub const TYPE_REVOKE: &str = "revoke";
pub const TYPE_FREEZE: &str = "freeze";
pub const TYPE_THAW: &str = "thaw";
pub const TYPE_CLAIM: &str = "claim";
pub const TYPE_RESOLVE: &str = "resolve";
pub const TYPE_SETTINGS: &str = "settings";

pub const POWER_ADMIT: &str = "admit";
pub const POWER_RENEW: &str = "renew";
pub const POWER_REMOVE: &str = "remove";
pub const POWER_REMOVE_ADMINS: &str = "remove-admins";
pub const POWER_FREEZE: &str = "freeze";
pub const POWER_THAW: &str = "thaw";
pub const POWER_TAKEOVER: &str = "takeover";
pub const POWER_HUB: &str = "hub";

/// Every power, sorted.
pub const POWERS: [&str; 8] =
    [POWER_ADMIT, POWER_FREEZE, POWER_HUB, POWER_REMOVE, POWER_REMOVE_ADMINS, POWER_RENEW, POWER_TAKEOVER, POWER_THAW];

/// Every command type an admin may be given, sorted.
pub const COMMANDS: [&str; 7] = ["action", "actions-off", "away-off", "hub", "mode", "paste", "paste-off"];

const ROLES: [&str; 5] = ["full", "phone", "lite", "watch", "shortcut"];
const OSES: [&str; 8] = ["linux", "windows", "macos", "ios", "android", "watchos", "wearos", "none"];

/// A key hash (SHA-256 of a SubjectPublicKeyInfo) or a record ID (SHA-256
/// of a body). In JSON it is standard base64, and hashes sort by that
/// text, as the canonical form wants.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn text(&self) -> String {
        STANDARD.encode(self.0)
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        if self.0 == other.0 { Ordering::Equal } else { self.text().cmp(&other.text()) }
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.text())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Hash, D::Error> {
        let s = String::deserialize(d)?;
        let raw = STANDARD.decode(&s).map_err(|_| serde::de::Error::custom("a hash is not base64"))?;
        let h: [u8; 32] = raw.try_into().map_err(|_| serde::de::Error::custom("a hash is not 32 bytes"))?;
        if STANDARD.encode(h) != s {
            return Err(serde::de::Error::custom("a hash is not in its one form"));
        }
        Ok(Hash(h))
    }
}

/// The hash of a certificate's key.
pub fn key_hash_of(c: &Cert) -> Hash {
    Hash(c.key_hash())
}

/// One entry of a record's seen: the highest seq of a signer the author
/// held.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Seen {
    pub key: Hash,
    pub seq: i64,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A record's body (docs/records-v2.md, "The record").
#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub v: i64,
    pub alg: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub group: String,
    pub signer: Hash,
    pub seq: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Hash>,
    pub time_ms: i64,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub powers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub store: String,
    #[serde(rename = "kind", default, skip_serializing_if = "String::is_empty")]
    pub hardware: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub holds_root: bool,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seen: Vec<Seen>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Hash>,
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub root: Vec<u8>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover_delay_ms: Option<i64>,
}

const COMMON: [&str; 7] = ["v", "alg", "type", "group", "signer", "seq", "time_ms"];

/// The fields beyond those every record has that a type may carry.
fn allowed(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        TYPE_DEVICE => &[
            "device",
            "name",
            "role",
            "os",
            "key",
            "admin",
            "powers",
            "commands",
            "store",
            "kind",
            "proof",
            "holds_root",
        ],
        TYPE_REVOKE | TYPE_FREEZE => &["keys", "seen"],
        TYPE_THAW | TYPE_RESOLVE => &["records"],
        TYPE_CLAIM => &["root", "seen"],
        TYPE_SETTINGS => &["takeover_delay_ms"],
        _ => return None,
    })
}

impl Body {
    /// The names of the fields b carries.
    fn present(&self) -> Vec<&'static str> {
        let mut n = Vec::new();
        let mut add = |on: bool, name: &'static str| {
            if on {
                n.push(name);
            }
        };
        add(!self.device.is_empty(), "device");
        add(!self.name.is_empty(), "name");
        add(!self.role.is_empty(), "role");
        add(!self.os.is_empty(), "os");
        add(self.key.is_some(), "key");
        add(self.admin.is_some(), "admin");
        add(!self.powers.is_empty(), "powers");
        add(!self.commands.is_empty(), "commands");
        add(!self.store.is_empty(), "store");
        add(!self.hardware.is_empty(), "kind");
        add(!self.proof.is_empty(), "proof");
        add(self.holds_root, "holds_root");
        add(!self.keys.is_empty(), "keys");
        add(!self.seen.is_empty(), "seen");
        add(!self.records.is_empty(), "records");
        add(!self.root.is_empty(), "root");
        add(self.takeover_delay_ms.is_some(), "takeover_delay_ms");
        n
    }

    /// Returns the canonical bytes of the body after checking its fields,
    /// as a signer's own code does before it signs.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let v = serde_json::to_value(self).map_err(|_| Error::msg("a record body does not encode"))?;
        let mut out = Vec::new();
        strict::write_canonical(&mut out, &v);
        Ok(out)
    }

    /// Reads a record body: its size, the strict and canonical form, no
    /// field its type does not know and none empty, and each field against
    /// its row (docs/records-v2.md, "Field rows").
    pub fn parse(data: &[u8]) -> Result<Body> {
        if data.len() > MAX_BODY {
            return Err(Error::msg(format!("a record body of {} bytes is over {MAX_BODY}", data.len())));
        }
        strict::check_canonical(data, &COMMON)?;
        let b: Body = serde_json::from_slice(data).map_err(|e| Error::msg(format!("a record body: {e}")))?;
        b.check()?;
        if b.encode()? != data {
            return Err(Error::msg("a record body has an empty field or a value not in its one form"));
        }
        Ok(b)
    }

    /// Puts the body's arrays in the order the canonical form wants.
    pub fn sort(&mut self) {
        self.powers.sort();
        self.commands.sort();
        self.keys.sort();
        self.records.sort();
        self.seen.sort_by_key(|s| s.key);
    }

    fn check(&self) -> Result<()> {
        if self.v != 2 {
            return Err(Error::msg(format!("a record of version {}", self.v)));
        }
        if self.alg != ALG_ES256 {
            return Err(Error::msg(format!("a record signed with {:?}", self.alg)));
        }
        let allowed =
            allowed(&self.kind).ok_or_else(|| Error::msg(format!("an unknown record type {:?}", self.kind)))?;
        for n in self.present() {
            if !allowed.contains(&n) {
                return Err(Error::msg(format!("a {} record has {n}", self.kind)));
            }
        }
        if self.group.is_empty() {
            return Err(Error::msg("a record has no group"));
        }
        if self.seq < 1 || self.seq > MAX_SEQ {
            return Err(Error::msg(format!("a record's seq {} is not from 1 to {MAX_SEQ}", self.seq)));
        }
        if (self.seq == 1) != self.prev.is_none() {
            return Err(Error::msg("a record has prev exactly when its seq is above 1"));
        }
        match self.kind.as_str() {
            TYPE_DEVICE => self.check_device(),
            TYPE_REVOKE | TYPE_FREEZE => {
                if self.keys.is_empty() || self.seen.is_empty() {
                    return Err(Error::msg(format!("a {} record needs keys and seen", self.kind)));
                }
                sorted_hashes(&self.keys, "keys")?;
                check_seen(&self.seen)
            }
            TYPE_THAW | TYPE_RESOLVE => {
                if self.records.is_empty() {
                    return Err(Error::msg(format!("a {} record needs records", self.kind)));
                }
                sorted_hashes(&self.records, "records")
            }
            TYPE_CLAIM => {
                if self.root.is_empty() || self.seen.is_empty() {
                    return Err(Error::msg("a claim needs root and seen"));
                }
                check_seen(&self.seen)
            }
            _ => match self.takeover_delay_ms {
                Some(d) if !(0..=MAX_DELAY).contains(&d) => {
                    Err(Error::msg(format!("a takeover delay of {d} ms is not from 0 to {MAX_DELAY}")))
                }
                _ => Ok(()),
            },
        }
    }

    fn check_device(&self) -> Result<()> {
        if !certs::is_id(&self.device) {
            return Err(Error::msg("a device record's device is not a device ID"));
        }
        if !valid_name(&self.name) {
            return Err(Error::msg("a device record's name is not 1 to 64 bytes without control characters"));
        }
        if !ROLES.contains(&self.role.as_str()) {
            return Err(Error::msg(format!("an unknown role {:?}", self.role)));
        }
        if !self.os.is_empty() && !OSES.contains(&self.os.as_str()) {
            return Err(Error::msg(format!("an unknown os {:?}", self.os)));
        }
        if self.key.is_none() {
            return Err(Error::msg("a device record has no key"));
        }
        if self.admin.is_none() && (!self.powers.is_empty() || !self.commands.is_empty()) {
            return Err(Error::msg("powers and commands come only with admin"));
        }
        sorted_of(&self.powers, &POWERS, "powers")?;
        sorted_of(&self.commands, &COMMANDS, "commands")
    }

    fn seen_of(&self, k: &Hash) -> i64 {
        self.seen.iter().find(|s| s.key == *k).map_or(0, |s| s.seq)
    }
}

/// Reports whether s is a device name: 1 to 64 bytes of UTF-8 without a
/// control character (U+0000 to U+001F, U+007F to U+009F).
pub fn valid_name(s: &str) -> bool {
    (1..=64).contains(&s.len()) && !s.chars().any(|c| c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c))
}

fn sorted_hashes(hs: &[Hash], field: &str) -> Result<()> {
    if hs.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error::msg(format!("{field} is not sorted, each once")));
    }
    Ok(())
}

fn check_seen(seen: &[Seen]) -> Result<()> {
    if let Some(s) = seen.iter().find(|s| !(0..=MAX_SEQ).contains(&s.seq)) {
        return Err(Error::msg(format!("a seen seq {} is not from 0 to {MAX_SEQ}", s.seq)));
    }
    if seen.windows(2).any(|w| w[0].key >= w[1].key) {
        return Err(Error::msg("seen is not sorted by key, each once"));
    }
    Ok(())
}

fn sorted_of(vs: &[String], known: &[&str], field: &str) -> Result<()> {
    for (i, v) in vs.iter().enumerate() {
        if !known.contains(&v.as_str()) {
            return Err(Error::msg(format!("an unknown value {v:?} in {field}")));
        }
        if i > 0 && vs[i - 1] >= *v {
            return Err(Error::msg(format!("{field} is not sorted, each once")));
        }
    }
    Ok(())
}

/// A signed record as it travels and is kept: its body's exact bytes, the
/// signature over them, and the signer's admin CA when an admin signed it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Record {
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    #[serde(with = "b64")]
    pub sig: Vec<u8>,
    #[serde(with = "b64::list", default)]
    pub chain: Vec<Vec<u8>>,
}

impl Record {
    /// The record ID: SHA-256 over the body.
    pub fn id(&self) -> Hash {
        Hash(sha256(&self.body))
    }

    /// Builds a record from a body the caller signed: the signature over
    /// body (ECDSA P-256 with SHA-256, DER) and the admin CA's DER when an
    /// admin key signed it.
    pub fn new(body: Vec<u8>, sig: Vec<u8>, admin_ca: Option<Vec<u8>>) -> Record {
        Record { body, sig, chain: admin_ca.into_iter().collect() }
    }
}

/// The most signatures a SigCache holds; when it is full it starts again.
pub const MAX_CACHE: usize = 8192;

/// Signatures already checked: an entry is a hash over the signer's key
/// hash, the body's hash and the signature, kept only for a signature that
/// verified, so that evaluating the same records again checks each
/// signature once. It is safe to share between threads and evaluations.
pub struct SigCache {
    seen: spin::Mutex<BTreeSet<[u8; 32]>>,
}

impl Default for SigCache {
    fn default() -> SigCache {
        SigCache::new()
    }
}

impl SigCache {
    pub const fn new() -> SigCache {
        SigCache { seen: spin::Mutex::new(BTreeSet::new()) }
    }

    fn entry(key: &Cert, data: &[u8], sig: &[u8]) -> [u8; 32] {
        let mut m = Vec::with_capacity(16 + 32 + 32 + sig.len());
        m.extend_from_slice(b"cbb sig cache v1");
        m.extend_from_slice(&key_hash_of(key).0);
        m.extend_from_slice(&sha256(data));
        m.extend_from_slice(sig);
        sha256(&m)
    }

    /// Reports whether sig over data verifies with key, from the cache when
    /// it was checked before.
    pub fn verifies(&self, key: &Cert, data: &[u8], sig: &[u8]) -> bool {
        let e = SigCache::entry(key, data, sig);
        if self.seen.lock().contains(&e) {
            return true;
        }
        let ok = key.verifies(data, sig);
        if ok {
            self.add([e]);
        }
        ok
    }

    /// The entries, sorted, to save with the member's state.
    pub fn entries(&self) -> Vec<[u8; 32]> {
        self.seen.lock().iter().copied().collect()
    }

    /// Adds saved entries. Only entries from the member's own saved state,
    /// checked with its secret, may come here: an entry stands for a
    /// signature that verified.
    pub fn add(&self, entries: impl IntoIterator<Item = [u8; 32]>) {
        let mut seen = self.seen.lock();
        for e in entries {
            if seen.len() >= MAX_CACHE {
                seen.clear();
            }
            seen.insert(e);
        }
    }

    pub fn len(&self) -> usize {
        self.seen.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn verifies(sigs: Option<&SigCache>, key: &Cert, data: &[u8], sig: &[u8]) -> bool {
    match sigs {
        Some(c) => c.verifies(key, data, sig),
        None => key.verifies(data, sig),
    }
}

/// A record whose body was read and whose signature verifies with the key
/// its body names.
#[derive(Clone, Debug)]
pub struct Signed {
    pub record: Record,
    pub body: Body,
    pub id: Hash,
    /// The admin CA in the chain; None when a root's own key signed.
    pub admin_ca: Option<Cert>,
}

/// Reads r's body and checks its signature: with an admin CA in the chain,
/// the signer is that CA's key; with none, a root the group may have, which
/// root_key finds by the signer. sigs, when given, holds signatures
/// already checked.
pub fn verify<'a>(r: &Record, root_key: impl Fn(&Hash) -> Option<&'a Cert>, sigs: Option<&SigCache>) -> Result<Signed> {
    let body = Body::parse(&r.body)?;
    let (key, admin_ca) = match r.chain.as_slice() {
        [] => (
            root_key(&body.signer).ok_or_else(|| Error::msg("a record's signer is no root of the group"))?.clone(),
            None,
        ),
        [ca] => {
            let ca = Cert::parse(ca)?;
            if key_hash_of(&ca) != body.signer {
                return Err(Error::msg("a record's signer is not its admin CA's key"));
            }
            (ca.clone(), Some(ca))
        }
        _ => return Err(Error::msg("a record's chain holds more than its admin CA")),
    };
    if key_hash_of(&key) != body.signer {
        return Err(Error::msg("a record's signer is not the key it is checked with"));
    }
    if !verifies(sigs, &key, &r.body, &r.sig) {
        return Err(Error::msg("a record's signature does not verify"));
    }
    Ok(Signed { record: r.clone(), body, id: r.id(), admin_ca })
}

/// What the evaluation takes (docs/records-v2.md, "The state").
pub struct Input<'a> {
    /// The group's first root; its tag is group.
    pub group_ca: &'a Cert,
    pub group: &'a str,
    pub records: &'a [Record],
    /// The member's clock, which counts sleep and does not jump, and the
    /// time on it when the member first held each claim, by record ID; a
    /// claim missing from it was first held now.
    pub now_ms: i64,
    pub first_seen: &'a BTreeMap<Hash, i64>,
    /// Signatures already checked, when the caller keeps them.
    pub sigs: Option<&'a SigCache>,
}

/// The group's state (docs/records-v2.md, "The state").
#[derive(Clone, Serialize, PartialEq, Debug, Default)]
pub struct State {
    pub roots: Vec<Hash>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub root_device: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Claim>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<Conflict>,
    pub stop: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_secrets_to: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nothing_to: Vec<String>,
    /// Records of a later version: the member keeps them and tells its
    /// user to update.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub newer: Vec<Hash>,
}

/// One device of the state.
#[derive(Clone, Serialize, PartialEq, Debug, Default)]
pub struct Device {
    pub device: String,
    pub name: String,
    pub role: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub os: String,
    pub keys: Vec<Hash>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub store: String,
    #[serde(rename = "kind", skip_serializing_if = "String::is_empty")]
    pub hardware: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proof: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin: Option<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub powers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub frozen: bool,
}

/// A claim of the state.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct Claim {
    pub record: Hash,
    pub claimant: Hash,
    pub root: Hash,
    pub state: &'static str,
    #[serde(skip_serializing_if = "is_zero")]
    pub left_ms: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// A conflict of the state.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct Conflict {
    pub kind: &'static str,
    pub records: Vec<Hash>,
    pub signers: Vec<Hash>,
}

impl State {
    /// The state as canonical JSON, the bytes the vectors compare.
    pub fn encode(&self) -> Vec<u8> {
        let v = serde_json::to_value(self).unwrap_or_default();
        let mut out = Vec::new();
        strict::write_canonical(&mut out, &v);
        out
    }
}

/// Turns a record set into the group's state. Records that do not verify
/// are dropped; the result depends only on the set, never on its order.
pub fn evaluate(input: &Input) -> State {
    evaluate_seqs(input).0
}

/// evaluate, and the highest seq of each signer among the records that
/// verify, which a member saves to notice a record set rolled back.
pub fn evaluate_seqs(input: &Input) -> (State, BTreeMap<Hash, i64>) {
    let e = Evaluation::new(input);
    let mut seqs = BTreeMap::new();
    for r in &e.recs {
        let s = seqs.entry(r.b().signer).or_insert(0);
        *s = r.b().seq.max(*s);
    }
    let mut path = vec![key_hash_of(input.group_ca)];
    let mut cuts = BTreeMap::new();
    let mut earlier = Vec::new();
    loop {
        let mut ep = Epoch::new(&e, path.clone(), cuts.clone());
        match ep.decide_claims(input.now_ms, input.first_seen) {
            Some((next, cut)) => {
                earlier.append(&mut ep.claims);
                cuts.insert(*path.last().unwrap_or(&Hash::default()), cut);
                path.push(next);
            }
            None => {
                earlier.append(&mut ep.claims);
                ep.claims = earlier;
                let mut state = ep.state();
                state.newer = newer(input, &state, &e.roots);
                return (state, seqs);
            }
        }
    }
}

/// The IDs of the records of a later version for this group that a
/// current root or admin of the state signed, sorted, at most MAX_NEWER
/// (docs/records-v2.md, "Records of a later version").
fn newer(input: &Input, state: &State, roots: &BTreeMap<Hash, Cert>) -> Vec<Hash> {
    let admins: BTreeSet<Hash> = state.devices.iter().filter_map(|d| d.admin).collect();
    let mut ids = BTreeSet::new();
    for r in input.records {
        if r.body.len() > MAX_BODY || crate::strict::check_canonical(&r.body, &["v", "group", "signer"]).is_err() {
            continue;
        }
        let Ok(serde_json::Value::Object(m)) = serde_json::from_slice::<serde_json::Value>(&r.body) else {
            continue;
        };
        let group = m.get("group").and_then(|g| g.as_str());
        let v = m.get("v").and_then(|v| v.as_i64());
        if group != Some(input.group) || !v.is_some_and(|v| v > 2 && v <= MAX_SEQ) {
            continue;
        }
        let Some(Ok(signer)) = m.get("signer").map(|s| serde_json::from_value::<Hash>(s.clone())) else {
            continue;
        };
        let key = match r.chain.as_slice() {
            [] if state.roots.contains(&signer) => roots.get(&signer).cloned(),
            [ca] if admins.contains(&signer) => Cert::parse(ca).ok().filter(|ca| key_hash_of(ca) == signer),
            _ => None,
        };
        if key.is_some_and(|k| verifies(input.sigs, &k, &r.body, &r.sig)) {
            ids.insert(r.id());
        }
    }
    ids.into_iter().take(MAX_NEWER).collect()
}

/// A verified record with the root that issued its admin CA.
struct Rec {
    s: Signed,
    issuer: Option<Hash>, // None for a root's own record
}

impl Rec {
    fn b(&self) -> &Body {
        &self.s.body
    }
    fn admin(&self) -> bool {
        self.s.admin_ca.is_some()
    }
}

struct Evaluation {
    roots: BTreeMap<Hash, Cert>,
    recs: Vec<Rec>,
    by_sig: BTreeMap<Hash, Vec<usize>>,
    devices: BTreeMap<String, Vec<usize>>,
}

impl Evaluation {
    fn new(input: &Input) -> Evaluation {
        let mut roots = BTreeMap::new();
        roots.insert(key_hash_of(input.group_ca), input.group_ca.clone());
        // The new roots of claims are the only other roots a record may be
        // signed under; a claim itself is signed by an admin CA.
        for r in input.records {
            if r.chain.len() != 1 {
                continue;
            }
            if let Ok(b) = Body::parse(&r.body) {
                if b.kind == TYPE_CLAIM {
                    if let Ok(c) = Cert::parse(&b.root) {
                        if certs::check_root(&c).is_ok() {
                            roots.insert(key_hash_of(&c), c);
                        }
                    }
                }
            }
        }
        let mut e = Evaluation { roots, recs: Vec::new(), by_sig: BTreeMap::new(), devices: BTreeMap::new() };
        // One body may come with more than one valid admin CA (an admin key
        // certified again); the smallest DER is kept, whatever the order.
        let mut by_id: BTreeMap<Hash, Rec> = BTreeMap::new();
        for r in input.records {
            let Ok(s) = verify(r, |h| e.roots.get(h), input.sigs) else { continue };
            if s.body.group != input.group {
                continue;
            }
            let issuer = match &s.admin_ca {
                Some(ca) => match e.issuer_of(ca) {
                    Some(h) => Some(h),
                    None => continue,
                },
                None => None,
            };
            let better = match (by_id.get(&s.id).and_then(|o| o.s.admin_ca.as_ref()), &s.admin_ca) {
                (None, _) => !by_id.contains_key(&s.id),
                (Some(old), Some(new)) => new.der < old.der,
                (Some(_), None) => false,
            };
            if better {
                by_id.insert(s.id, Rec { s, issuer });
            }
        }
        for (_, x) in by_id {
            let i = e.recs.len();
            e.by_sig.entry(x.s.body.signer).or_default().push(i);
            if x.s.body.kind == TYPE_DEVICE {
                e.devices.entry(x.s.body.device.clone()).or_default().push(i);
            }
            e.recs.push(x);
        }
        e
    }

    /// Finds the root that issued an admin CA.
    fn issuer_of(&self, c: &Cert) -> Option<Hash> {
        if !c.is_ca || c.path_len != Some(0) || !c.cert_sign || !c.p256 {
            return None;
        }
        self.roots.iter().find(|(_, root)| root.is_ca && c.signed_by(root)).map(|(h, _)| *h)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Unlabelled,
    In,
    Out,
    Undecided,
}

/// The evaluation under one path of roots.
struct Epoch<'a> {
    e: &'a Evaluation,
    path: Vec<Hash>,
    on_path: BTreeMap<Hash, usize>,
    cuts: BTreeMap<Hash, i64>,
    cur: Hash,
    voided: BTreeSet<Hash>,
    counted: Vec<bool>,
    forked: BTreeMap<Hash, i64>,
    admins: BTreeMap<Hash, usize>,
    label: Vec<Label>,
    revoked: BTreeSet<Hash>,
    frozen: BTreeSet<Hash>,
    conflicts: Vec<Conflict>,
    claims: Vec<Claim>,
    stop_full: bool,
    pending: Option<Hash>,
}

impl<'a> Epoch<'a> {
    fn new(e: &'a Evaluation, path: Vec<Hash>, cuts: BTreeMap<Hash, i64>) -> Epoch<'a> {
        let cur = *path.last().unwrap_or(&Hash::default());
        let on_path = path.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let n = e.recs.len();
        let mut ep = Epoch {
            e,
            path,
            on_path,
            cuts,
            cur,
            voided: BTreeSet::new(),
            counted: vec![false; n],
            forked: BTreeMap::new(),
            admins: BTreeMap::new(),
            label: vec![Label::Unlabelled; n],
            revoked: BTreeSet::new(),
            frozen: BTreeSet::new(),
            conflicts: Vec::new(),
            claims: Vec::new(),
            stop_full: false,
            pending: None,
        };
        ep.voided = ep.voids();
        for (signer, rs) in &e.by_sig {
            ep.chain(*signer, rs);
        }
        ep.find_admins();
        ep.do_label();
        ep.collect();
        ep
    }

    fn r(&self, i: usize) -> &'a Rec {
        &self.e.recs[i]
    }

    fn all(&self) -> core::ops::Range<usize> {
        0..self.e.recs.len()
    }

    fn of(&self, signer: &Hash) -> &'a [usize] {
        self.e.by_sig.get(signer).map_or(&[], |v| v.as_slice())
    }

    /// Reports whether record i is a root's own record that counts in this
    /// epoch: its root is on the path and it is within that root's cut.
    fn root_record(&self, i: usize) -> bool {
        let r = self.r(i);
        if r.admin() || !self.counted[i] || !self.on_path.contains_key(&r.b().signer) {
            return false;
        }
        !matches!(self.cuts.get(&r.b().signer), Some(cut) if r.b().seq > *cut)
    }

    /// The records the current root's resolve records name; a resolve
    /// counts here when its own chain is whole.
    fn voids(&self) -> BTreeSet<Hash> {
        let rs = self.of(&self.cur);
        let by_id: BTreeMap<Hash, usize> = rs.iter().map(|&i| (self.r(i).s.id, i)).collect();
        let mut v = BTreeSet::new();
        for &i in rs {
            let r = self.r(i);
            if r.admin() || r.b().kind != TYPE_RESOLVE || !self.whole(i, &by_id) {
                continue;
            }
            v.extend(r.b().records.iter().copied());
        }
        v
    }

    /// Reports whether i's prev chain down to seq 1 is held, each step one
    /// seq lower.
    fn whole(&self, mut i: usize, by_id: &BTreeMap<Hash, usize>) -> bool {
        let mut steps = 0;
        while self.r(i).b().seq > 1 {
            let Some(&p) = self.r(i).b().prev.as_ref().and_then(|p| by_id.get(p)) else { return false };
            if self.r(p).b().seq != self.r(i).b().seq - 1 || steps > MAX_SEQ {
                return false;
            }
            i = p;
            steps += 1;
        }
        true
    }

    /// Finds which of one signer's records count: whole chains, not on a
    /// branch a resolve voided, below the lowest seq with two records.
    fn chain(&mut self, signer: Hash, rs: &[usize]) {
        let by_id: BTreeMap<Hash, usize> = rs.iter().map(|&i| (self.r(i).s.id, i)).collect();
        let mut by_seq: BTreeMap<i64, usize> = BTreeMap::new();
        for &i in rs {
            *by_seq.entry(self.r(i).b().seq).or_default() += 1;
        }
        let dead = |mut i: usize| loop {
            let r = self.r(i);
            if self.voided.contains(&r.s.id) && by_seq[&r.b().seq] > 1 {
                return true;
            }
            if r.b().seq == 1 {
                return false;
            }
            i = by_id[r.b().prev.as_ref().unwrap_or(&Hash::default())];
        };
        let mut live: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
        for &i in rs {
            if self.whole(i, &by_id) && !dead(i) {
                live.entry(self.r(i).b().seq).or_default().push(i);
            }
        }
        let fork = live.iter().find(|(_, l)| l.len() > 1).map_or(MAX_SEQ + 1, |(s, _)| *s);
        if fork <= MAX_SEQ {
            self.forked.insert(signer, fork);
        }
        for (seq, l) in live {
            for i in l {
                if seq < fork && !self.voided.contains(&self.r(i).s.id) {
                    self.counted[i] = true;
                }
            }
        }
    }

    /// Reports whether root record a is newer than b: a later root on the
    /// path, then a higher seq.
    fn newer(&self, a: usize, b: usize) -> bool {
        let (a, b) = (self.r(a).b(), self.r(b).b());
        let pa = self.on_path.get(&a.signer).copied().unwrap_or(0);
        let pb = self.on_path.get(&b.signer).copied().unwrap_or(0);
        if pa != pb {
            return pa > pb;
        }
        a.seq > b.seq
    }

    /// The admin keys: the admin of a device record a root on the path
    /// signed, with the powers of the newest such record.
    fn find_admins(&mut self) {
        for rs in self.e.devices.values() {
            for &i in rs {
                let Some(a) = self.r(i).b().admin else { continue };
                if !self.root_record(i) {
                    continue;
                }
                match self.admins.get(&a) {
                    Some(&old) if !self.newer(i, old) => {}
                    _ => {
                        self.admins.insert(a, i);
                    }
                }
            }
        }
    }

    fn has(&self, admin: &Hash, power: &str) -> bool {
        self.admins.get(admin).is_some_and(|&i| self.r(i).b().powers.iter().any(|p| p == power))
    }

    /// Reports whether k is an admin key or the member key of a device
    /// whose newest root record names one.
    fn is_admin(&self, k: &Hash) -> bool {
        self.admins.contains_key(k) || self.admins.values().any(|&i| self.r(i).b().key.as_ref() == Some(k))
    }

    /// Reports whether k is a root key or the member key of the root's own
    /// device.
    fn is_root(&self, k: &Hash) -> bool {
        self.e.roots.contains_key(k) || self.root_device().is_some_and(|d| self.r(d).b().key.as_ref() == Some(k))
    }

    /// The current root's newest device record with holds_root.
    fn root_device(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        for &i in self.of(&self.cur) {
            let b = self.r(i).b();
            if b.kind == TYPE_DEVICE
                && b.holds_root
                && self.root_record(i)
                && best.is_none_or(|x| b.seq > self.r(x).b().seq)
            {
                best = Some(i);
            }
        }
        best
    }

    /// Reports whether an admin may sign record i.
    fn permitted(&self, i: usize) -> bool {
        let r = self.r(i);
        let a = &r.b().signer;
        if !r.issuer.is_some_and(|h| self.on_path.contains_key(&h)) || !self.admins.contains_key(a) {
            return false;
        }
        let b = r.b();
        match b.kind.as_str() {
            TYPE_DEVICE => {
                self.has(a, POWER_ADMIT) && b.admin.is_none() && !b.holds_root && b.role != "phone" && b.role != "watch"
            }
            TYPE_REVOKE => b.keys.iter().all(|k| {
                if self.is_root(k) {
                    false
                } else if self.is_admin(k) {
                    self.has(a, POWER_REMOVE_ADMINS)
                } else {
                    self.has(a, POWER_REMOVE)
                }
            }),
            TYPE_FREEZE => {
                self.has(a, POWER_FREEZE)
                    && b.keys.iter().all(|k| self.admins.contains_key(k) && !self.has(k, POWER_REMOVE_ADMINS))
            }
            TYPE_THAW => self.has(a, POWER_THAW) && self.has(a, POWER_REMOVE_ADMINS),
            TYPE_CLAIM => self.has(a, POWER_TAKEOVER) && r.issuer == Some(self.cur),
            _ => false,
        }
    }

    /// Reports whether a, a revoke or freeze, cuts off b: it names b's
    /// signer and saw fewer of its records than b's seq.
    fn cuts_off(&self, a: usize, b: usize) -> bool {
        let (a, b) = (self.r(a).b(), self.r(b).b());
        a.signer != b.signer
            && (a.kind == TYPE_REVOKE || a.kind == TYPE_FREEZE)
            && a.keys.contains(&b.signer)
            && a.seen_of(&b.signer) < b.seq
    }

    fn thawed_by_root(&self) -> BTreeSet<Hash> {
        let mut t = BTreeSet::new();
        for i in self.all() {
            if self.r(i).b().kind == TYPE_THAW && self.root_record(i) {
                t.extend(self.r(i).b().records.iter().copied());
            }
        }
        t
    }

    /// Gives every admin record its label: the grounded labelling of the
    /// attacks of removals, freezes and thaws.
    fn do_label(&mut self) {
        let thawed = self.thawed_by_root();
        let mut admin_recs = Vec::new();
        let mut root_acts = Vec::new();
        for i in self.all() {
            let r = self.r(i);
            if self.root_record(i) {
                if r.b().kind == TYPE_REVOKE || r.b().kind == TYPE_FREEZE && !thawed.contains(&r.s.id) {
                    root_acts.push(i);
                }
            } else if r.admin() && self.counted[i] {
                if !self.permitted(i) {
                    self.label[i] = Label::Out;
                }
                admin_recs.push(i);
            }
        }
        // A root's removal or freeze puts what it cuts off out for good,
        // and a root's thaw puts out the admin freezes it names.
        for &b in &admin_recs {
            if self.r(b).b().kind == TYPE_FREEZE && thawed.contains(&self.r(b).s.id) {
                self.label[b] = Label::Out;
            }
            if root_acts.iter().any(|&a| self.cuts_off(a, b)) {
                self.label[b] = Label::Out;
            }
        }
        let mut attackers: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &b in &admin_recs {
            for &a in &admin_recs {
                if self.label[a] == Label::Out {
                    continue;
                }
                let (ab, bb) = (self.r(a).b(), self.r(b).b());
                // An admin's removal of a claimant does not cut its claim:
                // decide_claims sees it as a dispute.
                if self.cuts_off(a, b) && bb.kind != TYPE_CLAIM
                    || ab.kind == TYPE_THAW && bb.kind == TYPE_FREEZE && ab.records.contains(&self.r(b).s.id)
                {
                    attackers.entry(b).or_default().push(a);
                }
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &admin_recs {
                if self.label[b] != Label::Unlabelled {
                    continue;
                }
                let mut all = true;
                for &a in attackers.get(&b).map_or(&[][..], |v| v.as_slice()) {
                    if self.label[a] == Label::In {
                        self.label[b] = Label::Out;
                        changed = true;
                        break;
                    }
                    if self.label[a] != Label::Out {
                        all = false;
                    }
                }
                if self.label[b] == Label::Unlabelled && all {
                    self.label[b] = Label::In;
                    changed = true;
                }
            }
        }
        let mut undec = Vec::new();
        for &b in &admin_recs {
            if self.label[b] == Label::Unlabelled {
                self.label[b] = Label::Undecided;
                if matches!(self.r(b).b().kind.as_str(), TYPE_REVOKE | TYPE_FREEZE | TYPE_THAW) {
                    undec.push(b);
                }
            }
        }
        self.conflicts_of(&undec, &attackers);
    }

    /// Groups undecided records that attack each other into conflicts.
    fn conflicts_of(&mut self, undec: &[usize], attackers: &BTreeMap<usize, Vec<usize>>) {
        let mut parent: BTreeMap<usize, usize> = undec.iter().map(|&r| (r, r)).collect();
        fn find(parent: &BTreeMap<usize, usize>, mut r: usize) -> usize {
            while parent[&r] != r {
                r = parent[&r];
            }
            r
        }
        for &b in undec {
            for &a in attackers.get(&b).map_or(&[][..], |v| v.as_slice()) {
                if parent.contains_key(&a) {
                    let (ra, rb) = (find(&parent, a), find(&parent, b));
                    parent.insert(ra, rb);
                }
            }
        }
        let mut by_root: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &r in undec {
            by_root.entry(find(&parent, r)).or_default().push(r);
        }
        for rs in by_root.values() {
            let mut c = Conflict { kind: "admins", records: Vec::new(), signers: Vec::new() };
            for &r in rs {
                c.records.push(self.r(r).s.id);
                if !c.signers.contains(&self.r(r).b().signer) {
                    c.signers.push(self.r(r).b().signer);
                }
            }
            self.conflicts.push(c);
            self.stop_full = true;
        }
    }

    /// Reports whether record i counts: a root's record in this epoch, or
    /// an admin record that is in.
    fn counts(&self, i: usize) -> bool {
        self.root_record(i) || self.r(i).admin() && self.label[i] == Label::In
    }

    /// Finds the revoked and frozen keys and the two histories.
    fn collect(&mut self) {
        let thawed = self.thawed_by_root();
        for i in self.all() {
            if !self.counts(i) {
                continue;
            }
            let b = self.r(i).b();
            match b.kind.as_str() {
                TYPE_REVOKE => self.revoked.extend(b.keys.iter().copied()),
                TYPE_FREEZE if !thawed.contains(&self.r(i).s.id) => self.frozen.extend(b.keys.iter().copied()),
                _ => {}
            }
        }
        let forked: Vec<(Hash, i64)> = self.forked.iter().map(|(k, v)| (*k, *v)).collect();
        for (signer, seq) in forked {
            let records =
                self.of(&signer).iter().filter(|&&i| self.r(i).b().seq == seq).map(|&i| self.r(i).s.id).collect();
            self.conflicts.push(Conflict { kind: "two_histories", records, signers: vec![signer] });
            if self.on_path.contains_key(&signer) {
                self.stop_full = true;
            }
        }
    }

    /// The admin removals and freezes that count and name the admin key k
    /// or the member key of its device.
    fn removals(&self, k: &Hash) -> Vec<usize> {
        let mut keys = vec![*k];
        if let Some(key) = self.admins.get(k).and_then(|&d| self.r(d).b().key) {
            keys.push(key);
        }
        self.all()
            .filter(|&i| {
                let r = self.r(i);
                r.admin()
                    && self.label[i] == Label::In
                    && (r.b().kind == TYPE_REVOKE || r.b().kind == TYPE_FREEZE)
                    && keys.iter().any(|key| r.b().keys.contains(key))
            })
            .collect()
    }

    /// Reports whether a root's freeze, not thawed by a root, names k.
    fn root_frozen(&self, k: &Hash) -> bool {
        if !self.frozen.contains(k) {
            return false;
        }
        let thawed = self.thawed_by_root();
        self.all().any(|i| {
            let r = self.r(i);
            r.b().kind == TYPE_FREEZE && self.root_record(i) && !thawed.contains(&r.s.id) && r.b().keys.contains(k)
        })
    }

    fn claim(&self, i: usize, state: &'static str) -> Claim {
        let r = self.r(i);
        Claim { record: r.s.id, claimant: r.b().signer, root: claim_root(r.b()), state, left_ms: 0 }
    }

    /// Looks at the claims under the current root and returns the next
    /// root and the current root's cut when one takes effect.
    fn decide_claims(&mut self, now: i64, first_seen: &BTreeMap<Hash, i64>) -> Option<(Hash, i64)> {
        let mut delay = DEFAULT_DELAY;
        let mut settings: Option<usize> = None;
        for &i in self.of(&self.cur) {
            if self.r(i).b().kind == TYPE_SETTINGS
                && self.root_record(i)
                && settings.is_none_or(|s| self.r(i).b().seq > self.r(s).b().seq)
            {
                settings = Some(i);
            }
        }
        if let Some(d) = settings.and_then(|s| self.r(s).b().takeover_delay_ms) {
            delay = d;
        }
        let cancelled = |c: usize| {
            let c = self.r(c);
            self.of(&self.cur).iter().any(|&i| {
                let b = self.r(i).b();
                self.root_record(i)
                    && (b.kind == TYPE_RESOLVE && b.records.contains(&c.s.id)
                        || b.kind == TYPE_REVOKE && b.keys.contains(&c.b().signer))
            })
        };
        let mut live = Vec::new();
        let mut decided = Vec::new();
        for i in self.all() {
            let c = self.r(i);
            if c.b().kind != TYPE_CLAIM
                || !c.admin()
                || c.issuer != Some(self.cur)
                || !self.counted[i] && !self.voided.contains(&c.s.id)
            {
                continue;
            }
            let root = Cert::parse(&c.b().root).ok();
            let root_hash = root.as_ref().map(key_hash_of);
            let state = match root_hash {
                None => Some("void"),
                Some(h) if !self.e.roots.contains_key(&h) || h == self.path[0] => Some("void"),
                _ if cancelled(i) => Some("cancelled"),
                _ if self.label[i] == Label::Out => Some("void"),
                Some(h) if self.on_path.contains_key(&h) => Some("void"),
                _ => None,
            };
            match state {
                Some(s) => decided.push(self.claim(i, s)),
                None => live.push(i),
            }
        }
        self.claims.append(&mut decided);
        // An admin's removal or freeze of a claimant that the claimant had
        // seen voids its claim; one it had not seen disputes it, whatever
        // else its author had seen (a claimed root can sign before its claim
        // takes effect).
        let mut disputes: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut kept = Vec::new();
        for &c in &live {
            let cb = self.r(c).b();
            let mut void = false;
            for r in self.removals(&cb.signer) {
                let rb = self.r(r).b();
                if cb.seen_of(&rb.signer) >= rb.seq {
                    void = true;
                } else {
                    disputes.entry(c).or_default().push(r);
                }
            }
            if void {
                let cl = self.claim(c, "void");
                self.claims.push(cl);
            } else {
                kept.push(c);
            }
        }
        // One claim at a time: a claim whose author held another live claim
        // counts for nothing.
        let mut first = Vec::new();
        for &c in &kept {
            let later =
                kept.iter().any(|&o| o != c && self.r(c).b().seen_of(&self.r(o).b().signer) >= self.r(o).b().seq);
            if later {
                let cl = self.claim(c, "void");
                self.claims.push(cl);
            } else {
                first.push(c);
            }
        }
        if first.len() > 1 {
            let mut conflict = Conflict { kind: "claims", records: Vec::new(), signers: Vec::new() };
            for &r in &first {
                let cl = self.claim(r, "competing");
                self.claims.push(cl);
                conflict.records.push(self.r(r).s.id);
                conflict.signers.push(self.r(r).b().signer);
            }
            self.conflicts.push(conflict);
            self.stop_full = true;
            return None;
        }
        let &c = first.first()?;
        if let Some(ds) = disputes.get(&c) {
            let cl = self.claim(c, "disputed");
            self.claims.push(cl);
            let mut conflict =
                Conflict { kind: "claims", records: vec![self.r(c).s.id], signers: vec![self.r(c).b().signer] };
            for &r in ds {
                conflict.records.push(self.r(r).s.id);
                if !conflict.signers.contains(&self.r(r).b().signer) {
                    conflict.signers.push(self.r(r).b().signer);
                }
            }
            self.conflicts.push(conflict);
            self.stop_full = true;
            return None;
        }
        let r = self.r(c);
        let mut cl = self.claim(c, "pending");
        let seen = first_seen.get(&r.s.id).copied().filter(|&s| s <= now).unwrap_or(now);
        if self.label[c] != Label::In || self.root_frozen(&r.b().signer) || now - seen < delay {
            cl.left_ms = (delay - (now - seen)).max(0);
            self.claims.push(cl);
            self.pending = Some(r.b().signer);
            return None;
        }
        cl.state = "effective";
        let next = cl.root;
        self.claims.push(cl);
        Some((next, r.b().seen_of(&self.cur)))
    }

    /// Builds the state of the last epoch.
    fn state(&self) -> State {
        let mut s = State { roots: self.path.clone(), stop: "none".into(), ..State::default() };
        if let Some(d) = self.root_device() {
            if !self.r(d).b().key.is_some_and(|k| self.revoked.contains(&k)) {
                s.root_device = self.r(d).b().device.clone();
            }
        }
        let forked_admin = self.forked.keys().any(|k| !self.on_path.contains_key(k));
        for (id, rs) in &self.e.devices {
            if let Some(d) = self.device(id, rs) {
                s.devices.push(d);
            }
            // The devices that an admin with two histories alone admitted
            // get nothing.
            let alone = !rs.is_empty()
                && rs.iter().all(|&i| self.forked.contains_key(&self.r(i).b().signer) && self.r(i).admin());
            if alone {
                s.nothing_to.push(id.clone());
            }
            if let Some(p) = self.pending {
                if rs.iter().any(|&i| self.r(i).b().admin == Some(p) && self.root_record(i)) {
                    s.no_secrets_to.push(id.clone());
                }
            }
        }
        s.devices.sort_by(|a, b| a.device.cmp(&b.device));
        s.nothing_to.sort();
        s.no_secrets_to.sort();
        s.revoked = self.revoked.iter().copied().collect();
        s.revoked.sort();
        s.claims = self.claims.clone();
        s.claims.sort_by_key(|c| c.record);
        s.conflicts = self.conflicts.clone();
        for c in &mut s.conflicts {
            c.records.sort();
            c.signers.sort();
        }
        s.conflicts.sort_by(|a, b| a.records.first().cmp(&b.records.first()));
        if self.stop_full {
            s.stop = "full".into();
        } else if forked_admin {
            s.stop = "secrets".into();
        }
        s
    }

    /// Builds one device of the state from its counting records.
    fn device(&self, id: &str, rs: &[usize]) -> Option<Device> {
        let mut counting: Vec<usize> = rs
            .iter()
            .copied()
            .filter(|&i| self.counts(i) && !self.r(i).b().key.is_some_and(|k| self.revoked.contains(&k)))
            .collect();
        if counting.is_empty() {
            return None;
        }
        let keys: BTreeSet<Hash> = counting.iter().filter_map(|&i| self.r(i).b().key).collect();
        // The newest record: a root's beats an admin's, a later root's an
        // earlier one's, then the higher seq; among admins the larger signer.
        counting.sort_by(|&a, &b| {
            let (ra, rb) = (!self.r(a).admin(), !self.r(b).admin());
            if ra != rb {
                return if ra { Ordering::Less } else { Ordering::Greater };
            }
            if ra {
                return if self.newer(a, b) {
                    Ordering::Less
                } else if self.newer(b, a) {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                };
            }
            let (ba, bb) = (self.r(a).b(), self.r(b).b());
            bb.signer.cmp(&ba.signer).then(bb.seq.cmp(&ba.seq))
        });
        let top = counting[0];
        let n = self.r(top).b();
        let mut d = Device {
            device: String::from(id),
            name: n.name.clone(),
            role: n.role.clone(),
            os: n.os.clone(),
            keys: keys.into_iter().collect(),
            store: n.store.clone(),
            hardware: n.hardware.clone(),
            proof: n.proof.clone(),
            ..Device::default()
        };
        d.keys.sort();
        if let Some(a) = n.admin {
            if !self.r(top).admin() && !self.revoked.contains(&a) && self.admins.get(&a) == Some(&top) {
                d.admin = Some(a);
                d.powers = n.powers.clone();
                d.commands = n.commands.clone();
                d.frozen = self.frozen.contains(&a);
            }
        }
        Some(d)
    }
}

fn claim_root(b: &Body) -> Hash {
    Cert::parse(&b.root).map(|c| key_hash_of(&c)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/interop/v2-records.json");
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    /// Every case of v2-records.json gives the state Go gives, byte for
    /// byte, in every order tried.
    #[test]
    fn v2_vectors() {
        let v = vectors();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 19);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let ca = Cert::parse(&STANDARD.decode(c["group_ca"].as_str().unwrap()).unwrap()).unwrap();
            let records: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            let mut first_seen = BTreeMap::new();
            for f in c["first_seen"].as_array().map_or(&[][..], |a| a.as_slice()) {
                let h: Hash = serde_json::from_value(f["record"].clone()).unwrap();
                first_seen.insert(h, f["ms"].as_i64().unwrap());
            }
            let want = c["state"].as_str().unwrap();
            let mut rs = records.clone();
            let cache = SigCache::new();
            for order in 0..4 {
                if order == 1 {
                    rs.reverse();
                } else if order > 1 {
                    let n = rs.len().max(1);
                    rs.rotate_left(order % n);
                }
                let input = Input {
                    group_ca: &ca,
                    group: c["group"].as_str().unwrap(),
                    records: &rs,
                    now_ms: c["now_ms"].as_i64().unwrap(),
                    first_seen: &first_seen,
                    sigs: if order % 2 == 0 { Some(&cache) } else { None },
                };
                let got = evaluate(&input).encode();
                assert_eq!(core::str::from_utf8(&got).unwrap(), want, "{name}, order {order}");
            }
        }
    }

    /// Each body in the vectors reads and writes back to the same bytes,
    /// and changed bodies are refused.
    #[test]
    fn bodies() {
        let v = vectors();
        let mut n = 0;
        for c in v["cases"].as_array().unwrap() {
            let records: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            for r in records {
                // The bodies of a later version have no alg and do not read.
                let Ok(b) = Body::parse(&r.body) else {
                    assert!(!r.body.windows(5).any(|w| w == br#""alg""#), "{}", c["name"]);
                    continue;
                };
                assert_eq!(b.encode().unwrap(), r.body);
                n += 1;
            }
        }
        assert!(n > 0);
        let good = r#"{"alg":"es256","device":"0123456789abcdef0123456789abcdef","group":"g","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","name":"Laptop","role":"full","seq":1,"signer":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","time_ms":1,"type":"device","v":2}"#;
        Body::parse(good.as_bytes()).unwrap();
        for bad in [
            good.replace(r#"{"#, r#"{"aaa":1,"#),
            good.replace(r#""alg":"es256""#, r#""alg":"es384""#),
            good.replace(r#""alg":"es256","#, ""),
            good.replace(r#""device""#, r#""commands":[],"device""#),
            good.replace(r#""key""#, r#""holds_root":false,"key""#),
            good.replace(r#""v":2"#, r#""v":1"#),
            good.replace(r#""seq":1"#, r#""seq":2"#),
            good.replace(r#""role":"full""#, r#""role":"linux""#),
            good.replace(r#""name""#, r#""keys":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"name""#),
            good.replace(r#"{"#, r#"{ "#),
        ] {
            assert!(Body::parse(bad.as_bytes()).is_err(), "{bad} is taken");
        }
    }
}
