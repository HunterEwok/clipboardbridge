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
/// The records one signer (an admin CA, or a root's own key) signs at most,
/// so a stolen admin cannot fill the set and shut the others out. Past
/// MAX_RECORDS the set still takes this many records from a path root's own
/// key, so it takes the root's removal of an admin that filled it.
pub const MAX_PER_ADMIN: usize = 1024;
/// Bits of Records::named and Records::own.
const NAMED_PHONE: u8 = 1;
const NAMED_OTHER: u8 = 2;
const NAMED_WATCH: u8 = 4;
const MAX_BODY: usize = 8 << 10;
const VERSION: i64 = 1;
/// The most bytes of a command's body: a hub command carries up to 256
/// clients' keys.
const MAX_COMMAND_BODY: usize = 64 << 10;
/// A paste command's body may be larger: it carries up to 1 MiB of text.
const MAX_PASTE_BODY: usize = 2 << 20;
/// The longest text of a paste command, and of one typed key by key.
pub const MAX_PASTE_TEXT: usize = 1 << 20;
pub const MAX_TYPE_TEXT: usize = 4 << 10;
/// The most addresses and clients a hub command gives, as Go's.
const MAX_HUB_ENDPOINTS: usize = 8;
const MAX_HUB_CLIENTS: usize = 256;
/// How long a command lives at most after it was signed.
pub const COMMAND_LIFETIME_MS: i64 = 30_000;
/// How far ahead of the receiver's clock a command's time may be.
pub const COMMAND_AHEAD_MS: i64 = 60_000;

/// A command (docs/protocol.md, section 15), as its receiver checked it.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct Command {
    #[serde(default)]
    v: i64,
    /// `mode`, `hub`, `paste`, `paste-off`, `action`, `actions-off` or
    /// `away-off`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub group: String,
    /// The signer's device ID, for showing.
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub time_ms: i64,
    #[serde(default)]
    pub expires_ms: i64,
    /// In a mode command, the mode; not checked against the known modes
    /// here. In a paste command, `paste` or `type`.
    #[serde(default)]
    pub mode: String,
    /// In a hub command, the order.
    #[serde(default)]
    pub hub: Option<serde_json::Value>,
    /// In a paste command: press Enter after the text.
    #[serde(default)]
    pub enter: bool,
    /// In a paste command: `text` or `secret`.
    #[serde(rename = "kind", default)]
    pub paste_kind: String,
    /// In a paste command: the text.
    #[serde(default)]
    pub text: String,
    /// In an action command: the name of the action, which the receiver
    /// defines.
    #[serde(default)]
    pub action: String,
}

/// The longest name of a quick action.
pub const MAX_ACTION_NAME: usize = 32;

/// Whether name may name a quick action, as Go's ValidActionName: 1 to
/// MAX_ACTION_NAME of a-z, 0-9 and -, starting with a letter.
/// Whether a watch's admin key may sign a command of type `kind`, as Go's
/// WatchCommand (docs/protocol.md, section 10, rule 8): one that turns
/// remote paste, the quick actions or sync away from home off, or that runs
/// a quick action.
pub fn watch_command(kind: &str) -> bool {
    matches!(kind, "paste-off" | "actions-off" | "away-off" | "action")
}

pub fn valid_action_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ACTION_NAME
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

impl Command {
    /// Reads and checks a command's body, in the strict form of signed
    /// bodies.
    pub(crate) fn parse(data: &[u8]) -> Result<Command> {
        if data.len() > MAX_PASTE_BODY {
            return Err(Error::msg("the command is too large"));
        }
        crate::strict::check(data, COMMAND_FIELDS)?;
        let body: Command = serde_json::from_slice(data).context("a command does not decode")?;
        if body.kind != "paste" && data.len() > MAX_COMMAND_BODY {
            return Err(Error::msg("the command is too large"));
        }
        body.check()?;
        Ok(body)
    }

    fn check(&self) -> Result<()> {
        if self.v != VERSION {
            return Err(Error::msg(format!("unknown command version {}", self.v)));
        }
        if !certs::is_id(&self.id) {
            return Err(Error::msg("the command has no valid ID"));
        }
        let hub = self.hub.as_ref().is_some_and(|h| !h.is_null());
        let paste = self.enter || !self.paste_kind.is_empty() || !self.text.is_empty();
        if paste && self.kind != "paste" {
            return Err(Error::msg(format!("a {} command carries a paste", self.kind)));
        }
        if self.kind != "action" && !self.action.is_empty() {
            return Err(Error::msg(format!("a {} command names an action", self.kind)));
        }
        match self.kind.as_str() {
            "mode" if self.mode.is_empty() || hub => return Err(Error::msg("a mode command names no mode")),
            "hub" if !hub || !self.mode.is_empty() => return Err(Error::msg("a hub command has no order")),
            "hub" if !self.hub_valid() => return Err(Error::msg("a hub command's order is not valid")),
            "paste-off" | "actions-off" | "away-off" if hub || !self.mode.is_empty() => {
                return Err(Error::msg(format!("a {} command carries an order", self.kind)));
            }
            "action" if hub || !self.mode.is_empty() => {
                return Err(Error::msg("an action command carries an order"));
            }
            "action" if !valid_action_name(&self.action) => {
                return Err(Error::msg(format!(
                    "an action command's name {:?} is not 1 to {MAX_ACTION_NAME} of a-z, 0-9 and -, starting with a letter",
                    self.action
                )));
            }
            "paste" => self.check_paste(hub)?,
            "mode" | "hub" | "paste-off" | "action" | "actions-off" | "away-off" => {}
            k => return Err(Error::msg(format!("unknown command type {k:?}"))),
        }
        if !certs::is_id(&self.to) {
            return Err(Error::msg("the command names no valid device"));
        }
        if !certs::is_id(&self.by) {
            return Err(Error::msg("a command's by is not a device ID"));
        }
        // A time before 1970 is no signing time; from it the difference cannot overflow.
        if self.time_ms < 0 || self.expires_ms <= self.time_ms || self.expires_ms - self.time_ms > COMMAND_LIFETIME_MS {
            return Err(Error::msg("the command's lifetime is not valid"));
        }
        Ok(())
    }

    /// Whether the hub order is valid, as Go's HubOrder.check: its members
    /// of the right types, the clients' keys base64 in its standard form, a
    /// forwarder with an address and a key or an address at least, at most
    /// 8 addresses and 256 clients, each client a device ID once with keys
    /// of 32 bytes.
    fn hub_valid(&self) -> bool {
        let Some(h) = self.hub.as_ref() else { return true };
        let Ok(o) = serde_json::from_value::<HubOrder>(h.clone()) else { return false };
        if o.forwarder.as_ref().is_some_and(|f| f.endpoint.is_empty() || f.key.is_empty())
            || (o.forwarder.is_none() && o.endpoints.is_empty())
            || o.endpoints.len() > MAX_HUB_ENDPOINTS
            || o.clients.len() > MAX_HUB_CLIENTS
        {
            return false;
        }
        let mut seen = BTreeSet::new();
        o.clients.iter().all(|c| {
            certs::is_id(&c.device) && seen.insert(c.device.as_str()) && c.key.len() == 32 && c.psk.len() == 32
        })
    }

    fn check_paste(&self, hub: bool) -> Result<()> {
        let limit = match self.mode.as_str() {
            "paste" => MAX_PASTE_TEXT,
            "type" => MAX_TYPE_TEXT,
            m => return Err(Error::msg(format!("a paste command's way {m:?} is not paste or type"))),
        };
        if hub {
            return Err(Error::msg("a paste command carries a hub order"));
        }
        if self.paste_kind != "text" && self.paste_kind != "secret" {
            return Err(Error::msg("a paste command's kind is not text or secret"));
        }
        if self.text.is_empty() {
            return Err(Error::msg("a paste command has no text"));
        }
        if self.text.len() > limit {
            return Err(Error::msg(format!("a paste command's text is longer than {limit} bytes")));
        }
        Ok(())
    }
}

/// A hub command's order, as Go's HubOrder reads it; only checked here.
#[derive(Deserialize)]
#[allow(dead_code)]
struct HubOrder {
    #[serde(default)]
    forwarder: Option<HubForwarder>,
    #[serde(default)]
    endpoints: Vec<String>,
    #[serde(default)]
    clients: Vec<HubClient>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct HubForwarder {
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    key: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct HubClient {
    #[serde(default)]
    device: String,
    #[serde(with = "b64", default)]
    key: Vec<u8>,
    #[serde(with = "b64", default)]
    psk: Vec<u8>,
}

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
}

/// What a record says; the fields depend on its type.
#[derive(Deserialize, Default, Clone)]
pub(crate) struct Body {
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
    /// Where the device's keys live: `file`, `hardware` or `proven`.
    #[serde(default)]
    store: String,
    /// The kind of hardware its keys are in and the proof of it, read only
    /// so that a body is valid where the other members find it valid: both
    /// are strings.
    #[serde(rename = "kind", default)]
    #[allow(dead_code)]
    hardware: String,
    #[serde(default)]
    #[allow(dead_code)]
    proof: String,
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
    matches!(os, "linux" | "windows" | "macos" | "ios" | "android" | "watchos" | "wearos" | "none")
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

/// Where a device of role keeps its keys, as its record's store says, as
/// Go's StoreOf: a record without one is from before the field, when a
/// phone's keys were in hardware and every other device's in a file.
pub fn store_of<'a>(store: &'a str, role: &str) -> &'a str {
    match store {
        "file" | "hardware" | "proven" => store,
        _ if role == "phone" || role == "watch" => "hardware",
        _ => "file",
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

/// The members every record's body has, and every command's.
const RECORD_FIELDS: &[&str] = &["v", "type", "group", "time_ms"];
const COMMAND_FIELDS: &[&str] = &["v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"];

impl Body {
    /// Reads and checks a record's body, in the strict form of signed bodies.
    pub(crate) fn parse(data: &[u8]) -> Result<Body> {
        if data.len() > MAX_BODY {
            return Err(Error::msg("the record is too large"));
        }
        crate::strict::check(data, RECORD_FIELDS)?;
        let body: Body = serde_json::from_slice(data).context("a record does not decode")?;
        body.check()?;
        Ok(body)
    }

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
                if !matches!(role(&self.role), "full" | "phone" | "lite" | "shortcut" | "watch") {
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

/// A record body's ID and the key hash of one signer of it.
type Envelope = ([u8; 32], KeyHash);

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
    /// `full`, `phone`, `lite`, `shortcut` or `watch`.
    pub role: String,
    /// Its operating system; empty when its record does not tell.
    pub os: String,
    pub key: KeyHash,
    /// Where its keys live (store_of).
    pub store: String,
    pub admin: bool,
    /// The admin CA its record names, whether or not it still counts.
    pub admin_key: Option<KeyHash>,
    /// An admin computer another admin froze: no admin, and refused.
    pub frozen: bool,
    /// Every key that a counting device record names for it and that is
    /// not revoked, key among them.
    pub keys: Vec<KeyHash>,
}

/// The set of a group's records. It only grows.
pub struct Records {
    group_ca: Cert,
    tag: String,
    ca_key: KeyHash,
    /// Each body under every signer that signed it, by its ID and the
    /// signer: which signer's copy a device saw first changes nothing.
    by_id: BTreeMap<Envelope, Signed>,
    /// The roots records may be signed under: the group CA and the new root
    /// of every root record that may make it a known root (may_be_known);
    /// the other root records wait in pending, by record ID.
    roots: BTreeMap<KeyHash, Cert>,
    pending: Vec<Envelope>,
    /// The exact records held, by body ID.
    sigs: BTreeMap<[u8; 32], Vec<Record>>,
    /// For each root, the admin CAs that device records its own key signed
    /// name (NAMED_PHONE, NAMED_WATCH or NAMED_OTHER), and the roles of its
    /// own device records.
    named: BTreeMap<(KeyHash, KeyHash), u8>,
    own: BTreeMap<KeyHash, u8>,
    /// The records each signer signed (MAX_PER_ADMIN).
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
    revokers: BTreeMap<KeyHash, Vec<Envelope>>,
    phone_admin: BTreeSet<KeyHash>,
    /// The watches' admin CAs (rule 8).
    watch: BTreeSet<KeyHash>,
    /// The known roots: the group CA and the new roots of the root records
    /// that a known root or an admin phone under one signed.
    roots: BTreeSet<KeyHash>,
    /// The freezes that count, for each frozen admin CA (rule 4), by
    /// record ID.
    freezes: BTreeMap<KeyHash, Vec<Envelope>>,
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
            pending: Vec::new(),
            sigs: BTreeMap::new(),
            named: BTreeMap::new(),
            own: BTreeMap::new(),
            per_signer: BTreeMap::new(),
            ev: RefCell::new(None),
        }
    }

    /// The number of records, a body that several signers signed counting
    /// once for each.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the set holds exactly r: its body with the same signature
    /// and chain.
    pub fn has(&self, r: &Record) -> bool {
        self.sigs.get(&r.id()).is_some_and(|rs| rs.iter().any(|o| o.sig == r.sig && o.chain == r.chain))
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Checks a record and adds it; reports whether it was new. The limits
    /// are checked after the signature, so that a record nobody signed never
    /// fills the set.
    pub fn add(&mut self, r: &Record) -> Result<bool> {
        if self.has(r) {
            return Ok(false);
        }
        let s = self.verify(r)?;
        let id = (s.id, s.signer);
        if self.by_id.contains_key(&id) {
            return Ok(false);
        }
        if self.per_signer.get(&s.signer).copied().unwrap_or(0) >= MAX_PER_ADMIN {
            return Err(Error::msg("too many records from one signer"));
        }
        let n = self.by_id.len();
        if n >= MAX_RECORDS
            && (n >= MAX_RECORDS + MAX_PER_ADMIN
                || s.signer != s.anchor
                || !self.path().iter().any(|c| c.key_hash() == s.anchor))
        {
            return Err(Error::msg("too many records"));
        }
        *self.per_signer.entry(s.signer).or_insert(0) += 1;
        if s.body.kind == "device" && s.signer == s.anchor {
            let bit = match role(&s.body.role) {
                "phone" => NAMED_PHONE,
                "watch" => NAMED_WATCH,
                _ => NAMED_OTHER,
            };
            if let Some(a) = s.body.admin {
                *self.named.entry((s.anchor, a)).or_insert(0) |= bit;
            }
            if s.body.device == s.body.by {
                *self.own.entry(s.anchor).or_insert(0) |= bit;
            }
        }
        if s.root.is_some() {
            self.pending.push(id);
        }
        self.sigs.entry(s.id).or_default().push(r.clone());
        self.by_id.insert(id, s);
        *self.ev.get_mut() = None;
        self.promote();
        Ok(true)
    }

    /// Moves the root records of pending that may make their new root a
    /// known root into roots, until none does.
    fn promote(&mut self) {
        let mut grew = true;
        while grew {
            grew = false;
            let mut rest = Vec::new();
            for id in core::mem::take(&mut self.pending) {
                let r = &self.by_id[&id];
                if !self.may_be_known(r) {
                    rest.push(id);
                    continue;
                }
                let root = r.root.clone().expect("a root record");
                if let alloc::collections::btree_map::Entry::Vacant(e) = self.roots.entry(root.key_hash()) {
                    e.insert(root);
                    grew = true;
                }
            }
            self.pending = rest;
        }
    }

    /// Reports whether the root record r may make its new root a known root
    /// (known_roots), leaving out the revocations and freezes that can still
    /// stop it: it was signed by its root's own key, by an admin CA that a
    /// phone's device record from that root's own key names, or by one a
    /// computer's names when that root is a computer. A root that a
    /// computer's admin CA names in a phone's group is never known, so
    /// nothing signed under it enters the set.
    fn may_be_known(&self, r: &Signed) -> bool {
        let named = self.named.get(&(r.anchor, r.signer)).copied().unwrap_or(0);
        r.signer == r.anchor
            || named & NAMED_PHONE != 0
            || named & NAMED_OTHER != 0 && self.own.get(&r.anchor) == Some(&NAMED_OTHER)
    }

    /// Adds the valid records among rs and returns those that were new, and
    /// an error for each one that is not valid. A record signed under a new
    /// root is taken once the records that make that root known are in.
    pub fn add_all(&mut self, rs: &[Record]) -> (Vec<Record>, Vec<Error>) {
        let mut fresh = Vec::new();
        let mut pending: Vec<Record> = rs.to_vec();
        loop {
            let mut rest = Vec::new();
            let mut errs = Vec::new();
            let roots = self.roots.len();
            for r in pending {
                match self.add(&r) {
                    Err(e) => {
                        rest.push(r);
                        errs.push(e);
                    }
                    Ok(true) => fresh.push(r),
                    Ok(false) => {}
                }
            }
            if self.roots.len() == roots || rest.is_empty() {
                return (fresh, errs);
            }
            pending = rest;
        }
    }

    /// The key that signed r and the root it is anchored to: a root's own
    /// key (no chain), or an admin CA under one of the roots (a chain of
    /// one).
    fn signer_of(&self, r: &Record) -> Result<(KeyHash, KeyHash)> {
        Ok(match r.chain.len() {
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
        })
    }

    fn verify(&self, r: &Record) -> Result<Signed> {
        let body = Body::parse(&r.body)?;
        if body.group != self.tag {
            return Err(Error::msg("the record is for another group"));
        }
        let (signer, anchor) = self.signer_of(r)?;
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
        self.steps().0
    }

    /// The path and the root records that lead along it, one for each root
    /// after the group CA.
    fn steps(&self) -> (Vec<Cert>, Vec<&Signed>) {
        let mut path = vec![self.group_ca.clone()];
        let mut steps = Vec::new();
        let mut on = vec![self.ca_key];
        loop {
            let cur = path.last().unwrap().key_hash();
            let mut next: Option<(&Signed, &Cert, [u8; 32])> = None;
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
                if next.is_none_or(|(_, _, best)| sum < best) {
                    next = Some((r, root, sum));
                }
            }
            match next {
                None => return (path, steps),
                Some((r, root, _)) => {
                    on.push(root.key_hash());
                    path.push(root.clone());
                    steps.push(r);
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
        let (mut admins, mut freezers, mut revoked, mut thawed) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
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
                    // A watch freezes an admin computer as any admin does,
                    // but never takes the group over.
                    if let Some(a) = b.admin
                        && role(&b.role) != "phone"
                    {
                        freezers.insert(a);
                        if role(&b.role) != "watch" {
                            admins.insert(a);
                        }
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
                && (o.signer == root || (freezers.contains(&o.signer) && !revoked.contains(&o.signer)))
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
            watch: BTreeSet::new(),
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
            } else if r.body.kind == "device" && ev.root_signed(r) {
                // Only a root's own record makes a key an admin's.
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
            if let Some(a) = r.body.admin
                && r.body.kind == "device"
                && role(&r.body.role) == "watch"
                && ev.root_signed(r)
            {
                ev.watch.insert(a);
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
            if r.body.kind != "freeze" || thawed.contains(&id.0) || !ev.roots.contains(&r.anchor) {
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
    /// phone under a known root while no revocation from that root's own
    /// key names the admin phone's admin CA, signed, or that an admin
    /// computer signed under a root that is a computer (computer_hand_over).
    fn known_roots(&self) -> BTreeSet<KeyHash> {
        let mut known = BTreeSet::from([self.ca_key]);
        // The admin CAs each root's own key revoked: such an admin phone's
        // root records under that root no longer count.
        let removed: BTreeSet<(KeyHash, KeyHash)> = self
            .by_id
            .values()
            .filter(|r| r.body.kind == "revoke" && r.signer == r.anchor)
            .flat_map(|r| r.body.keys.iter().map(|k| (r.anchor, *k)))
            .collect();
        loop {
            let phones: BTreeSet<KeyHash> = self.by_id.values().filter_map(|r| phone_admin_of(r, &known)).collect();
            let mut grew = false;
            for r in self.by_id.values() {
                let Some(root) = &r.root else { continue };
                if !known.contains(&r.anchor)
                    || (r.signer != r.anchor
                        && !(phones.contains(&r.signer) && !removed.contains(&(r.anchor, r.signer)))
                        && !self.computer_hand_over(r))
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

    /// Whether a device record counts, as Go's Records.counts: signed
    /// under a root on the path by an admin CA that still stands under it
    /// and is no watch's, which admits nobody (rule 8).
    fn counts(&self, r: &Signed, on: &[KeyHash]) -> bool {
        on.contains(&r.anchor)
            && self.signed_by_root(r)
            && r.body.key.is_some_and(|k| self.issued(&r.signer, &k))
            && self.kept_by_freezes(&self.ev(), r)
            && !self.watch(&r.signer)
    }

    /// Whether k is a watch's admin CA (docs/protocol.md, section 10, rule
    /// 8), as Go's Records.Watch.
    pub fn watch(&self, k: &KeyHash) -> bool {
        self.ev().watch.contains(k)
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
            if self.watch(&admin) {
                return Some("a watch certifies no devices");
            }
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
        // The chain must end at a root on the path: a root that only the
        // identity trusts, as one a Welcome named, is no anchor.
        for root in path {
            if top.signed_by(&root) {
                if !self.issued(&root.key_hash(), &leaf) {
                    return Some("the certificate is from a root that handed the group over");
                }
                return None;
            }
        }
        Some("the certificate is not from a root of the group")
    }

    /// The records that lead to the path: each root record on it and, for
    /// one an admin CA signed, the device records its root's own key signed
    /// that name that admin CA or the root's own device, as Go's
    /// Records.PathRecords. A new member gets them in the Welcome's records
    /// (docs/protocol.md, section 5).
    pub fn path_records(&self) -> Vec<Record> {
        let mut out = Vec::new();
        for st in self.steps().1 {
            out.push(st.record.clone());
            if st.signer == st.anchor {
                continue;
            }
            for r in self.by_id.values() {
                let b = &r.body;
                if b.kind == "device"
                    && r.signer == st.anchor
                    && r.anchor == st.anchor
                    && (b.device == b.by || b.admin == Some(st.signer))
                {
                    out.push(r.record.clone());
                }
            }
        }
        out
    }

    /// The devices list: the latest device record that counts for each
    /// device among those whose key is not revoked, sorted by name and then
    /// ID, as Go's Devices: the latest is one whose signer is not revoked
    /// before one whose signer is, then by time and record ID; a device is
    /// an admin, with that record's role and store, only by the latest of its
    /// records that a known root's own key signed.
    pub fn devices(&self) -> Vec<Device> {
        let on: Vec<KeyHash> = self.path().iter().map(Cert::key_hash).collect();
        let mut latest: BTreeMap<&str, &Signed> = BTreeMap::new();
        let mut certified: BTreeMap<&str, &Signed> = BTreeMap::new();
        let mut keys: BTreeMap<&str, Vec<KeyHash>> = BTreeMap::new();
        // By record ID, as Go, so the keys come in the same order; a device
        // whose records name more than one key stays listed while any of
        // them is not revoked.
        for r in self.by_id.values() {
            let Some(key) = r.body.key else { continue };
            if r.body.kind != "device" || !self.counts(r, &on) || self.revoked(&key) {
                continue;
            }
            let ks = keys.entry(r.body.device.as_str()).or_default();
            if !ks.contains(&key) {
                ks.push(key);
            }
            // A signer that stands sorts after one that is revoked.
            let order = |r: &Signed| (!self.revoked(&r.signer), r.body.time_ms, r.id, r.signer);
            if latest.get(r.body.device.as_str()).is_none_or(|cur| order(r) > order(cur)) {
                latest.insert(&r.body.device, r);
            }
            let root_signed = self.ev().root_signed(r);
            if root_signed
                && certified
                    .get(r.body.device.as_str())
                    .is_none_or(|cur| (r.body.time_ms, r.id, r.signer) > (cur.body.time_ms, cur.id, cur.signer))
            {
                certified.insert(&r.body.device, r);
            }
        }
        let mut out: Vec<Device> = latest
            .into_iter()
            .map(|(id, r)| {
                // a is the record that says what powers the device has.
                let c = certified.get(id).copied().filter(|c| c.body.admin.is_some());
                let (a, admin) = (c.unwrap_or(r), c.and_then(|c| c.body.admin));
                Device {
                    id: id.to_string(),
                    name: r.body.name.clone(),
                    role: role(&a.body.role).to_string(),
                    os: os_of(&r.body).to_string(),
                    key: r.body.key.unwrap(),
                    store: store_of(&a.body.store, role(&a.body.role)).to_string(),
                    admin: admin.is_some_and(|a| !self.revoked(&a) && !self.frozen(&a)),
                    admin_key: admin,
                    frozen: self.frozen(&r.body.key.unwrap()) || admin.is_some_and(|a| self.frozen(&a)),
                    keys: keys.remove(id).unwrap_or_default(),
                }
            })
            .collect();
        out.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        out
    }

    /// The root's own device, with its key, as Go's RootMember: the newest
    /// full or phone device record the current root signed for itself. None
    /// in a group whose root names no admins (path length 0).
    pub fn root_member(&self) -> Option<(String, KeyHash)> {
        let path = self.path();
        let root = path.last().unwrap();
        if root.path_len == Some(0) {
            return None;
        }
        let cur = root.key_hash();
        self.by_id
            .values()
            .filter(|r| {
                r.body.kind == "device"
                    && r.signer == cur
                    && matches!(role(&r.body.role), "phone" | "full")
                    && r.body.device == r.body.by
                    && r.body.key.is_some()
            })
            .max_by_key(|r| (r.body.time_ms, r.id, r.signer))
            .map(|r| (r.body.device.clone(), r.body.key.unwrap()))
    }

    /// Whether the device `dev` with the verified chain (leaf first) is the
    /// group's root or an admin, as Go's adminPeer: an admin CA of its own
    /// under a root on the path that is neither revoked nor frozen, the
    /// root's own device by its key, or an admin of the devices list by its
    /// key. Only such a device may be the group's hub (docs/protocol.md,
    /// section 11).
    pub fn admin_peer(&self, dev: &str, chain: &[Cert]) -> bool {
        let Some(leaf) = chain.first() else { return false };
        if let Some(ca) = chain.get(1)
            && ca.is_ca
            && ca.common_name.as_deref() == Some(format!("clipboardbridge admin {dev}").as_str())
        {
            let k = ca.key_hash();
            return leaf.signed_by(ca)
                && self.path().iter().any(|root| crate::certs::check_admin_ca(ca, root).is_ok())
                && !self.revoked(&k)
                && !self.frozen(&k);
        }
        let key = leaf.key_hash();
        if self.root_member().is_some_and(|(id, k)| id == dev && k == key) && !self.revoked(&key) {
            return true;
        }
        self.devices().iter().any(|d| d.id == dev && d.key == key && d.admin)
    }

    /// Whether the device `dev` may be the group's hub by the records
    /// alone, as Go's Records.MayHost: the root's own device, whose key is
    /// not revoked, or a device listed as an admin other than a watch. For
    /// the hub that a hub
    /// moving names (docs/protocol.md, section 11, "Moving the hub"); a
    /// peer's own offer is checked with [`Records::admin_peer`].
    pub fn may_host(&self, dev: &str) -> bool {
        if self.root_member().is_some_and(|(id, k)| id == dev && !self.revoked(&k)) {
            return true;
        }
        self.devices().iter().any(|d| d.id == dev && d.admin && d.role != "watch")
    }

    /// Checks a command for the member `me` at now_ms, as Go's
    /// Records.VerifyCommand: its signer is an admin of the group now (a
    /// root on the path, or an admin CA under one that is neither revoked
    /// nor frozen), its by is the signer's device when the records show it
    /// (command_signer), it is for `me` in this group, it has not expired and it
    /// was not signed in the future. The caller keeps the replay cache.
    pub fn verify_command(&self, c: &Record, me: &str, now_ms: i64) -> Result<Command> {
        let body = Command::parse(&c.body)?;
        if body.group != self.tag {
            return Err(Error::msg("the command is for another group"));
        }
        if body.to != me {
            return Err(Error::msg("the command is for another device"));
        }
        let not_admin = || Error::msg("the command's signer is not an admin of the group");
        let (signer, anchor) = self.signer_of(c).map_err(|_| not_admin())?;
        let on_path = self.path().iter().any(|root| root.key_hash() == anchor);
        if !on_path
            || self.revoked(&signer)
            || self.frozen(&signer)
            || !(signer == anchor || self.issued(&anchor, &signer))
        {
            return Err(not_admin());
        }
        if self.watch(&signer) && !watch_command(&body.kind) {
            return Err(Error::msg(format!("a watch does not sign {} commands", body.kind)));
        }
        // by names the signer's device whenever the records show it.
        if let (Some(d), _) = self.command_signer(c) {
            if d.id != body.by {
                return Err(Error::msg("a command's by is not the device of its signer"));
            }
        }
        if body.expires_ms <= now_ms {
            return Err(Error::msg("the command expired; check the clocks of both devices"));
        }
        if body.time_ms > now_ms + COMMAND_AHEAD_MS {
            return Err(Error::msg("the command was signed in the future; check the clocks of both devices"));
        }
        Ok(body)
    }

    /// The device whose admin key signed the command c, which
    /// verify_command took, as Go's CommandSigner: the device that holds
    /// the group's root when the root's own key signed it (the bool is
    /// true), or the device whose record names the admin CA that did. None
    /// when no listed device holds the key, as for an admin phone whose own
    /// record is not here yet.
    pub fn command_signer(&self, c: &Record) -> (Option<Device>, bool) {
        let Ok((signer, anchor)) = self.signer_of(c) else { return (None, false) };
        let root = signer == anchor;
        let id = if root {
            match self.root_member() {
                Some((id, _)) => Some(id),
                None => return (None, true),
            }
        } else {
            None
        };
        let d = self.devices().into_iter().find(|d| match &id {
            Some(id) => &d.id == id,
            None => d.admin_key == Some(signer),
        });
        (d, root)
    }

    /// The devices that may be the group's hubs, in the order in which
    /// they serve, as Go's Records.HubOrder (docs/protocol.md, section 11,
    /// "Several hubs"): the phones first, then the others, and in each part
    /// the root's own device first, then by device ID.
    pub fn hub_order(&self) -> Vec<String> {
        let root = self.root_member().filter(|(_, k)| !self.revoked(k)).map(|(id, _)| id);
        let mut hubs: Vec<(bool, bool, String)> = self
            .devices()
            .into_iter()
            .filter(|d| d.admin && d.role != "watch" || root.as_deref() == Some(d.id.as_str()))
            .map(|d| (d.role != "phone", root.as_deref() != Some(d.id.as_str()), d.id))
            .collect();
        hubs.sort();
        hubs.into_iter().map(|(_, _, id)| id).collect()
    }

    /// Every record, sorted by ID and, for a body several signers signed,
    /// by signer.
    pub fn all(&self) -> Vec<Record> {
        self.by_id.values().map(|r| r.record.clone()).collect()
    }

    /// SHA-256 over each record's ID and signer's key hash, sorted as all
    /// sorts them, in base64, as the hello carries it; "" for an empty set.
    pub fn digest(&self) -> String {
        if self.by_id.is_empty() {
            return String::new();
        }
        let ids: Vec<u8> = self.by_id.keys().flat_map(|(id, signer)| id.iter().chain(signer.iter())).copied().collect();
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
