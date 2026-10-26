// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The signed files that describe a release (docs/protocol.md, section 16),
//! checked as the Go package internal/release checks them: keys.json, in
//! which a root key certifies the release keys; release.json, which lists a
//! release's files with their hashes; and a channel file such as
//! stable.json, which names the current release of its channel.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

use crate::certs::{b64, hex, sha256};
use crate::error::{Error, Result};

/// The largest body a file may carry.
pub const MAX_BODY: usize = 256 << 10;
/// The longest a keys or channel file may stay valid after it was signed.
pub const MAX_LIFETIME_MS: i64 = 100 * 24 * 3600 * 1000;

/// The envelope of every release file.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct File {
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    #[serde(with = "b64")]
    pub sig: Vec<u8>,
    /// SHA-256 of the signer's SubjectPublicKeyInfo.
    #[serde(with = "b64")]
    pub key: Vec<u8>,
}

#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    v: i64,
    #[serde(default, rename = "type")]
    kind: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Key {
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    pub name: String,
    /// `release` when absent; a key of another use, such as the `status`
    /// key of the revocation mirror, signs no release.
    #[serde(default, rename = "use")]
    pub usage: String,
}

/// The body of keys.json.
#[derive(Clone, Deserialize, Debug)]
pub struct Keys {
    pub seq: u64,
    pub time_ms: i64,
    pub expires_ms: i64,
    pub keys: Vec<Key>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Binary {
    pub name: String,
    pub sha256: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Asset {
    pub name: String,
    pub size: i64,
    pub sha256: String,
    #[serde(default)]
    pub binaries: Vec<Binary>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Docker {
    pub image: String,
    pub digest: String,
}

/// The body of release.json.
#[derive(Clone, Deserialize, Debug)]
pub struct Release {
    pub version: String,
    pub channel: String,
    pub time_ms: i64,
    #[serde(default)]
    pub min_from: String,
    pub files: Vec<Asset>,
    #[serde(default)]
    pub docker: Option<Docker>,
}

/// The body of a channel file.
#[derive(Clone, Deserialize, Debug)]
pub struct Channel {
    pub channel: String,
    pub seq: u64,
    pub time_ms: i64,
    pub expires_ms: i64,
    pub release: String,
    pub release_sha256: String,
}

/// What a device keeps between checks: the highest sequence numbers and
/// version it has taken.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Debug)]
pub struct Seen {
    #[serde(default)]
    pub keys_seq: u64,
    #[serde(default)]
    pub channel_seq: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The revocation list's, which the lite member does not take but keeps.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub status_seq: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl File {
    /// SHA-256 over the body, which names a release.json.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.body)
    }

    fn verify(&self, spkis: &[&[u8]]) -> Result<()> {
        if self.body.len() > MAX_BODY {
            return Err(Error::msg("the file is too large"));
        }
        for spki in spkis {
            if sha256(spki)[..] != self.key[..] {
                continue;
            }
            let key = VerifyingKey::from_public_key_der(spki).map_err(|_| Error::msg("a key is not P-256"))?;
            let sig = Signature::from_der(&self.sig).map_err(|_| Error::msg("the signature is not valid"))?;
            return key.verify(&self.body, &sig).map_err(|_| Error::msg("the signature is not valid"));
        }
        Err(Error::msg("the signature is not valid"))
    }
}

fn decode<'a, T: Deserialize<'a>>(body: &'a [u8], kind: &str) -> Result<T> {
    let h: Head = serde_json::from_slice(body).map_err(|e| Error::with("the file is not valid", e))?;
    if h.kind != kind {
        return Err(Error::msg(format!("the file is a {:?}, not a {kind:?}", h.kind)));
    }
    if h.v != 1 {
        return Err(Error::msg(format!("unknown version {}", h.v)));
    }
    serde_json::from_slice(body).map_err(|e| Error::with("the file is not valid", e))
}

fn lifetime(time_ms: i64, expires_ms: i64) -> Result<()> {
    if expires_ms <= time_ms || expires_ms - time_ms > MAX_LIFETIME_MS {
        return Err(Error::msg("the file's lifetime is out of range"));
    }
    Ok(())
}

fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn is_channel(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn name_ok(s: &str, max: usize, slash: bool) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c) || (slash && *c == b'/'))
}

/// Parses a version of the form X.Y.Z or X.Y.Z-rc.N into X, Y, Z and the
/// release candidate's number, u32::MAX for a release.
pub fn parse_version(s: &str) -> Option<[u32; 4]> {
    fn number(part: &str, zero: bool) -> Option<u32> {
        if part.is_empty() || part.len() > 6 || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if (part.len() > 1 || !zero) && part.starts_with('0') {
            return None;
        }
        part.parse().ok()
    }
    let (main, rc) = match s.split_once("-rc.") {
        Some((m, n)) => (m, number(n, false)?),
        None => (s, u32::MAX),
    };
    let mut out = [0u32, 0, 0, rc];
    let mut parts = main.split('.');
    for p in out.iter_mut().take(3) {
        *p = number(parts.next()?, true)?;
    }
    if parts.next().is_some() { None } else { Some(out) }
}

/// Compares two versions, a release candidate before its release; a string that is not a version sorts below
/// every version.
pub fn compare(a: &str, b: &str) -> core::cmp::Ordering {
    parse_version(a).cmp(&parse_version(b))
}

fn decode_keys(body: &[u8]) -> Result<Keys> {
    let k: Keys = decode(body, "keys")?;
    if k.seq == 0 {
        return Err(Error::msg("keys.json has no sequence number"));
    }
    lifetime(k.time_ms, k.expires_ms)?;
    if k.keys.is_empty() || k.keys.len() > 8 {
        return Err(Error::msg("keys.json must hold 1 to 8 keys"));
    }
    for key in &k.keys {
        if key.name.is_empty() || key.name.len() > 64 {
            return Err(Error::msg("a key has no valid name"));
        }
        VerifyingKey::from_public_key_der(&key.key).map_err(|_| Error::msg("a key is not P-256"))?;
    }
    Ok(k)
}

fn decode_release(body: &[u8]) -> Result<Release> {
    let r: Release = decode(body, "release")?;
    if parse_version(&r.version).is_none() || (!r.min_from.is_empty() && parse_version(&r.min_from).is_none()) {
        return Err(Error::msg("release.json names no valid version"));
    }
    if !is_channel(&r.channel) || r.files.is_empty() || r.files.len() > 256 {
        return Err(Error::msg("release.json is not valid"));
    }
    let mut names = BTreeSet::new();
    for a in &r.files {
        if !name_ok(&a.name, 128, false) || !names.insert(a.name.as_str()) {
            return Err(Error::msg(format!("{:?} is not a valid file name", a.name)));
        }
        if a.size < 0 || !is_hex_sha256(&a.sha256) || a.binaries.len() > 64 {
            return Err(Error::msg(format!("the entry for {} is not valid", a.name)));
        }
        for b in &a.binaries {
            if !name_ok(&b.name, 256, true) || b.name.contains("..") || !is_hex_sha256(&b.sha256) {
                return Err(Error::msg(format!("a binary in {} is not valid", a.name)));
            }
        }
    }
    if let Some(d) = &r.docker {
        let ok = d.digest.strip_prefix("sha256:").is_some_and(is_hex_sha256);
        if d.image.is_empty() || !ok {
            return Err(Error::msg("the Docker image is not valid"));
        }
    }
    Ok(r)
}

fn decode_channel(body: &[u8]) -> Result<Channel> {
    let c: Channel = decode(body, "channel")?;
    if !is_channel(&c.channel) || c.seq == 0 {
        return Err(Error::msg("the channel file is not valid"));
    }
    lifetime(c.time_ms, c.expires_ms)?;
    if parse_version(&c.release).is_none() || !is_hex_sha256(&c.release_sha256) {
        return Err(Error::msg("the channel file names no valid release"));
    }
    Ok(c)
}

/// Checks keys.json against the pinned root keys (SubjectPublicKeyInfos,
/// DER) at now_ms, and that it is not older than seen.
pub fn verify_keys(f: &File, roots: &[&[u8]], now_ms: i64, seen: &Seen) -> Result<Keys> {
    f.verify(roots)?;
    let k = decode_keys(&f.body)?;
    if now_ms >= k.expires_ms {
        return Err(Error::msg("keys.json has expired"));
    }
    if k.seq < seen.keys_seq {
        return Err(Error::msg("keys.json is older than one already seen"));
    }
    Ok(k)
}

/// Checks a channel file and the release.json it names, as Go's
/// release.Check does, and returns the release and the new Seen to keep.
pub fn check(
    keys: &File,
    channel: &File,
    rel: &File,
    roots: &[&[u8]],
    name: &str,
    now_ms: i64,
    seen: &Seen,
) -> Result<(Release, Seen)> {
    let k = verify_keys(keys, roots, now_ms, seen).map_err(|e| e.context("keys.json is not valid"))?;
    let spkis: Vec<&[u8]> = k
        .keys
        .iter()
        .filter(|key| key.usage.is_empty() || key.usage == "release")
        .map(|key| key.key.as_slice())
        .collect();
    channel.verify(&spkis).map_err(|e| e.context(format!("{name}.json is not valid")))?;
    let c = decode_channel(&channel.body).map_err(|e| e.context(format!("{name}.json is not valid")))?;
    if c.channel != name {
        return Err(Error::msg(format!("{name}.json is for the channel {:?}", c.channel)));
    }
    if now_ms >= c.expires_ms {
        return Err(Error::msg(format!("{name}.json has expired")));
    }
    if c.seq < seen.channel_seq {
        return Err(Error::msg(format!("{name}.json is older than one already seen")));
    }
    rel.verify(&spkis).map_err(|e| e.context("release.json is not valid"))?;
    if hex(&rel.hash()) != c.release_sha256 {
        return Err(Error::msg(format!("release.json is not the release {name}.json names")));
    }
    let r = decode_release(&rel.body).map_err(|e| e.context("release.json is not valid"))?;
    if r.version != c.release || r.channel != c.channel {
        return Err(Error::msg(format!(
            "release.json is {} on {}, {name}.json names {}",
            r.version, r.channel, c.release
        )));
    }
    if !seen.version.is_empty() && compare(&r.version, &seen.version).is_lt() {
        return Err(Error::msg("release.json is older than a release already seen"));
    }
    let version = if !seen.version.is_empty() && compare(&seen.version, &r.version).is_gt() {
        seen.version.clone()
    } else {
        r.version.clone()
    };
    Ok((r, Seen { keys_seq: k.seq, channel_seq: c.seq, version, status_seq: seen.status_seq }))
}

impl Release {
    /// Reports whether a device at installed may update to this release in
    /// one step, or must first take min_from.
    pub fn direct(&self, installed: &str) -> bool {
        self.min_from.is_empty() || compare(installed, &self.min_from).is_ge()
    }

    /// Checks that data is the release's file name.
    pub fn check_file(&self, name: &str, data: &[u8]) -> Result<()> {
        let a = self
            .files
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| Error::msg(format!("{name} is not in the release")))?;
        if a.size != data.len() as i64 || hex(&sha256(data)) != a.sha256 {
            return Err(Error::msg(format!("{name} does not match release.json")));
        }
        Ok(())
    }
}
