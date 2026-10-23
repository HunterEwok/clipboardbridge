// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Device IDs, certificates and their checks (docs/protocol.md, sections 1,
//! 2 and 10), as the Go package internal/group does them.
//!
//! Every key is ECDSA P-256 and every signature ECDSA with SHA-256. This
//! module parses certificates and checks them; a lite member never issues
//! one, except the self-signed certificate it pairs with (pair.rs).

use std::fmt;

use base64::Engine as _;
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};
use x509_parser::prelude::*;

use crate::error::{Error, Result};

/// A device ID: 128 random bits as 32 lowercase hex characters.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DeviceId(String);

impl DeviceId {
    /// Checks that s is a device ID.
    pub fn parse(s: &str) -> Result<DeviceId> {
        if is_id(s) { Ok(DeviceId(s.to_string())) } else { Err(Error::msg(format!("{s:?} is not a device ID"))) }
    }

    /// A new random device ID.
    pub fn random() -> DeviceId {
        DeviceId(random_id())
    }

    /// The device's mDNS host name, cb-<device ID>.local, which is also the
    /// one DNS name of its member certificate.
    pub fn host_name(&self) -> String {
        format!("cb-{}.local", self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reports whether s is 32 lowercase hex characters: a device or event ID.
pub fn is_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A random event or device ID.
pub fn random_id() -> String {
    hex(&random_bytes::<16>())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("the system has no randomness");
    b
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, b).as_ref().try_into().unwrap()
}

/// The hash that names a key in records: SHA-256 over its
/// SubjectPublicKeyInfo.
pub type KeyHash = [u8; 32];

/// The fingerprint a join QR code carries: SHA-256 over the DER, in
/// base64url without padding.
pub fn qr_fingerprint(der: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(der))
}

/// The short identifier of a group: the first 8 bytes of SHA-256 over the
/// group CA certificate, in hex.
pub fn tag(group_ca: &Cert) -> String {
    hex(&sha256(&group_ca.der)[..8])
}

const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// A parsed certificate: its DER and what the checks need from it.
#[derive(Clone)]
pub struct Cert {
    pub der: Vec<u8>,
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub not_before: i64, // Unix seconds
    pub not_after: i64,
    pub is_ca: bool,
    pub path_len: Option<u32>, // the basic constraints' path length, when present
    pub cert_sign: bool,       // key usage certSign
    pub server_auth: bool,
    pub client_auth: bool,
    pub spki: Vec<u8>,
    pub p256: bool,
    point: Vec<u8>, // the uncompressed public key
    tbs: Vec<u8>,
    ecdsa_sha256: bool,
    sig: Vec<u8>,
    issuer_name: Vec<u8>,
    subject_name: Vec<u8>,
}

impl fmt::Debug for Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cert({:?})", self.common_name)
    }
}

impl PartialEq for Cert {
    fn eq(&self, other: &Cert) -> bool {
        self.der == other.der
    }
}

impl Cert {
    /// Parses a DER certificate.
    pub fn parse(der: &[u8]) -> Result<Cert> {
        let (rest, c) = X509Certificate::from_der(der).map_err(|e| Error::msg(format!("not a certificate: {e}")))?;
        if !rest.is_empty() {
            return Err(Error::msg("not a certificate: trailing data"));
        }
        let tbs = &c.tbs_certificate;
        let ext_err = |e: X509Error| Error::msg(format!("a certificate's extensions: {e}"));
        let bc = c.basic_constraints().map_err(ext_err)?;
        let ku = c.key_usage().map_err(ext_err)?;
        let eku = c.extended_key_usage().map_err(ext_err)?;
        let san = c.subject_alternative_name().map_err(ext_err)?;
        let spki = tbs.subject_pki.clone();
        let p256 = spki.algorithm.algorithm.to_id_string() == OID_EC_PUBLIC_KEY
            && spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_some_and(|o| o.to_id_string() == OID_P256);
        Ok(Cert {
            der: der.to_vec(),
            common_name: tbs.subject().iter_common_name().last().and_then(|a| a.as_str().ok()).map(str::to_string),
            dns_names: san
                .map(|s| {
                    s.value
                        .general_names
                        .iter()
                        .filter_map(|n| match n {
                            GeneralName::DNSName(d) => Some(d.to_string()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            not_before: tbs.validity.not_before.timestamp(),
            not_after: tbs.validity.not_after.timestamp(),
            is_ca: bc.as_ref().is_some_and(|b| b.value.ca),
            path_len: bc.as_ref().and_then(|b| b.value.path_len_constraint),
            cert_sign: ku.as_ref().is_some_and(|k| k.value.key_cert_sign()),
            server_auth: eku.as_ref().is_some_and(|e| e.value.server_auth || e.value.any),
            client_auth: eku.as_ref().is_some_and(|e| e.value.client_auth || e.value.any),
            spki: spki.raw.to_vec(),
            p256,
            point: spki.subject_public_key.data.to_vec(),
            tbs: tbs.as_ref().to_vec(),
            ecdsa_sha256: c.signature_algorithm.algorithm.to_id_string() == OID_ECDSA_SHA256,
            sig: c.signature_value.data.to_vec(),
            issuer_name: tbs.issuer.as_raw().to_vec(),
            subject_name: tbs.subject.as_raw().to_vec(),
        })
    }

    /// The hash of the certificate's public key, as records name it.
    pub fn key_hash(&self) -> KeyHash {
        sha256(&self.spki)
    }

    /// The certificate's public key, uncompressed.
    pub fn public_key(&self) -> &[u8] {
        &self.point
    }

    /// Reports whether data carries a valid signature by this
    /// certificate's key (ECDSA P-256 with SHA-256, DER).
    pub fn verifies(&self, data: &[u8], sig: &[u8]) -> bool {
        self.p256 && UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &self.point).verify(data, sig).is_ok()
    }

    /// Reports whether parent signed this certificate.
    pub fn signed_by(&self, parent: &Cert) -> bool {
        self.ecdsa_sha256 && parent.verifies(&self.tbs, &self.sig)
    }

    fn valid_at(&self, t: i64) -> bool {
        self.not_before <= t && t <= self.not_after
    }
}

/// Checks a group CA or root certificate: self-signed, a P-256 key, and a
/// path length from 0 to max_path (Go's checkCA).
pub fn check_ca(c: &Cert, what: &str, max_path: u32) -> Result<()> {
    if !c.is_ca || c.path_len.is_none_or(|n| n > max_path) {
        return Err(Error::msg(format!("the {what} certificate is not a CA with a path length of at most {max_path}")));
    }
    if !c.p256 {
        return Err(Error::msg(format!("the {what} key is not a P-256 key")));
    }
    if !c.signed_by(c) {
        return Err(Error::msg(format!("the {what} certificate is not self-signed")));
    }
    Ok(())
}

/// Checks the new root of a root record: a self-signed CA with path length
/// 1 and a P-256 key.
pub fn check_root(c: &Cert) -> Result<()> {
    check_ca(c, "new root", 1)?;
    if c.path_len != Some(1) || !c.cert_sign {
        return Err(Error::msg("the new root does not certify admin CAs"));
    }
    Ok(())
}

/// Checks that c is an admin CA certified by root: a CA with path length 0
/// and a P-256 key, signed by root, which allows one level of CAs below it.
pub fn check_admin_ca(c: &Cert, root: &Cert) -> Result<()> {
    if !c.is_ca || c.path_len != Some(0) || !c.cert_sign {
        return Err(Error::msg("the signer is not an admin CA"));
    }
    if !c.p256 {
        return Err(Error::msg("the admin CA key is not a P-256 key"));
    }
    if root.path_len.is_none_or(|n| n < 1) {
        return Err(Error::msg("the group CA certifies no admin CAs"));
    }
    if !c.signed_by(root) {
        return Err(Error::msg("the admin CA is not from the group CA"));
    }
    Ok(())
}

/// Returns the device ID a member certificate names: its CN, and exactly one
/// DNS name, cb-<that ID>.local.
pub fn device_of(c: &Cert) -> Result<DeviceId> {
    let id = DeviceId::parse(c.common_name.as_deref().unwrap_or(""))?;
    if c.dns_names.len() != 1 || c.dns_names[0] != id.host_name() {
        return Err(Error::msg(format!("the certificate of {id} does not name {}", id.host_name())));
    }
    Ok(id)
}

/// Verifies a peer's member certificate chain (leaf first, then the admin
/// CA that issued it, if one did) to one of the trusted roots at time t,
/// Unix seconds, for server use, and returns the device it names. The time is max(now, the
/// current root's NotBefore), as Go's verifyTime: a device whose clock is
/// behind still accepts certificates, an expired one is rejected.
pub fn verify_member(chain: &[Cert], trusted: &[Cert], t: i64) -> Result<DeviceId> {
    let leaf = chain.first().ok_or_else(|| Error::msg("the peer sent no certificate"))?;
    if leaf.is_ca {
        return Err(Error::msg("the peer's certificate is a CA"));
    }
    // A lite member only dials, so its peers are servers.
    if !leaf.server_auth || !leaf.valid_at(t) {
        return Err(Error::msg("the peer's certificate is expired or not for this use"));
    }
    let from = |child: &Cert, parent: &Cert| child.issuer_name == parent.subject_name && child.signed_by(parent);
    let mut ok = trusted.iter().any(|root| root.valid_at(t) && from(leaf, root));
    if !ok {
        // Through one admin CA under a root.
        ok = chain[1..].iter().any(|admin| {
            admin.valid_at(t)
                && from(leaf, admin)
                && trusted.iter().any(|root| {
                    root.valid_at(t) && admin.issuer_name == root.subject_name && check_admin_ca(admin, root).is_ok()
                })
        });
    }
    if !ok {
        return Err(Error::msg("the peer's certificate is not from the group"));
    }
    device_of(leaf)
}

/// Serde helpers for byte strings as standard base64, Go's encoding of
/// []byte in JSON.
pub mod b64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = Option::<String>::deserialize(d)?.unwrap_or_default();
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        use super::*;

        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match b {
                Some(b) => s.serialize_str(&STANDARD.encode(b)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(s) => STANDARD.decode(s).map(Some).map_err(serde::de::Error::custom),
                None => Ok(None),
            }
        }
    }

    pub mod list {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for b in v {
                seq.serialize_element(&STANDARD.encode(b))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
            let v = Option::<Vec<String>>::deserialize(d)?.unwrap_or_default();
            v.into_iter().map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom)).collect()
        }
    }

    pub mod hashes {
        use super::*;

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
            let v = Option::<Vec<String>>::deserialize(d)?.unwrap_or_default();
            v.into_iter()
                .map(|s| {
                    let raw = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
                    raw.try_into().map_err(|_| serde::de::Error::custom("a key hash is not 32 bytes"))
                })
                .collect()
        }
    }

    pub mod opt_hash {
        use super::*;

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(s) => {
                    let raw = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
                    raw.try_into().map(Some).map_err(|_| serde::de::Error::custom("a key hash is not 32 bytes"))
                }
                None => Ok(None),
            }
        }
    }
}
