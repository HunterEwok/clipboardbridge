// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust core's group rules for the phone apps (docs/records-v2.md): the
//! iPhone and Android apps call these through UniFFI bindings instead of
//! writing the rules again in Swift and Kotlin. The calls take and give
//! JSON in the forms of testdata/interop/v2-records.json, so the bindings
//! stay small and the apps decode with their own JSON readers.

// As in the core: nothing outside the tests may panic, since a panic here is
// a crash of the phone's app. (UniFFI's scaffolding is unsafe code of its
// own, so unsafe_code is not forbidden here; this crate writes none.)
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::collections::BTreeMap;

use cbb_core::authority::{self, Body, Hash, Input, Record};
use cbb_core::certs::{Cert, b64};
use cbb_core::error::Error;
use serde::Deserialize;

uniffi::setup_scaffolding!();

/// A refusal or a failure: a short message for the user and the details
/// under it (each cause with its type), which the apps show in debug mode
/// and always log.
#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    Failed { message: String, details: String },
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let CoreError::Failed { message, details } = self;
        if details.is_empty() { f.write_str(message) } else { write!(f, "{message}: {details}") }
    }
}

impl std::error::Error for CoreError {}

impl From<Error> for CoreError {
    fn from(e: Error) -> CoreError {
        CoreError::Failed { message: e.message().into(), details: e.details() }
    }
}

fn failed(message: &str, cause: impl std::fmt::Display) -> CoreError {
    CoreError::Failed { message: message.into(), details: cause.to_string() }
}

/// What evaluate_records takes, as a case of v2-records.json holds it.
#[derive(Deserialize)]
struct EvalInput {
    #[serde(with = "b64")]
    group_ca: Vec<u8>,
    group: String,
    now_ms: i64,
    #[serde(default)]
    first_seen: Vec<FirstSeen>,
    records: Vec<Record>,
}

#[derive(Deserialize)]
struct FirstSeen {
    record: Hash,
    ms: i64,
}

/// Evaluates a record set into the group's state. input is JSON:
/// `group_ca` (base64 DER), `group` (its tag), `now_ms` (the phone's clock
/// that counts sleep), `first_seen` (`[{record, ms}]`: when the phone first
/// held each claim) and `records` (`[{body, sig, chain}]`, base64). The
/// result is the state's canonical JSON (docs/records-v2.md, "The state").
/// Records that do not verify are left out, never an error.
#[uniffi::export]
pub fn evaluate_records(input: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    let input: EvalInput = serde_json::from_slice(&input).map_err(|e| failed("The records could not be read.", e))?;
    let ca = Cert::parse(&input.group_ca)?;
    let first_seen: BTreeMap<Hash, i64> = input.first_seen.iter().map(|f| (f.record, f.ms)).collect();
    let state = authority::evaluate(&Input {
        group_ca: &ca,
        group: &input.group,
        records: &input.records,
        now_ms: input.now_ms,
        first_seen: &first_seen,
    });
    Ok(state.encode())
}

/// Turns a record body the app built (any JSON encoder, any order, `v` and
/// `signer` set) into the canonical bytes it signs, after checking every
/// field against its row. The app signs SHA-256 over the result with its
/// root or admin key.
#[uniffi::export]
pub fn canonical_body(json: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    let mut body: Body = serde_json::from_slice(&json).map_err(|e| failed("The record could not be written.", e))?;
    body.sort();
    Ok(body.encode()?)
}

/// Checks a received record body: its size, the canonical form, no unknown
/// or empty field, and each field against its row. It returns the body as
/// it is when it is valid.
#[uniffi::export]
pub fn check_body(body: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    Body::parse(&body)?;
    Ok(body)
}

/// The canonical form of a signed body in the strict form, for the other
/// signed files of version 2.
#[uniffi::export]
pub fn canonicalize(body: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    Ok(cbb_core::strict::canonicalize(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/interop/v2-records.json");
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    /// The calls give the vectors' states from the vectors' JSON as it is.
    #[test]
    fn evaluates_the_vectors() {
        let v = vectors();
        for c in v["cases"].as_array().unwrap() {
            let got = evaluate_records(serde_json::to_vec(c).unwrap()).unwrap();
            assert_eq!(std::str::from_utf8(&got).unwrap(), c["state"].as_str().unwrap(), "{}", c["name"]);
        }
    }

    /// A body built in any order comes back canonical and checks.
    #[test]
    fn writes_and_checks_bodies() {
        let v = vectors();
        let body = v["cases"][0]["records"][0]["body"].as_str().unwrap();
        let body = base64_decode(body);
        let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        assert_eq!(canonical_body(pretty).unwrap(), body);
        assert_eq!(check_body(body.clone()).unwrap(), body);
        value["v"] = 1.into();
        let err = canonical_body(serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert!(err.to_string().contains("version 1"), "{err}");
        assert!(check_body(b"{}".to_vec()).is_err());
        assert!(evaluate_records(b"[]".to_vec()).is_err());
    }

    fn base64_decode(s: &str) -> Vec<u8> {
        #[derive(Deserialize)]
        struct B(#[serde(with = "b64")] Vec<u8>);
        serde_json::from_value::<B>(serde_json::Value::String(s.into())).unwrap().0
    }
}
