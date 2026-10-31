// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The core's one entry point (docs/core-api.md): a request in bytes, an
//! answer in bytes. Every program that uses the core's rules (the phones
//! through UniFFI, Go through cgo or wasm) calls `call` and nothing else,
//! so the bindings stay one function wide and the request's ABI version
//! says which shape of request and answer both sides speak.
//!
//! A request is a JSON object `{"abi": 1, "op": "...", "args": {...}}`. The
//! answer is `{"abi": 1, "ok": ...}` or `{"abi": 1, "error": {"code": n,
//! "name": "...", "message": "...", "details": "..."}}`, where code and name
//! are stable and listed in Code. `call` never panics on any input and
//! always answers.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::Value;

use crate::authority::{self, Body, Hash, Input, Record};
use crate::certs::{Cert, b64};
use crate::error::Error;
use crate::strict;

/// The version of the request and answer shapes. A change that an older
/// caller would misread raises it; the core answers only its own version.
pub const ABI: u32 = 1;

/// The largest request the core reads, in bytes: far above any group's
/// records, and small enough for a microcontroller to refuse early.
pub const MAX_REQUEST: usize = 8 << 20;

/// The core's version, as its crate states it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The commit the core was built from, when the build passes it in
/// `CBB_SOURCE` (the release builds and CI do); empty otherwise.
pub const SOURCE: &str = match option_env!("CBB_SOURCE") {
    Some(s) => s,
    None => "",
};

/// The error codes of an answer. The numbers and names never change
/// meaning; new ones are added at the end of their range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Code {
    /// The request is not a JSON object of the right shape, or an argument
    /// is missing or of the wrong type.
    Request = 1,
    /// The request's ABI version is not the core's.
    Abi = 2,
    /// The request names an operation the core does not have.
    Op = 3,
    /// The request is larger than MAX_REQUEST.
    TooLarge = 4,
    /// A record body is refused: its size, form or a field.
    Body = 10,
    /// A certificate is refused.
    Cert = 11,
    /// A signed body is not in the strict canonical form.
    Strict = 12,
}

impl Code {
    /// The code's stable name.
    pub fn name(self) -> &'static str {
        match self {
            Code::Request => "request",
            Code::Abi => "abi",
            Code::Op => "op",
            Code::TooLarge => "too_large",
            Code::Body => "body",
            Code::Cert => "cert",
            Code::Strict => "strict",
        }
    }
}

/// A refused request: its code, and the core's error with the message for
/// the user and the details under it.
struct Refusal {
    code: Code,
    err: Error,
}

fn refuse(code: Code, err: Error) -> Refusal {
    Refusal { code, err }
}

fn bad_args(e: serde_json::Error) -> Refusal {
    refuse(Code::Request, Error::with("The request's arguments could not be read.", e))
}

#[derive(Deserialize)]
struct Request {
    abi: u32,
    op: String,
    #[serde(default)]
    args: Value,
}

/// Answers one request. It never panics and always returns an answer in
/// the shape above, also for bytes that are not a request at all.
pub fn call(request: &[u8]) -> Vec<u8> {
    let result = if request.len() > MAX_REQUEST {
        Err(refuse(Code::TooLarge, Error::msg("The request is too large.")))
    } else {
        serde_json::from_slice::<Request>(request)
            .map_err(|e| refuse(Code::Request, Error::with("The request could not be read.", e)))
            .and_then(|r| {
                if r.abi != ABI {
                    return Err(refuse(
                        Code::Abi,
                        Error::msg(alloc::format!(
                            "The request is for version {} of the core's calls, this core has {ABI}.",
                            r.abi
                        )),
                    ));
                }
                dispatch(&r.op, r.args)
            })
    };
    let mut out = alloc::format!("{{\"abi\":{ABI},");
    match result {
        Ok(ok) => {
            out.push_str("\"ok\":");
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(&ok);
            bytes.push(b'}');
            bytes
        }
        Err(r) => {
            let mut err = BTreeMap::new();
            err.insert("code".to_string(), Value::from(r.code as u32));
            err.insert("name".to_string(), Value::from(r.code.name()));
            err.insert("message".to_string(), Value::from(r.err.message()));
            err.insert("details".to_string(), Value::from(r.err.details()));
            out.push_str("\"error\":");
            let mut bytes = out.into_bytes();
            strict::write_canonical(&mut bytes, &Value::Object(err.into_iter().collect()));
            bytes.push(b'}');
            bytes
        }
    }
}

/// Runs one operation and gives its result as JSON bytes.
fn dispatch(op: &str, args: Value) -> Result<Vec<u8>, Refusal> {
    match op {
        "version" => Ok(version()),
        "evaluate" => evaluate(serde_json::from_value(args).map_err(bad_args)?),
        "canonical_body" => canonical_body(args),
        "check_body" => check_body(serde_json::from_value(args).map_err(bad_args)?),
        "canonicalize" => canonicalize(serde_json::from_value(args).map_err(bad_args)?),
        _ => Err(refuse(Code::Op, Error::msg(alloc::format!("The core has no call named {op:?}.")))),
    }
}

fn json(v: Value) -> Vec<u8> {
    let mut out = Vec::new();
    strict::write_canonical(&mut out, &v);
    out
}

fn b64_value(data: &[u8]) -> Value {
    use base64::Engine as _;
    Value::from(base64::engine::general_purpose::STANDARD.encode(data))
}

/// `version`: the ABI, the core's version and the commit it was built from.
fn version() -> Vec<u8> {
    let mut m = serde_json::Map::new();
    m.insert("abi".into(), Value::from(ABI));
    m.insert("core".into(), Value::from(VERSION));
    if !SOURCE.is_empty() {
        m.insert("source".into(), Value::from(SOURCE));
    }
    json(Value::Object(m))
}

/// The arguments of `evaluate`, as a case of v2-records.json holds them.
#[derive(Deserialize)]
struct EvalArgs {
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

/// `evaluate`: the group's state from a record set (docs/records-v2.md,
/// "The state"). Records that do not verify are left out, never an error.
fn evaluate(a: EvalArgs) -> Result<Vec<u8>, Refusal> {
    let ca = Cert::parse(&a.group_ca)
        .map_err(|e| refuse(Code::Cert, e.context("The group's certificate could not be read.")))?;
    let first_seen: BTreeMap<Hash, i64> = a.first_seen.iter().map(|f| (f.record, f.ms)).collect();
    let state = authority::evaluate(&Input {
        group_ca: &ca,
        group: &a.group,
        records: &a.records,
        now_ms: a.now_ms,
        first_seen: &first_seen,
    });
    Ok(state.encode())
}

/// `canonical_body`: a body the caller built (any order, `v` and `signer`
/// set) as the canonical bytes it signs, after each field is checked
/// against its row. The answer is `{"body": base64}`.
fn canonical_body(args: Value) -> Result<Vec<u8>, Refusal> {
    let mut body: Body = serde_json::from_value(args)
        .map_err(|e| refuse(Code::Body, Error::with("The record could not be written.", e)))?;
    body.sort();
    let bytes = body.encode().map_err(|e| refuse(Code::Body, e))?;
    Ok(json(body_answer(&bytes)))
}

fn body_answer(bytes: &[u8]) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("body".into(), b64_value(bytes));
    Value::Object(m)
}

#[derive(Deserialize)]
struct BodyArgs {
    #[serde(with = "b64")]
    body: Vec<u8>,
}

/// `check_body`: checks a received body (its size, the canonical form, no
/// unknown or empty field, each field against its row) and answers with
/// the body as it is.
fn check_body(a: BodyArgs) -> Result<Vec<u8>, Refusal> {
    Body::parse(&a.body).map_err(|e| refuse(Code::Body, e))?;
    Ok(json(body_answer(&a.body)))
}

/// `canonicalize`: the strict canonical form of a signed body, for the
/// other signed files of version 2.
fn canonicalize(a: BodyArgs) -> Result<Vec<u8>, Refusal> {
    let bytes = strict::canonicalize(&a.body).map_err(|e| refuse(Code::Strict, e))?;
    Ok(json(body_answer(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn vectors() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/interop/v2-records.json");
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    fn ask(op: &str, args: Value) -> Value {
        let req = serde_json::json!({"abi": ABI, "op": op, "args": args});
        let out = call(&serde_json::to_vec(&req).unwrap());
        serde_json::from_slice(&out).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out)))
    }

    fn code(answer: &Value) -> u64 {
        assert_eq!(answer["abi"], ABI);
        assert!(answer.get("ok").is_none(), "{answer}");
        let e = &answer["error"];
        assert!(!e["message"].as_str().unwrap().is_empty(), "{answer}");
        e["code"].as_u64().unwrap()
    }

    /// evaluate gives each case's state from the case's own JSON.
    #[test]
    fn evaluates_the_vectors() {
        for c in vectors()["cases"].as_array().unwrap() {
            let req = serde_json::json!({"abi": ABI, "op": "evaluate", "args": c});
            let out = call(&serde_json::to_vec(&req).unwrap());
            let want = alloc::format!("{{\"abi\":{ABI},\"ok\":{}}}", c["state"].as_str().unwrap());
            assert_eq!(String::from_utf8(out).unwrap(), want, "{}", c["name"]);
        }
    }

    /// A body built in any order comes back canonical and checks; the
    /// refusals carry their codes.
    #[test]
    fn writes_and_checks_bodies() {
        let v = vectors();
        let b64 = v["cases"][0]["records"][0]["body"].clone();
        let body = base64::engine::general_purpose::STANDARD.decode(b64.as_str().unwrap()).unwrap();
        let mut value: Value = serde_json::from_slice(&body).unwrap();
        let ok = ask("canonical_body", value.clone());
        assert_eq!(ok["ok"]["body"], b64);
        let ok = ask("check_body", serde_json::json!({"body": b64}));
        assert_eq!(ok["ok"]["body"], b64);
        let ok = ask("canonicalize", serde_json::json!({"body": b64}));
        assert_eq!(ok["ok"]["body"], b64);

        value["v"] = 1.into();
        let refused = ask("canonical_body", value);
        assert_eq!(code(&refused), Code::Body as u64);
        assert!(refused["error"]["message"].as_str().unwrap().contains("version 1"), "{refused}");
        let empty = base64::engine::general_purpose::STANDARD.encode(b"{}");
        assert_eq!(code(&ask("check_body", serde_json::json!({"body": empty}))), Code::Body as u64);
        let cut = base64::engine::general_purpose::STANDARD.encode(b"{\"a\":");
        assert_eq!(code(&ask("canonicalize", serde_json::json!({"body": cut}))), Code::Strict as u64);
        assert_eq!(
            code(&ask("evaluate", serde_json::json!({"group_ca": "AAAA", "group": "x", "now_ms": 0, "records": []}))),
            Code::Cert as u64
        );
    }

    /// Requests of the wrong shape, version or size are refused with their
    /// codes, and any bytes at all get an answer.
    #[test]
    fn refuses_bad_requests() {
        let read = |b: &[u8]| -> Value { serde_json::from_slice(&call(b)).unwrap() };
        assert_eq!(code(&read(b"")), Code::Request as u64);
        assert_eq!(code(&read(b"\xff\x00[")), Code::Request as u64);
        assert_eq!(code(&read(b"[]")), Code::Request as u64);
        assert_eq!(code(&read(br#"{"abi":2,"op":"version"}"#)), Code::Abi as u64);
        assert_eq!(code(&read(br#"{"abi":1,"op":"nothing"}"#)), Code::Op as u64);
        assert_eq!(code(&read(br#"{"abi":1,"op":"evaluate","args":{}}"#)), Code::Request as u64);
        assert_eq!(code(&read(&alloc::vec![b' '; MAX_REQUEST + 1])), Code::TooLarge as u64);
        let names: Vec<_> = [Code::Request, Code::Abi, Code::Op, Code::TooLarge, Code::Body, Code::Cert, Code::Strict]
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, ["request", "abi", "op", "too_large", "body", "cert", "strict"]);
    }

    /// version names the ABI and the core's version.
    #[test]
    fn tells_its_version() {
        let v = ask("version", Value::Null);
        assert_eq!(v["ok"]["abi"], ABI);
        assert_eq!(v["ok"]["core"], VERSION);
    }
}
