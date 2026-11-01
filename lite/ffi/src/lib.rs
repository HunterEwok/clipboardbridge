// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust core's one entry point for the phone apps (docs/core-api.md):
//! the iPhone and Android apps call `call` through UniFFI bindings instead
//! of writing the group's rules again in Swift and Kotlin. A request and
//! its answer are JSON bytes, so the binding stays one function wide and
//! the apps decode with their own JSON readers.

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

uniffi::setup_scaffolding!();

/// Answers one request of the core (docs/core-api.md). It never fails: a
/// refusal is an answer with an error code, a message for the user and
/// the details under it, which the apps show in debug mode and always log.
#[uniffi::export]
pub fn call(request: Vec<u8>) -> Vec<u8> {
    cbb_core::api::call(&request)
}

/// The version of the request and answer shapes this library speaks.
#[uniffi::export]
pub fn abi() -> u32 {
    cbb_core::api::ABI
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The binding answers as the core does.
    #[test]
    fn answers_as_the_core() {
        let req = format!(r#"{{"abi":{},"op":"version"}}"#, abi());
        let answer: serde_json::Value = serde_json::from_slice(&call(req.into_bytes())).unwrap();
        assert_eq!(answer["ok"]["abi"], abi());
        let answer: serde_json::Value = serde_json::from_slice(&call(b"nonsense".to_vec())).unwrap();
        assert_eq!(answer["error"]["name"], "request");
    }
}
