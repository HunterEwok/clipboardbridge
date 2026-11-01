// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust core's one entry point for the phone apps (docs/core-api.md):
//! the iPhone and Android apps call `call` through UniFFI bindings instead
//! of writing the group's rules again in Swift and Kotlin. A request and
//! its answer are JSON bytes, so the binding stays one function wide and
//! the apps decode with their own JSON readers.
//!
//! The same entry point is a plain C function too, `cbb_call`, declared in
//! `include/cbb_core.h`: Go links it through cgo and the Swift kit through
//! that header, so neither needs generated bindings.

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

/// The C form of `abi`.
#[unsafe(no_mangle)]
pub extern "C" fn cbb_abi() -> u32 {
    cbb_core::api::ABI
}

/// The C form of `call`: answers the `len` bytes at `request` with bytes
/// the caller owns and gives back with `cbb_free`, their length written to
/// `answer_len`. A null `request` with `len` 0 is an empty request. It
/// returns null only when `answer_len` is null or `request` is null with a
/// length.
///
/// # Safety
///
/// `request` must point to `len` readable bytes (or be null with `len`
/// 0) and `answer_len` to a writable `size_t`, for the time of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_call(request: *const u8, len: usize, answer_len: *mut usize) -> *mut u8 {
    if answer_len.is_null() || (request.is_null() && len != 0) {
        return core::ptr::null_mut();
    }
    let req: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: the caller gives len readable bytes at request, not null.
        unsafe { core::slice::from_raw_parts(request, len) }
    };
    let answer = cbb_core::api::call(req).into_boxed_slice();
    // SAFETY: the caller gives a writable size_t at answer_len, not null.
    unsafe { answer_len.write(answer.len()) };
    Box::into_raw(answer).cast::<u8>()
}

/// Gives back an answer of `cbb_call`, with the length it wrote. Null does
/// nothing.
///
/// # Safety
///
/// `answer` must be null or what `cbb_call` returned, with its length, and
/// not given back before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_free(answer: *mut u8, len: usize) {
    if answer.is_null() {
        return;
    }
    // SAFETY: answer and len are a boxed slice cbb_call let go of.
    drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(answer, len)) });
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

    /// The C functions answer as the core does, give the answer back, and
    /// refuse null pointers without reading them.
    #[test]
    fn answers_through_c() {
        assert_eq!(cbb_abi(), abi());
        let req = format!(r#"{{"abi":{},"op":"version"}}"#, abi()).into_bytes();
        let mut n = 0usize;
        // SAFETY: req and n live for the call; the answer is freed once.
        let got = unsafe {
            let p = cbb_call(req.as_ptr(), req.len(), &mut n);
            assert!(!p.is_null());
            let got = core::slice::from_raw_parts(p, n).to_vec();
            cbb_free(p, n);
            got
        };
        assert_eq!(got, call(req.clone()));
        // SAFETY: null pointers are refused or read as an empty request.
        unsafe {
            assert!(cbb_call(req.as_ptr(), 0, core::ptr::null_mut()).is_null());
            assert!(cbb_call(core::ptr::null(), 3, &mut n).is_null());
            let p = cbb_call(core::ptr::null(), 0, &mut n);
            let answer: serde_json::Value = serde_json::from_slice(core::slice::from_raw_parts(p, n)).unwrap();
            assert_eq!(answer["error"]["name"], "request");
            cbb_free(p, n);
            cbb_free(core::ptr::null_mut(), 0);
        }
    }

    /// include/cbb_core.h declares the C functions this library exports.
    #[test]
    fn the_header_declares_them() {
        let h = include_str!("../include/cbb_core.h");
        for decl in [
            "uint32_t cbb_abi(void);",
            "uint8_t *cbb_call(const uint8_t *request, size_t len, size_t *answer_len);",
            "void cbb_free(uint8_t *answer, size_t len);",
        ] {
            assert!(h.contains(decl), "{decl}");
        }
    }
}
