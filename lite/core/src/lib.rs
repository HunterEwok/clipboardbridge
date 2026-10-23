// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The protocol core of the clipboardbridge lite member (docs/protocol.md):
//! certificates and their checks, the signed records, the hybrid clock, the
//! sync engine, the frames of the member protocol and the joiner's side of
//! the pairing. It does no I/O and needs no operating system, only an
//! allocator and a source of randomness, so the same code runs in cbb-lite
//! on Linux and on a microcontroller such as the ESP32.
//!
//! With the tls feature it has the members' TLS as well (rustls without
//! the standard library, a RustCrypto provider and a session without I/O).
//!
//! Randomness comes from the getrandom crate: on Linux from the kernel, on a
//! microcontroller from the function the firmware registers as getrandom's
//! custom backend. Without the std feature the locks are spin locks.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

pub mod certs;
pub mod clip;
pub mod error;
pub mod hlc;
pub mod identity;
pub mod pair;
pub mod records;
pub mod sync;
pub mod third_party {
    pub mod cpace;
}
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(test)]
mod vectors;
pub mod wire;
