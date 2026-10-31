// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The readers of network input, for the cargo fuzz targets in fuzz/ (the
//! feature `fuzzing`): each reads one body and checks what holds of every
//! body it takes.

/// A record's body: one it takes is in the strict form.
pub fn record_body(data: &[u8]) {
    if crate::records::Body::parse(data).is_ok() {
        assert!(
            crate::strict::check(data, &["v", "type", "group", "time_ms"]).is_ok(),
            "took a record not in the strict form"
        );
    }
}

/// A command's body: one it takes is in the strict form.
pub fn command(data: &[u8]) {
    if crate::records::Command::parse(data).is_ok() {
        assert!(
            crate::strict::check(data, &["v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"]).is_ok(),
            "took a command not in the strict form"
        );
    }
}

/// A server credential's body.
pub fn credential(data: &[u8]) {
    let _ = crate::credential::Body::parse(data);
}

/// The files of a release: keys.json, release.json and a channel's file.
pub fn release(data: &[u8]) {
    let _ = crate::release::decode_keys(data);
    let _ = crate::release::decode_release(data);
    let _ = crate::release::decode_channel(data);
}

/// A member protocol frame's payload and a manifest.
pub fn wire(data: &[u8]) {
    let _ = serde_json::from_slice::<crate::media::Manifest>(data).map(|m| m.validate());
    let _ = crate::wire::decode(data);
}
