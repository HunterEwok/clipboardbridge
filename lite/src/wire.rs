// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The frames of the member protocol over a stream (cbb_core::wire has the
//! messages).

use std::io::Read;

use serde::Deserialize;

pub use cbb_core::wire::*;

use crate::error::{Context, Error, Result};

/// Reads one frame of at most max bytes and returns its JSON.
pub fn read_frame(r: &mut (impl Read + ?Sized), max: usize) -> Result<Vec<u8>> {
    let mut n = [0u8; 4];
    r.read_exact(&mut n).context("the connection broke")?;
    let size = frame_len(n, max)?;
    // Read the body as it arrives rather than trusting the length.
    let mut data = Vec::new();
    r.take(size as u64).read_to_end(&mut data).context("the connection broke")?;
    if data.len() != size {
        return Err(Error::msg("the connection broke in the middle of a frame"));
    }
    Ok(data)
}

/// Reads one frame of at most max bytes and decodes it.
pub fn read_json<T: for<'de> Deserialize<'de>>(r: &mut impl Read, max: usize) -> Result<T> {
    serde_json::from_slice(&read_frame(r, max)?).context("a frame is not a message")
}
