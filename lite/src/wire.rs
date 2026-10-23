// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The frames of the member protocol (docs/protocol.md, section 4): a
//! 4-byte big-endian length and a JSON message.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::certs::b64;
use crate::clip::{Event, Hello};
use crate::error::{Context, Error, Result};
use crate::records::Record;

/// The largest frame.
pub const MAX_FRAME: usize = 7 << 20;

/// One message of the member protocol. The hello and the event are decoded
/// on their own, so an event this member cannot read, for example from a
/// newer version, is dropped without ending the connection.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Message {
    #[serde(rename = "t", default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hello: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Value>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Record>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub admin_ca: Option<Vec<u8>>,
}

/// The content of a hello.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct HelloBody {
    #[serde(rename = "wall_ms", default)]
    pub wall: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub records: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

/// The roles a peer may claim.
pub fn known_role(r: &str) -> bool {
    matches!(r, "linux" | "mac" | "phone" | "lite")
}

/// A hello message.
pub fn hello(h: &Hello, records: String, name: &str) -> Message {
    let body = HelloBody {
        wall: h.wall,
        current: h.current.as_ref().map(|e| serde_json::to_value(e).unwrap()),
        records,
        name: name.to_string(),
    };
    Message {
        kind: "hello".into(),
        role: "lite".into(),
        hello: Some(serde_json::to_value(body).unwrap()),
        ..Default::default()
    }
}

/// An event message.
pub fn event(ev: &Event) -> Message {
    Message { kind: "event".into(), event: Some(serde_json::to_value(ev).unwrap()), ..Default::default() }
}

/// A message with only its type, such as a ping or a goodbye.
pub fn bare(kind: &str) -> Message {
    Message { kind: kind.into(), ..Default::default() }
}

/// Decodes a hello and returns the rest of it as it came. A current event
/// that does not decode, for example from a newer version, counts as none.
pub fn decode_hello(v: Option<&Value>) -> Result<(Hello, HelloBody)> {
    let v = v.filter(|v| v.is_object()).ok_or_else(|| Error::msg("the hello does not decode"))?;
    let b: HelloBody = serde_json::from_value(v.clone()).context("the hello does not decode")?;
    let current =
        b.current.as_ref().filter(|c| !c.is_null()).and_then(|c| serde_json::from_value::<Event>(c.clone()).ok());
    Ok((Hello { wall: b.wall, current }, b))
}

/// Encodes a message as a frame.
pub fn frame(m: &Message) -> Result<Vec<u8>> {
    let data = serde_json::to_vec(m).context("cannot encode a message")?;
    if data.len() > MAX_FRAME {
        return Err(Error::msg("the message is too large"));
    }
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&data);
    Ok(out)
}

/// Writes one frame of at most max bytes of JSON.
pub fn write_json<T: Serialize>(w: &mut impl Write, v: &T, max: usize) -> Result<()> {
    let data = serde_json::to_vec(v).context("cannot encode a frame")?;
    if data.len() > max {
        return Err(Error::msg("the frame is too large"));
    }
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&data);
    w.write_all(&out).context("the connection broke")?;
    w.flush().context("the connection broke")
}

/// Reads one frame of at most max bytes and decodes it.
pub fn read_json<T: for<'de> Deserialize<'de>>(r: &mut impl Read, max: usize) -> Result<T> {
    let mut n = [0u8; 4];
    r.read_exact(&mut n).context("the connection broke")?;
    let size = u32::from_be_bytes(n) as usize;
    if size > max {
        return Err(Error::msg(format!("a frame of {size} bytes is too large")));
    }
    // Read the body as it arrives rather than trusting the length.
    let mut data = Vec::new();
    r.take(size as u64).read_to_end(&mut data).context("the connection broke")?;
    if data.len() != size {
        return Err(Error::msg("the connection broke in the middle of a frame"));
    }
    serde_json::from_slice(&data).context("a frame is not a message")
}
