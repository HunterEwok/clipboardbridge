// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The local control socket (docs/protocol.md, section 8): a JSON header on
//! one line, then exactly len bytes of payload. The lite member serves the
//! operations a member without CA keys has: copy, paste, status, devices
//! and watch, so the Go command line and connectors can talk to it too.

use std::io::{BufRead, BufReader, Read, Write};

use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};

const MAX_HEADER: usize = 64 << 10;
const MAX_PAYLOAD: usize = (1 << 20) + 64;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Header {
    #[serde(default)]
    pub op: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub via: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub seq: u64,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub ttl_ms: i64,
    #[serde(default, skip_serializing_if = "is_zero_us")]
    pub len: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// The causes behind error, for debug mode; Go clients ignore it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub details: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub done: bool,
    /// cbb global on: the user agreed to what the warning says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub consent: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}
fn is_zero_i(n: &i64) -> bool {
    *n == 0
}
fn is_zero_us(n: &usize) -> bool {
    *n == 0
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Status {
    pub device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<Device>,
    pub version: String,
    /// Sync away from home; None while it is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub away: Option<Away>,
}

/// Sync away from home on a client of the group's hub, with the names of
/// the Go service's status.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Away {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// The hub; empty until it offered its tunnel.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hub_device: String,
    /// Connected to the hub through the tunnel now.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub through: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keys_in_file: bool,
    /// What went wrong last, for the user.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// The underlying error, for debugging.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Device {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub skew_ms: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admin: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub online: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[serde(rename = "self")]
    pub this: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub listed: bool,
}

/// A header and its payload.
#[derive(Default, Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(header: Header, payload: Vec<u8>) -> Message {
        Message { header, payload }
    }
}

/// Writes one message.
pub fn write(w: &mut impl Write, m: &Message) -> Result<()> {
    if m.payload.len() > MAX_PAYLOAD {
        return Err(Error::msg("the text is larger than 1 MiB"));
    }
    let mut h = m.header.clone();
    h.len = m.payload.len();
    let mut buf = serde_json::to_vec(&h).context("cannot encode a message")?;
    if buf.len() > MAX_HEADER {
        return Err(Error::msg("the header is too long"));
    }
    buf.push(b'\n');
    buf.extend_from_slice(&m.payload);
    w.write_all(&buf).context("the connection to the service broke")?;
    w.flush().context("the connection to the service broke")
}

/// Reads messages from a connection.
pub struct Reader<R: Read> {
    r: BufReader<R>,
}

impl<R: Read> Reader<R> {
    pub fn new(r: R) -> Reader<R> {
        Reader { r: BufReader::new(r) }
    }

    /// Reads one message; None at the end of the stream.
    pub fn read(&mut self) -> Result<Option<Message>> {
        let mut line = Vec::new();
        let n =
            (&mut self.r).take(MAX_HEADER as u64 + 1).read_until(b'\n', &mut line).context("the connection broke")?;
        if n == 0 {
            return Ok(None);
        }
        if line.last() != Some(&b'\n') {
            return Err(Error::msg("the header is too long"));
        }
        let header: Header = serde_json::from_slice(&line).context("a bad header")?;
        if header.len > MAX_PAYLOAD {
            return Err(Error::msg(format!("a bad payload length {}", header.len)));
        }
        let mut payload = vec![0; header.len];
        self.r.read_exact(&mut payload).context("the connection broke")?;
        Ok(Some(Message { header, payload }))
    }
}

/// The answer to a request: op reply, done.
pub fn reply(header: Header, payload: Vec<u8>) -> Message {
    Message::new(Header { op: "reply".into(), done: true, ..header }, payload)
}

/// A failed request.
pub fn failure(e: &Error) -> Message {
    reply(Header { error: e.message().to_string(), details: e.details(), ..Default::default() }, Vec::new())
}

/// Whether an operation changes the group or this device's place in it, so
/// that the service takes it only on the admin socket, which only root and
/// the service's own user reach, as on a full member.
pub fn is_admin(op: &str) -> bool {
    !matches!(
        op,
        "copy" | "paste" | "status" | "devices" | "watch" | "copied" | "clipboard" | "answer" | "reply" | "write"
    )
}

/// The admin socket next to the control socket at `socket`.
pub fn admin_socket(socket: &std::path::Path) -> std::path::PathBuf {
    socket.with_file_name("admin.sock")
}
