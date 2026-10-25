// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The frames of the member protocol (docs/protocol.md, section 4): a
//! 4-byte big-endian length and a JSON message.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

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
    /// In a tunnel message, the group's hub's offer (section 11), decoded
    /// on its own with [`TunnelOffer`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<Value>,
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
    /// The sender's operating system, as device records name it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    /// What the sender says about its device, for showing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<Value>,
    /// The sender's WireGuard public key, for the group's hub (section 11);
    /// absent while sync away from home is off on it.
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub tunnel_key: Option<Vec<u8>>,
}

/// What a hello says about the sender's device (section 4, "Device"): its
/// form, its system's version, its own version and its network card's MAC
/// address. Shown, never trusted; any field may be empty.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct DeviceInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub form: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
}

/// The forms a device may name, for its icon.
pub const FORMS: [&str; 12] =
    ["laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other"];

impl DeviceInfo {
    /// The same without its invalid fields: an unknown form, a version
    /// longer than 32 bytes or with control characters, a MAC address other
    /// than six lowercase hex bytes with colons.
    pub fn cleaned(&self) -> DeviceInfo {
        let short =
            |s: &str| if s.len() <= 32 && !s.chars().any(char::is_control) { s.to_string() } else { String::new() };
        let mac_ok = self.mac.len() == 17
            && self.mac.split(':').count() == 6
            && self
                .mac
                .split(':')
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        DeviceInfo {
            form: if FORMS.contains(&self.form.as_str()) { self.form.clone() } else { String::new() },
            os_version: short(&self.os_version),
            version: short(&self.version),
            mac: if mac_ok { self.mac.clone() } else { String::new() },
        }
    }

    /// Whether it says nothing.
    pub fn is_empty(&self) -> bool {
        *self == DeviceInfo::default()
    }

    /// The device of a hello's body, cleaned; empty when it has none or it
    /// does not decode.
    pub fn of(body: &HelloBody) -> DeviceInfo {
        body.device
            .as_ref()
            .and_then(|v| serde_json::from_value::<DeviceInfo>(v.clone()).ok())
            .map(|d| d.cleaned())
            .unwrap_or_default()
    }
}

/// The group's hub's offer for a member's tunnel key (section 11).
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct TunnelOffer {
    #[serde(with = "b64")]
    pub hub_key: Vec<u8>,
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// AmneziaWG's settings, when the hub's tunnel is obfuscated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<Value>,
    /// The way to the hub's forwarder over VLESS, then the only way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless: Option<Value>,
}

/// The roles a peer may claim.
pub fn known_role(r: &str) -> bool {
    matches!(r, "full" | "phone" | "lite")
}

/// A hello message from a lite member running on `os` (`"linux"`, or
/// `"none"` for firmware) with what it says about its device, with its
/// tunnel key while sync away from home is on.
pub fn hello(
    h: &Hello,
    records: String,
    name: &str,
    os: &str,
    device: &DeviceInfo,
    tunnel_key: Option<&[u8]>,
) -> Message {
    let device = device.cleaned();
    let body = HelloBody {
        wall: h.wall,
        current: h.current.as_ref().map(|e| serde_json::to_value(e).unwrap()),
        records,
        name: name.to_string(),
        os: os.to_string(),
        device: if device.is_empty() { None } else { Some(serde_json::to_value(&device).unwrap()) },
        tunnel_key: tunnel_key.map(<[u8]>::to_vec),
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

/// Encodes v as a frame of at most max bytes of JSON.
pub fn json_frame<T: Serialize>(v: &T, max: usize) -> Result<Vec<u8>> {
    let data = serde_json::to_vec(v).context("cannot encode a frame")?;
    if data.len() > max {
        return Err(Error::msg("the frame is too large"));
    }
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&data);
    Ok(out)
}

/// Reads the length of a frame from its first four bytes, and checks that
/// it is at most max.
pub fn frame_len(head: [u8; 4], max: usize) -> Result<usize> {
    let size = u32::from_be_bytes(head) as usize;
    if size > max {
        return Err(Error::msg(format!("a frame of {size} bytes is too large")));
    }
    Ok(size)
}
