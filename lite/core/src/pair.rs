// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group (docs/protocol.md, section 6): the joiner's side of the
//! pairing exchange, CPace and the Welcome, which runs inside TLS. This
//! module only decides; the program runs the TLS connection and passes the
//! frames (see [`Exchange`]).
//!
//! A lite member joins as a Mac does, without CA keys: either it listens and
//! shows a QR code that the phone app scans (the phone, or a Linux member
//! for the shortcut, dials it and confirms first), or it dials a Linux
//! member's open pairing window with the code that cbb pair shows.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::certs::{self, Cert, DeviceId, b64};
use crate::error::{Context, Error, Result, Wrap};
use crate::identity::{self, Identity};
use crate::third_party::cpace;
use crate::wire;

/// The TLS exporter label that binds the exchange to the connection.
pub const EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL-clipboardbridge-pair-v1";
const CHANNEL_PREFIX: &[u8] = b"clipboardbridge pair v1\x00";
/// The largest frame of the exchange.
pub const MAX_FRAME: usize = 64 << 10;
/// How many wrong codes a listening join takes.
pub const MAX_FAILURES: u32 = 3;

/// The joiner's CPace associated data. The role tells the admitting member
/// that this is a lite member, which gets no CA keys and is listed as lite.
#[derive(Serialize)]
struct Info<'a> {
    name: &'a str,
    os: &'a str,
    role: &'a str,
}

/// The member's CPace associated data.
#[derive(Deserialize)]
struct MemberAd {
    device: String,
    group: String,
}

/// What a new device receives after a successful exchange.
#[derive(Deserialize, Default)]
struct Welcome {
    #[serde(with = "b64", default)]
    cert: Vec<u8>,
    #[serde(with = "b64::opt", default)]
    issuer: Option<Vec<u8>>,
    #[serde(with = "b64", default)]
    group_ca: Vec<u8>,
    #[serde(with = "b64::list", default)]
    roots: Vec<Vec<u8>>,
    #[serde(with = "b64::opt", default)]
    group_ca_key: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default)]
    phone_ca: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default)]
    phone_ca_key: Option<Vec<u8>>,
}

impl Welcome {
    /// Reports whether the Welcome carries CA keys, which the member sends
    /// only to a computer it makes an admin.
    fn holds_ca_keys(&self) -> bool {
        self.group_ca_key.is_some() || self.phone_ca.is_some() || self.phone_ca_key.is_some()
    }
}

/// Every frame of the exchange; each uses some of the fields.
#[derive(Serialize, Deserialize, Default)]
struct Frame {
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    msg: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    ad: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    tag: Option<Vec<u8>>,
    #[serde(default, skip_serializing)]
    welcome: Option<Welcome>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    ok: bool,
}

/// Why a pairing failed, by the codes that travel in frames.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Refusal {
    WrongCode,
    Closed,
    Busy,
    Expired,
    TooMany,
    Refused,
}

impl Refusal {
    /// The refusal a frame's error code names.
    pub fn of(code: &str) -> Refusal {
        match code {
            "wrong-code" => Refusal::WrongCode,
            "closed" => Refusal::Closed,
            "busy" => Refusal::Busy,
            "expired" => Refusal::Expired,
            "too-many" => Refusal::TooMany,
            _ => Refusal::Refused, // the peer's own words are never shown
        }
    }

    /// The message for the user.
    pub fn message(self) -> &'static str {
        match self {
            Refusal::WrongCode => "wrong code",
            Refusal::Closed => "the pairing window is closed",
            Refusal::Busy => "another device is pairing; try again in a minute",
            Refusal::Expired => "the pairing window expired",
            Refusal::TooMany => "three failed attempts; the pairing window is closed",
            Refusal::Refused => "the other device refused the pairing",
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for Refusal {}

/// Returns the six digits of a code a user typed, without spaces and
/// dashes.
pub fn normalize_code(s: &str) -> Result<String> {
    let c: String = s.chars().filter(|c| *c != ' ' && *c != '-').collect();
    if c.len() != 6 || !c.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::msg("the code is six digits"));
    }
    Ok(c)
}

/// A random six-digit code.
pub fn new_code() -> String {
    let n = u32::from_le_bytes(certs::random_bytes::<4>()) % 1_000_000;
    format!("{n:06}")
}

/// A device that joins: its new device ID, its key and the self-signed
/// certificate it pairs with.
pub struct Joiner {
    pub id: DeviceId,
    /// The new device key, PKCS #8.
    pub key: Vec<u8>,
    /// The self-signed certificate it presents in the TLS handshake.
    pub cert: Vec<u8>,
    name: String,
}

impl Joiner {
    /// A joiner with a new device ID and key; name is shown in the devices
    /// list.
    pub fn new(name: &str) -> Result<Joiner> {
        if !crate::records::valid_name(name) {
            return Err(Error::msg("the device name must be 1 to 64 bytes without control characters"));
        }
        let id = DeviceId::random();
        let key = identity::new_key()?;
        let cert =
            certs::self_signed(&id, &identity::signing_key(&key)?).wrap("cannot make the pairing certificate")?;
        Ok(Joiner { id, key, cert, name: name.to_string() })
    }

    /// The fingerprint of the joiner's certificate that the QR code carries.
    pub fn fingerprint(&self) -> String {
        certs::qr_fingerprint(&self.cert)
    }

    /// Starts the exchange on a TLS connection whose handshake is done:
    /// member_der is the certificate the member presented, and sid the
    /// 32 bytes the connection exports for EXPORTER_LABEL. member_first is
    /// set when the member dialed this joiner, which showed its QR code:
    /// the member confirms first then, so a device that does not know the
    /// code learns nothing. Returns the exchange and the first frame to
    /// send.
    pub fn start(
        &self,
        code: &str,
        member_der: &[u8],
        sid: &[u8],
        member_first: bool,
    ) -> Result<(Exchange<'_>, Vec<u8>)> {
        let code = normalize_code(code)?;
        let member_cert = Cert::parse(member_der).wrap("the member's certificate")?;
        let ci = channel_id(member_der, &self.cert);
        let ad = serde_json::to_vec(&Info { name: &self.name, os: "linux", role: "lite" }).unwrap();
        let (st, msg) = cpace::start(&cpace::Config {
            role: cpace::Role::Initiator,
            password: code.as_bytes(),
            channel_id: &ci,
            session_id: sid,
            ad: &ad,
        })
        .context("cannot start the exchange")?;
        let first = frame(&Frame { msg: Some(msg), ad: Some(ad), ..Default::default() })?;
        Ok((Exchange { joiner: self, st, member_cert, member_first, member: None }, first))
    }
}

/// The joiner's side of one exchange. The program sends the frame start
/// returned, passes the member's reply to [`Exchange::reply`] and sends what
/// it returns, passes the member's last frame to [`Exchange::welcome`],
/// stores the identity it returns, and sends [`done`] with whether it
/// could. A [`Failure`] may carry a frame to send before closing.
pub struct Exchange<'a> {
    joiner: &'a Joiner,
    st: cpace::State,
    member_cert: Cert,
    member_first: bool,
    member: Option<MemberAd>,
}

/// A failed step: the error, and the frame that tells the member, if any.
#[derive(Debug)]
pub struct Failure {
    pub error: Error,
    pub send: Option<Vec<u8>>,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure { error, send: None }
    }
}

impl Exchange<'_> {
    /// Takes the member's reply, a frame's JSON, and returns the frame
    /// with this joiner's confirmation.
    pub fn reply(&mut self, body: &[u8]) -> core::result::Result<Vec<u8>, Failure> {
        let reply: Frame = decode(body)?;
        if !reply.error.is_empty() {
            return Err(Error::with("the pairing failed", Refusal::of(&reply.error)).into());
        }
        let peer_ad = reply.ad.unwrap_or_default();
        self.st.finish(&reply.msg.unwrap_or_default(), &peer_ad).context("the pairing failed")?;
        let member: MemberAd = serde_json::from_slice(&peer_ad).context("the member's description does not decode")?;
        if self.member_first && self.st.verify(&reply.tag.unwrap_or_default()).is_err() {
            return Err(Failure {
                error: Error::with("the pairing failed", Refusal::WrongCode),
                send: frame(&Frame { error: "wrong-code".into(), ..Default::default() }).ok(),
            });
        }
        self.member = Some(member);
        Ok(frame(&Frame { tag: self.st.tag(), ..Default::default() })?)
    }

    /// Takes the member's last frame, which carries the Welcome, and
    /// returns the new identity for the program to store. If it fails, the
    /// program sends done(false).
    pub fn welcome(&self, body: &[u8]) -> Result<Identity> {
        let member =
            self.member.as_ref().ok_or_else(|| Error::msg("the pairing failed: the frames came out of order"))?;
        let last: Frame = decode(body)?;
        if !last.error.is_empty() {
            return Err(Error::with("the pairing failed", Refusal::of(&last.error)));
        }
        let proved = self.member_first || last.tag.as_deref().is_some_and(|t| self.st.verify(t).is_ok());
        let Some(welcome) = last.welcome.filter(|_| proved) else {
            return Err(Error::msg("the other device did not prove that it knows the code"));
        };
        self.identity(&welcome, member)
    }

    /// Checks what the member sent and builds the new identity.
    fn identity(&self, w: &Welcome, member: &MemberAd) -> Result<Identity> {
        let member_cert = &self.member_cert;
        if w.holds_ca_keys() {
            return Err(Error::msg("the member sent CA keys, which a lite member never holds"));
        }
        let group_ca = Cert::parse(&w.group_ca).wrap("the group CA")?;
        if certs::tag(&group_ca) != member.group {
            return Err(Error::msg("the member sent another group CA than it announced"));
        }
        let roots = w.roots.iter().map(|d| Cert::parse(d)).collect::<Result<Vec<_>>>()?;
        let mut id = Identity {
            id: self.joiner.id.clone(),
            key: self.joiner.key.clone(),
            cert: Cert::parse(&w.cert).wrap("the new member certificate")?,
            issuer: None,
            group_ca,
            roots,
        };
        // An admin issues with its admin CA, under one of the group's roots.
        let mut issuers = id.trusted();
        if let Some(der) = &w.issuer {
            let issuer = Cert::parse(der).wrap("the member's issuer")?;
            if !issuers.iter().any(|root| certs::check_admin_ca(&issuer, root).is_ok()) {
                return Err(Error::msg("the member's issuer is not under a root of the group"));
            }
            issuers.insert(0, issuer.clone());
            id.issuer = Some(issuer);
        }
        // The member's own certificate is from that CA, or from a root, and
        // names the device it announced.
        if !issuers.iter().any(|i| member_cert.signed_by(i)) {
            return Err(Error::msg("the member's certificate is not from the group CA"));
        }
        if certs::device_of(member_cert).map(|d| d.to_string()).ok().as_deref() != Some(member.device.as_str()) {
            return Err(Error::msg("the member's certificate does not name the member"));
        }
        id.check()?;
        Ok(id)
    }
}

/// The joiner's last frame: ok once it stored its identity (the member
/// admitted the device when it sent the Welcome, whether or not it hears
/// this), refused otherwise.
pub fn done(ok: bool) -> Vec<u8> {
    let f = if ok {
        Frame { ok: true, ..Default::default() }
    } else {
        Frame { error: "refused".into(), ..Default::default() }
    };
    frame(&f).unwrap()
}

fn frame(f: &Frame) -> Result<Vec<u8>> {
    wire::json_frame(f, MAX_FRAME)
}

fn decode(body: &[u8]) -> Result<Frame> {
    serde_json::from_slice(body).context("a frame is not a message")
}

/// The CPace channel identifier for the two certificates, the member's
/// first.
pub fn channel_id(member_cert: &[u8], joiner_cert: &[u8]) -> Vec<u8> {
    let mut ci = CHANNEL_PREFIX.to_vec();
    ci.extend_from_slice(&certs::sha256(member_cert));
    ci.extend_from_slice(&certs::sha256(joiner_cert));
    ci
}

/// The text of the join QR code, as Go's phone.JoinQR writes it.
pub fn join_qr(code: &str, addrs: &[String], fingerprint: &str) -> String {
    let mut text = format!("clipboardbridge://join?code={}", query_escape(code));
    for a in addrs {
        text.push_str(&format!("&addr={}", query_escape(a)));
    }
    if !fingerprint.is_empty() {
        text.push_str(&format!("&fp={}", query_escape(fingerprint)));
    }
    text
}

/// Escapes s for a URL query as Go's url.QueryEscape does.
fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decodes the frames of testdata/interop/pairing.json as a lite member
/// reads them, and encodes those it writes the same way.
#[cfg(test)]
pub fn check_frames_for_tests(frames: &[serde_json::Value]) {
    let decoded: Vec<Frame> = frames.iter().map(|f| serde_json::from_value(f.clone()).unwrap()).collect();
    // The joiner's first frame: its AD is the device info.
    let info: serde_json::Value = serde_json::from_slice(decoded[0].ad.as_deref().unwrap()).unwrap();
    assert_eq!(info["os"], "linux");
    assert_eq!(serde_json::to_value(&decoded[0]).unwrap(), frames[0]);
    // The member's AD names the device and the group.
    let member: MemberAd = serde_json::from_slice(decoded[1].ad.as_deref().unwrap()).unwrap();
    assert!(certs::is_id(&member.device));
    assert_eq!(member.group.len(), 16);
    assert!(decoded[1].tag.is_some() && decoded[2].tag.is_some());
    assert_eq!(serde_json::to_value(&decoded[2]).unwrap(), frames[2]);
    // A plain Welcome is taken, one with CA keys is refused.
    let plain = decoded[3].welcome.as_ref().unwrap();
    assert!(!plain.cert.is_empty() && !plain.group_ca.is_empty() && !plain.holds_ca_keys());
    assert!(decoded[4].welcome.as_ref().unwrap().holds_ca_keys());
    assert_eq!(Refusal::of(&decoded[5].error), Refusal::WrongCode);
    assert!(decoded[6].ok);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(normalize_code(" 123-456 ").unwrap(), "123456");
        assert!(normalize_code("12345").is_err());
        assert!(normalize_code("12345a").is_err());
        assert_eq!(new_code().len(), 6);
    }

    #[test]
    fn qr_text_as_go_writes_it() {
        let text = join_qr(
            "246802",
            &["192.168.1.20:8767".into(), "[fd00::5]:8767".into()],
            "qFnj7UvLCE_WNnna2IEmMaLbkA6tHcKf0VijTRzekKA",
        );
        assert_eq!(
            text,
            "clipboardbridge://join?code=246802&addr=192.168.1.20%3A8767&addr=%5Bfd00%3A%3A5%5D%3A8767&fp=qFnj7UvLCE_WNnna2IEmMaLbkA6tHcKf0VijTRzekKA"
        );
    }

    #[test]
    fn the_joiner_certificate() {
        let j = Joiner::new("router").unwrap();
        let c = Cert::parse(&j.cert).unwrap();
        assert_eq!(c.common_name.as_deref(), Some(j.id.as_str()));
        assert!(c.p256);
        assert_eq!(j.fingerprint().len(), 43);
    }
}
