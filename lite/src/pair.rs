// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group (docs/protocol.md, section 6): the joiner's side of the
//! pairing, with CPace inside TLS and the Welcome.
//!
//! A lite member joins as a Mac does, without CA keys: either it listens and
//! shows a QR code that the phone app scans (the phone, or a Linux member
//! for the shortcut, dials it and confirms first), or it dials a Linux
//! member's open pairing window with the code that cbb pair shows.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::certs::{self, Cert, DeviceId, b64};
use crate::error::{Context, Error, Result, Wrap};
use crate::identity::{self, Identity};
use crate::third_party::cpace;
use crate::tls;
use crate::wire;

const EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL-clipboardbridge-pair-v1";
const CHANNEL_PREFIX: &[u8] = b"clipboardbridge pair v1\x00";
const MAX_FRAME: usize = 64 << 10;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a listening join waits, and how many wrong codes it takes.
pub const LIFETIME: Duration = Duration::from_secs(5 * 60);
const MAX_FAILURES: u32 = 3;

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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
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
    fn of(code: &str) -> Refusal {
        match code {
            "wrong-code" => Refusal::WrongCode,
            "closed" => Refusal::Closed,
            "busy" => Refusal::Busy,
            "expired" => Refusal::Expired,
            "too-many" => Refusal::TooMany,
            _ => Refusal::Refused, // the peer's own words are never shown
        }
    }

    fn message(self) -> &'static str {
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

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Refusal {}

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
    key: Vec<u8>,
    cert: Vec<u8>,
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
        let pair = rcgen::KeyPair::try_from(key.as_slice()).context("cannot use the new key")?;
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, id.as_str());
        params.not_before = rcgen::date_time_ymd(1970, 1, 1);
        params.not_after = rcgen::date_time_ymd(9999, 12, 31);
        let cert = params.self_signed(&pair).context("cannot make the pairing certificate")?;
        Ok(Joiner { id, key, cert: cert.der().to_vec(), name: name.to_string() })
    }

    /// The fingerprint of the joiner's certificate that the QR code carries.
    pub fn fingerprint(&self) -> String {
        certs::qr_fingerprint(&self.cert)
    }

    /// Runs the joining side over a connection a member dialed to this
    /// joiner, which showed its QR code. The member confirms first, so a
    /// device that does not know the code learns nothing.
    pub fn accept(&self, sock: TcpStream, code: &str, save: &dyn Fn(&Identity) -> Result<()>) -> Result<Identity> {
        let cfg = tls::pair_server(&self.cert, &self.key)?;
        let conn = rustls::ServerConnection::new(Arc::new(cfg)).context("cannot set up TLS")?;
        self.run(rustls::StreamOwned::new(conn, sock), code, true, save)
    }

    /// Runs the joining side over a connection to a member's open pairing
    /// window, with the code the user typed.
    pub fn join(&self, sock: TcpStream, code: &str, save: &dyn Fn(&Identity) -> Result<()>) -> Result<Identity> {
        let cfg = tls::pair_client(&self.cert, &self.key)?;
        let conn = rustls::ClientConnection::new(Arc::new(cfg), tls::server_name(None)).context("cannot set up TLS")?;
        self.run(rustls::StreamOwned::new(conn, sock), code, false, save)
    }

    fn run<C, D>(
        &self,
        mut tc: rustls::StreamOwned<C, TcpStream>,
        code: &str,
        member_first: bool,
        save: &dyn Fn(&Identity) -> Result<()>,
    ) -> Result<Identity>
    where
        C: std::ops::DerefMut<Target = rustls::ConnectionCommon<D>>
            + std::ops::Deref<Target = rustls::ConnectionCommon<D>>,
        D: rustls::SideData,
    {
        let code = normalize_code(code)?;
        tc.sock.set_read_timeout(Some(ATTEMPT_TIMEOUT)).context("the connection broke")?;
        tc.sock.set_write_timeout(Some(ATTEMPT_TIMEOUT)).context("the connection broke")?;
        while tc.conn.is_handshaking() {
            tc.conn.complete_io(&mut tc.sock).context("the TLS handshake failed")?;
        }
        if tc.conn.alpn_protocol() != Some(tls::PAIR_PROTOCOL) {
            return Err(Error::msg("the device does not offer pairing"));
        }
        let member_der = tc
            .conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.to_vec())
            .ok_or_else(|| Error::msg("the device does not offer pairing"))?;
        let member_cert = Cert::parse(&member_der).wrap("the member's certificate")?;
        let mut sid = [0u8; 32];
        tc.conn.export_keying_material(&mut sid, EXPORTER_LABEL, None).context("cannot bind the pairing to TLS")?;
        let ci = channel_id(&member_der, &self.cert);
        let id = self.exchange(&mut tc, &code, &ci, &sid, &member_cert, member_first, save)?;
        tc.conn.send_close_notify();
        let _ = tc.flush();
        Ok(id)
    }

    /// Runs the frames of the exchange, bound to the channel by ci and sid,
    /// with the member whose certificate is member_cert.
    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &self,
        rw: &mut (impl Read + Write),
        code: &str,
        ci: &[u8],
        sid: &[u8],
        member_cert: &Cert,
        member_first: bool,
        save: &dyn Fn(&Identity) -> Result<()>,
    ) -> Result<Identity> {
        let ad = serde_json::to_vec(&Info { name: &self.name, os: "linux", role: "lite" }).unwrap();
        let (mut st, msg) = cpace::start(&cpace::Config {
            role: cpace::Role::Initiator,
            password: code.as_bytes(),
            channel_id: ci,
            session_id: sid,
            ad: &ad,
        })
        .context("cannot start the exchange")?;
        wire::write_json(rw, &Frame { msg: Some(msg), ad: Some(ad), ..Default::default() }, MAX_FRAME)?;
        let reply: Frame = wire::read_json(rw, MAX_FRAME)?;
        if !reply.error.is_empty() {
            return Err(Error::with("the pairing failed", Refusal::of(&reply.error)));
        }
        let peer_ad = reply.ad.unwrap_or_default();
        st.finish(&reply.msg.unwrap_or_default(), &peer_ad).context("the pairing failed")?;
        let member: MemberAd = serde_json::from_slice(&peer_ad).context("the member's description does not decode")?;
        if member_first && st.verify(&reply.tag.unwrap_or_default()).is_err() {
            let _ = wire::write_json(rw, &Frame { error: "wrong-code".into(), ..Default::default() }, MAX_FRAME);
            return Err(Error::with("the pairing failed", Refusal::WrongCode));
        }
        wire::write_json(rw, &Frame { tag: st.tag(), ..Default::default() }, MAX_FRAME)?;
        let last: Frame = wire::read_json(rw, MAX_FRAME)?;
        if !last.error.is_empty() {
            return Err(Error::with("the pairing failed", Refusal::of(&last.error)));
        }
        let proved = member_first || last.tag.as_deref().is_some_and(|t| st.verify(t).is_ok());
        let Some(welcome) = last.welcome.filter(|_| proved) else {
            return Err(Error::msg("the other device did not prove that it knows the code"));
        };
        let res = self.identity(&welcome, member_cert, &member).and_then(|id| save(&id).map(|_| id));
        match res {
            Ok(id) => {
                // The identity is stored, and the member admitted the
                // device when it sent the welcome, whether or not it hears
                // this.
                let _ = wire::write_json(rw, &Frame { ok: true, ..Default::default() }, MAX_FRAME);
                Ok(id)
            }
            Err(e) => {
                let _ = wire::write_json(rw, &Frame { error: "refused".into(), ..Default::default() }, MAX_FRAME);
                Err(e)
            }
        }
    }

    /// Checks what the member sent and builds the new identity.
    fn identity(&self, w: &Welcome, member_cert: &Cert, member: &MemberAd) -> Result<Identity> {
        if w.holds_ca_keys() {
            return Err(Error::msg("the member sent CA keys, which a lite member never holds"));
        }
        let group_ca = Cert::parse(&w.group_ca).wrap("the group CA")?;
        if certs::tag(&group_ca) != member.group {
            return Err(Error::msg("the member sent another group CA than it announced"));
        }
        let roots = w.roots.iter().map(|d| Cert::parse(d)).collect::<Result<Vec<_>>>()?;
        let mut id = Identity {
            id: self.id.clone(),
            key: self.key.clone(),
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

/// The CPace channel identifier for the two certificates, the member's
/// first.
fn channel_id(member_cert: &[u8], joiner_cert: &[u8]) -> Vec<u8> {
    let mut ci = CHANNEL_PREFIX.to_vec();
    ci.extend_from_slice(&certs::sha256(member_cert));
    ci.extend_from_slice(&certs::sha256(joiner_cert));
    ci
}

/// Reports whether an address may reach the member port: what mDNS would
/// publish (private IPv4, unique-local and link-local IPv6) or loopback.
pub fn home_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return home_address(IpAddr::V4(v4));
            }
            a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The addresses for the QR code: those mDNS would publish, IPv4 first,
/// without link-local ones, at most four.
pub fn qr_addresses(port: u16) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if iface.is_loopback() {
            continue;
        }
        match iface.ip() {
            IpAddr::V4(a) if a.is_private() => v4.push(SocketAddr::new(IpAddr::V4(a), port).to_string()),
            IpAddr::V6(a) if (a.segments()[0] & 0xfe00) == 0xfc00 => {
                v6.push(SocketAddr::new(IpAddr::V6(a), port).to_string())
            }
            _ => {}
        }
    }
    v4.extend(v6);
    v4.dedup();
    v4.truncate(4);
    v4
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

/// Listens for a member that dials this joiner, for up to LIFETIME. It
/// calls shown with the QR code's text once it listens, takes one attempt
/// at a time, gives up after the third wrong code, and returns the new
/// identity, which save stored.
#[allow(clippy::too_many_arguments)]
pub fn listen(
    joiner: &Joiner,
    ln: TcpListener,
    addrs: Option<Vec<String>>,
    code: &str,
    wait: Duration,
    shown: &dyn Fn(&str),
    save: &dyn Fn(&Identity) -> Result<()>,
    log: &dyn Fn(&str),
) -> Result<Identity> {
    let port = ln.local_addr().context("cannot listen")?.port();
    let addrs = addrs.unwrap_or_else(|| qr_addresses(port));
    if addrs.is_empty() {
        return Err(Error::msg(
            "this device has no address on the home network; connect it to the network, or use join -code",
        ));
    }
    shown(&join_qr(code, &addrs, &joiner.fingerprint()));
    ln.set_nonblocking(true).context("cannot listen")?;
    let end = Instant::now() + wait;
    let mut failures = 0;
    while Instant::now() < end {
        let (sock, from) = match ln.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(Error::with("cannot accept a connection", e)),
        };
        if !home_address(from.ip()) {
            continue;
        }
        let _ = sock.set_nonblocking(false);
        match joiner.accept(sock, code, save) {
            Ok(id) => return Ok(id),
            Err(e) => {
                log(&format!("cbb-lite: a pairing attempt from {from} failed: {}", e.for_log()));
                if e.details().contains(Refusal::WrongCode.message()) {
                    failures += 1;
                    if failures >= MAX_FAILURES {
                        return Err(Error::with("the pairing failed", Refusal::TooMany));
                    }
                }
            }
        }
    }
    Err(Error::msg("no device joined this one in time; run join again"))
}

#[cfg(test)]
pub fn channel_id_for_tests(member_cert: &[u8], joiner_cert: &[u8]) -> Vec<u8> {
    channel_id(member_cert, joiner_cert)
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
