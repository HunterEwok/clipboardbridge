// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! TLS configurations for member connections and pairing (docs/protocol.md,
//! sections 4 and 6), with rustls and ring. The certificate checks are this
//! crate's own (certs.rs), so they follow Go's rules exactly: the chain to
//! a root of the group at max(now, the root's start), through at most one
//! admin CA, and the records' revocations.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::certs::{self, Cert, DeviceId, Usage};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::records::Records;

/// The ALPN protocol of member connections.
pub const MEMBER_PROTOCOL: &[u8] = b"clipboardbridge/1";
/// The ALPN protocol of pairing connections.
pub const PAIR_PROTOCOL: &[u8] = b"clipboardbridge-pair/1";

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls_err(msg: &str) -> rustls::Error {
    rustls::Error::General(msg.to_string())
}

fn now_secs() -> i64 {
    crate::uptime::wall_ms() / 1000
}

/// Verifies the TLS 1.3 handshake signature with the key of a certificate
/// this crate parsed.
fn verify_sig(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    let c = Cert::parse(cert).map_err(|e| tls_err(e.message()))?;
    let spki = SubjectPublicKeyInfoDer::from(c.spki);
    verify_tls13_signature_with_raw_key(message, &spki, dss, &provider().signature_verification_algorithms)
}

fn schemes() -> Vec<SignatureScheme> {
    provider().signature_verification_algorithms.supported_schemes()
}

/// Checks the member that this member dialed.
#[derive(Debug)]
struct MemberVerifier {
    self_id: DeviceId,
    peer: Option<DeviceId>, // the device discovery found; None for an address given by hand
    trusted: Vec<Cert>,
    root_start: i64,
    records: Arc<Mutex<Records>>,
}

/// Checks a member chain as Go's checkPeer does, and returns the device.
/// usage is the side the peer is on: Server for a member this one dialed.
pub fn check_member(
    chain: &[CertificateDer<'_>],
    trusted: &[Cert],
    root_start: i64,
    records: &Mutex<Records>,
    usage: Usage,
) -> Result<(DeviceId, Vec<Cert>)> {
    let certs = chain.iter().map(|c| Cert::parse(c)).collect::<Result<Vec<_>>>()?;
    let t = now_secs().max(root_start);
    let dev = certs::verify_member(&certs, trusted, t, usage)?;
    // Only the leaf and its issuer count, as the peer sends them.
    let used: Vec<Cert> = certs.into_iter().take(2).collect();
    if let Some(why) = records.lock().unwrap().refused(&used) {
        return Err(Error::msg(why));
    }
    Ok((dev, used))
}

impl ServerCertVerifier for MemberVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.clone()];
        chain.extend(intermediates.iter().cloned());
        let (dev, _) = check_member(&chain, &self.trusted, self.root_start, &self.records, Usage::Server)
            .map_err(|e| tls_err(e.message()))?;
        if dev == self.self_id {
            return Err(tls_err("connected to itself"));
        }
        if let Some(want) = &self.peer {
            if &dev != want {
                return Err(tls_err(&format!("reached {dev} instead of {want}")));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

/// The client configuration for dialing a member: TLS 1.3 only, ALPN
/// clipboardbridge/1, this member's certificate with its issuer, and the
/// server checked against the group's roots and records. peer is the
/// device that discovery found, when known.
pub fn member_client(
    id: &Identity,
    peer: Option<DeviceId>,
    records: Arc<Mutex<Records>>,
) -> Result<rustls::ClientConfig> {
    let verifier = MemberVerifier {
        self_id: id.id.clone(),
        peer,
        trusted: id.trusted(),
        root_start: id.root().not_before,
        records,
    };
    let chain: Vec<CertificateDer<'static>> = id.chain().into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone()));
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::with("cannot set up TLS", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(chain, key)
        .map_err(|e| Error::with("cannot use the member certificate", e))?;
    cfg.alpn_protocols = vec![MEMBER_PROTOCOL.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(cfg)
}

/// Checks a member that dialed this one.
#[derive(Debug)]
struct MemberClientVerifier {
    self_id: DeviceId,
    trusted: Vec<Cert>,
    root_start: i64,
    records: Arc<Mutex<Records>>,
}

impl ClientCertVerifier for MemberClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.clone()];
        chain.extend(intermediates.iter().cloned());
        let (dev, _) = check_member(&chain, &self.trusted, self.root_start, &self.records, Usage::Client)
            .map_err(|e| tls_err(e.message()))?;
        if dev == self.self_id {
            return Err(tls_err("connected to itself"));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

/// The server configuration for members that dial this one (phones, Macs
/// and lite members with a lower device ID): TLS 1.3 only, ALPN
/// clipboardbridge/1, this member's certificate with its issuer, a client
/// certificate of the group required, no session tickets.
pub fn member_server(id: &Identity, records: Arc<Mutex<Records>>) -> Result<rustls::ServerConfig> {
    let verifier = MemberClientVerifier {
        self_id: id.id.clone(),
        trusted: id.trusted(),
        root_start: id.root().not_before,
        records,
    };
    let chain: Vec<CertificateDer<'static>> = id.chain().into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone()));
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::with("cannot set up TLS", e))?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(chain, key)
        .map_err(|e| Error::with("cannot use the member certificate", e))?;
    cfg.alpn_protocols = vec![MEMBER_PROTOCOL.to_vec()];
    cfg.send_tls13_tickets = 0;
    Ok(cfg)
}

/// Takes any server certificate: the joiner checks the member through the
/// CPace exchange and the Welcome instead.
#[derive(Debug)]
struct AnyServer;

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

/// Requires a client certificate and takes any, for the joiner that
/// listens; the exchange checks the member.
#[derive(Debug)]
struct AnyClient;

impl ClientCertVerifier for AnyClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

/// The joiner's server configuration, for a member that dials it: TLS 1.3,
/// ALPN clipboardbridge-pair/1, its self-signed certificate, any client
/// certificate required, no session tickets.
pub fn pair_server(cert: &[u8], key: &[u8]) -> Result<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::with("cannot set up TLS", e))?
        .with_client_cert_verifier(Arc::new(AnyClient))
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|e| Error::with("cannot use the pairing certificate", e))?;
    cfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
    cfg.send_tls13_tickets = 0;
    Ok(cfg)
}

/// The joiner's client configuration, for dialing a member's open pairing
/// window.
pub fn pair_client(cert: &[u8], key: &[u8]) -> Result<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::with("cannot set up TLS", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer))
        .with_client_auth_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|e| Error::with("cannot use the pairing certificate", e))?;
    cfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(cfg)
}

/// A server name for the TLS client: the peer's host name, or a fixed one
/// for an address given by hand (members do not look at it).
pub fn server_name(peer: Option<&DeviceId>) -> ServerName<'static> {
    let name = peer.map(DeviceId::host_name).unwrap_or_else(|| "clipboardbridge.invalid".to_string());
    ServerName::try_from(name).unwrap_or_else(|_| ServerName::try_from("clipboardbridge.invalid").unwrap())
}
