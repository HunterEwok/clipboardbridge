// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! TLS for cbb-lite: the core's TLS (cbb_core::tls, the same code a
//! microcontroller runs) with the system clock, driven over blocking
//! sockets.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use cbb_core::tls::rustls::pki_types::UnixTime;
use cbb_core::tls::rustls::time_provider::TimeProvider;
pub use cbb_core::tls::*;

use crate::error::{Context, Result};
use crate::records::Records;

#[derive(Debug)]
struct SystemClock;

impl TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_millis(crate::uptime::wall_ms().max(0) as u64)))
    }
}

/// The system clock, for the TLS configurations.
pub fn clock() -> Clock {
    Arc::new(SystemClock)
}

/// The records' judgement of a member chain, under their lock.
pub fn refused(records: &Arc<Mutex<Records>>) -> Refused {
    let records = records.clone();
    Arc::new(move |chain| records.lock().unwrap().refused(chain).map(String::from))
}

/// Sends what the session queued.
pub fn flush(s: &mut Session, mut sock: &TcpStream) -> io::Result<()> {
    let out = s.take_outgoing();
    if out.is_empty() {
        return Ok(());
    }
    sock.write_all(&out)
}

/// Reads once from the socket into the session; false at the end of the
/// stream.
fn fill(s: &mut Session, mut sock: &TcpStream, buf: &mut [u8]) -> io::Result<bool> {
    let n = sock.read(buf)?;
    if n == 0 {
        return Ok(false);
    }
    s.feed(&buf[..n]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.for_log()))?;
    Ok(true)
}

/// Completes the handshake over the socket; a failure has the message
/// what, and the cause under it.
pub fn handshake(s: &mut Session, mut sock: &TcpStream, what: &str) -> Result<()> {
    let mut buf = vec![0u8; 16 << 10];
    loop {
        flush(s, sock).context(what.to_string())?;
        if !s.is_handshaking() {
            return Ok(());
        }
        let n = sock.read(&mut buf).context(what.to_string())?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof)).context(what.to_string());
        }
        if let Err(e) = s.feed(&buf[..n]) {
            // The alert that tells the peer why, if rustls made one.
            let _ = flush(s, sock);
            return Err(e.context(what.to_string()));
        }
    }
}

/// A TLS stream over a blocking socket, for the pairing.
pub struct Stream {
    pub session: Session,
    pub sock: TcpStream,
    buf: Vec<u8>,
}

impl Stream {
    pub fn new(session: Session, sock: TcpStream) -> Stream {
        Stream { session, sock, buf: vec![0u8; 16 << 10] }
    }

    /// Sends a close_notify.
    pub fn close(&mut self) {
        if self.session.close().is_ok() {
            let _ = flush(&mut self.session, &self.sock);
        }
    }
}

impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.session.read(out);
            if n > 0 || out.is_empty() || self.session.peer_closed() {
                return Ok(n);
            }
            let more = fill(&mut self.session, &self.sock, &mut self.buf);
            flush(&mut self.session, &self.sock)?;
            if !more? {
                return Ok(0);
            }
        }
    }
}

impl Write for Stream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.session.write(data).map_err(|e| io::Error::other(e.for_log()))?;
        flush(&mut self.session, &self.sock)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        flush(&mut self.session, &self.sock)
    }
}
