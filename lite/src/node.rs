// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member protocol (docs/protocol.md, section 4) on a lite member: it
//! dials the Linux members, as a Mac does, sends its hello, forwards each
//! event the first time the engine sees it to every other connection,
//! exchanges the group's records and keeps a renewed certificate.
//!
//! Each connection has two threads: the one that dialed reads, and a writer
//! sends what is queued, and a ping after 5 seconds of silence. Both use
//! the TLS state under a lock; only the reader waits on the socket without
//! it.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::certs::{Cert, DeviceId};
use crate::clip::{Engine, Event, Hello, Kind, Outcome, Via};
use crate::error::{Context, Error, Result};
use crate::identity::Identity;
use crate::records::{Record, Records};
use crate::tls;
use crate::uptime;
use crate::wire::{self, Message};

const PING_EVERY: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const QUEUE_LEN: usize = 256;
const RECORDS_CHUNK: usize = 1 << 20;
/// The slowest transfer a frame is given time for.
const MIN_RATE: usize = 16 << 10;

/// A text to put into the member's own clipboard.
#[derive(Clone, Debug)]
pub struct WriteReq {
    pub text: String,
    pub kind: Kind,
    pub via: Via,
    pub seq: u64,
    /// For a secret: how long it may stay in the clipboard.
    pub ttl: Option<Duration>,
}

/// A connected member.
#[derive(Clone, Debug)]
pub struct Peer {
    pub id: DeviceId,
    pub role: String,
    pub name: String,
}

/// The lite member's set of connections.
pub struct Node {
    ident: RwLock<Arc<Identity>>,
    name: String,
    pub engine: Arc<Engine>,
    records: Arc<Mutex<Records>>,
    state_dir: PathBuf,
    conns: Mutex<HashMap<DeviceId, Arc<Conn>>>,
    on_write: Box<dyn Fn(WriteReq) + Send + Sync>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    closed: AtomicBool,
}

enum Out {
    Hello(Hello, Duration),
    Event(Event, Duration),
    Records(Vec<Record>),
    Wake, // makes the writer look at the closed flag
}

struct Conn {
    id: DeviceId,
    sock: TcpStream,
    tls: Mutex<rustls::ClientConnection>,
    tx: SyncSender<Out>,
    peer: Mutex<Option<(String, String)>>, // role and name, from the hello
    chain: Vec<Cert>,
    closed: AtomicBool,
    bye: AtomicBool,
}

impl Node {
    pub fn new(
        ident: Identity,
        name: &str,
        engine: Arc<Engine>,
        records: Records,
        state_dir: PathBuf,
        on_write: Box<dyn Fn(WriteReq) + Send + Sync>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Node {
        Node {
            ident: RwLock::new(Arc::new(ident)),
            name: name.to_string(),
            engine,
            records: Arc::new(Mutex::new(records)),
            state_dir,
            conns: Mutex::new(HashMap::new()),
            on_write,
            log,
            closed: AtomicBool::new(false),
        }
    }

    pub fn identity(&self) -> Arc<Identity> {
        self.ident.read().unwrap().clone()
    }

    fn logf(&self, s: &str) {
        (self.log)(s)
    }

    /// Reports whether a connection to the device is up.
    pub fn connected(&self, id: &DeviceId) -> bool {
        self.conns.lock().unwrap().contains_key(id)
    }

    /// The connected members that sent their hello, sorted by device ID.
    pub fn peers(&self) -> Vec<Peer> {
        let conns = self.conns.lock().unwrap();
        let mut out: Vec<Peer> = conns
            .values()
            .filter_map(|c| c.peer.lock().unwrap().clone().map(|(role, name)| Peer { id: c.id.clone(), role, name }))
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// The devices list from the records.
    pub fn devices(&self) -> Vec<crate::records::Device> {
        self.records.lock().unwrap().devices()
    }

    /// Makes an event from a deliberate action and sends it.
    pub fn send(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        let (ev, out) = self.engine.send(text, kind, via)?;
        self.forward(&ev, None);
        if out.write {
            self.write(&ev, out.seq);
        }
        Ok(())
    }

    /// Passes a change a clipboard watcher reported to the engine and sends
    /// the event, if any.
    pub fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        if let Some(ev) = self.engine.copied(text, kind, via)? {
            self.forward(&ev, None);
        }
        Ok(())
    }

    fn write(&self, ev: &Event, seq: u64) {
        let ttl = (ev.kind == Kind::Secret)
            .then(|| {
                self.engine
                    .local()
                    .map(|(_, _, age)| Duration::from_secs(60).saturating_sub(age).max(Duration::from_millis(1)))
            })
            .flatten();
        (self.on_write)(WriteReq { text: ev.text.clone(), kind: ev.kind, via: ev.via, seq, ttl });
    }

    fn apply(&self, out: Outcome, from: &DeviceId) {
        let Some(ev) = out.forward else { return };
        self.forward(&ev, Some(from));
        if out.write {
            self.write(&ev, out.seq);
        }
    }

    fn forward(&self, ev: &Event, from: Option<&DeviceId>) {
        let now = uptime::now();
        for c in self.conns.lock().unwrap().values() {
            if Some(&c.id) != from {
                self.enqueue(c, Out::Event(ev.clone(), now));
            }
        }
    }

    fn enqueue(&self, c: &Arc<Conn>, o: Out) {
        if c.closed.load(Ordering::SeqCst) {
            return;
        }
        if let Err(TrySendError::Full(_)) = c.tx.try_send(o) {
            self.logf(&format!("cbb-lite: {} is too slow; closing the connection", c.id));
            c.close(false);
        }
    }

    /// Closes every connection with a goodbye and refuses new ones.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for c in self.conns.lock().unwrap().values() {
            c.close(true);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Connects to the member at addr and runs the connection until it ends.
    /// peer is the device that discovery found there, or None for an
    /// address given by hand; the device is then the one the certificate
    /// names. A device already connected is not connected twice.
    pub fn dial(&self, addr: SocketAddr, peer: Option<DeviceId>) -> Result<()> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        let sock = TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT).context(format!("cannot connect to {addr}"))?;
        let _ = sock.set_nodelay(true);
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        let ident = self.identity();
        let cfg = tls::member_client(&ident, peer.clone(), self.records.clone())?;
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), tls::server_name(peer.as_ref()))
            .context("cannot set up TLS")?;
        let mut s = &sock;
        while conn.is_handshaking() {
            conn.complete_io(&mut s).context(format!("the TLS handshake with {addr} failed"))?;
        }
        if conn.alpn_protocol() != Some(tls::MEMBER_PROTOCOL)
            || conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(Error::msg(format!("{addr} does not speak the member protocol")));
        }
        let presented = conn.peer_certificates().unwrap_or_default().to_vec();
        let (id, chain) = tls::check_member(&presented, &ident.trusted(), ident.root().not_before, &self.records)?;
        if self.connected(&id) {
            let _ = sock.shutdown(Shutdown::Both);
            return Ok(());
        }
        sock.set_read_timeout(Some(TIMEOUT)).context("the connection broke")?;
        let (tx, rx) = mpsc::sync_channel(QUEUE_LEN);
        let c = Arc::new(Conn {
            id: id.clone(),
            sock,
            tls: Mutex::new(conn),
            tx,
            peer: Mutex::new(None),
            chain,
            closed: AtomicBool::new(false),
            bye: AtomicBool::new(false),
        });
        {
            let mut conns = self.conns.lock().unwrap();
            if self.is_closed() {
                return Err(Error::msg("the service is stopping"));
            }
            if let Some(old) = conns.insert(id.clone(), c.clone()) {
                old.close(false);
            }
            // The connection is in the forwarding set before the engine
            // makes the hello, so no event falls between the two.
            let hello = self.engine.connected(id.as_str());
            let _ = c.tx.try_send(Out::Hello(hello, uptime::now()));
        }
        self.logf(&format!("cbb-lite: connected to {id} at {addr}"));
        let writer = {
            let c = c.clone();
            let records = self.records.clone();
            let name = self.name.clone();
            let log = self.log.clone();
            std::thread::spawn(move || writer(&c, rx, &records, &name, &*log))
        };
        let res = self.reader(&c);
        c.close(false);
        let _ = writer.join();
        {
            let mut conns = self.conns.lock().unwrap();
            if conns.get(&id).is_some_and(|cur| Arc::ptr_eq(cur, &c)) {
                conns.remove(&id);
            }
        }
        self.engine.disconnected(id.as_str());
        match &res {
            Ok(()) => self.logf(&format!("cbb-lite: {id} said goodbye")),
            Err(e) => self.logf(&format!("cbb-lite: the connection to {id} ended: {}", e.for_log())),
        }
        res
    }

    fn reader(&self, c: &Arc<Conn>) -> Result<()> {
        let mut r = TlsReader { c, pending: Vec::new(), pos: 0 };
        let mut first = true;
        loop {
            let m: Message = match wire::read_json(&mut r, wire::MAX_FRAME) {
                Ok(m) => m,
                Err(_) if c.closed.load(Ordering::SeqCst) => return Ok(()),
                Err(e) => return Err(e),
            };
            if c.closed.load(Ordering::SeqCst) {
                return Ok(());
            }
            if first {
                first = false;
                if m.kind != "hello" || !wire::known_role(&m.role) {
                    return Err(Error::msg(format!("{} did not start with a hello", c.id)));
                }
                let (h, body) = wire::decode_hello(m.hello.as_ref())?;
                let name = if crate::records::valid_name(&body.name) { body.name.clone() } else { String::new() };
                *c.peer.lock().unwrap() = Some((m.role.clone(), name));
                let out = self
                    .engine
                    .reconcile(c.id.as_str(), h)
                    .map_err(|e| e.context(format!("bad hello from {}", c.id)))?;
                self.apply(out, &c.id);
                let st = self.records.lock().unwrap();
                let mine = st.digest();
                if !mine.is_empty() && mine != body.records {
                    for chunk in chunk_records(st.all()) {
                        self.enqueue(c, Out::Records(chunk));
                    }
                }
                continue;
            }
            match m.kind.as_str() {
                "event" => {
                    let Some(ev) = m.event.and_then(|v| serde_json::from_value::<Event>(v).ok()) else {
                        self.logf(&format!("cbb-lite: dropped an event from {} that does not decode", c.id));
                        continue;
                    };
                    match self.engine.received(ev) {
                        Ok(out) => self.apply(out, &c.id),
                        Err(e) => self.logf(&format!("cbb-lite: dropped a bad event from {}: {}", c.id, e.for_log())),
                    }
                }
                "cert" => {
                    if let Some(cert) = m.cert {
                        if let Err(e) = self.renewed(&cert, m.issuer.as_deref()) {
                            self.logf(&format!("cbb-lite: a renewed certificate from {}: {}", c.id, e.for_log()));
                        }
                    }
                }
                "records" if !m.records.is_empty() => self.add_records(&m.records, &c.id),
                "bye" => return Ok(()),
                _ => {} // a ping, or a message from a newer version
            }
        }
    }

    /// Keeps a certificate an admin renewed for this member.
    fn renewed(&self, der: &[u8], issuer: Option<&[u8]>) -> Result<()> {
        let mut ident = self.ident.write().unwrap();
        let next = ident.with_cert_from(der, issuer)?;
        let chain: Vec<Cert> = std::iter::once(next.cert.clone()).chain(next.issuer.clone()).collect();
        if let Some(why) = self.records.lock().unwrap().refused(&chain) {
            return Err(Error::msg(why));
        }
        next.save(&self.state_dir)?;
        self.logf(&format!("cbb-lite: got a renewed certificate, valid until {}", date(next.cert.not_after)));
        *ident = Arc::new(next);
        Ok(())
    }

    fn add_records(&self, rs: &[Record], from: &DeviceId) {
        let fresh = {
            let mut st = self.records.lock().unwrap();
            let (fresh, errs) = st.add_all(rs);
            for e in errs {
                self.logf(&format!("cbb-lite: dropped a record from {from}: {}", e.for_log()));
            }
            if fresh.is_empty() {
                return;
            }
            if let Err(e) = st.save(&self.state_dir) {
                self.logf(&format!("cbb-lite: {}", e.for_log()));
            }
            // A new root that took the group over is trusted from now on.
            let roots = st.roots();
            let mut ident = self.ident.write().unwrap();
            if roots.iter().map(|c| &c.der).ne(ident.roots.iter().map(|c| &c.der)) {
                let mut next = (**ident).clone();
                next.roots = roots;
                match next.save(&self.state_dir) {
                    Ok(()) => *ident = Arc::new(next),
                    Err(e) => self.logf(&format!("cbb-lite: keeping the group's new root: {}", e.for_log())),
                }
            }
            let own: Vec<Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
            if st.refused(&own).is_some() {
                self.logf("cbb-lite: this device was removed from the group; join it again to sync");
            }
            fresh
        };
        // Pass them on, and drop the connections that are refused now.
        let st = self.records.lock().unwrap();
        for c in self.conns.lock().unwrap().values() {
            if let Some(why) = st.refused(&c.chain) {
                self.logf(&format!("cbb-lite: closing the connection to {}: {why}", c.id));
                c.close(false);
            } else if &c.id != from && c.peer.lock().unwrap().is_some() {
                for chunk in chunk_records(fresh.clone()) {
                    self.enqueue(c, Out::Records(chunk));
                }
            }
        }
    }
}

impl Conn {
    /// Ends the connection: with bye, the writer first sends what is queued
    /// and a goodbye; without, at once.
    fn close(&self, bye: bool) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if bye {
            self.bye.store(true, Ordering::SeqCst);
            let _ = self.sock.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = self.tx.try_send(Out::Wake);
        } else {
            let _ = self.sock.shutdown(Shutdown::Both);
            let _ = self.tx.try_send(Out::Wake);
        }
    }

    /// Writes one frame through TLS.
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        let mut tls = self.tls.lock().unwrap();
        let mut rest = frame;
        let mut s = &self.sock;
        while !rest.is_empty() {
            let n = tls.writer().write(rest)?;
            rest = &rest[n..];
            while tls.wants_write() {
                tls.write_tls(&mut s)?;
            }
        }
        Ok(())
    }
}

/// Reads plaintext from the connection, waiting on the socket without the
/// TLS lock.
struct TlsReader<'a> {
    c: &'a Conn,
    pending: Vec<u8>,
    pos: usize,
}

impl Read for TlsReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let mut tls = self.c.tls.lock().unwrap();
                match tls.reader().read(buf) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                if self.pos < self.pending.len() {
                    let mut rest = &self.pending[self.pos..];
                    let n = tls.read_tls(&mut rest)?;
                    self.pos += n;
                    let state = tls.process_new_packets();
                    let mut s = &self.c.sock;
                    while tls.wants_write() {
                        tls.write_tls(&mut s)?;
                    }
                    if let Err(e) = state {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                    continue;
                }
            }
            self.pending.resize(16 << 10, 0);
            self.pos = 0;
            let n = (&self.c.sock).read(&mut self.pending)?;
            self.pending.truncate(n);
            if n == 0 {
                return Ok(0);
            }
        }
    }
}

fn writer(c: &Conn, rx: mpsc::Receiver<Out>, records: &Mutex<Records>, name: &str, log: &(dyn Fn(&str) + Send + Sync)) {
    let message = |o: Out| -> Option<Message> {
        match o {
            Out::Hello(mut h, queued) => {
                if let Some(ev) = h.current.as_mut() {
                    ev.age = add_age(ev.age, uptime::now().saturating_sub(queued));
                }
                Some(wire::hello(&h, records.lock().unwrap().digest(), name))
            }
            Out::Event(mut ev, queued) => {
                ev.age = add_age(ev.age, uptime::now().saturating_sub(queued));
                Some(wire::event(&ev))
            }
            Out::Records(rs) => Some(Message { kind: "records".into(), records: rs, ..Default::default() }),
            Out::Wake => None,
        }
    };
    let write = |m: &Message| -> bool {
        let f = match wire::frame(m) {
            Ok(f) => f,
            Err(e) => {
                log(&format!("cbb-lite: to {}: {}", c.id, e.for_log()));
                return true; // drop this one message
            }
        };
        if !c.bye.load(Ordering::SeqCst) {
            let _ = c.sock.set_write_timeout(Some(TIMEOUT + Duration::from_secs((f.len() / MIN_RATE) as u64)));
        }
        if let Err(e) = c.send(&f) {
            if !c.closed.load(Ordering::SeqCst) {
                log(&format!("cbb-lite: writing to {}: {e}", c.id));
            }
            c.close(false);
            return false;
        }
        true
    };
    loop {
        if c.closed.load(Ordering::SeqCst) {
            if c.bye.load(Ordering::SeqCst) {
                // Send what is still queued, then the goodbye.
                while let Ok(o) = rx.try_recv() {
                    if let Some(m) = message(o) {
                        if !write(&m) {
                            return;
                        }
                    }
                }
                write(&wire::bare("bye"));
                let _ = c.sock.shutdown(Shutdown::Both);
            }
            return;
        }
        match rx.recv_timeout(PING_EVERY) {
            Ok(o) => {
                if let Some(m) = message(o) {
                    if !write(&m) {
                        return;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !write(&wire::bare("ping")) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Adds the time an event waited to its age, without overflowing.
fn add_age(age: i64, d: Duration) -> i64 {
    age.saturating_add(d.as_millis().min(i64::MAX as u128) as i64)
}

/// Splits records into groups whose encoded size stays near 1 MiB.
fn chunk_records(rs: Vec<Record>) -> Vec<Vec<Record>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut size = 0;
    for r in rs {
        let n = (r.body.len() + r.sig.len() + r.chain.iter().map(Vec::len).sum::<usize>()) * 4 / 3 + 64;
        if !cur.is_empty() && size + n > RECORDS_CHUNK {
            out.push(std::mem::take(&mut cur));
            size = 0;
        }
        cur.push(r);
        size += n;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A Unix time as a date, YYYY-MM-DD.
pub fn date(secs: i64) -> String {
    // Days since the epoch to a civil date (Howard Hinnant's algorithm).
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::date(0), "1970-01-01");
        assert_eq!(super::date(1761024000), "2025-10-21");
    }
}
