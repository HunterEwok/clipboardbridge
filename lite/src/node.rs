// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member protocol (docs/protocol.md, section 4) on a lite member: it
//! dials the computers, and takes the connections of phones and of the
//! lite members with a lower device ID; it sends its hello, forwards each
//! event the first time the engine sees it to every other connection,
//! exchanges the group's records and keeps a renewed certificate.
//!
//! Each connection has two threads: the one that dialed or accepted reads, and a writer
//! sends what is queued, and a ping after 5 seconds of silence. Both use
//! the TLS state under a lock; only the reader waits on the socket without
//! it.

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::certs::{Cert, DeviceId, Usage};
use crate::clip::{Engine, Event, Hello, Kind, Outcome, Via};
use crate::error::{Context, Error, Result};
use crate::identity::Identity;
use crate::identity::Stored as _;
use crate::pair::home_address;
use crate::records::Stored as _;
use crate::records::{Record, Records};
use crate::tls;
use crate::uptime;
use crate::wire::{self, Message};

/// How long a device that discovery finds counts as at home without a
/// connection to it (docs/protocol.md, section 11).
const NEAR_GRACE: Duration = Duration::from_secs(30);

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
    /// Its operating system, from its hello; empty when it sent none.
    pub os: String,
}

/// Called with a tunnel offer and the device that sent it.
pub type OnTunnel = Box<dyn Fn(&DeviceId, &serde_json::Value) + Send + Sync>;

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
    /// The tunnel key the hellos offer the group's hub; None while sync away
    /// from home is off.
    tunnel_key: Arc<RwLock<Option<Vec<u8>>>>,
    on_tunnel: RwLock<Option<OnTunnel>>,
    /// The members discovery finds on the home network now.
    /// The devices discovery finds on the home network, by the uptime they
    /// were first found.
    home: Mutex<HashMap<DeviceId, Duration>>,
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
    tls: Mutex<tls::Session>,
    tx: SyncSender<Out>,
    peer: Mutex<Option<(String, String, String)>>, // role, name and system, from the hello
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
            tunnel_key: Arc::new(RwLock::new(None)),
            on_tunnel: RwLock::new(None),
            home: Mutex::new(HashMap::new()),
        }
    }

    /// Sets the tunnel key the hellos offer from now on, and connects to
    /// the full members again, so that the group's hub gets it.
    pub fn set_tunnel_key(&self, key: Option<Vec<u8>>) {
        *self.tunnel_key.write().unwrap() = key;
        for c in self.conns.lock().unwrap().values() {
            if c.peer.lock().unwrap().as_ref().is_some_and(|(role, _, _)| role == "full") {
                c.close(true);
            }
        }
    }

    /// Sets what is called with the tunnel offers of full members.
    pub fn on_tunnel(&self, f: OnTunnel) {
        *self.on_tunnel.write().unwrap() = Some(f);
    }

    /// Records whether discovery finds the device on the home network.
    pub fn found(&self, id: &DeviceId, here: bool) {
        let mut home = self.home.lock().unwrap();
        if here {
            home.entry(id.clone()).or_insert_with(uptime::now);
        } else {
            home.remove(id);
        }
    }

    /// Reports whether discovery found the device on the home network within
    /// NEAR_GRACE. Anyone on a network can announce a device's name and the
    /// group's tag, so past that only a connection to it counts.
    pub fn at_home(&self, id: &DeviceId) -> bool {
        self.home.lock().unwrap().get(id).is_some_and(|at| uptime::now().saturating_sub(*at) < NEAR_GRACE)
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
            .filter_map(|c| {
                c.peer.lock().unwrap().clone().map(|(role, name, os)| Peer { id: c.id.clone(), role, name, os })
            })
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
            self.logf(&format!("cbb: {} is too slow; closing the connection", c.id));
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
        // Away from home the member protocol goes only through the group's
        // tunnel, whose port is on the loopback address.
        if !home_address(addr.ip()) {
            return Err(Error::msg(format!(
                "{addr} is not on the home network; away from home this device reaches the group only through its tunnel (cbb global on)"
            )));
        }
        let sock = TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT).context(format!("cannot connect to {addr}"))?;
        let _ = sock.set_nodelay(true);
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        let ident = self.identity();
        let cfg = tls::member_client(&ident, peer.clone(), tls::refused(&self.records), &tls::clock())?;
        let conn = tls::Session::client(Arc::new(cfg), tls::server_name(peer.as_ref()))?;
        let (conn, id, chain) = self.handshake(&sock, conn, addr, Usage::Server)?;
        if self.connected(&id) {
            let _ = sock.shutdown(Shutdown::Both);
            return Ok(());
        }
        self.run(sock, conn, id, chain, addr)
    }

    /// Runs a connection that a member (a phone or a lite member)
    /// opened to this one until it ends. It replaces an older connection
    /// to the same device. handshaken is called once the handshake is over,
    /// whether it worked or not.
    pub fn accept(&self, sock: TcpStream, addr: SocketAddr, handshaken: &mut dyn FnMut()) -> Result<()> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        let _ = sock.set_nodelay(true);
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        let cfg = tls::member_server(&self.identity(), tls::refused(&self.records), &tls::clock())?;
        let conn = tls::Session::server(Arc::new(cfg))?;
        let res = self.handshake(&sock, conn, addr, Usage::Client);
        handshaken();
        let (conn, id, chain) = res?;
        self.run(sock, conn, id, chain, addr)
    }

    /// Completes the TLS handshake and checks the peer: usage is the side
    /// it is on.
    fn handshake(
        &self,
        sock: &TcpStream,
        mut conn: tls::Session,
        addr: SocketAddr,
        usage: Usage,
    ) -> Result<(tls::Session, DeviceId, Vec<Cert>)> {
        tls::handshake(&mut conn, sock, &format!("the TLS handshake with {addr} failed"))?;
        if conn.alpn_protocol() != Some(tls::MEMBER_PROTOCOL)
            || conn.protocol_version() != Some(tls::rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(Error::msg(format!("{addr} does not speak the member protocol")));
        }
        let presented = conn.peer_certificates().unwrap_or_default().to_vec();
        let ident = self.identity();
        let (id, chain) = tls::check_member(
            &presented,
            &ident.trusted(),
            ident.root().not_before,
            &tls::refused(&self.records),
            usage,
            uptime::wall_ms() / 1000,
        )?;
        Ok((conn, id, chain))
    }

    fn run(&self, sock: TcpStream, conn: tls::Session, id: DeviceId, chain: Vec<Cert>, addr: SocketAddr) -> Result<()> {
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
        self.logf(&format!("cbb: connected to {id} at {addr}"));
        let writer = {
            let c = c.clone();
            let records = self.records.clone();
            let name = self.name.clone();
            let key = self.tunnel_key.clone();
            let log = self.log.clone();
            std::thread::spawn(move || writer(&c, rx, &records, &name, &key, &*log))
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
            Ok(()) => self.logf(&format!("cbb: {id} said goodbye")),
            Err(e) => self.logf(&format!("cbb: the connection to {id} ended: {}", e.for_log())),
        }
        res
    }

    fn reader(&self, c: &Arc<Conn>) -> Result<()> {
        let mut r = TlsReader { c, buf: Vec::new() };
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
                let os = if crate::records::valid_os(&body.os) { body.os.clone() } else { String::new() };
                *c.peer.lock().unwrap() = Some((m.role.clone(), name, os));
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
                        self.logf(&format!("cbb: dropped an event from {} that does not decode", c.id));
                        continue;
                    };
                    match self.engine.received(ev) {
                        Ok(out) => self.apply(out, &c.id),
                        Err(e) => self.logf(&format!("cbb: dropped a bad event from {}: {}", c.id, e.for_log())),
                    }
                }
                "cert" => {
                    if let Some(cert) = m.cert
                        && let Err(e) = self.renewed(&cert, m.issuer.as_deref())
                    {
                        self.logf(&format!("cbb: a renewed certificate from {}: {}", c.id, e.for_log()));
                    }
                }
                "records" if !m.records.is_empty() => self.add_records(&m.records, &c.id),
                // Only the group's root or an admin can be its hub, by the
                // records and the key it proved, not by the role its hello
                // claims (docs/protocol.md, section 11).
                "tunnel" if m.tunnel.is_some() => {
                    if !self.records.lock().unwrap().admin_peer(c.id.as_str(), &c.chain) {
                        self.logf(&format!(
                            "cbb: ignored a tunnel offer from {}: only the group's root or an admin can be its hub",
                            c.id
                        ));
                    } else if let (Some(v), Some(f)) = (m.tunnel.as_ref(), self.on_tunnel.read().unwrap().as_ref()) {
                        f(&c.id, v);
                    }
                }
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
        self.logf(&format!("cbb: got a renewed certificate, valid until {}", date(next.cert.not_after)));
        *ident = Arc::new(next);
        Ok(())
    }

    fn add_records(&self, rs: &[Record], from: &DeviceId) {
        let fresh = {
            let mut st = self.records.lock().unwrap();
            let (fresh, errs) = st.add_all(rs);
            for e in errs {
                self.logf(&format!("cbb: dropped a record from {from}: {}", e.for_log()));
            }
            if fresh.is_empty() {
                return;
            }
            if let Err(e) = st.save(&self.state_dir) {
                self.logf(&format!("cbb: {}", e.for_log()));
            }
            // A new root that took the group over is trusted from now on.
            let roots = st.roots();
            let mut ident = self.ident.write().unwrap();
            if roots.iter().map(|c| &c.der).ne(ident.roots.iter().map(|c| &c.der)) {
                let mut next = (**ident).clone();
                next.roots = roots;
                match next.save(&self.state_dir) {
                    Ok(()) => *ident = Arc::new(next),
                    Err(e) => self.logf(&format!("cbb: keeping the group's new root: {}", e.for_log())),
                }
            }
            let own: Vec<Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
            if st.refused(&own).is_some() {
                self.logf("cbb: this device was removed from the group; join it again to sync");
            }
            fresh
        };
        // Pass them on, and drop the connections that are refused now.
        let st = self.records.lock().unwrap();
        for c in self.conns.lock().unwrap().values() {
            if let Some(why) = st.refused(&c.chain) {
                self.logf(&format!("cbb: closing the connection to {}: {why}", c.id));
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
        tls.write(frame).map_err(|e| io::Error::other(e.for_log()))?;
        tls::flush(&mut tls, &self.sock)
    }
}

/// Reads plaintext from the connection, waiting on the socket without the
/// TLS lock.
struct TlsReader<'a> {
    c: &'a Conn,
    buf: Vec<u8>,
}

impl Read for TlsReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let tls = &mut *self.c.tls.lock().unwrap();
                let n = tls.read(out);
                if n > 0 || out.is_empty() || tls.peer_closed() {
                    return Ok(n);
                }
            }
            self.buf.resize(16 << 10, 0);
            let n = (&self.c.sock).read(&mut self.buf)?;
            if n == 0 {
                return Ok(0);
            }
            let mut tls = self.c.tls.lock().unwrap();
            let fed = tls.feed(&self.buf[..n]);
            // Replies rustls queued (a key update, an alert) go out first.
            tls::flush(&mut tls, &self.c.sock)?;
            fed.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.for_log()))?;
        }
    }
}

fn writer(
    c: &Conn,
    rx: mpsc::Receiver<Out>,
    records: &Mutex<Records>,
    name: &str,
    key: &RwLock<Option<Vec<u8>>>,
    log: &(dyn Fn(&str) + Send + Sync),
) {
    let message = |o: Out| -> Option<Message> {
        match o {
            Out::Hello(mut h, queued) => {
                if let Some(ev) = h.current.as_mut() {
                    ev.age = add_age(ev.age, uptime::now().saturating_sub(queued));
                }
                Some(wire::hello(
                    &h,
                    records.lock().unwrap().digest(),
                    name,
                    "linux",
                    crate::device::own(),
                    key.read().unwrap().as_deref(),
                ))
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
                log(&format!("cbb: to {}: {}", c.id, e.for_log()));
                return true; // drop this one message
            }
        };
        if !c.bye.load(Ordering::SeqCst) {
            let _ = c.sock.set_write_timeout(Some(TIMEOUT + Duration::from_secs((f.len() / MIN_RATE) as u64)));
        }
        if let Err(e) = c.send(&f) {
            if !c.closed.load(Ordering::SeqCst) {
                log(&format!("cbb: writing to {}: {e}", c.id));
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
                    if let Some(m) = message(o)
                        && !write(&m)
                    {
                        return;
                    }
                }
                write(&wire::bare("bye"));
                let _ = c.sock.shutdown(Shutdown::Both);
            }
            return;
        }
        match rx.recv_timeout(PING_EVERY) {
            Ok(o) => {
                if let Some(m) = message(o)
                    && !write(&m)
                {
                    return;
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
