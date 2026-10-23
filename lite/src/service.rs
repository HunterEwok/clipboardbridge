// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's service: the control socket, the identity, the sync
//! engine and the connections to the Linux members.

use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::clip::{Engine, Kind, Via};
use crate::control::{self, Device, Header, Message, Status};
use crate::discovery;
use crate::error::{Context, Error, Result};
use crate::files;
use crate::hlc::{Clock, Timestamp};
use crate::identity::Identity;
use crate::node::{Node, WriteReq};
use crate::records::Records;
use crate::uptime;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MARK_FILE: &str = "hlc.mark";
const WATCH_QUEUE: usize = 16;

/// How the service runs.
pub struct Config {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub name: String,
    /// Members to dial by address, for networks where multicast does not
    /// reach.
    pub peers: Vec<SocketAddr>,
    /// Find the members with mDNS.
    pub mdns: bool,
}

struct Service {
    node: RwLock<Option<Arc<Node>>>,
    watchers: Mutex<Vec<SyncSender<WriteReq>>>,
    pending: Mutex<Option<WriteReq>>, // a write decided while no watcher was connected
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Logs to standard error, which systemd or procd keeps.
pub fn log_line(s: &str) {
    eprintln!("{s}");
}

/// Runs the service until SIGTERM or SIGINT.
pub fn run(cfg: Config) -> Result<()> {
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    std::fs::create_dir_all(&cfg.state_dir).context(format!("cannot create {}", cfg.state_dir.display()))?;
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(log_line);
    let svc = Arc::new(Service {
        node: RwLock::new(None),
        watchers: Mutex::new(Vec::new()),
        pending: Mutex::new(None),
        log: log.clone(),
    });
    let ln = listen(&cfg.socket)?;
    {
        let svc = svc.clone();
        std::thread::spawn(move || {
            for conn in ln.incoming().flatten() {
                let svc = svc.clone();
                std::thread::spawn(move || svc.serve(conn));
            }
        });
    }

    // Wait until the device is in a group: cbb-lite join may run meanwhile.
    let mut said = false;
    let ident = loop {
        if STOP.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&cfg.socket);
            return Ok(());
        }
        match Identity::load(&cfg.state_dir)? {
            Some(id) => break id,
            None => {
                if !said {
                    log("cbb-lite: this device is in no group yet; run cbb-lite join");
                    said = true;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    };
    let records = Records::load(&cfg.state_dir, &ident.group_ca)?;
    let ident = with_roots(ident, &records, &cfg.state_dir, &*log);
    log(&format!("cbb-lite: device {} in group {}, version {VERSION}", ident.id, ident.tag()));
    let engine = Arc::new(Engine::new(
        ident.id.as_str(),
        clock(&cfg.state_dir),
        Box::new(uptime::wall_ms),
        Box::new(uptime::now),
    ));
    let tag = ident.tag();
    let node = {
        let svc = svc.clone();
        Arc::new(Node::new(
            ident,
            &cfg.name,
            engine.clone(),
            records,
            cfg.state_dir.clone(),
            Box::new(move |w| svc.deliver(w)),
            log.clone(),
        ))
    };
    engine.rejoin();
    *svc.node.write().unwrap() = Some(node.clone());
    discovery::start(node.clone(), tag, cfg.peers.clone(), cfg.mdns, log.clone());

    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }
    log("cbb-lite: stopping");
    node.close();
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::fs::remove_file(&cfg.socket);
    Ok(())
}

/// Takes roots that the records know and the identity does not.
fn with_roots(ident: Identity, records: &Records, dir: &Path, log: &dyn Fn(&str)) -> Identity {
    let roots = records.roots();
    if roots.is_empty() || roots.iter().map(|c| &c.der).eq(ident.roots.iter().map(|c| &c.der)) {
        return ident;
    }
    let mut next = ident.clone();
    next.roots = roots;
    match next.save(dir) {
        Ok(()) => next,
        Err(e) => {
            log(&format!("cbb-lite: {}", e.for_log()));
            ident
        }
    }
}

/// The hybrid clock, which never goes back before the mark it saved.
fn clock(dir: &Path) -> Clock {
    let path = dir.join(MARK_FILE);
    let floor = std::fs::read_to_string(&path).ok().and_then(|s| Timestamp::parse(s.trim())).unwrap_or_default();
    let log_path = path.display().to_string();
    Clock::new(
        Box::new(uptime::wall_ms),
        floor,
        Some(Box::new(move |t| match files::write_atomic(&path, format!("{t}\n").as_bytes(), 0o600) {
            Ok(()) => true,
            Err(e) => {
                log_line(&format!("cbb-lite: saving {log_path}: {}", e.for_log()));
                false
            }
        })),
    )
}

/// Listens on the control socket: mode 0660, in its own directory.
fn listen(path: &Path) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context(format!("cannot create {}", dir.display()))?;
    }
    if UnixStream::connect(path).is_ok() {
        return Err(Error::msg(format!("another cbb-lite service runs at {}", path.display())));
    }
    let _ = std::fs::remove_file(path);
    let ln = UnixListener::bind(path).context(format!("cannot listen at {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).context("cannot set the socket's mode")?;
    Ok(ln)
}

fn kind_of(s: &str) -> Result<Kind> {
    match s {
        "" | "text" => Ok(Kind::Text),
        "secret" => Ok(Kind::Secret),
        _ => Err(Error::msg(format!("unknown kind {s:?}"))),
    }
}

fn via_of(s: &str) -> Result<Via> {
    match s {
        "" | "copy" => Ok(Via::Copy),
        "iphone" => Ok(Via::Phone),
        "universal-clipboard" => Ok(Via::Universal),
        _ => Err(Error::msg(format!("unknown via {s:?}"))),
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Text => "text",
        Kind::Secret => "secret",
    }
}

fn via_name(v: Via) -> &'static str {
    match v {
        Via::Copy => "copy",
        Via::Phone => "iphone",
        Via::Universal => "universal-clipboard",
    }
}

impl Service {
    fn node(&self) -> Result<Arc<Node>> {
        self.node.read().unwrap().clone().ok_or_else(|| Error::msg("this device is in no group; run cbb-lite join"))
    }

    /// Passes a write the engine decided on to every watcher.
    fn deliver(&self, w: WriteReq) {
        let mut ws = self.watchers.lock().unwrap();
        ws.retain(|tx| !matches!(tx.try_send(w.clone()), Err(mpsc::TrySendError::Disconnected(_))));
        if ws.is_empty() {
            *self.pending.lock().unwrap() = Some(w);
        }
    }

    fn serve(&self, conn: UnixStream) {
        let mut out = match conn.try_clone() {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut r = control::Reader::new(conn);
        let m = match r.read() {
            Ok(Some(m)) => m,
            _ => return,
        };
        if m.header.op == "watch" {
            self.watch(m, r, out);
            return;
        }
        let answer = match self.request(&m) {
            Ok(a) => a,
            Err(e) => {
                (self.log)(&format!("cbb-lite: {}: {}", m.header.op, e.for_log()));
                control::failure(&e)
            }
        };
        let _ = control::write(&mut out, &answer);
    }

    fn request(&self, m: &Message) -> Result<Message> {
        let h = &m.header;
        match h.op.as_str() {
            "copy" => {
                let text = String::from_utf8(m.payload.clone()).context("the text is not UTF-8")?;
                self.node()?.send(&text, kind_of(&h.kind)?, via_of(&h.via)?)?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "paste" => {
                let (text, kind, _) =
                    self.node()?.engine.local().ok_or_else(|| Error::msg("the clipboard is empty"))?;
                Ok(control::reply(Header { kind: kind_name(kind).into(), ..Default::default() }, text.into_bytes()))
            }
            "status" => {
                let node = self.node()?;
                let id = node.identity();
                let skews = node.engine.skews();
                let peers = node
                    .peers()
                    .into_iter()
                    .map(|p| Device {
                        skew_ms: skews.get(p.id.as_str()).copied().unwrap_or(0),
                        id: p.id.to_string(),
                        name: p.name,
                        role: p.role,
                        ..Default::default()
                    })
                    .collect();
                let status = Status {
                    device: id.id.to_string(),
                    group: id.tag(),
                    role: "lite".into(),
                    peers,
                    version: VERSION.into(),
                };
                Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
            }
            "devices" => {
                let node = self.node()?;
                let me = node.identity().id.to_string();
                let peers = node.peers();
                let mut out: Vec<Device> = node
                    .devices()
                    .into_iter()
                    .map(|d| Device {
                        online: peers.iter().any(|p| p.id.as_str() == d.id),
                        this: d.id == me,
                        listed: true,
                        id: d.id,
                        name: d.name,
                        role: d.role,
                        admin: d.admin,
                        ..Default::default()
                    })
                    .collect();
                for p in peers {
                    if !out.iter().any(|d| d.id == p.id.as_str()) {
                        out.push(Device {
                            id: p.id.to_string(),
                            name: p.name,
                            role: p.role,
                            online: true,
                            ..Default::default()
                        });
                    }
                }
                Ok(control::reply(Header { devices: out, ..Default::default() }, Vec::new()))
            }
            "pair" | "pair-phone" | "revoke" => {
                Err(Error::msg("a lite member admits and removes no devices; use the phone app or a Linux member"))
            }
            "join" => Err(Error::msg("run cbb-lite join on this device, with the service stopped or running")),
            op => Err(Error::msg(format!("unknown operation {op:?}"))),
        }
    }

    /// Serves a watcher: what it reports goes to the engine, the writes the
    /// engine decides on go to it.
    fn watch(&self, m: Message, mut r: control::Reader<UnixStream>, mut out: UnixStream) {
        let node = match self.node() {
            Ok(n) => n,
            Err(e) => {
                let _ = control::write(&mut out, &control::failure(&e));
                return;
            }
        };
        if let (Ok(text), Ok(kind)) = (String::from_utf8(m.payload), kind_of(&m.header.kind)) {
            node.engine.clipboard_is(&text, kind);
        }
        let (tx, rx) = mpsc::sync_channel::<WriteReq>(WATCH_QUEUE);
        if control::write(&mut out, &Message::new(Header { op: "reply".into(), ..Default::default() }, Vec::new()))
            .is_err()
        {
            return;
        }
        // A write decided while no watcher was connected, if the member's
        // own text is still that.
        if let Some(w) = self.pending.lock().unwrap().take() {
            if node.engine.local().is_some_and(|(t, _, _)| t == w.text) {
                let _ = tx.try_send(w);
            }
        }
        self.watchers.lock().unwrap().push(tx);
        let done = Arc::new(AtomicBool::new(false));
        {
            let done = done.clone();
            std::thread::spawn(move || {
                while let Ok(w) = rx.recv() {
                    let h = Header {
                        op: "write".into(),
                        kind: kind_name(w.kind).into(),
                        via: if w.via == Via::Copy { String::new() } else { via_name(w.via).into() },
                        seq: w.seq,
                        ttl_ms: w.ttl.map(|d| d.as_millis() as i64).unwrap_or(0),
                        ..Default::default()
                    };
                    if done.load(Ordering::SeqCst)
                        || control::write(&mut out, &Message::new(h, w.text.into_bytes())).is_err()
                    {
                        return;
                    }
                }
            });
        }
        while let Ok(Some(m)) = r.read() {
            let text = String::from_utf8(m.payload).unwrap_or_default();
            let (Ok(kind), Ok(via)) = (kind_of(&m.header.kind), via_of(&m.header.via)) else {
                (self.log)(&format!(
                    "cbb-lite: a watcher reported an unknown kind {:?} or via {:?}",
                    m.header.kind, m.header.via
                ));
                continue;
            };
            match m.header.op.as_str() {
                "copied" => {
                    if let Err(e) = node.copied(&text, kind, via) {
                        (self.log)(&format!("cbb-lite: a copy from a watcher: {}", e.for_log()));
                    }
                }
                "clipboard" => node.engine.clipboard_is(&text, kind),
                op => (self.log)(&format!("cbb-lite: a watcher sent {op:?}")),
            }
        }
        done.store(true, Ordering::SeqCst);
    }
}
