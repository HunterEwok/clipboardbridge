// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's service: the control socket, the identity, the sync
//! engine and the connections to the other members.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::away::Away;
use crate::clip::{Engine, Kind, Mode, Via};
use crate::control::{self, Device, Header, Message, Status};
use crate::discovery;
use crate::error::{Context, Error, Result};
use crate::files;
use crate::hlc::{Clock, Timestamp};
use crate::identity::Identity;
use crate::identity::Stored as _;
use crate::node::{Node, WriteReq};
use crate::records::Records;
use crate::records::Stored as _;
use crate::uptime;
use crate::wire;

/// The release's version, such as "0.3.0", which the release build passes in
/// `CBB_VERSION`; other builds say "dev", as the Go service does.
pub const VERSION: &str = match option_env!("CBB_VERSION") {
    Some(v) => v,
    None => "dev",
};
const MARK_FILE: &str = "hlc.mark";
/// The sync mode, in the state directory. A device that joined its group
/// gets one at once, with own; without it, the device joined before sync
/// modes existed and keeps sharing as it did.
const MODE_FILE: &str = "mode";
/// The most command IDs the replay cache keeps; a command lives at most 30
/// seconds, so this many in that time is far more than any admin sends.
const MAX_COMMANDS: usize = 4096;
const WATCH_QUEUE: usize = 16;

/// How the service runs.
pub struct Config {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub name: String,
    /// Members to dial by address, for networks where multicast does not
    /// reach.
    pub peers: Vec<SocketAddr>,
    /// Find the members with mDNS, and publish this one.
    pub mdns: bool,
    /// The member port, where phones and other lite members dial
    /// this one; None listens nowhere.
    pub port: Option<u16>,
}

struct Service {
    node: RwLock<Option<Arc<Node>>>,
    away: RwLock<Option<Arc<Away>>>,
    watchers: Mutex<Vec<SyncSender<WriteReq>>>,
    pending: Mutex<Option<WriteReq>>, // a write decided while no watcher was connected
    state_dir: PathBuf,
    /// The replay cache: the IDs of the commands carried out, until they
    /// expire, in milliseconds since the Unix epoch.
    commands: Mutex<HashMap<String, i64>>,
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
        away: RwLock::new(None),
        watchers: Mutex::new(Vec::new()),
        pending: Mutex::new(None),
        state_dir: cfg.state_dir.clone(),
        commands: Mutex::new(HashMap::new()),
        log: log.clone(),
    });
    let admin_socket = control::admin_socket(&cfg.socket);
    for (ln, admin) in [(listen(&cfg.socket, false)?, false), (listen(&admin_socket, true)?, true)] {
        let svc = svc.clone();
        std::thread::spawn(move || {
            for conn in ln.incoming().flatten() {
                let svc = svc.clone();
                std::thread::spawn(move || svc.serve(conn, admin));
            }
        });
    }

    // Wait until the device is in a group: cbb join may run meanwhile.
    let mut said = false;
    let ident = loop {
        if STOP.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&cfg.socket);
            let _ = std::fs::remove_file(&admin_socket);
            return Ok(());
        }
        match Identity::load(&cfg.state_dir)? {
            Some(id) => break id,
            None => {
                if !said {
                    log("cbb: this device is in no group yet; run cbb join");
                    said = true;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    };
    let records = Records::load(&cfg.state_dir, &ident.group_ca)?;
    let ident = with_roots(ident, &records, &cfg.state_dir, &*log);
    log(&format!("cbb: device {} in group {}, version {VERSION}", ident.id, ident.tag()));
    let engine = Arc::new(Engine::new(
        ident.id.as_str(),
        clock(&cfg.state_dir),
        Box::new(uptime::wall_ms),
        Box::new(uptime::now),
    ));
    let tag = ident.tag();
    let away = Arc::new(Away::new(cfg.state_dir.clone(), tag.clone(), ident.id.clone(), log.clone()));
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
    engine.set_mode(load_mode(&cfg.state_dir)?);
    log(&format!("cbb: the sync mode is {}", engine.mode().name()));
    {
        let svc = svc.clone();
        node.on_command(Box::new(move |peer, c| svc.command(peer, c)));
    }
    node.set_tunnel_key(away.key());
    {
        let away = away.clone();
        let n = Arc::downgrade(&node);
        node.on_tunnel(Box::new(move |from, v, may_host| {
            if let (Some(hub), Some(node)) = (away.offered(from, v, may_host), n.upgrade()) {
                away.retry(&node, &hub);
            }
        }));
    }
    *svc.node.write().unwrap() = Some(node.clone());
    *svc.away.write().unwrap() = Some(away.clone());
    let port = cfg.port.and_then(|p| discovery::listen(node.clone(), p, log.clone()));
    if let Some(p) = port {
        log(&format!("cbb: listening on port {p}"));
    }
    discovery::start(node.clone(), tag, cfg.peers.clone(), cfg.mdns, port, log.clone());
    {
        let node = node.clone();
        std::thread::spawn(move || away.run(node));
    }

    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }
    log("cbb: stopping");
    node.close();
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::fs::remove_file(&cfg.socket);
    let _ = std::fs::remove_file(&admin_socket);
    Ok(())
}

/// Takes the roots that the records lead to when they differ from the
/// identity's, compared by content, so a root the records do not name never
/// stays trusted; an empty set says nothing yet.
fn with_roots(ident: Identity, records: &Records, dir: &Path, log: &dyn Fn(&str)) -> Identity {
    let roots = records.roots();
    if records.is_empty() || roots.iter().map(|c| &c.der).eq(ident.roots.iter().map(|c| &c.der)) {
        return ident;
    }
    let mut next = ident.clone();
    next.roots = roots;
    match next.save(dir) {
        Ok(()) => next,
        Err(e) => {
            log(&format!("cbb: {}", e.for_log()));
            ident
        }
    }
}

/// Reads the sync mode from dir: shared when there is no mode file.
pub fn load_mode(dir: &Path) -> Result<Mode> {
    match std::fs::read_to_string(dir.join(MODE_FILE)) {
        Ok(s) => Mode::parse(s.trim()).map_err(|e| e.context(MODE_FILE)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Mode::Shared),
        Err(e) => Err(e).context(format!("cannot read {}", dir.join(MODE_FILE).display())),
    }
}

fn save_mode(dir: &Path, m: Mode) -> Result<()> {
    files::write_atomic(&dir.join(MODE_FILE), format!("{}\n", m.name()).as_bytes(), 0o600)
        .map_err(|e| e.context("saving the sync mode"))
}

/// Gives a device that just joined a group the sync mode of a new device,
/// own, unless it has a mode from an earlier group.
pub fn new_device_mode(dir: &Path) -> Result<()> {
    if dir.join(MODE_FILE).exists() {
        return Ok(());
    }
    save_mode(dir, Mode::Own)
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
                log_line(&format!("cbb: saving {log_path}: {}", e.for_log()));
                false
            }
        })),
    )
}

/// Listens on the control socket: mode 0660, in its own directory; the
/// admin socket gets mode 0600, for root and the service's user only.
fn listen(path: &Path, admin: bool) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context(format!("cannot create {}", dir.display()))?;
    }
    if UnixStream::connect(path).is_ok() {
        return Err(Error::msg(format!("another lite member service runs at {}", path.display())));
    }
    let _ = std::fs::remove_file(path);
    // The socket is made in a new directory that only the service can enter,
    // narrowed there and then moved into place, so nobody can connect before
    // its mode is right, whatever the umask.
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".c{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::DirBuilder::new().mode(0o700).create(&tmp).context(format!("cannot create {}", tmp.display()))?;
    let made = (|| {
        let tmp_path = tmp.join("s");
        let ln = UnixListener::bind(&tmp_path).context(format!("cannot listen at {}", path.display()))?;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(if admin { 0o600 } else { 0o660 }))
            .context("cannot set the socket's mode")?;
        std::fs::rename(&tmp_path, path).context(format!("cannot move the socket to {}", path.display()))?;
        Ok(ln)
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    made
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
        "phone" | "iphone" => Ok(Via::Phone),
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
        Via::Phone => "phone",
        Via::Universal => "universal-clipboard",
    }
}

impl Service {
    fn node(&self) -> Result<Arc<Node>> {
        self.node.read().unwrap().clone().ok_or_else(|| Error::msg("this device is in no group; run cbb join"))
    }

    fn away(&self) -> Result<Arc<Away>> {
        self.away.read().unwrap().clone().ok_or_else(|| Error::msg("this device is in no group; run cbb join"))
    }

    /// cbb global: shows sync away from home, or turns it on or off. The
    /// lite member keeps its keys in files, so turning it on needs the
    /// user's consent.
    fn global(&self, h: &Header) -> Result<Message> {
        let (node, away) = (self.node()?, self.away()?);
        match h.name.as_str() {
            "" => {}
            "on" if !h.consent => {
                return Err(Error::msg(
                    "this device keeps its keys in files, so sync away from home needs your consent; run cbb global on and read what it says",
                ));
            }
            "on" => node.set_tunnel_key(Some(away.turn_on()?)),
            "off" => {
                away.turn_off()?;
                node.set_tunnel_key(None);
            }
            "hub" | "relay" => {
                return Err(Error::msg(
                    "the lite member is a client of the group's hub; make a full member the hub, or meet at a relay, there",
                ));
            }
            n => return Err(Error::msg(format!("unknown cbb global {n:?}"))),
        }
        let status = Status { away: away.status(&node), ..Default::default() };
        Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
    }

    /// Changes the sync mode and saves it.
    fn set_mode(&self, name: &str) -> Result<()> {
        let m = Mode::parse(name)?;
        let node = self.node()?;
        save_mode(&self.state_dir, m)?;
        node.engine.set_mode(m);
        (self.log)(&format!("cbb: the sync mode is {} now", m.name()));
        Ok(())
    }

    /// Carries out a command a member sent (docs/protocol.md, section 15):
    /// one that an admin signed for this device in its group, that has not
    /// expired and was not carried out before. The lite member takes mode
    /// commands; it is never the group's hub, so it refuses hub commands.
    fn command(&self, peer: &crate::certs::DeviceId, c: &crate::records::Record) -> wire::CommandResult {
        let refused = |id: &str, why: String| {
            (self.log)(&format!("cbb: refused a command from {peer}: {why}"));
            wire::CommandResult { id: id.to_string(), status: "refused".into(), reason: why }
        };
        let node = match self.node() {
            Ok(n) => n,
            Err(e) => return refused("", e.message().to_string()),
        };
        let now = uptime::wall_ms();
        let me = node.identity().id.to_string();
        let body = match node.records().lock().unwrap().verify_command(c, &me, now) {
            Ok(b) => b,
            Err(e) => return refused("", e.message().to_string()),
        };
        {
            let mut seen = self.commands.lock().unwrap();
            seen.retain(|_, exp| *exp > now);
            if seen.contains_key(&body.id) {
                return refused(&body.id, "this command was carried out already".into());
            }
            if seen.len() >= MAX_COMMANDS {
                return refused(&body.id, "too many commands; try again in a minute".into());
            }
            seen.insert(body.id.clone(), body.expires_ms);
        }
        if body.kind == "hub" {
            return refused(&body.id, "the lite member is never the group's hub".into());
        }
        if let Err(e) = Mode::parse(&body.mode) {
            return refused(&body.id, e.message().to_string());
        }
        if let Err(e) = self.set_mode(&body.mode) {
            (self.log)(&format!("cbb: a command from {peer}: {}", e.for_log()));
            return wire::CommandResult { id: body.id, status: "failed".into(), reason: e.message().to_string() };
        }
        (self.log)(&format!("cbb: {} set the sync mode to {}", body.by, body.mode));
        wire::CommandResult { id: body.id, status: "done".into(), reason: String::new() }
    }

    /// Passes a write the engine decided on to every watcher.
    fn deliver(&self, w: WriteReq) {
        let mut ws = self.watchers.lock().unwrap();
        ws.retain(|tx| !matches!(tx.try_send(w.clone()), Err(mpsc::TrySendError::Disconnected(_))));
        if ws.is_empty() {
            *self.pending.lock().unwrap() = Some(w);
        }
    }

    fn serve(&self, conn: UnixStream, admin: bool) {
        let mut out = match conn.try_clone() {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut r = control::Reader::new(conn);
        let m = match r.read() {
            Ok(Some(m)) => m,
            _ => return,
        };
        if control::is_admin(&m.header.op) && !admin {
            let e = Error::msg(format!(
                "{:?} changes the group, so the service takes it only on its admin socket, which only the administrator reaches",
                m.header.op
            ));
            let _ = control::write(&mut out, &control::failure(&e));
            return;
        }
        if m.header.op == "watch" {
            self.watch(m, r, out);
            return;
        }
        let answer = match self.request(&m) {
            Ok(a) => a,
            Err(e) => {
                (self.log)(&format!("cbb: {}: {}", m.header.op, e.for_log()));
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
                // The local clipboard's text in a mode that takes the
                // group's copies, and the group's current text in one that
                // keeps its clipboard to itself, as on a full member.
                let engine = self.node()?.engine.clone();
                let got = if engine.mode().receives() {
                    engine.local()
                } else {
                    engine.current().map(|ev| (ev.text, ev.kind, Duration::ZERO))
                };
                let (text, kind, _) = got.ok_or_else(|| Error::msg("the clipboard is empty"))?;
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
                        os: p.os,
                        ..Default::default()
                    })
                    .collect();
                let status = Status {
                    device: id.id.to_string(),
                    group: id.tag(),
                    role: "lite".into(),
                    os: "linux".into(),
                    peers,
                    version: VERSION.into(),
                    mode: node.engine.mode().name().into(),
                    away: self.away()?.status(&node),
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
                        os: peers
                            .iter()
                            .find(|p| p.id.as_str() == d.id && !p.os.is_empty())
                            .map_or(d.os.clone(), |p| p.os.clone()),
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
                            os: p.os,
                            online: true,
                            ..Default::default()
                        });
                    }
                }
                Ok(control::reply(Header { devices: out, ..Default::default() }, Vec::new()))
            }
            "away" => self.global(h),
            "mode" => {
                if !h.device.is_empty() {
                    return Err(Error::msg(
                        "only an admin sets the sync mode of another device; the lite member is never one: use the phone app or a Linux member",
                    ));
                }
                self.set_mode(&h.name)?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "pair" | "pair-phone" | "revoke" => {
                Err(Error::msg("a lite member admits and removes no devices; use the phone app or a Linux member"))
            }
            "join" => Err(Error::msg("run cbb join on this device, with the service stopped or running")),
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
        if let Some(w) = self.pending.lock().unwrap().take()
            && node.engine.local().is_some_and(|(t, _, _)| t == w.text)
        {
            let _ = tx.try_send(w);
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
                    "cbb: a watcher reported an unknown kind {:?} or via {:?}",
                    m.header.kind, m.header.via
                ));
                continue;
            };
            match m.header.op.as_str() {
                "copied" => {
                    if let Err(e) = node.copied(&text, kind, via) {
                        (self.log)(&format!("cbb: a copy from a watcher: {}", e.for_log()));
                    }
                }
                "clipboard" => node.engine.clipboard_is(&text, kind),
                op => (self.log)(&format!("cbb: a watcher sent {op:?}")),
            }
        }
        done.store(true, Ordering::SeqCst);
    }
}
