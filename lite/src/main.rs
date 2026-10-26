// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb is the lite member of clipboardbridge for small Linux devices,
//! such as routers and small boards: a member without CA keys that only
//! dials the computers, joins by QR code through the
//! phone, and syncs (docs/design.md, roadmap item 11).

mod actions;
mod away;
mod control;
mod device;
mod discovery;
mod error;
mod files;
mod identity;
mod next;
mod node;
mod pair;
mod pastehelper;
mod records;
mod remotepaste;
mod service;
mod tls;
mod tunnel;
mod uptime;
mod wire;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use cbb_core::{certs, clip, hlc};
use error::{Context, Error, Result};
use identity::Stored as _;

const USAGE: &str = "Usage: cbb [-state dir] [-socket path] [-debug] <command> [arguments]

Commands:
  join [-name name] [-port port] [-addr host[:port]]...
                       Join a group: show a QR code for the phone app to scan
                       (-addr: where the phone reaches this device, when the
                       code would name the wrong addresses).
  join -code host:port Join with the code from cbb pair on a Linux member.
  run [-name name] [-port port] [-peer host:port]... [-no-mdns] [-no-listen]
                       Run the service (started by systemd or procd): it
                       dials the computers, and phones and other lite
                       members dial it on the member port (8764, CBB_PORT).
  copy [-secret]       Send standard input to the group.
  paste [-terminal [-lines] [-secret]]
                       Print this member's clipboard text; -terminal makes
                       it safe to paste into a terminal: no control
                       characters, only the first line unless -lines, and
                       no secret unless -secret.
  status               Show this device, its group and the group's devices.
  mode [own|shared|receive|send]
                       Show or change the sync mode: what moves between this
                       device's clipboard and the group (a new device keeps
                       its own; cbb copy and cbb paste work in every mode).
  global [on|off]      Show sync away from home, or turn it on or off here:
                       through the group's own WireGuard tunnel to its hub.
  watch [-0]           Print every text the group sends here, one per line
                       (with -0, each followed by a zero byte).
  paste-receive [on [-enter] [-console] | off]
                       Show remote paste here, or turn it on or off: whether
                       the group's admins may put a text into tmux, or with
                       -console into the active text console, here (-enter:
                       and press Enter after it).
  action [enable NAME [-by root,phone,computer] [-any-key] [-yes] |
         disable NAME | off]
                       Show the quick actions here, or turn one on or off
                       for the group's admins: reboot (a minute later, and
                       only for keys in hardware unless -any-key),
                       cancel-shutdown and restart. enable, with sudo, writes
                       the polkit rule that lets the service reboot.
  paste-helper tmux|console
                       The paste targets: tmux starts the one for tmux, the
                       clipboardbridge-console unit the one for the console.
  next paste|copy|join The same for the ZX Spectrum Next's .cbb dot command,
                       in frames its Z80 reads (lite/README.md).
  version              Print the version and that this is the lite member.
  help                 Print this help.

This is the lite member: the commands of a full member, such as pair or
invite, are not here. The state directory is /var/lib/clipboardbridge
(CBB_STATE), the control socket /run/clipboardbridge/control.sock
(CBB_SOCKET). -debug, or CBB_DEBUG=1, shows the details of errors.
";

/// The commands of a full member (cmd/cbb) that the lite member does not
/// have, so that it says so instead of "unknown command".
const FULL_ONLY: &[&str] =
    &["revoke", "admin", "takeover", "new", "pair", "invite", "holder", "forward", "relay", "service", "agent"];

struct Global {
    state: PathBuf,
    socket: PathBuf,
}

fn main() {
    error::from_env();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut g = Global {
        state: std::env::var_os("CBB_STATE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/clipboardbridge")),
        socket: std::env::var_os("CBB_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/clipboardbridge/control.sock")),
    };
    while let Some(a) = args.first().cloned() {
        match flag(&a) {
            Some("state") if args.len() > 1 => g.state = PathBuf::from(args.remove(1)),
            Some("socket") if args.len() > 1 => g.socket = PathBuf::from(args.remove(1)),
            Some("debug") => error::set_show_details(true),
            _ => break,
        }
        args.remove(0);
    }
    let code = match args.first().map(String::as_str) {
        None => {
            eprint!("{USAGE}");
            2
        }
        Some(cmd) => {
            let rest = &args[1..];
            let res = match cmd {
                "join" => join(&g, rest, false),
                "next" => std::process::exit(next::run(&g, rest)),
                "run" => cmd_run(&g, rest),
                "copy" => cmd_copy(&g, rest),
                "paste" => cmd_paste(&g, rest),
                "status" => cmd_status(&g, rest),
                "global" => cmd_global(&g, rest),
                "watch" => cmd_watch(&g, rest),
                "mode" => cmd_mode(&g, rest),
                "paste-receive" => cmd_paste_receive(&g, rest),
                "action" => cmd_action(&g, rest),
                "paste-helper" => pastehelper::run(&g.socket, rest),
                "version" | "-version" | "--version" => {
                    println!(
                        "cbb {} ({}/{}), the lite member",
                        service::VERSION,
                        std::env::consts::OS,
                        std::env::consts::ARCH
                    );
                    Ok(())
                }
                "help" | "-h" | "-help" | "--help" => {
                    print!("{USAGE}");
                    Ok(())
                }
                _ if FULL_ONLY.contains(&cmd) => Err(Error::msg(format!(
                    "cbb {cmd} is a command of a full member; this device runs the lite member (see cbb help)"
                ))),
                _ => Err(Error::msg(format!("unknown command {cmd:?}; see cbb help"))),
            };
            match res {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("cbb: {}", e.for_user());
                    1
                }
            }
        }
    };
    std::process::exit(code);
}

/// The name of a flag, with one dash or two.
fn flag(a: &str) -> Option<&str> {
    a.strip_prefix("--").or_else(|| a.strip_prefix('-')).filter(|f| !f.is_empty())
}

fn host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most len bytes into buf.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } == 0;
    let name = if ok {
        String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == 0).unwrap_or(0)]).to_string()
    } else {
        String::new()
    };
    let name: String = name.split('.').next().unwrap_or("").chars().take(64).collect();
    if records::valid_name(&name) { name } else { "lite".into() }
}

fn resolve(s: &str) -> Result<SocketAddr> {
    s.to_socket_addrs()
        .context(format!("{s:?} is not host:port"))?
        .next()
        .ok_or_else(|| Error::msg(format!("{s:?} has no address")))
}

/// host:port, with brackets around an IPv6 host.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// The member port: 8764, or CBB_PORT.
fn member_port() -> u16 {
    std::env::var("CBB_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8764)
}

/// Joins a group. For the Next (for_next), the QR code and the outcome come
/// in its frames, and so do the log lines, as `CBB#` lines it skips.
fn join(g: &Global, args: &[String], for_next: bool) -> Result<()> {
    let mut name = host_name();
    let mut port = member_port();
    let mut addrs = Vec::new();
    let mut code_addr = None;
    let mut i = 0;
    while i < args.len() {
        let next = || args.get(i + 1).cloned().ok_or_else(|| Error::msg(format!("{} needs a value", args[i])));
        match flag(&args[i]) {
            Some("name") => name = next()?,
            Some("port") => port = next()?.parse().context("the port is a number")?,
            Some("addr") => addrs.push(next()?),
            Some("code") if !for_next => code_addr = Some(next()?),
            _ => return Err(Error::msg(format!("unknown argument {:?}; see cbb help", args[i]))),
        }
        i += 2;
    }
    if identity::Identity::load(&g.state)?.is_some() {
        return Err(Error::msg(format!(
            "this device is already in a group; to join another, stop the service and remove {}",
            g.state.join(identity::FILE_NAME).display()
        )));
    }
    std::fs::create_dir_all(&g.state).context(format!(
        "cannot create {0}; make it for the service's user first: \
         sudo install -d -o clipboardbridge -g clipboardbridge -m 0700 {0}",
        g.state.display()
    ))?;
    let joiner = pair::Joiner::new(&name)?;
    let state = g.state.clone();
    let save = move |id: &identity::Identity, rs: &[records::Record]| {
        let mut set = records::Records::new(&id.group_ca);
        let _ = set.add_all(rs);
        records::Stored::save(&set, &state)?;
        id.save(&state)?;
        service::new_device_mode(&state)
    };
    let id = match code_addr {
        Some(a) => {
            print!("Pairing code: ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).context("cannot read the code")?;
            let code = pair::normalize_code(line.trim())?;
            let sock = TcpStream::connect_timeout(&resolve(&a)?, Duration::from_secs(10))
                .context(format!("cannot connect to {a}"))?;
            pair::join(&joiner, sock, &code, &save)?
        }
        None => {
            let ln = TcpListener::bind(("::", port))
                .or_else(|_| TcpListener::bind(("0.0.0.0", port)))
                .or_else(|_| TcpListener::bind(("0.0.0.0", 0)))
                .context("cannot listen for the phone")?;
            // An address without a port gets the one listened on.
            let bound = ln.local_addr().context("cannot listen for the phone")?.port();
            let addrs: Vec<String> =
                addrs.into_iter().map(|a| if resolve(&a).is_ok() { a } else { join_host_port(&a, bound) }).collect();
            let code = pair::new_code();
            let shown = |text: &str| {
                if for_next {
                    let frame = next::qr_frame(text);
                    let mut out = std::io::stdout();
                    if frame.is_empty() {
                        // Fail now rather than leave the Next waiting for a
                        // pairing nobody can start.
                        out.write_all(b"CBBERR cannot make the QR code\r").ok();
                        out.flush().ok();
                        std::process::exit(1);
                    }
                    out.write_all(&frame).ok();
                    out.flush().ok();
                    return;
                }
                println!("In the Clipboard Bridge app, tap \"Connect a new device\" (or run the shortcut");
                println!("\"clipboardbridge: add a computer\") and scan this:\n");
                print!("{}", qr(text));
                println!("\nOr paste this into the app: {text}");
                println!("\nWaiting up to 5 minutes. Press Ctrl+C to cancel.");
                println!("Without a phone: run cbb pair on a full member and cbb join -code <its address> here.");
                std::io::stdout().flush().ok();
            };
            let log = |s: &str| {
                if for_next {
                    print!("CBB# {}\r", next::to_spectrum(s).escape_ascii());
                    std::io::stdout().flush().ok();
                } else {
                    eprintln!("{s}");
                }
            };
            pair::listen(&joiner, ln, (!addrs.is_empty()).then_some(addrs), &code, pair::LIFETIME, &shown, &save, &log)?
        }
    };
    wait_for_group(g);
    if for_next {
        print!("CBB# joined the group {} as {}\r", id.tag(), id.id);
    } else {
        println!("Joined the group {} as {}.", id.tag(), id.id);
        let mode = service::load_mode(&g.state).unwrap_or(clip::Mode::Own);
        println!("{}", mode_line(mode.name()));
        if mode != clip::Mode::Shared {
            println!("To share this device's clipboard with the group: sudo cbb mode shared");
        }
    }
    Ok(())
}

/// Waits until a running service has taken the group that join saved: it
/// looks for the identity every two seconds, and a command right after cbb
/// join would otherwise find it in no group. A service that is not running
/// takes the group when it starts.
fn wait_for_group(g: &Global) {
    let status = control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match request(g, &status) {
            Ok(m) if m.header.status.as_ref().is_some_and(|s| !s.group.is_empty()) => return,
            Ok(_) => std::thread::sleep(Duration::from_millis(200)),
            Err(_) => return,
        }
    }
}

/// Draws text as a QR code with half blocks, black on white whatever the
/// terminal's colors, as cbb join does.
fn qr(text: &str) -> String {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M) else {
        return String::new();
    };
    let size = code.width() as i32;
    let quiet = 2;
    let n = size + 2 * quiet;
    let black = |x: i32, y: i32| {
        let (x, y) = (x - quiet, y - quiet);
        x >= 0 && y >= 0 && x < size && y < size && code[(x as usize, y as usize)] == qrcode::Color::Dark
    };
    let mut out = String::new();
    for y in (0..n).step_by(2) {
        out.push_str("  ");
        for x in 0..n {
            let fg = if black(x, y) { "30" } else { "97" };
            let bg = if black(x, y + 1) { "40" } else { "107" };
            out.push_str(&format!("\x1b[{fg};{bg}m▀"));
        }
        out.push_str("\x1b[0m\n");
    }
    out
}

fn cmd_run(g: &Global, args: &[String]) -> Result<()> {
    let mut cfg = service::Config {
        state_dir: g.state.clone(),
        socket: g.socket.clone(),
        name: host_name(),
        peers: Vec::new(),
        mdns: true,
        port: Some(member_port()),
    };
    let mut i = 0;
    while i < args.len() {
        let next = || args.get(i + 1).cloned().ok_or_else(|| Error::msg(format!("{} needs a value", args[i])));
        match flag(&args[i]) {
            Some("name") => cfg.name = next()?,
            Some("peer") => cfg.peers.push(resolve(&next()?)?),
            Some("port") => cfg.port = Some(next()?.parse().context("the port is a number")?),
            Some("no-mdns") => {
                cfg.mdns = false;
                i += 1;
                continue;
            }
            Some("no-listen") => {
                cfg.port = None;
                i += 1;
                continue;
            }
            _ => return Err(Error::msg(format!("unknown argument {:?}; see cbb help", args[i]))),
        }
        i += 2;
    }
    if !records::valid_name(&cfg.name) {
        return Err(Error::msg("the device name must be 1 to 64 bytes without control characters"));
    }
    service::run(cfg)
}

/// Connects to the service's control socket, which only the members of the
/// clipboardbridge group may use.
fn connect(g: &Global) -> Result<UnixStream> {
    match UnixStream::connect(&g.socket) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(Error::msg(
            "no permission to use the Clipboard Bridge service; add your user to the clipboardbridge group and log in again",
        )),
        c => c.context(format!(
            "cannot reach the lite member's service at {}; is it running (systemctl status clipboardbridge)?",
            g.socket.display()
        )),
    }
}

/// Sends one request to the service and returns its answer.
fn request(g: &Global, m: &control::Message) -> Result<control::Message> {
    let conn = if control::is_admin(&m.header.op) {
        let path = control::admin_socket(&g.socket);
        match UnixStream::connect(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Error::msg(
                    "this command changes the group, so only the administrator may run it; run it with sudo",
                ));
            }
            c => c.context(format!(
                "cannot reach the lite member's service at {}; is it running (systemctl status clipboardbridge)?",
                path.display()
            ))?,
        }
    } else {
        connect(g)?
    };
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(&mut w, m)?;
    let answer = control::Reader::new(conn).read()?.ok_or_else(|| Error::msg("the service closed the connection"))?;
    check(answer)
}

fn check(m: control::Message) -> Result<control::Message> {
    if m.header.error.is_empty() {
        return Ok(m);
    }
    let e = Error::msg(m.header.error.clone());
    if m.header.details.is_empty() { Err(e) } else { Err(Error::with(m.header.error, Detail(m.header.details))) }
}

/// The details the service sent with an error.
#[derive(Debug)]
struct Detail(String);

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Detail {}

fn cmd_copy(g: &Global, args: &[String]) -> Result<()> {
    let secret = match args {
        [] => false,
        [a] if flag(a) == Some("secret") => true,
        _ => return Err(Error::msg("usage: cbb copy [-secret] < text")),
    };
    let mut text = Vec::new();
    std::io::stdin().take(clip::MAX_TEXT as u64 + 1).read_to_end(&mut text).context("cannot read standard input")?;
    let h = control::Header {
        op: "copy".into(),
        kind: if secret { "secret".into() } else { String::new() },
        ..Default::default()
    };
    request(g, &control::Message::new(h, text))?;
    Ok(())
}

/// Names an operating system for the user, as cbb status does.
fn os_name(os: &str) -> &str {
    match os {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        "ios" => "iOS",
        "android" => "Android",
        "none" => "device",
        _ => "?",
    }
}

fn cmd_paste(g: &Global, args: &[String]) -> Result<()> {
    let (mut terminal, mut lines, mut secret) = (false, false, false);
    for a in args {
        match flag(a) {
            Some("terminal") => terminal = true,
            Some("lines") => lines = true,
            Some("secret") => secret = true,
            _ => return Err(Error::msg("usage: cbb paste [-terminal [-lines] [-secret]]")),
        }
    }
    if (lines || secret) && !terminal {
        return Err(Error::msg("-lines and -secret go with -terminal"));
    }
    let m =
        request(g, &control::Message::new(control::Header { op: "paste".into(), ..Default::default() }, Vec::new()))?;
    let mut out = m.payload;
    if terminal {
        if m.header.kind == "secret" && !secret {
            return Err(Error::msg("the clipboard holds a secret; add -secret to paste it"));
        }
        let (text, dropped) = terminal_text(&String::from_utf8_lossy(&out), lines);
        if dropped > 0 {
            eprintln!("cbb: pasted only the first line; {dropped} more left out (add -lines to paste them)");
        }
        out = text.into_bytes();
    }
    std::io::stdout().write_all(&out).context("cannot write the text")?;
    Ok(())
}

/// Makes a text safe to paste into a terminal, as the full member's
/// terminalText does: it drops the control characters of C0 but tab and line
/// feed, DEL and those of C1, ends with no line feed, and unless `all` keeps
/// only the first line, returning how many lines it left out.
fn terminal_text(text: &str, all: bool) -> (String, usize) {
    let text: String = text
        .replace("\r\n", "\n")
        .chars()
        .filter(|&c| c == '\t' || c == '\n' || !(c < ' ' || ('\u{7f}'..'\u{a0}').contains(&c)))
        .filter(|&c| c != char::REPLACEMENT_CHARACTER)
        .collect();
    let text = text.trim_matches('\n');
    match text.split_once('\n') {
        Some((first, rest)) if !all => (first.to_string(), rest.matches('\n').count() + 1),
        _ => (text.to_string(), 0),
    }
}

fn cmd_status(g: &Global, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(Error::msg("status takes no arguments"));
    }
    let m =
        request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))?;
    let s = m.header.status.unwrap_or_default();
    println!("device  {}\ngroup   {}\nrole    {}\nversion {}", s.device, s.group, s.role, s.version);
    if !s.mode.is_empty() {
        println!("mode    {}", s.mode);
    }
    if s.peers.is_empty() {
        println!("no members connected");
    }
    print_away(s.away.as_ref());
    if s.group.is_empty() {
        return Ok(());
    }
    let devs =
        request(g, &control::Message::new(control::Header { op: "devices".into(), ..Default::default() }, Vec::new()))?;
    for d in devs.header.devices {
        let mut marks = [(d.this, "this device"), (d.online, "online"), (d.admin, "admin")]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, s)| s.to_string())
            .collect::<Vec<_>>();
        if let Some(p) = s.peers.iter().find(|p| p.id == d.id) {
            marks.push(format!("clock {:+} ms", p.skew_ms));
        }
        println!("{}  {:<24} {:<8} {:<8} {}", d.id, d.name, os_name(&d.os), d.role, marks.join(", "));
    }
    Ok(())
}

fn cmd_mode(g: &Global, args: &[String]) -> Result<()> {
    let h = match args {
        [] => control::Header { op: "status".into(), ..Default::default() },
        [m] if !m.starts_with('-') => control::Header { op: "mode".into(), name: m.clone(), ..Default::default() },
        _ => return Err(Error::msg("usage: cbb mode [own|shared|receive|send]")),
    };
    request(g, &control::Message::new(h, Vec::new()))?;
    let m =
        request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))?;
    let mode = m.header.status.map(|s| s.mode).unwrap_or_default();
    println!("{}", mode_line(&mode));
    Ok(())
}

/// What the sync mode mode does, as cbb mode on a full member says it.
fn mode_line(mode: &str) -> String {
    match mode {
        "own" => "Sync mode own: this device keeps its clipboard to itself; cbb paste prints the group's text, and cbb copy sends to the group.".into(),
        "shared" => "Sync mode shared: copies here go to the group, and the group's copies come here.".into(),
        "receive" => "Sync mode receive: the group's copies come here, and copies here stay here.".into(),
        "send" => "Sync mode send: copies here go to the group, and the group's copies do not come here.".into(),
        "" => "This lite member's service does not know sync modes yet; update it.".into(),
        m => format!("Sync mode {m}."),
    }
}

fn cmd_paste_receive(g: &Global, args: &[String]) -> Result<()> {
    let usage = || Error::msg("usage: cbb paste-receive [on [-enter] [-console] | off]");
    let mut h = control::Header { op: "status".into(), ..Default::default() };
    for (i, a) in args.iter().enumerate() {
        match (i, a.as_str(), flag(a)) {
            (0, "on" | "off", _) => {
                h.op = "paste-receive".into();
                h.name = a.clone();
            }
            (1.., _, Some("enter")) if h.name == "on" => h.enter = true,
            (1.., _, Some("console")) if h.name == "on" => h.console = true,
            _ => return Err(usage()),
        }
    }
    let m = request(g, &control::Message::new(h, Vec::new()))?;
    let p = m.header.status.and_then(|s| s.paste).ok_or_else(|| Error::msg("this device is in no group"))?;
    println!("{}", paste_line(&p));
    Ok(())
}

/// How remote paste stands here, as cbb paste-receive on a full member says
/// it.
fn paste_line(p: &control::Paste) -> String {
    if !p.on {
        return "Remote paste is off: the group's admins cannot paste here.".into();
    }
    let line = match (p.enter, p.console) {
        (true, true) => "Remote paste is on: the group's admins may paste here, press Enter, and reach text consoles.",
        (true, false) => "Remote paste is on: the group's admins may paste here and press Enter.",
        (false, true) => {
            "Remote paste is on: the group's admins may paste here and reach text consoles, without Enter."
        }
        (false, false) => "Remote paste is on: the group's admins may paste here, without Enter.",
    };
    if p.targets.is_empty() {
        return format!("{line} Nothing here can paste yet: the tmux and console helpers do it.");
    }
    line.into()
}

const ACTION_USAGE: &str =
    "usage: cbb action [enable NAME [-by root,phone,computer] [-any-key] [-yes] | disable NAME | off]";

/// cbb action: shows this device's quick actions and sets them, as on a
/// full member (docs/design.md, "Quick actions"). Enabling says what it lets
/// the group's admins do and asks first; for reboot, as root, it writes the
/// polkit rule that lets the service ask logind, and disabling takes it
/// back.
fn cmd_action(g: &Global, args: &[String]) -> Result<()> {
    let usage = || Error::msg(ACTION_USAGE);
    let (verb, name) = match args {
        [] => {
            let m = request(
                g,
                &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()),
            )?;
            let st = m.header.status.ok_or_else(|| Error::msg("this device is in no group"))?;
            for a in &st.actions {
                println!("{:<16} {}", a.name, action_line(a));
            }
            return Ok(());
        }
        [v] if v == "off" => {
            let m = request(
                g,
                &control::Message::new(control::Header { op: "actions-off".into(), ..Default::default() }, Vec::new()),
            )?;
            // The rights go too, when this runs as root here.
            if let Err(e) = grant(&m)
                && is_root()
            {
                eprintln!("cbb: the actions are off, but the rights stay: {}", e.for_user());
            }
            println!("The quick actions are off here.");
            return Ok(());
        }
        [v, name, ..] if v == "enable" || v == "disable" => (v.as_str(), name.clone()),
        _ => return Err(usage()),
    };
    let mut a = control::Action { name, on: verb == "enable", ..Default::default() };
    let mut yes = false;
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        match flag(arg) {
            Some("by") if a.on => a.by = actions::parse_kinds(rest.next().ok_or_else(usage)?)?,
            Some("any-key") if a.on => a.any_key = true,
            Some("yes") if a.on => yes = true,
            _ => return Err(usage()),
        }
    }
    if !actions::PRESETS.contains(&a.name.as_str()) {
        return Err(Error::msg(format!(
            "this device has no action {:?}: the lite member has reboot, cancel-shutdown and restart",
            a.name
        )));
    }
    if a.on && !yes {
        print!("{}Type yes to turn it on: ", action_warning(&a));
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).context("cannot read the answer")?;
        if !line.trim().eq_ignore_ascii_case("yes") {
            println!("Nothing changed.");
            return Err(Error::msg("the action stays as it was"));
        }
    }
    let h = control::Header { op: "action-set".into(), actions: vec![a.clone()], ..Default::default() };
    let m = request(g, &control::Message::new(h, Vec::new()))?;
    if let Err(e) = grant(&m) {
        if a.on {
            // Without the right the action would only fail; leave it off.
            let off = control::Action { on: false, ..a.clone() };
            let h = control::Header { op: "action-set".into(), actions: vec![off], ..Default::default() };
            let _ = request(g, &control::Message::new(h, Vec::new()));
        }
        return Err(e.context(format!("giving the service the right to {}", a.name)));
    }
    println!("{}: {}.", a.name, action_line(&a));
    Ok(())
}

/// Writes or removes the polkit rule for the actions a status says are on.
fn grant(m: &control::Message) -> Result<()> {
    let on: Vec<String> =
        m.header.status.iter().flat_map(|s| &s.actions).filter(|a| a.on).map(|a| a.name.clone()).collect();
    actions::grant(std::path::Path::new("/"), &on).map(|_| ())
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// How an action stands and who may run it, as on a full member.
fn action_line(a: &control::Action) -> String {
    if !a.on {
        return "off".into();
    }
    let mut who = if a.by.is_empty() { "every admin".to_string() } else { a.by.join(", ") };
    if actions::hardware_by_default(&a.name) && !a.any_key {
        who += ", keys in hardware only";
    }
    format!("on, for {who}")
}

/// What turning a on lets the group's admins do, and the rights it grants
/// here.
fn action_warning(a: &control::Action) -> String {
    let what = match a.name.as_str() {
        actions::REBOOT => "reboot this device, a minute after they ask",
        actions::CANCEL => "cancel a reboot that is pending",
        _ => "restart the Clipboard Bridge service here",
    };
    let mut who = if a.by.is_empty() {
        "the group's admins".to_string()
    } else {
        format!("the group's admins of the kinds {}", a.by.join(", "))
    };
    if actions::hardware_by_default(&a.name) && !a.any_key {
        who += " whose keys are in hardware (phones, computers with the key in a TPM)";
    }
    let mut s = format!("Turning {} on lets {who} {what}, from wherever they are in the group.\n", a.name);
    let rights = actions::rights(std::slice::from_ref(&a.name));
    if !rights.is_empty() {
        s += "It gives the Clipboard Bridge service these rights, in a polkit rule, and no others:\n";
        for r in rights {
            s += &format!("  {r}\n");
        }
        if !is_root() {
            s += "Writing the rule needs root: run this with sudo.\n";
        }
    }
    s + "Any admin can turn it off from afar, and only you turn it on again.\n\n"
}

/// What a user agrees to before the lite member, whose keys sit in files,
/// syncs away from home (docs/design.md, "Turning it on, step by step").
const KEYS_WARNING: &str = "Sync away from home lets this device reach the group's hub from the internet,
through the group's own WireGuard tunnel, with the clipboard encrypted end to end.

This device keeps its keys in files, not in a security chip. Whoever copies those
files (with root on this device, from its disk or memory card, or from an
unencrypted backup) can act as this device from anywhere until you remove it from
the group. To keep that from happening:

  - encrypt the disk or memory card where you can (LUKS);
  - keep the service's state directory out of unencrypted backups;
  - remove the device at once (Remove on the phone, or cbb revoke on a full
    member) when it is lost or someone else may have had root on it.

";

fn cmd_global(g: &Global, args: &[String]) -> Result<()> {
    let mut h = control::Header { op: "away".into(), ..Default::default() };
    match args {
        // Only showing it needs no root: the status carries it.
        [] => h.op = "status".into(),
        [a] if a == "on" => {
            print!("{KEYS_WARNING}Type yes to turn sync away from home on: ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).context("cannot read the answer")?;
            if !line.trim().eq_ignore_ascii_case("yes") {
                println!("Nothing changed.");
                return Err(Error::msg("sync away from home stays as it was"));
            }
            h.name = "on".into();
            h.consent = true;
        }
        [a] if a == "off" => h.name = "off".into(),
        _ => return Err(Error::msg("usage: cbb global [on|off]")),
    }
    let m = request(g, &control::Message::new(h, Vec::new()))?;
    print_away(m.header.status.and_then(|s| s.away).as_ref());
    Ok(())
}

/// Prints sync away from home as cbb global on a full member does.
fn print_away(a: Option<&control::Away>) {
    let Some(a) = a else {
        println!("Sync away from home: off (cbb global on turns it on).");
        return;
    };
    match () {
        _ if a.hub_device.is_empty() && !a.keys_in_file => println!("Sync away from home: off."),
        _ if a.hub_device.is_empty() => {
            println!("Sync away from home: on; waiting to meet the group's hub on the home network.")
        }
        _ if a.through => {
            println!("Sync away from home: on; connected to the hub {} through the tunnel.", a.hub_device)
        }
        _ => println!(
            "Sync away from home: on; the hub is {}, at {}; not connected through the tunnel.",
            a.hub_device,
            a.endpoints.join(", ")
        ),
    }
    if !a.error.is_empty() {
        println!("  Last problem: {}.", a.error.trim_end_matches('.'));
        if !a.detail.is_empty() && error::show_details() {
            println!("  Detail: {}", a.detail);
        }
    }
}

fn cmd_watch(g: &Global, args: &[String]) -> Result<()> {
    let zero = match args {
        [] => false,
        [a] if a == "-0" => true,
        _ => return Err(Error::msg("usage: cbb watch [-0]")),
    };
    let conn = connect(g)?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(
        &mut w,
        &control::Message::new(control::Header { op: "watch".into(), ..Default::default() }, Vec::new()),
    )?;
    let mut r = control::Reader::new(conn);
    let first = r.read()?.ok_or_else(|| Error::msg("the service closed the connection"))?;
    check(first)?;
    let mut last = 0;
    let mut out = std::io::stdout();
    while let Some(m) = r.read()? {
        if m.header.op != "write" || m.header.seq <= last {
            continue;
        }
        last = m.header.seq;
        out.write_all(&m.payload).context("cannot write the text")?;
        out.write_all(if zero { b"\0" } else { b"\n" }).context("cannot write the text")?;
        out.flush().ok();
    }
    Err(Error::msg("the service stopped"))
}

#[cfg(test)]
mod tests {
    use super::terminal_text;

    #[test]
    fn terminal_text_is_safe() {
        for (input, all, want, dropped) in [
            ("ls -l\n", false, "ls -l", 0),
            ("a\tb", false, "a\tb", 0),
            ("echo \x1b[201~; rm -rf ~\n", false, "echo [201~; rm -rf ~", 0),
            ("x\u{9b}31my\x7f\0", false, "x31my", 0),
            ("one\r\ntwo\nthree\n", false, "one", 2),
            ("one\r\ntwo\nthree\n", true, "one\ntwo\nthree", 0),
            ("\n\nfirst\n", false, "first", 0),
            ("line\rover", false, "lineover", 0),
        ] {
            assert_eq!(terminal_text(input, all), (want.to_string(), dropped), "{input:?}");
        }
    }
}
