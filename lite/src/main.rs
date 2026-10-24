// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb is the lite member of clipboardbridge for small Linux devices,
//! such as routers and small boards: a member without CA keys that only
//! dials the computers, joins by QR code through the
//! phone, and syncs (docs/design.md, roadmap item 11).

mod control;
mod discovery;
mod error;
mod files;
mod identity;
mod next;
mod node;
mod pair;
mod records;
mod service;
mod tls;
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
  paste                Print this member's clipboard text.
  status               Show this device, its group and the group's devices.
  watch [-0]           Print every text the group sends here, one per line
                       (with -0, each followed by a zero byte).
  next paste|copy|join The same for the ZX Spectrum Next's .cbb dot command,
                       in frames its Z80 reads (lite/README.md).
  version              Print the version and that this is the lite member.
  help                 Print this help.

This is the lite member: the commands of a full member, such as pair or
global, are not here. The state directory is /var/lib/clipboardbridge
(CBB_STATE), the control socket /run/clipboardbridge/control.sock
(CBB_SOCKET). -debug, or CBB_DEBUG=1, shows the details of errors.
";

/// The commands of a full member (cmd/cbb) that the lite member does not
/// have, so that it says so instead of "unknown command".
const FULL_ONLY: &[&str] =
    &["global", "revoke", "admin", "new", "pair", "invite", "holder", "forward", "relay", "service", "agent"];

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
                "paste" => cmd_simple(&g, "paste", rest),
                "status" => cmd_simple(&g, "status", rest),
                "watch" => cmd_watch(&g, rest),
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
    let save = move |id: &identity::Identity| id.save(&state);
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
                println!("In the clipboardbridge app, tap \"Connect a new device\" (or run the shortcut");
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
    if for_next {
        print!("CBB# joined the group {} as {}\r", id.tag(), id.id);
    } else {
        println!("Joined the group {} as {}.", id.tag(), id.id);
    }
    Ok(())
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

/// Sends one request to the service and returns its answer.
fn request(g: &Global, m: &control::Message) -> Result<control::Message> {
    let conn = UnixStream::connect(&g.socket).context(format!(
        "cannot reach the lite member's service at {}; is it running (systemctl status clipboardbridge)?",
        g.socket.display()
    ))?;
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

fn cmd_simple(g: &Global, op: &str, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(Error::msg(format!("{op} takes no arguments")));
    }
    let m = request(g, &control::Message::new(control::Header { op: op.into(), ..Default::default() }, Vec::new()))?;
    match op {
        "paste" => {
            std::io::stdout().write_all(&m.payload).context("cannot write the text")?;
        }
        "status" => {
            let s = m.header.status.unwrap_or_default();
            println!("device  {}\ngroup   {}\nrole    {}\nversion {}", s.device, s.group, s.role, s.version);
            if s.peers.is_empty() {
                println!("no members connected");
            }
            if s.group.is_empty() {
                return Ok(());
            }
            let devs = request(
                g,
                &control::Message::new(control::Header { op: "devices".into(), ..Default::default() }, Vec::new()),
            )?;
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
        }
        _ => {}
    }
    Ok(())
}

fn cmd_watch(g: &Global, args: &[String]) -> Result<()> {
    let zero = match args {
        [] => false,
        [a] if a == "-0" => true,
        _ => return Err(Error::msg("usage: cbb watch [-0]")),
    };
    let conn = UnixStream::connect(&g.socket).context(format!(
        "cannot reach the lite member's service at {}; is it running (systemctl status clipboardbridge)?",
        g.socket.display()
    ))?;
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
