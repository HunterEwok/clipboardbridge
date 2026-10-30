// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The user at the other end of a control connection, as the full member's
//! internal/service/peer.go: a watcher that offers a paste target gets its
//! remote pastes only when its user may take them (docs/protocol.md,
//! section 8). The control socket's group is for the clipboard, while a
//! remote paste goes to the screen or the console of one user.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

/// Whether a watcher's user may take what goes to a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Refused,
    /// Nothing tells who is at the screen (no logind).
    Unchecked,
    Allowed,
}

/// The user of the process at the other end of s, from the kernel.
#[cfg(target_os = "linux")]
pub fn uid(s: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for the kernel to write a ucred, and
    // the descriptor stays open while s lives.
    let ok = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len)
    } == 0;
    ok.then_some(cred.uid)
}

/// The user of the process at the other end of s, from the kernel.
#[cfg(not(target_os = "linux"))]
pub fn uid(s: &UnixStream) -> Option<u32> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: uid and gid are valid for the kernel to write, and the
    // descriptor stays open while s lives.
    (unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
}

/// Root and the service's own user, which take every target.
pub fn privileged(uid: u32) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    uid == 0 || uid == unsafe { libc::geteuid() }
}

/// Whether the user uid may take the remote pastes of target: root and the
/// service's own user every one; the console only them; tmux and the
/// desktop the user at the screen, as at_screen tells.
pub fn may_take(uid: Option<u32>, target: &str, at_screen: impl Fn(u32, &str) -> Verdict) -> Verdict {
    match uid {
        None => Verdict::Refused,
        Some(u) if privileged(u) => Verdict::Allowed,
        Some(_) if target == crate::service::CONSOLE => Verdict::Refused,
        Some(u) => at_screen(u, target),
    }
}

/// Asks logind: the desktop goes to the user of an active session, tmux to
/// a user with a session, as one over SSH. Without logind nothing tells who
/// is at the screen.
pub fn at_screen(uid: u32, target: &str) -> Verdict {
    let Some(list) = loginctl(&["list-sessions", "--no-legend"]) else {
        return Verdict::Unchecked;
    };
    let user = format!("User={uid}");
    for id in list.lines().filter_map(|l| l.split_whitespace().next()) {
        let props = loginctl(&["show-session", id, "-p", "User", "-p", "State"]).unwrap_or_default();
        let has = |kv: &str| props.lines().any(|l| l.trim() == kv);
        if has(&user) && (has("State=active") || target == crate::service::TMUX && has("State=online")) {
            return Verdict::Allowed;
        }
    }
    Verdict::Refused
}

fn loginctl(args: &[&str]) -> Option<String> {
    let out = Command::new("loginctl").args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{CONSOLE, DESKTOP, TMUX};

    #[test]
    fn reads_its_own_user() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no preconditions.
        assert_eq!(uid(&a), Some(unsafe { libc::geteuid() }));
    }

    #[test]
    fn takes_only_the_user_at_the_screen() {
        // A user that is neither root nor this test's.
        // SAFETY: geteuid has no preconditions.
        let other = if unsafe { libc::geteuid() } == 1001 { 1002 } else { 1001 };
        let screen = |u: u32, _: &str| if u == other { Verdict::Allowed } else { Verdict::Refused };
        assert_eq!(may_take(None, DESKTOP, screen), Verdict::Refused);
        assert_eq!(may_take(Some(0), CONSOLE, screen), Verdict::Allowed);
        assert_eq!(may_take(Some(other), CONSOLE, screen), Verdict::Refused);
        assert_eq!(may_take(Some(other), TMUX, screen), Verdict::Allowed);
        assert_eq!(may_take(Some(other + 1), DESKTOP, screen), Verdict::Refused);
        assert_eq!(may_take(Some(other), DESKTOP, |_, _| Verdict::Unchecked), Verdict::Unchecked);
    }
}
