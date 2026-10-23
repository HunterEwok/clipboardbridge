// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The sync engine: the group's current event on this member and what goes
//! into the member's own clipboard (docs/protocol.md, section 5). It follows
//! Go's package clip, so a lite member behaves as the others do; it only
//! decides, and the caller does the networking.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::certs::{is_id, random_bytes, random_id};
use crate::error::{Error, Result};
use crate::hlc::{Clock, Timestamp};

/// The largest text, in bytes, that the group carries.
pub const MAX_TEXT: usize = 1 << 20;
const SECRET_TTL: Duration = Duration::from_secs(60);
const LIVE_WINDOW: Duration = Duration::from_secs(60);
const REJOIN_WINDOW: Duration = Duration::from_secs(30);
const SECRET_MEMORY: Duration = Duration::from_secs(12 * 3600);
const ECHO_WINDOW: Duration = Duration::from_secs(10);
const MAX_AGE_MS: i64 = 365 * 24 * 3600 * 1000;
const MAX_SECRETS: usize = 4096;
const SEEN_IDS: usize = 4096;

/// Normal text or a secret, such as a password.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Text,
    Secret,
}

/// How a text reached the member that made the event.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum Via {
    #[default]
    #[serde(rename = "copy")]
    Copy,
    #[serde(rename = "iphone")]
    Phone,
    #[serde(rename = "universal-clipboard")]
    Universal,
}

impl Via {
    fn is_copy(&self) -> bool {
        *self == Via::Copy
    }
}

/// One copy, as it travels between members.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default, skip_serializing_if = "Via::is_copy")]
    pub via: Via,
    #[serde(default)]
    pub time: Timestamp,
    #[serde(rename = "age_ms", default)]
    pub age: i64,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default)]
    pub text: String,
}

impl Event {
    /// Reports whether this is the mark of a secret: the event without its
    /// text.
    pub fn is_mark(&self) -> bool {
        self.kind == Kind::Secret && self.text.is_empty()
    }

    /// Checks an event received from another member.
    pub fn validate(&self) -> Result<()> {
        if !is_id(&self.id) {
            return Err(Error::msg("bad event ID"));
        }
        if !is_id(&self.origin) {
            return Err(Error::msg("bad origin device ID"));
        }
        if self.time.is_zero() || !self.time.valid() {
            return Err(Error::msg("bad timestamp"));
        }
        if self.age < 0 {
            return Err(Error::msg(format!("negative event age {} ms", self.age)));
        }
        if self.is_mark() {
            return Ok(());
        }
        check_text(&self.text)
    }

    /// Reports whether self sorts after f: by timestamp, then by ID.
    pub fn later(&self, f: &Event) -> bool {
        if self.time != f.time {
            return self.time > f.time;
        }
        self.id > f.id
    }
}

pub fn check_text(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::msg("the text is empty"));
    }
    if s.len() > MAX_TEXT {
        return Err(Error::msg(format!("the text of {} bytes is larger than 1 MiB", s.len())));
    }
    Ok(())
}

/// What a member sends when a connection starts.
#[derive(Clone, Debug, Default)]
pub struct Hello {
    pub wall: i64,
    pub current: Option<Event>,
}

/// What to do with an event that came in.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// The event to send on to the other members, if anything is new.
    pub forward: Option<Event>,
    /// Write the event's text to the local clipboard.
    pub write: bool,
    /// Orders the writes.
    pub seq: u64,
}

#[derive(Clone, Default)]
struct Local {
    text: String, // empty when unknown
    kind: Kind,
    at: Duration,
}

type Sum = [u8; 32];

struct Inner {
    current: Event,
    copied_at: Duration,
    local: Local,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    written: VecDeque<(Sum, Duration)>,
    secrets: HashMap<Sum, Duration>,
    seq: u64,
    skews: HashMap<String, i64>,
    peers: HashMap<String, usize>,
    synced: bool,
    offline_copy: bool,
    rejoined: bool,
    rejoin_at: Duration,
}

/// The state of one member. It is safe for concurrent use.
pub struct Engine {
    self_id: String,
    clock: Clock,
    wall: Box<dyn Fn() -> i64 + Send + Sync>,
    uptime: Box<dyn Fn() -> Duration + Send + Sync>,
    key: hmac::Key,
    inner: Mutex<Inner>,
}

impl Engine {
    pub fn new(
        self_id: &str,
        clock: Clock,
        wall: Box<dyn Fn() -> i64 + Send + Sync>,
        uptime: Box<dyn Fn() -> Duration + Send + Sync>,
    ) -> Engine {
        Engine {
            self_id: self_id.to_string(),
            clock,
            wall,
            uptime,
            key: hmac::Key::new(hmac::HMAC_SHA256, &random_bytes::<32>()),
            inner: Mutex::new(Inner {
                current: Event::default(),
                copied_at: Duration::ZERO,
                local: Local::default(),
                seen: HashSet::new(),
                seen_order: VecDeque::new(),
                written: VecDeque::new(),
                secrets: HashMap::new(),
                seq: 0,
                skews: HashMap::new(),
                peers: HashMap::new(),
                synced: false,
                offline_copy: false,
                rejoined: false,
                rejoin_at: Duration::ZERO,
            }),
        }
    }

    fn sum(&self, text: &str) -> Sum {
        hmac::sign(&self.key, text.as_bytes()).as_ref().try_into().unwrap()
    }

    /// The group's current event with its age as of now, unless there is
    /// none or it is a secret that expired or is known only by its mark.
    #[allow(dead_code)]
    pub fn current(&self) -> Option<Event> {
        let st = self.inner.lock().unwrap();
        let now = (self.uptime)();
        self.live(&st, now).then(|| self.with_age(&st, now))
    }

    /// The text of this member's own clipboard, its kind, and how long ago
    /// it was copied; None when unknown or an expired secret.
    pub fn local(&self) -> Option<(String, Kind, Duration)> {
        let st = self.inner.lock().unwrap();
        let now = (self.uptime)();
        local_live(&st, now).then(|| (st.local.text.clone(), st.local.kind, now.saturating_sub(st.local.at)))
    }

    /// Records what the local clipboard holds without making an event.
    pub fn clipboard_is(&self, text: &str, kind: Kind) {
        let mut st = self.inner.lock().unwrap();
        if check_text(text).is_err() {
            st.local = Local::default();
            return;
        }
        let now = (self.uptime)();
        st.local = Local { text: text.to_string(), kind, at: now };
        if kind == Kind::Secret {
            add_secret(&mut st, self.sum(text), now);
        }
    }

    /// Records a change that a clipboard watcher reported, and returns the
    /// event to send, or None when the clipboard did not really change for
    /// the group.
    pub fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<Option<Event>> {
        check_text(text)?;
        let mut st = self.inner.lock().unwrap();
        let now = (self.uptime)();
        settle(&mut st, now);
        let sum = self.sum(text);
        if local_has(&st, text, now)
            || st.written.iter().any(|(s, at)| *s == sum && now.saturating_sub(*at) <= ECHO_WINDOW)
        {
            return Ok(None);
        }
        if via == Via::Universal && self.live(&st, now) && st.current.text == text {
            st.local = Local { text: text.to_string(), kind: st.current.kind, at: st.copied_at };
            return Ok(None);
        }
        if kind == Kind::Text && has_secret(&st, &sum, now) {
            st.local = Local::default();
            return Ok(None);
        }
        Ok(Some(self.new_event(&mut st, text, kind, via, sum, now)))
    }

    /// Makes an event from a deliberate action; it always makes one, and the
    /// outcome tells whether to write it to the member's own clipboard.
    pub fn send(&self, text: &str, mut kind: Kind, via: Via) -> Result<(Event, Outcome)> {
        check_text(text)?;
        let mut st = self.inner.lock().unwrap();
        let now = (self.uptime)();
        settle(&mut st, now);
        let sum = self.sum(text);
        if has_secret(&st, &sum, now) {
            kind = Kind::Secret;
        }
        let mut out = Outcome::default();
        if !local_has(&st, text, now) {
            st.seq += 1;
            out.write = true;
            out.seq = st.seq;
            add_written(&mut st, sum, now);
        }
        let ev = self.new_event(&mut st, text, kind, via, sum, now);
        Ok((ev, out))
    }

    fn new_event(&self, st: &mut Inner, text: &str, kind: Kind, via: Via, sum: Sum, now: Duration) -> Event {
        let ev = Event {
            id: random_id(),
            origin: self.self_id.clone(),
            via,
            time: self.clock.now(),
            age: 0,
            kind,
            text: text.to_string(),
        };
        add_seen(st, &ev.id);
        st.current = ev.clone();
        st.copied_at = now;
        st.local = Local { text: text.to_string(), kind, at: now };
        if kind == Kind::Secret {
            add_secret(st, sum, now);
        }
        st.offline_copy = !st.synced || st.peers.is_empty();
        ev
    }

    /// Applies an event a peer delivered.
    pub fn received(&self, ev: Event) -> Result<Outcome> {
        ev.validate()?;
        let mut st = self.inner.lock().unwrap();
        Ok(self.receive(&mut st, ev))
    }

    /// Records an open connection to peer and returns the hello to send on
    /// it.
    pub fn connected(&self, peer: &str) -> Hello {
        let mut st = self.inner.lock().unwrap();
        *st.peers.entry(peer.to_string()).or_default() += 1;
        let mut h = Hello { wall: (self.wall)(), current: None };
        if !st.current.id.is_empty() {
            let mut ev = self.with_age(&st, (self.uptime)());
            if ev.kind == Kind::Secret {
                ev.text.clear();
            }
            h.current = Some(ev);
        }
        h
    }

    /// Records that a connection to peer is gone.
    pub fn disconnected(&self, peer: &str) {
        let mut st = self.inner.lock().unwrap();
        match st.peers.get_mut(peer) {
            Some(n) if *n > 1 => {
                *n -= 1;
                return;
            }
            _ => {}
        }
        st.peers.remove(peer);
        st.skews.remove(peer);
        if st.peers.is_empty() {
            settle(&mut st, (self.uptime)());
            st.synced = false;
        }
    }

    /// Records that this member itself was away: the service just started.
    pub fn rejoin(&self) {
        let mut st = self.inner.lock().unwrap();
        let now = (self.uptime)();
        settle(&mut st, now);
        st.rejoined = true;
        st.rejoin_at = now;
        st.synced = false;
    }

    /// Applies the hello a peer sent when the connection started.
    pub fn reconcile(&self, peer: &str, h: Hello) -> Result<Outcome> {
        if let Some(c) = &h.current {
            c.validate()?;
            if c.kind == Kind::Secret && !c.is_mark() {
                return Err(Error::msg("a hello must not carry a secret's text"));
            }
        }
        let mut st = self.inner.lock().unwrap();
        let known = st.skews.contains_key(peer);
        if h.wall > 0 && (known || st.skews.len() < 1024) {
            let skew = h.wall - (self.wall)();
            st.skews.insert(peer.to_string(), skew);
        }
        let mut out = Outcome::default();
        if let Some(c) = h.current {
            out = self.receive(&mut st, c);
        }
        st.synced = !st.peers.is_empty();
        Ok(out)
    }

    /// For each connected peer, how far its wall clock was ahead of this
    /// member's, in milliseconds, when its hello arrived.
    pub fn skews(&self) -> HashMap<String, i64> {
        self.inner.lock().unwrap().skews.clone()
    }

    fn receive(&self, st: &mut Inner, ev: Event) -> Outcome {
        let now = (self.uptime)();
        let age = Duration::from_millis(ev.age.min(MAX_AGE_MS) as u64);
        if st.seen.contains(&ev.id) {
            if st.current.id != ev.id {
                return Outcome::default();
            }
            // The full event may follow the mark of the same secret.
            if st.current.is_mark() && !ev.is_mark() {
                add_secret(st, self.sum(&ev.text), now);
                st.copied_at = now.saturating_sub(age);
                st.current = ev.clone();
                return self.decide_write(st, Outcome { forward: Some(ev), ..Default::default() }, now);
            }
            if st.rejoined && !st.synced && in_rejoin_window(st, now) {
                return self.decide_write(st, Outcome::default(), now);
            }
            return Outcome::default();
        }
        self.clock.observe(ev.time);
        add_seen(st, &ev.id);
        if ev.kind == Kind::Secret && !ev.is_mark() {
            add_secret(st, self.sum(&ev.text), now);
        }
        let out = Outcome { forward: Some(ev.clone()), ..Default::default() };
        if !st.current.id.is_empty() && !ev.later(&st.current) {
            return out;
        }
        st.current = ev;
        st.copied_at = now.saturating_sub(age);
        self.decide_write(st, out, now)
    }

    fn decide_write(&self, st: &mut Inner, mut out: Outcome, now: Duration) -> Outcome {
        settle(st, now);
        if !self.live(st, now) || local_has(st, &st.current.text, now) {
            return out;
        }
        if now.saturating_sub(st.copied_at) > LIVE_WINDOW && (!in_rejoin_window(st, now) || st.offline_copy) {
            return out;
        }
        st.seq += 1;
        out.write = true;
        out.seq = st.seq;
        st.local = Local { text: st.current.text.clone(), kind: st.current.kind, at: st.copied_at };
        let sum = self.sum(&st.current.text);
        add_written(st, sum, now);
        st.offline_copy = false;
        out
    }

    fn live(&self, st: &Inner, now: Duration) -> bool {
        if st.current.id.is_empty() || st.current.is_mark() {
            return false;
        }
        st.current.kind != Kind::Secret || now.saturating_sub(st.copied_at) < SECRET_TTL
    }

    fn with_age(&self, st: &Inner, now: Duration) -> Event {
        let mut ev = st.current.clone();
        ev.age = (now.saturating_sub(st.copied_at).as_millis() as i64).min(MAX_AGE_MS);
        ev
    }
}

fn settle(st: &mut Inner, now: Duration) {
    if st.offline_copy && st.synced && !in_rejoin_window(st, now) {
        st.offline_copy = false;
    }
}

fn in_rejoin_window(st: &Inner, now: Duration) -> bool {
    st.rejoined && now.saturating_sub(st.rejoin_at) < REJOIN_WINDOW
}

fn local_live(st: &Inner, now: Duration) -> bool {
    !st.local.text.is_empty() && (st.local.kind != Kind::Secret || now.saturating_sub(st.local.at) < SECRET_TTL)
}

fn local_has(st: &Inner, text: &str, now: Duration) -> bool {
    local_live(st, now) && st.local.text == text
}

fn add_seen(st: &mut Inner, id: &str) {
    if st.seen.contains(id) {
        return;
    }
    if st.seen_order.len() >= SEEN_IDS {
        if let Some(old) = st.seen_order.pop_front() {
            st.seen.remove(&old);
        }
    }
    st.seen.insert(id.to_string());
    st.seen_order.push_back(id.to_string());
}

fn add_written(st: &mut Inner, sum: Sum, now: Duration) {
    if st.written.len() >= 8 {
        st.written.pop_front();
    }
    st.written.push_back((sum, now));
}

fn add_secret(st: &mut Inner, sum: Sum, now: Duration) {
    if !st.secrets.contains_key(&sum) && st.secrets.len() >= MAX_SECRETS {
        if let Some(oldest) = st.secrets.iter().min_by_key(|(_, at)| **at).map(|(s, _)| *s) {
            st.secrets.remove(&oldest);
        }
    }
    st.secrets.insert(sum, now);
}

fn has_secret(st: &Inner, sum: &Sum, now: Duration) -> bool {
    st.secrets.get(sum).is_some_and(|at| now.saturating_sub(*at) <= SECRET_MEMORY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn engine(id: &str, t: Arc<AtomicU64>) -> Engine {
        let t2 = t.clone();
        Engine::new(
            id,
            Clock::new(
                Box::new(move || 1_761_024_000_000 + t2.load(Ordering::SeqCst) as i64),
                Timestamp::default(),
                None,
            ),
            Box::new(|| 1_761_024_000_000),
            Box::new(move || Duration::from_millis(t.load(Ordering::SeqCst))),
        )
    }

    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn two_members_converge() {
        let t = Arc::new(AtomicU64::new(100_000));
        let (a, b) = (engine(A, t.clone()), engine(B, t.clone()));
        a.rejoin();
        b.rejoin();
        let ha = a.connected(B);
        let hb = b.connected(A);
        a.reconcile(B, hb).unwrap();
        b.reconcile(A, ha).unwrap();
        t.fetch_add(60_000, Ordering::SeqCst);

        let (ev, out) = a.send("hello", Kind::Text, Via::Copy).unwrap();
        assert!(out.write);
        let got = b.received(ev.clone()).unwrap();
        assert!(got.write && got.forward.is_some());
        assert_eq!(b.local().unwrap().0, "hello");
        // A duplicate does nothing.
        let again = b.received(ev).unwrap();
        assert!(!again.write && again.forward.is_none());
        // The echo of the write is no new copy.
        assert!(b.copied("hello", Kind::Text, Via::Copy).unwrap().is_none());
    }

    #[test]
    fn hellos_carry_only_the_mark_of_a_secret() {
        let t = Arc::new(AtomicU64::new(100_000));
        let a = engine(A, t);
        a.send("hunter2", Kind::Secret, Via::Copy).unwrap();
        let h = a.connected(B);
        let cur = h.current.unwrap();
        assert!(cur.is_mark());
        // A hello with a secret's text is refused.
        let mut bad = cur.clone();
        bad.text = "hunter2".into();
        assert!(a.reconcile(B, Hello { wall: 0, current: Some(bad) }).is_err());
    }

    #[test]
    fn old_events_are_not_written_outside_the_windows() {
        let t = Arc::new(AtomicU64::new(1_000_000));
        let b = engine(B, t.clone());
        let ev = Event {
            id: "77aa0000000000000000000000000000".into(),
            origin: A.into(),
            time: Timestamp { wall: 1_761_024_000_000, logical: 0 },
            age: 120_000,
            text: "old".into(),
            ..Default::default()
        };
        let out = b.received(ev).unwrap();
        assert!(out.forward.is_some() && !out.write);
    }
}
