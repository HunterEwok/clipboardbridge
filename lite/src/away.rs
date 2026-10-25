// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home on the lite member (docs/protocol.md, section 11):
//! off until the user turns it on (cbb global on), then the hellos offer the
//! device's tunnel key, it keeps the offer of the group's hub, and whenever
//! the hub is neither found at home nor connected it dials the hub through
//! the tunnel. It fails closed: without the tunnel, it syncs at home only,
//! and cbb global says why.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::certs::DeviceId;
use crate::control;
use crate::error::{Error, Result};
use crate::node::Node;
use crate::tunnel::{self, Hub, Link, State};
use crate::uptime;
use crate::wire::TunnelOffer;

const MAX_WAIT: Duration = Duration::from_secs(30);
const STEADY: Duration = Duration::from_secs(30);
/// How long discovery is given to find the hub at home after the service
/// starts, before the tunnel is tried.
const FIRST_WAIT: Duration = Duration::from_secs(5);

/// Sync away from home on this device.
pub struct Away {
    dir: PathBuf,
    group: String,
    me: DeviceId,
    st: Mutex<Option<State>>,
    /// What went wrong last, for the user, and the details behind it.
    error: Mutex<Option<(String, String)>>,
    /// A connection to the hub through the tunnel is being made or is up.
    through: AtomicBool,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Away {
    /// Reads the tunnel state; a state of another group is dropped, so the
    /// user turns sync away from home on again for this one.
    pub fn new(dir: PathBuf, group: String, me: DeviceId, log: Arc<dyn Fn(&str) + Send + Sync>) -> Away {
        let mut error = None;
        let st = match State::load(&dir) {
            Ok(Some(st)) if st.group == group => Some(st),
            Ok(Some(_)) => {
                if let Err(e) = State::remove(&dir) {
                    log(&format!("cbb: {}", e.for_log()));
                }
                None
            }
            Ok(None) => None,
            Err(e) => {
                // Fails closed: off, and cbb global says why.
                log(&format!("cbb: sync away from home is off: {}", e.for_log()));
                error = Some((e.message().to_string(), e.details()));
                None
            }
        };
        Away { dir, group, me, st: Mutex::new(st), error: Mutex::new(error), through: AtomicBool::new(false), log }
    }

    /// The tunnel key the hellos offer; None while sync away from home is
    /// off.
    pub fn key(&self) -> Option<Vec<u8>> {
        self.st.lock().unwrap().as_ref().map(State::public_key)
    }

    /// Turns sync away from home on, with a new key if it was off, and
    /// returns the key.
    pub fn turn_on(&self) -> Result<Vec<u8>> {
        let mut st = self.st.lock().unwrap();
        if st.is_none() {
            let next = State::new(&self.group)?;
            next.save(&self.dir)?;
            *st = Some(next);
            (self.log)("cbb: sync away from home is on");
        }
        *self.error.lock().unwrap() = None;
        Ok(st.as_ref().unwrap().public_key())
    }

    /// Turns sync away from home off and forgets its keys.
    pub fn turn_off(&self) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        State::remove(&self.dir)?;
        if st.take().is_some() {
            (self.log)("cbb: sync away from home is off");
        }
        *self.error.lock().unwrap() = None;
        Ok(())
    }

    /// Keeps the offer the group's root or an admin sent, if sync away from
    /// home is on. The first hub's offer stays until sync away from home is
    /// turned off and on again; another device's offer, and one that does
    /// not decode, are ignored, so neither moves nor stops the tunnel.
    pub fn offered(&self, from: &DeviceId, v: &serde_json::Value) {
        let mut st = self.st.lock().unwrap();
        let Some(cur) = st.as_mut() else { return };
        if let Some(h) = &cur.to_hub
            && h.device != from.as_str()
        {
            (self.log)(&format!(
                "cbb: ignored the tunnel offer from {from}: this device keeps the offer of the hub {}; run cbb global off and cbb global on here to take another",
                h.device
            ));
            return;
        }
        let hub = serde_json::from_value::<TunnelOffer>(v.clone())
            .map_err(|e| Error::with("the hub's offer does not decode", e))
            .and_then(|o| tunnel::hub_from_offer(from, &o));
        let hub = match hub {
            Ok(h) => h,
            Err(e) => {
                (self.log)(&format!("cbb: ignored a tunnel offer from {from}: {}", e.for_log()));
                *self.error.lock().unwrap() = Some((e.message().to_string(), e.details()));
                return;
            }
        };
        if cur.to_hub.as_ref() == Some(&hub) {
            return;
        }
        let mut next = cur.clone();
        let first = next.to_hub.is_none();
        next.to_hub = Some(hub);
        if let Err(e) = next.save(&self.dir) {
            (self.log)(&format!("cbb: {}", e.for_log()));
            return;
        }
        if first {
            (self.log)(&format!("cbb: {from} is the group's hub for sync away from home"));
        }
        *cur = next;
    }

    /// What cbb global and cbb status show; None while it is off.
    pub fn status(&self, node: &Node) -> Option<control::Away> {
        let st = self.st.lock().unwrap();
        let error = self.error.lock().unwrap().clone();
        let Some(st) = st.as_ref() else {
            // Off, unless the state could not be read.
            return error.map(|(e, d)| control::Away { error: e, detail: d, ..Default::default() });
        };
        let mut a = control::Away { keys_in_file: true, ..Default::default() };
        if let Some(h) = &st.to_hub {
            a.hub_device = h.device.clone();
            a.endpoints = h.endpoints.iter().map(ToString::to_string).collect();
            a.through =
                self.through.load(Ordering::SeqCst) && DeviceId::parse(&h.device).is_ok_and(|id| node.connected(&id));
        }
        if let Some((e, d)) = error {
            a.error = e;
            a.detail = d;
        }
        Some(a)
    }

    fn fail(&self, e: &Error) {
        let mut cur = self.error.lock().unwrap();
        if cur.as_ref().is_none_or(|(m, _)| m != e.message()) {
            (self.log)(&format!("cbb: away from home: {}", e.for_log()));
        }
        *cur = Some((e.message().to_string(), e.details()));
    }

    /// Dials the hub through the tunnel whenever it is neither found at
    /// home nor connected, until the service stops.
    pub fn run(self: Arc<Self>, node: Arc<Node>) {
        std::thread::sleep(FIRST_WAIT);
        let mut link: Option<(Hub, Link)> = None;
        let mut wait = Duration::from_secs(1);
        while !node.is_closed() {
            let st = self.st.lock().unwrap().clone();
            let Some((st, hub)) = st.and_then(|s| s.to_hub.clone().map(|h| (s, h))) else {
                link = None;
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            let Ok(id) = DeviceId::parse(&hub.device) else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            if node.connected(&id) || node.at_home(&id) {
                // At home the tunnel is not used, so it sends nothing.
                link = None;
                wait = Duration::from_secs(1);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            if link.as_ref().is_none_or(|(h, _)| *h != hub) {
                link = None;
                match Link::start(&st, &hub, &self.me, self.log.clone()) {
                    Ok(l) => link = Some((hub.clone(), l)),
                    Err(e) => {
                        self.fail(&e);
                        std::thread::sleep(wait);
                        wait = (wait * 2).min(MAX_WAIT);
                        continue;
                    }
                }
            }
            let (_, l) = link.as_ref().unwrap();
            let start = uptime::now();
            self.through.store(true, Ordering::SeqCst);
            let res = node.dial(l.local(), Some(id.clone()));
            self.through.store(false, Ordering::SeqCst);
            match res {
                Ok(()) => *self.error.lock().unwrap() = None,
                Err(e) if !l.answered() => self.fail(&e.context(
                    "the hub does not answer through the tunnel: it may be off, its UDP port closed, or the network on the way down",
                )),
                Err(e) => self.fail(&e),
            }
            if uptime::now().saturating_sub(start) > STEADY {
                wait = Duration::from_secs(1);
            }
            std::thread::sleep(wait);
            wait = (wait * 2).min(MAX_WAIT);
        }
    }
}
