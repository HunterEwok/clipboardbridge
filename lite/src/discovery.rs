// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Finding the Linux members and dialing them (docs/protocol.md, sections 3
//! and 4). A lite member only browses, as a Mac does: it publishes nothing
//! and listens for nobody. Members can also be given by address, for a
//! network where multicast does not reach.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::certs::DeviceId;
use crate::node::Node;
use crate::pair::home_address;
use crate::uptime;

const SERVICE: &str = "_clipboardbridge._tcp.local.";
const MAX_WAIT: Duration = Duration::from_secs(30);
const STEADY: Duration = Duration::from_secs(30);

/// The addresses of a found member; None once it is gone.
type Addrs = Arc<Mutex<Option<Vec<SocketAddr>>>>;

/// Dials the member at addrs again and again, waiting 1 s after a round of
/// failures, doubling to 30 s; a connection that lasted more than 30 s
/// resets the wait.
fn dial_loop(node: Arc<Node>, addrs: Addrs, peer: Option<DeviceId>) {
    let mut wait = Duration::from_secs(1);
    loop {
        if node.is_closed() {
            return;
        }
        let Some(list) = addrs.lock().unwrap().clone() else { return };
        if peer.as_ref().is_some_and(|p| node.connected(p)) {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let mut steady = false;
        for a in list {
            let start = uptime::now();
            let res = node.dial(a, peer.clone());
            if uptime::now().saturating_sub(start) > STEADY {
                steady = true;
            }
            if res.is_ok() || steady {
                break;
            }
        }
        if steady {
            wait = Duration::from_secs(1);
        }
        std::thread::sleep(wait);
        wait = (wait * 2).min(MAX_WAIT);
    }
}

/// Starts dialing: the members at the given addresses, and, with mdns, the
/// Linux members of the group tag that browsing finds.
pub fn start(node: Arc<Node>, tag: String, statics: Vec<SocketAddr>, mdns: bool, log: Arc<dyn Fn(&str) + Send + Sync>) {
    for a in statics {
        let node = node.clone();
        std::thread::spawn(move || dial_loop(node, Arc::new(Mutex::new(Some(vec![a]))), None));
    }
    if !mdns {
        return;
    }
    std::thread::spawn(move || {
        if let Err(e) = browse(node, &tag, &*log) {
            log(&format!("cbb-lite: finding the members failed: {e}; give them with -peer"));
        }
    });
}

fn browse(node: Arc<Node>, tag: &str, log: &(dyn Fn(&str) + Send + Sync)) -> Result<(), mdns_sd::Error> {
    let daemon = mdns_sd::ServiceDaemon::new()?;
    let events = daemon.browse(SERVICE)?;
    let mut found: HashMap<DeviceId, Addrs> = HashMap::new();
    while let Ok(ev) = events.recv() {
        if node.is_closed() {
            break;
        }
        match ev {
            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                let Some(id) = instance_id(&info.fullname) else { continue };
                // Members of another group, or of a replaced CA, are ignored.
                if info.get_property_val_str("g") != Some(tag) {
                    continue;
                }
                let addrs = order(info.get_addresses().iter().map(|ip| match ip {
                    mdns_sd::ScopedIp::V6(v6) if v6.addr().is_unicast_link_local() => {
                        SocketAddr::V6(SocketAddrV6::new(*v6.addr(), info.port, 0, v6.scope_id().index))
                    }
                    other => SocketAddr::new(other.to_ip_addr(), info.port),
                }));
                if addrs.is_empty() {
                    continue;
                }
                match found.get(&id) {
                    Some(cur) => *cur.lock().unwrap() = Some(addrs),
                    None => {
                        log(&format!("cbb-lite: found {id} at {}", addrs[0]));
                        let cur: Addrs = Arc::new(Mutex::new(Some(addrs)));
                        found.insert(id.clone(), cur.clone());
                        let node = node.clone();
                        std::thread::spawn(move || dial_loop(node, cur, Some(id)));
                    }
                }
            }
            mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                if let Some(id) = instance_id(&fullname) {
                    if let Some(cur) = found.remove(&id) {
                        *cur.lock().unwrap() = None;
                    }
                }
            }
            _ => {}
        }
    }
    let _ = daemon.shutdown();
    Ok(())
}

/// The device ID in an instance name, <device ID>._clipboardbridge._tcp.local.
fn instance_id(fullname: &str) -> Option<DeviceId> {
    let label = fullname.strip_suffix(SERVICE)?.strip_suffix('.')?;
    DeviceId::parse(label).ok()
}

/// The addresses that would be published, IPv4 first, then routable IPv6,
/// then link-local IPv6.
fn order(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = addrs.filter(|a| home_address(a.ip()) && !a.ip().is_loopback()).collect();
    out.sort_by_key(|a| match a.ip() {
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if !v6.is_unicast_link_local() => 1,
        IpAddr::V6(_) => 2,
    });
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(instance_id(&format!("{id}._clipboardbridge._tcp.local.")).unwrap().as_str(), id);
        assert!(instance_id("printer._clipboardbridge._tcp.local.").is_none());
        assert!(instance_id(&format!("{id}._http._tcp.local.")).is_none());
    }

    #[test]
    fn address_order() {
        let got = order(
            ["[fe80::1]:8764", "[fd00::2]:8764", "192.168.1.5:8764", "8.8.8.8:8764"].iter().map(|s| s.parse().unwrap()),
        );
        let want: Vec<SocketAddr> =
            ["192.168.1.5:8764", "[fd00::2]:8764", "[fe80::1]:8764"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(got, want);
    }
}
