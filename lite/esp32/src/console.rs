// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The console on the board's USB port (UART0 in the QEMU build): a line of
//! text per command, typed in any serial terminal such as espflash's
//! monitor. It sets the Wi-Fi network up, shows the state and runs the
//! self-test. The board echoes what is typed, and stars for a password.

use alloc::string::String;
use alloc::vec::Vec;

use cbb_core::error::{self, Error, Result};
use cbb_core::store::Fields;
use esp_println::{print, println};

use crate::selftest;
use crate::store::{Store, Wifi, tag};

/// The longest line the console takes; a Wi-Fi password is at most 64 bytes.
const MAX_LINE: usize = 128;

/// What the rest of the firmware has to act on after a line.
pub enum Event {
    /// The Wi-Fi network to join changed; None to leave it.
    #[cfg_attr(feature = "qemu", allow(dead_code))]
    Wifi(Option<Wifi>),
}

enum Ask {
    Command,
    Ssid,
    Password(String),
}

pub struct Console {
    line: Vec<u8>,
    ask: Ask,
    last: u8,
}

impl Console {
    pub fn new() -> Console {
        Console { line: Vec::new(), ask: Ask::Command, last: 0 }
    }

    pub fn start(&self) {
        println!();
        println!("cbb-esp32 {}: type help for the commands", env!("CARGO_PKG_VERSION"));
        self.prompt();
    }

    fn prompt(&self) {
        match self.ask {
            Ask::Command => print!("cbb> "),
            Ask::Ssid => print!("Wi-Fi network name: "),
            Ask::Password(_) => print!("Password (empty for an open network): "),
        }
    }

    /// Takes one byte from the terminal. network says how the network is
    /// doing, for status.
    pub fn feed(&mut self, b: u8, store: &mut Result<Store>, network: &dyn Fn() -> String) -> Option<Event> {
        let last = core::mem::replace(&mut self.last, b);
        match b {
            b'\n' if last == b'\r' => None,
            b'\r' | b'\n' => {
                println!();
                let line = core::mem::take(&mut self.line);
                let event = match String::from_utf8(line) {
                    Ok(line) => self.line_done(line.trim(), store, network),
                    Err(_) => {
                        println!("That line is not valid UTF-8; type it again.");
                        None
                    }
                };
                self.prompt();
                event
            }
            // Backspace and delete.
            0x08 | 0x7f => {
                if self.line.pop().is_some() {
                    // A whole UTF-8 character goes, not one of its bytes.
                    while self.line.last().is_some_and(|c| c & 0xc0 == 0x80) {
                        self.line.pop();
                    }
                    print!("\x08 \x08");
                }
                None
            }
            // Ctrl-C drops the line and any question.
            0x03 => {
                self.line.clear();
                self.ask = Ask::Command;
                println!("^C");
                self.prompt();
                None
            }
            b if b < 0x20 => None,
            b => {
                if self.line.len() < MAX_LINE {
                    self.line.push(b);
                    if matches!(self.ask, Ask::Password(_)) {
                        if b & 0xc0 != 0x80 {
                            print!("*");
                        }
                    } else {
                        print!("{}", b as char);
                    }
                }
                None
            }
        }
    }

    fn line_done(&mut self, line: &str, store: &mut Result<Store>, network: &dyn Fn() -> String) -> Option<Event> {
        match core::mem::replace(&mut self.ask, Ask::Command) {
            Ask::Command => self.command(line, store, network),
            Ask::Ssid if line.is_empty() => {
                println!("Nothing changed.");
                None
            }
            Ask::Ssid if line.len() > 32 => {
                println!("A Wi-Fi network name is at most 32 bytes.");
                None
            }
            Ask::Ssid => {
                self.ask = Ask::Password(line.into());
                None
            }
            Ask::Password(_) if line.len() > 64 => {
                println!("A Wi-Fi password is at most 64 bytes.");
                None
            }
            Ask::Password(_) if !line.is_empty() && line.len() < 8 => {
                println!("A Wi-Fi password has at least 8 characters.");
                None
            }
            Ask::Password(ssid) => {
                let wifi = Wifi { ssid, password: line.into() };
                let saved = edit(store, |f| {
                    f.set(tag::WIFI_SSID, wifi.ssid.as_bytes());
                    f.set(tag::WIFI_PASSWORD, wifi.password.as_bytes());
                });
                match saved {
                    Ok(()) => println!("Saved. Joining {}.", wifi.ssid),
                    Err(e) => println!("{}\nJoining {} until the board restarts.", e.for_user(), wifi.ssid),
                }
                Some(Event::Wifi(Some(wifi)))
            }
        }
    }

    fn command(&mut self, line: &str, store: &mut Result<Store>, network: &dyn Fn() -> String) -> Option<Event> {
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (None, ..) => None,
            (Some("help"), None, _) => {
                println!("  status        what the board knows and how its network is doing");
                println!("  wifi          set the Wi-Fi network to join (asks for its name and password)");
                println!("  wifi forget   leave the Wi-Fi network and forget it");
                println!("  debug on|off  show the details of errors, or not (debug build: on by default)");
                println!("  selftest      run the TLS 1.3 self-test");
                None
            }
            (Some("status"), None, _) => {
                println!("  firmware: cbb-esp32 {}", env!("CARGO_PKG_VERSION"));
                match store {
                    Ok(s) => match s.wifi() {
                        Some(w) => println!("  Wi-Fi network: {}", w.ssid),
                        None => println!("  Wi-Fi network: none set, type wifi"),
                    },
                    Err(e) => println!("  settings: {}", e.for_user()),
                }
                println!("  network: {}", network());
                println!("  error details: {}", if error::show_details() { "on" } else { "off" });
                None
            }
            (Some("wifi"), None, _) => {
                self.ask = Ask::Ssid;
                None
            }
            (Some("wifi"), Some("forget"), None) => {
                match edit(store, |f| {
                    f.remove(tag::WIFI_SSID);
                    f.remove(tag::WIFI_PASSWORD);
                }) {
                    Ok(()) => println!("Forgot the Wi-Fi network."),
                    Err(e) => println!("{}", e.for_user()),
                }
                Some(Event::Wifi(None))
            }
            (Some("debug"), Some(mode @ ("on" | "off")), None) => {
                let on = mode == "on";
                error::set_show_details(on);
                if let Err(e) = edit(store, |f| f.set(tag::DEBUG, [on as u8])) {
                    println!("{}", e.for_user());
                }
                println!("Error details are {mode}.");
                None
            }
            (Some("selftest"), None, _) => {
                match selftest::run() {
                    Ok(()) => println!("cbb-esp32: self-test passed"),
                    Err(e) => println!("cbb-esp32: self-test failed: {}", e.for_user()),
                }
                None
            }
            _ => {
                println!("Unknown command; type help.");
                None
            }
        }
    }
}

/// Changes the saved fields and saves them.
fn edit(store: &mut Result<Store>, change: impl FnOnce(&mut Fields)) -> Result<()> {
    let Ok(s) = store.as_mut() else {
        return Err(Error::msg("cannot save the settings: the flash storage did not open (see status)"));
    };
    let mut fields = s.fields().clone();
    change(&mut fields);
    s.save(fields)
}
