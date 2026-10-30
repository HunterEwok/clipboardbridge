// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The strict form of signed bodies (docs/protocol.md, section 1, "Signed
//! bodies"), which every member reads alike, as Go's checkStrict.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;

use crate::error::{Error, Result};

/// How deeply a signed body nests arrays and objects at most.
const MAX_DEPTH: usize = 16;

/// Checks that b is one JSON object in valid UTF-8; member names of 1 to 64
/// of a-z, 0-9 and _, without escapes, none twice in one object; no null;
/// integers only, without fraction or exponent, in the range of i64; a
/// surrogate escape only as one half of a pair. Each name in required must
/// be a member of the object.
pub fn check(b: &[u8], required: &[&str]) -> Result<()> {
    if core::str::from_utf8(b).is_err() {
        return Err(Error::msg("a signed body is not valid UTF-8"));
    }
    let mut p = Parser { b, i: 0 };
    p.space();
    if p.peek() != Some(b'{') {
        return Err(Error::msg("a signed body is not a JSON object"));
    }
    let names = p.object(0).map_err(|e| Error::msg(format!("a signed body: {e}")))?;
    p.space();
    if p.i != b.len() {
        return Err(Error::msg("a signed body has more after its object"));
    }
    for n in required {
        if !names.contains(*n) {
            return Err(Error::msg(format!("a signed body has no {n}")));
        }
    }
    Ok(())
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

type Step<T = ()> = core::result::Result<T, &'static str>;

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Step {
        self.space();
        match self.peek() {
            None => Err("it ends early"),
            Some(b'{' | b'[') if depth >= MAX_DEPTH => Err("it nests too deeply"),
            Some(b'{') => self.object(depth + 1).map(|_| ()),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string(),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => Err("it has a null"),
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(_) => Err("an unexpected character"),
        }
    }

    fn object(&mut self, depth: usize) -> Step<BTreeSet<String>> {
        self.i += 1; // {
        let mut names = BTreeSet::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(names);
        }
        loop {
            self.space();
            let name = self.name()?;
            if !names.insert(name) {
                return Err("a member is there twice");
            }
            self.space();
            if self.peek() != Some(b':') {
                return Err("a member has no value");
            }
            self.i += 1;
            self.value(depth)?;
            self.space();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(names);
                }
                Some(_) => return Err("an unexpected character in an object"),
                None => return Err("it ends early"),
            }
        }
    }

    /// A member name: 1 to 64 of a-z, 0-9 and _ in quotes.
    fn name(&mut self) -> Step<String> {
        if self.peek() != Some(b'"') {
            return Err("a member has no name");
        }
        let start = self.i + 1;
        self.i = start;
        loop {
            match self.peek() {
                None => return Err("it ends early"),
                Some(b'"') => break,
                Some(b'a'..=b'z' | b'0'..=b'9' | b'_') => self.i += 1,
                Some(_) => return Err("a member name is not of a-z, 0-9 and _"),
            }
        }
        let name = &self.b[start..self.i];
        self.i += 1;
        if name.is_empty() || name.len() > 64 {
            return Err("a member name is not 1 to 64 characters");
        }
        // Only ASCII got here.
        Ok(String::from(core::str::from_utf8(name).unwrap_or_default()))
    }

    fn array(&mut self, depth: usize) -> Step {
        self.i += 1; // [
        self.space();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.space();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                Some(_) => return Err("an unexpected character in an array"),
                None => return Err("it ends early"),
            }
        }
    }

    fn string(&mut self) -> Step {
        self.i += 1; // "
        loop {
            match self.peek() {
                None => return Err("it ends early"),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(());
                }
                Some(c) if c < 0x20 => return Err("a string holds a control character"),
                Some(b'\\') => {}
                Some(_) => {
                    self.i += 1;
                    continue;
                }
            }
            self.i += 1;
            match self.peek() {
                None => return Err("it ends early"),
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.i += 1,
                Some(b'u') => {
                    let r = self.hex4()?;
                    if (0xd800..0xdc00).contains(&r) {
                        if self.b.get(self.i) != Some(&b'\\') || self.b.get(self.i + 1) != Some(&b'u') {
                            return Err("a string has half a surrogate pair");
                        }
                        self.i += 1;
                        if !(0xdc00..=0xdfff).contains(&self.hex4()?) {
                            return Err("a string has half a surrogate pair");
                        }
                    } else if (0xdc00..=0xdfff).contains(&r) {
                        return Err("a string has half a surrogate pair");
                    }
                }
                Some(_) => return Err("a string has an unknown escape"),
            }
        }
    }

    /// The u and four hex digits of a \u escape.
    fn hex4(&mut self) -> Step<u32> {
        let digits = self.b.get(self.i + 1..self.i + 5).ok_or("it ends early")?;
        let mut v = 0;
        for &c in digits {
            v = v * 16 + (c as char).to_digit(16).ok_or("a string has a wrong \\u escape")?;
        }
        self.i += 5;
        Ok(v)
    }

    fn literal(&mut self, s: &[u8]) -> Step {
        if !self.b[self.i..].starts_with(s) {
            return Err("an unknown literal");
        }
        self.i += s.len();
        Ok(())
    }

    /// -?(0|[1-9][0-9]*), in the range of i64.
    fn integer(&mut self) -> Step {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == digits {
            return Err("a number has no digits");
        }
        if self.b[digits] == b'0' && self.i > digits + 1 {
            return Err("a number has a leading zero");
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("a number is not an integer");
        }
        let text = core::str::from_utf8(&self.b[start..self.i]).map_err(|_| "a number is not valid")?;
        text.parse::<i64>().map(|_| ()).map_err(|_| "a number is out of range")
    }
}
