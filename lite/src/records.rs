// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's records in the state directory, in records.json.

use std::path::Path;

pub use cbb_core::records::*;

use crate::certs::Cert;
use crate::error::{Error, Result, Wrap};
use crate::files;

/// The name of the records file in the state directory.
pub const FILE_NAME: &str = "records.json";

/// Reading and writing the records file.
pub trait Stored: Sized {
    /// Writes the records to dir/records.json in one step.
    fn save(&self, dir: &Path) -> Result<()>;
    /// Reads dir/records.json for the group of group_ca; a missing file is
    /// an empty set, and records not valid for the group are left out.
    fn load(dir: &Path, group_ca: &Cert) -> Result<Self>;
}

impl Stored for Records {
    fn save(&self, dir: &Path) -> Result<()> {
        files::write_atomic(&dir.join(FILE_NAME), &self.to_file()?, 0o600)
    }

    fn load(dir: &Path, group_ca: &Cert) -> Result<Records> {
        let path = dir.join(FILE_NAME);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Records::new(group_ca)),
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        Records::from_file(&data, group_ca).wrap(format!("{} is damaged", path.display()))
    }
}
