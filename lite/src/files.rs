// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Writing state files in one step.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{Error, Result};

/// Writes data to path with the given mode, through a temporary file in the
/// same directory and a rename, so a crash leaves either the old file or the
/// new one.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let fail = |e| Error::with(format!("cannot write {}", path.display()), e);
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(&tmp).map_err(fail)?;
    f.write_all(data).map_err(fail)?;
    f.sync_all().map_err(fail)?;
    drop(f);
    fs::rename(&tmp, path).map_err(fail)?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
