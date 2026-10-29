//! Directory listing that never follows symlinks and never stats a denied path.

use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::deny::DenyList;
use crate::diag::Diag;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

#[derive(Debug)]
pub struct NameEntry {
    pub name: std::ffi::OsString,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct Classified {
    pub kind: EntryKind,
    pub meta: Metadata,
    pub target: Option<String>,
}

pub fn mtime_secs(meta: &Metadata) -> Option<i64> {
    let modified = meta.modified().ok()?;
    system_time_secs(modified)
}

fn system_time_secs(t: SystemTime) -> Option<i64> {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).ok(),
        Err(e) => {
            let secs = e.duration().as_secs();
            i64::try_from(secs).ok().map(|n| -n)
        }
    }
}

/// Names inside `dir`, sorted by raw bytes. Does not stat children.
pub fn read_names(dir: &Path) -> io::Result<Vec<NameEntry>> {
    let rd = fs::read_dir(dir)?;
    let mut out = Vec::new();
    for ent in rd {
        let ent = ent?;
        out.push(NameEntry {
            name: ent.file_name(),
            path: ent.path(),
        });
    }
    out.sort_by(|a, b| a.name.as_encoded_bytes().cmp(b.name.as_encoded_bytes()));
    Ok(out)
}

/// Classify with `symlink_metadata`. Broken symlinks are reported as symlinks.
pub fn classify(path: &Path) -> io::Result<Classified> {
    let meta = fs::symlink_metadata(path)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(path).ok().map(|p| p.display().to_string());
        Ok(Classified {
            kind: EntryKind::Symlink,
            meta,
            target,
        })
    } else if ft.is_dir() {
        Ok(Classified {
            kind: EntryKind::Dir,
            meta,
            target: None,
        })
    } else {
        Ok(Classified {
            kind: EntryKind::File,
            meta,
            target: None,
        })
    }
}

pub fn rel_join(parent: &str, name: &str) -> String {
    if parent.is_empty() || parent == "." {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

pub fn lossy(name: &std::ffi::OsStr) -> String {
    name.to_string_lossy().into_owned()
}

/// Human output is one line per entry. Escape the few characters that would
/// split a line or swallow a backslash.
pub fn human_text(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

pub fn file_size(kind: EntryKind, meta: &Metadata) -> Option<u64> {
    match kind {
        EntryKind::File => Some(meta.len()),
        EntryKind::Dir | EntryKind::Symlink => None,
    }
}

/// Skip a child that the deny list forbids. Returns true when the caller
/// should not stat or read the child.
pub fn skip_denied(path: &Path, deny: &DenyList, diag: &Diag) -> bool {
    if deny.is_denied(path) {
        diag.denied(path);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_join_roots() {
        assert_eq!(rel_join("", "a"), "a");
        assert_eq!(rel_join(".", "a"), "a");
        assert_eq!(rel_join("a", "b"), "a/b");
    }
}
