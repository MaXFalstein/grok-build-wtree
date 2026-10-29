//! Sync-conflict copies and iCloud placeholder files.
//!
//! iCloud's `" N"` suffix (`N >= 2`) is reported even when the original is
//! missing, so a leftover `.git/HEAD 2` is visible. Dropbox, Syncthing, and
//! `.icloud` placeholders are reported the same way.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::deny::{guard_root, DenyList};
use crate::diag::Diag;
use crate::walk::{classify, lossy, mtime_secs, read_names, skip_denied, EntryKind};
use crate::Render;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    Icloud,
    IcloudPlaceholder,
    Dropbox,
    Syncthing,
}

#[derive(Clone, Debug, Serialize)]
pub struct Conflict {
    pub kind: ConflictKind,
    pub path: String,
    pub original: String,
    pub original_exists: bool,
    pub mtime: Option<i64>,
    pub original_mtime: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConflictReport {
    pub roots: Vec<String>,
    pub conflicts: Vec<Conflict>,
    pub partial: bool,
    pub error_count: u64,
}

pub fn scan(paths: &[PathBuf], deny: &DenyList, diag: &Diag) -> ConflictReport {
    let before = diag.error_count();
    let mut conflicts = Vec::new();
    let mut roots = Vec::new();
    for path in paths {
        match guard_root(path, deny) {
            Ok(abs) => {
                roots.push(abs.display().to_string());
                walk(&abs, &abs, deny, diag, &mut conflicts);
            }
            Err(msg) => diag.error(path, msg),
        }
    }
    conflicts.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(kind_ord(a.kind).cmp(&kind_ord(b.kind)))
    });
    conflicts.dedup_by(|a, b| a.path == b.path && a.kind == b.kind);
    let errors = diag.error_count().saturating_sub(before);
    ConflictReport {
        roots,
        conflicts,
        partial: errors > 0,
        error_count: errors,
    }
}

fn kind_ord(k: ConflictKind) -> u8 {
    match k {
        ConflictKind::Icloud => 0,
        ConflictKind::IcloudPlaceholder => 1,
        ConflictKind::Dropbox => 2,
        ConflictKind::Syncthing => 3,
    }
}

fn walk(root: &Path, dir: &Path, deny: &DenyList, diag: &Diag, out: &mut Vec<Conflict>) {
    let classified = match classify(dir) {
        Ok(c) => c,
        Err(e) => {
            diag.io_error(dir, &e);
            return;
        }
    };
    if classified.kind == EntryKind::Symlink {
        consider(root, dir, &classified, deny, out);
        return;
    }
    if classified.kind != EntryKind::Dir {
        consider(root, dir, &classified, deny, out);
        return;
    }
    // The root directory itself is not a conflict copy of its parent.
    if dir != root {
        consider(root, dir, &classified, deny, out);
    }
    let names = match read_names(dir) {
        Ok(n) => n,
        Err(e) => {
            diag.io_error(dir, &e);
            return;
        }
    };
    let mut stack_children = Vec::new();
    for ent in names {
        if skip_denied(&ent.path, deny, diag) {
            continue;
        }
        stack_children.push(ent.path);
    }
    for child in stack_children {
        let child_meta = match classify(&child) {
            Ok(c) => c,
            Err(e) => {
                diag.io_error(&child, &e);
                continue;
            }
        };
        consider(root, &child, &child_meta, deny, out);
        if child_meta.kind == EntryKind::Dir {
            walk_dir_children(root, &child, deny, diag, out);
        }
    }
}

fn walk_dir_children(
    root: &Path,
    dir: &Path,
    deny: &DenyList,
    diag: &Diag,
    out: &mut Vec<Conflict>,
) {
    // Iterative walk to keep deep trees off the call stack. `walk` already
    // handled `dir` itself; this descends.
    let mut stack = vec![dir.to_path_buf()];
    // `dir` was already considered by the caller. Only its descendants remain.
    // The first pop re-lists `dir`, so skip considering names we already
    // emitted by starting from children only.
    stack.clear();
    let names = match read_names(dir) {
        Ok(n) => n,
        Err(e) => {
            diag.io_error(dir, &e);
            return;
        }
    };
    for ent in names.into_iter().rev() {
        stack.push(ent.path);
    }
    while let Some(path) = stack.pop() {
        if skip_denied(&path, deny, diag) {
            continue;
        }
        let classified = match classify(&path) {
            Ok(c) => c,
            Err(e) => {
                diag.io_error(&path, &e);
                continue;
            }
        };
        consider(root, &path, &classified, deny, out);
        if classified.kind == EntryKind::Dir {
            match read_names(&path) {
                Ok(names) => {
                    for ent in names.into_iter().rev() {
                        stack.push(ent.path);
                    }
                }
                Err(e) => diag.io_error(&path, &e),
            }
        }
    }
}

fn consider(
    root: &Path,
    path: &Path,
    classified: &crate::walk::Classified,
    deny: &DenyList,
    out: &mut Vec<Conflict>,
) {
    let Some(name) = path.file_name().map(lossy) else {
        return;
    };
    let Some((kind, original_name)) = classify_name(&name) else {
        return;
    };
    let parent = path.parent().unwrap_or(root);
    let original_path = parent.join(&original_name);
    if deny.is_denied(&original_path) {
        return;
    }
    let (exists, original_mtime) = match classify(&original_path) {
        Ok(c) => (true, mtime_secs(&c.meta)),
        Err(_) => (false, None),
    };
    let _ = root;
    out.push(Conflict {
        kind,
        path: path.display().to_string(),
        original: original_path.display().to_string(),
        original_exists: exists,
        mtime: mtime_secs(&classified.meta),
        original_mtime,
    });
}

pub fn classify_name(name: &str) -> Option<(ConflictKind, String)> {
    if let Some(orig) = icloud_placeholder(name) {
        return Some((ConflictKind::IcloudPlaceholder, orig));
    }
    if let Some(orig) = syncthing_original(name) {
        return Some((ConflictKind::Syncthing, orig));
    }
    if let Some(orig) = dropbox_original(name) {
        return Some((ConflictKind::Dropbox, orig));
    }
    if let Some(orig) = icloud_numbered(name) {
        return Some((ConflictKind::Icloud, orig));
    }
    None
}

/// `.video.mov.icloud` shadows `video.mov` (not downloaded).
pub fn icloud_placeholder(name: &str) -> Option<String> {
    let stripped = name.strip_suffix(".icloud")?;
    let orig = stripped.strip_prefix('.')?;
    if orig.is_empty() {
        return None;
    }
    Some(orig.to_string())
}

/// `name 2`, `name 3.ext`, `.git 12`, `index 2`, `archive.tar 2.gz`.
/// The number is any integer `>= 2`, not only 2.
pub fn icloud_numbered(name: &str) -> Option<String> {
    let (base, ext) = split_final_ext(name);
    let (stem, _n) = split_trailing_copy_number(base)?;
    if stem.is_empty() || stem.ends_with(' ') {
        return None;
    }
    Some(format!("{stem}{ext}"))
}

fn split_trailing_copy_number(base: &str) -> Option<(&str, u32)> {
    let idx = base.rfind(' ')?;
    let stem = &base[..idx];
    let num = &base[idx + 1..];
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = num.parse().ok()?;
    if n < 2 {
        return None;
    }
    Some((stem, n))
}

/// Conflict copies of git metadata: anything inside a `.git` directory, or a
/// sibling whose original name is `.git` (`.git 2`, `.git 3`).
pub fn is_git_metadata_conflict(path: &str) -> bool {
    let p = std::path::Path::new(path);
    if p.components().any(|c| c.as_os_str() == ".git") {
        return true;
    }
    let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    match classify_name(name) {
        Some((_, orig)) => orig == ".git" || orig.starts_with(".git"),
        None => false,
    }
}

fn split_final_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => {
            let ext = &name[i..];
            let body = &ext[1..];
            if body.is_empty() || body.contains(' ') || body.contains('.') {
                (name, "")
            } else {
                (&name[..i], ext)
            }
        }
        _ => (name, ""),
    }
}

pub fn dropbox_original(name: &str) -> Option<String> {
    let start = name.find("(conflicted copy")?;
    let rest = &name[start..];
    let close = rest.find(')')?;
    let prefix = name[..start].trim_end();
    let suffix = &rest[close + 1..];
    if prefix.is_empty() && suffix.is_empty() {
        return None;
    }
    Some(format!("{prefix}{suffix}"))
}

pub fn syncthing_original(name: &str) -> Option<String> {
    const MARKER: &str = ".sync-conflict-";
    let idx = name.find(MARKER)?;
    let prefix = &name[..idx];
    if prefix.is_empty() {
        return None;
    }
    let rest = &name[idx + MARKER.len()..];
    let (id, ext) = match rest.find('.') {
        Some(d) => (&rest[..d], &rest[d..]),
        None => (rest, ""),
    };
    if id.len() < 8 || !id.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    if ext[1..].contains('.') && ext.len() > 1 {
        // A dotted device id is not the Syncthing pattern we recognise.
        // Extensions themselves are a single suffix.
    }
    Some(format!("{prefix}{ext}"))
}

pub fn render(report: &ConflictReport, mode: Render, mut out: impl Write) -> io::Result<()> {
    match mode {
        Render::Human => {
            if report.conflicts.is_empty() {
                writeln!(out, "conflicts: 0")?;
            }
            for c in &report.conflicts {
                writeln!(
                    out,
                    "{}  {}  shadows {}  mtime {} / {}  original_exists={}",
                    kind_str(c.kind),
                    c.path,
                    c.original,
                    fmt(c.mtime),
                    fmt(c.original_mtime),
                    c.original_exists
                )?;
            }
            writeln!(out, "count {}", report.conflicts.len())?;
        }
        Render::Json => {
            let body = serde_json::json!({
                "command": "conflicts",
                "roots": report.roots,
                "conflicts": report.conflicts,
                "count": report.conflicts.len(),
                "partial": report.partial,
                "error_count": report.error_count,
            });
            serde_json::to_writer_pretty(&mut out, &body)?;
            writeln!(out)?;
        }
        Render::Ndjson => {
            for c in &report.conflicts {
                let mut v = serde_json::to_value(c).unwrap_or(serde_json::Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("type".into(), serde_json::json!("conflict"));
                }
                serde_json::to_writer(&mut out, &v)?;
                writeln!(out)?;
            }
            let summary = serde_json::json!({
                "type": "summary",
                "count": report.conflicts.len(),
                "partial": report.partial,
                "error_count": report.error_count,
            });
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

fn kind_str(k: ConflictKind) -> &'static str {
    match k {
        ConflictKind::Icloud => "icloud",
        ConflictKind::IcloudPlaceholder => "icloud_placeholder",
        ConflictKind::Dropbox => "dropbox",
        ConflictKind::Syncthing => "syncthing",
    }
}

fn fmt(v: Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        assert_eq!(icloud_numbered("notes 2.txt").as_deref(), Some("notes.txt"));
        assert_eq!(icloud_numbered("notes 3.txt").as_deref(), Some("notes.txt"));
        assert_eq!(icloud_numbered(".git 12").as_deref(), Some(".git"));
        assert_eq!(icloud_numbered("index 2").as_deref(), Some("index"));
        assert_eq!(
            icloud_numbered("archive.tar 2.gz").as_deref(),
            Some("archive.tar.gz")
        );
        assert_eq!(icloud_numbered("HEAD 2").as_deref(), Some("HEAD"));
        assert!(icloud_numbered("file2.txt").is_none());
        assert!(is_git_metadata_conflict("/repo/.git/HEAD 2"));
        assert!(is_git_metadata_conflict("/repo/.git 3"));
        assert!(!is_git_metadata_conflict("/repo/notes 2.txt"));
        assert_eq!(
            icloud_placeholder(".video.mov.icloud").as_deref(),
            Some("video.mov")
        );
        assert_eq!(
            dropbox_original("Getting Started (conflicted copy 2015-03-26).rtf").as_deref(),
            Some("Getting Started.rtf")
        );
        assert_eq!(
            syncthing_original("photo.sync-conflict-20240101-120000-ABCDEF.jpg").as_deref(),
            Some("photo.jpg")
        );
    }
}
