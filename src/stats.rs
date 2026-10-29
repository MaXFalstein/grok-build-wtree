//! Per-path totals. Counts hidden files and gitignored files. Never follows
//! symlinks. Directory levels are scanned in parallel; each directory is read
//! by one task so rayon joins are not nested.

use std::io::{self, Write};
use std::path::Path;

use rayon::prelude::*;
use serde::Serialize;

use crate::deny::{guard_root, DenyList};
use crate::diag::Diag;
use crate::walk::{classify, mtime_secs, read_names, skip_denied, EntryKind};
use crate::Render;

#[derive(Clone, Debug, Serialize)]
pub struct PathStats {
    pub path: String,
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub newest_mtime: Option<i64>,
    pub oldest_mtime: Option<i64>,
    pub partial: bool,
    pub error_count: u64,
}

#[derive(Clone, Debug, Default)]
struct Accum {
    files: u64,
    dirs: u64,
    symlinks: u64,
    bytes: u64,
    newest: Option<i64>,
    oldest: Option<i64>,
    errors: u64,
}

impl Accum {
    fn observe_mtime(&mut self, mtime: Option<i64>) {
        if let Some(t) = mtime {
            self.newest = Some(self.newest.map(|n| n.max(t)).unwrap_or(t));
            self.oldest = Some(self.oldest.map(|n| n.min(t)).unwrap_or(t));
        }
    }

    fn merge(&mut self, other: Accum) {
        self.files += other.files;
        self.dirs += other.dirs;
        self.symlinks += other.symlinks;
        self.bytes += other.bytes;
        self.errors += other.errors;
        self.observe_mtime(other.newest);
        self.observe_mtime(other.oldest);
    }
}

struct DirOut {
    acc: Accum,
    subdirs: Vec<std::path::PathBuf>,
}

pub fn scan_many(paths: &[std::path::PathBuf], deny: &DenyList, diag: &Diag) -> Vec<PathStats> {
    if paths.len() <= 1 {
        return paths.iter().map(|p| scan_one(p, deny, diag)).collect();
    }
    paths.par_iter().map(|p| scan_one(p, deny, diag)).collect()
}

pub fn scan_one(path: &Path, deny: &DenyList, diag: &Diag) -> PathStats {
    let display = path.display().to_string();
    let abs = match guard_root(path, deny) {
        Ok(p) => p,
        Err(msg) => {
            diag.error(path, msg);
            return PathStats {
                path: display,
                files: 0,
                dirs: 0,
                symlinks: 0,
                bytes: 0,
                newest_mtime: None,
                oldest_mtime: None,
                partial: true,
                error_count: 1,
            };
        }
    };
    let classified = match classify(&abs) {
        Ok(c) => c,
        Err(e) => {
            diag.io_error(&abs, &e);
            return empty(display, true, 1);
        }
    };
    let mut acc = Accum::default();
    match classified.kind {
        EntryKind::Symlink => {
            acc.symlinks = 1;
            acc.observe_mtime(mtime_secs(&classified.meta));
        }
        EntryKind::File => {
            acc.files = 1;
            acc.bytes = classified.meta.len();
            acc.observe_mtime(mtime_secs(&classified.meta));
        }
        EntryKind::Dir => {
            let mut level = vec![abs];
            while !level.is_empty() {
                let batch: Vec<DirOut> = if level.len() == 1 {
                    vec![scan_dir(&level[0], deny, diag)]
                } else {
                    level.par_iter().map(|d| scan_dir(d, deny, diag)).collect()
                };
                level.clear();
                for part in batch {
                    level.extend(part.subdirs);
                    acc.merge(part.acc);
                }
            }
        }
    }
    PathStats {
        path: display,
        files: acc.files,
        dirs: acc.dirs,
        symlinks: acc.symlinks,
        bytes: acc.bytes,
        newest_mtime: acc.newest,
        oldest_mtime: acc.oldest,
        partial: acc.errors > 0,
        error_count: acc.errors,
    }
}

fn empty(path: String, partial: bool, errors: u64) -> PathStats {
    PathStats {
        path,
        files: 0,
        dirs: 0,
        symlinks: 0,
        bytes: 0,
        newest_mtime: None,
        oldest_mtime: None,
        partial,
        error_count: errors,
    }
}

fn scan_dir(dir: &Path, deny: &DenyList, diag: &Diag) -> DirOut {
    let mut acc = Accum {
        dirs: 1,
        ..Accum::default()
    };
    if let Ok(meta) = std::fs::symlink_metadata(dir) {
        acc.observe_mtime(mtime_secs(&meta));
    }
    let names = match read_names(dir) {
        Ok(n) => n,
        Err(e) => {
            diag.io_error(dir, &e);
            acc.errors += 1;
            return DirOut {
                acc,
                subdirs: Vec::new(),
            };
        }
    };
    let mut subdirs = Vec::new();
    for ent in names {
        if skip_denied(&ent.path, deny, diag) {
            continue;
        }
        let classified = match classify(&ent.path) {
            Ok(c) => c,
            Err(e) => {
                diag.io_error(&ent.path, &e);
                acc.errors += 1;
                continue;
            }
        };
        let mt = mtime_secs(&classified.meta);
        match classified.kind {
            EntryKind::Symlink => {
                acc.symlinks += 1;
                acc.observe_mtime(mt);
            }
            EntryKind::Dir => {
                acc.observe_mtime(mt);
                subdirs.push(ent.path);
            }
            EntryKind::File => {
                acc.files += 1;
                acc.bytes += classified.meta.len();
                acc.observe_mtime(mt);
            }
        }
    }
    DirOut { acc, subdirs }
}

pub fn any_partial(rows: &[PathStats]) -> bool {
    rows.iter().any(|r| r.partial)
}

pub fn render(rows: &[PathStats], mode: Render, mut out: impl Write) -> io::Result<()> {
    match mode {
        Render::Human => {
            for (i, row) in rows.iter().enumerate() {
                if i > 0 {
                    writeln!(out)?;
                }
                writeln!(out, "{}", row.path)?;
                writeln!(out, "  files: {}", row.files)?;
                writeln!(out, "  dirs: {}", row.dirs)?;
                writeln!(out, "  symlinks: {}", row.symlinks)?;
                writeln!(out, "  bytes: {}", row.bytes)?;
                writeln!(out, "  newest_mtime: {}", fmt_opt(row.newest_mtime))?;
                writeln!(out, "  oldest_mtime: {}", fmt_opt(row.oldest_mtime))?;
            }
        }
        Render::Json => {
            let body = serde_json::json!({
                "command": "stats",
                "partial": any_partial(rows),
                "error_count": rows.iter().map(|r| r.error_count).sum::<u64>(),
                "paths": rows,
            });
            serde_json::to_writer_pretty(&mut out, &body)?;
            writeln!(out)?;
        }
        Render::Ndjson => {
            for row in rows {
                let mut v = serde_json::to_value(row).unwrap_or(serde_json::Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("type".into(), serde_json::json!("path"));
                }
                serde_json::to_writer(&mut out, &v)?;
                writeln!(out)?;
            }
            let summary = serde_json::json!({
                "type": "summary",
                "partial": any_partial(rows),
                "error_count": rows.iter().map(|r| r.error_count).sum::<u64>(),
                "count": rows.len(),
            });
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

fn fmt_opt(v: Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
}
