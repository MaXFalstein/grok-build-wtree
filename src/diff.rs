//! Compare two trees by relative path. `.git` is skipped: a linked worktree's
//! `.git` file and an origin's `.git` directory are not working-tree content.
//! Directory mtimes are not compared; creating a file bumps every parent.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use globset::GlobSet;
use serde::Serialize;

use crate::deny::{guard_root, DenyList};
use crate::diag::Diag;
use crate::walk::{classify, lossy, mtime_secs, read_names, rel_join, skip_denied, EntryKind};
use crate::Render;

#[derive(Clone, Debug)]
pub struct DiffOpts<'a> {
    pub globs: &'a GlobSet,
    /// When false, mtime-only differences are counted as drift, not changes.
    pub compare_mtime: bool,
    pub skip_git: bool,
    pub skip_dir_names: &'a [&'a str],
}

#[derive(Clone, Debug, Serialize)]
pub struct SideMeta {
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub mtime: Option<i64>,
    pub target: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Changed {
    pub path: String,
    pub kind_changed: bool,
    pub size_changed: bool,
    pub mtime_changed: bool,
    pub target_changed: bool,
    pub a: SideMeta,
    pub b: SideMeta,
}

#[derive(Clone, Debug, Serialize)]
pub struct Only {
    pub path: String,
    #[serde(flatten)]
    pub meta: SideMeta,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffCounts {
    pub only_a: u64,
    pub only_b: u64,
    pub changed: u64,
    pub mtime_drift: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffReport {
    pub a: String,
    pub b: String,
    pub only_a: Vec<Only>,
    pub only_b: Vec<Only>,
    pub changed: Vec<Changed>,
    pub counts: DiffCounts,
    pub partial: bool,
    pub error_count: u64,
}

#[derive(Clone, Debug)]
struct Meta {
    kind: EntryKind,
    size: Option<u64>,
    mtime: Option<i64>,
    target: Option<String>,
}

impl Meta {
    fn side(&self) -> SideMeta {
        SideMeta {
            kind: self.kind,
            size: self.size,
            mtime: self.mtime,
            target: self.target.clone(),
        }
    }
}

pub fn compare(
    a: &Path,
    b: &Path,
    opts: &DiffOpts<'_>,
    deny: &DenyList,
    diag: &Diag,
) -> DiffReport {
    let before = diag.error_count();
    let map_a = match guard_root(a, deny) {
        Ok(p) => collect(&p, opts, deny, diag),
        Err(msg) => {
            diag.error(a, msg);
            BTreeMap::new()
        }
    };
    let map_b = match guard_root(b, deny) {
        Ok(p) => collect(&p, opts, deny, diag),
        Err(msg) => {
            diag.error(b, msg);
            BTreeMap::new()
        }
    };
    let mut only_a = Vec::new();
    let mut only_b = Vec::new();
    let mut changed = Vec::new();
    let mut mtime_drift = 0u64;

    for (path, ma) in &map_a {
        match map_b.get(path) {
            None => only_a.push(Only {
                path: path.clone(),
                meta: ma.side(),
            }),
            Some(mb) => {
                let kind_changed = ma.kind != mb.kind;
                let target_changed = ma.target != mb.target;
                let size_changed =
                    ma.kind == EntryKind::File && mb.kind == EntryKind::File && ma.size != mb.size;
                let mtime_changed =
                    ma.kind != EntryKind::Dir && mb.kind != EntryKind::Dir && ma.mtime != mb.mtime;
                let meaningful = kind_changed
                    || target_changed
                    || size_changed
                    || (opts.compare_mtime && mtime_changed);
                if meaningful {
                    changed.push(Changed {
                        path: path.clone(),
                        kind_changed,
                        size_changed,
                        mtime_changed,
                        target_changed,
                        a: ma.side(),
                        b: mb.side(),
                    });
                } else if mtime_changed {
                    mtime_drift += 1;
                }
            }
        }
    }
    for (path, mb) in &map_b {
        if !map_a.contains_key(path) {
            only_b.push(Only {
                path: path.clone(),
                meta: mb.side(),
            });
        }
    }
    let errors = diag.error_count().saturating_sub(before);
    DiffReport {
        a: a.display().to_string(),
        b: b.display().to_string(),
        counts: DiffCounts {
            only_a: only_a.len() as u64,
            only_b: only_b.len() as u64,
            changed: changed.len() as u64,
            mtime_drift,
        },
        only_a,
        only_b,
        changed,
        partial: errors > 0,
        error_count: errors,
    }
}

fn collect(
    root: &Path,
    opts: &DiffOpts<'_>,
    deny: &DenyList,
    diag: &Diag,
) -> BTreeMap<String, Meta> {
    let mut map = BTreeMap::new();
    let classified = match classify(root) {
        Ok(c) => c,
        Err(e) => {
            diag.io_error(root, &e);
            return map;
        }
    };
    if classified.kind == EntryKind::Symlink {
        diag.error(root, "refusing to follow symlink root");
        return map;
    }
    if classified.kind != EntryKind::Dir {
        map.insert(
            ".".into(),
            Meta {
                kind: classified.kind,
                size: Some(classified.meta.len()),
                mtime: mtime_secs(&classified.meta),
                target: classified.target,
            },
        );
        return map;
    }
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let names = match read_names(&dir) {
            Ok(n) => n,
            Err(e) => {
                diag.io_error(&dir, &e);
                continue;
            }
        };
        // Pop order is reversed; push in reverse so siblings are visited in
        // sorted order. The map is a BTreeMap, so output order does not depend
        // on this, but error order does.
        for ent in names.into_iter().rev() {
            if skip_denied(&ent.path, deny, diag) {
                continue;
            }
            let name = lossy(&ent.name);
            if opts.skip_git && name == ".git" {
                continue;
            }
            let child_rel = rel_join(&rel, &name);
            if !opts.globs.is_empty()
                && (opts.globs.is_match(&name) || opts.globs.is_match(&child_rel))
            {
                continue;
            }
            let classified = match classify(&ent.path) {
                Ok(c) => c,
                Err(e) => {
                    diag.io_error(&ent.path, &e);
                    continue;
                }
            };
            if classified.kind == EntryKind::Dir && opts.skip_dir_names.contains(&name.as_str()) {
                continue;
            }
            let size = match classified.kind {
                EntryKind::File => Some(classified.meta.len()),
                EntryKind::Dir | EntryKind::Symlink => None,
            };
            map.insert(
                child_rel.clone(),
                Meta {
                    kind: classified.kind,
                    size,
                    mtime: mtime_secs(&classified.meta),
                    target: classified.target,
                },
            );
            if classified.kind == EntryKind::Dir {
                stack.push((ent.path, child_rel));
            }
        }
    }
    map
}

pub fn problems(report: &DiffReport) -> bool {
    report.counts.only_a > 0 || report.counts.only_b > 0 || report.counts.changed > 0
}

pub fn render(
    report: &DiffReport,
    show_sizes: bool,
    show_mtimes: bool,
    mode: Render,
    mut out: impl Write,
) -> io::Result<()> {
    match mode {
        Render::Human => {
            writeln!(out, "only in A ({}): {}", report.counts.only_a, report.a)?;
            for item in &report.only_a {
                writeln!(out, "  {}", format_only(item, show_sizes, show_mtimes))?;
            }
            writeln!(out, "only in B ({}): {}", report.counts.only_b, report.b)?;
            for item in &report.only_b {
                writeln!(out, "  {}", format_only(item, show_sizes, show_mtimes))?;
            }
            writeln!(out, "changed ({}):", report.counts.changed)?;
            for item in &report.changed {
                writeln!(out, "  {}", format_changed(item, show_sizes, show_mtimes))?;
            }
            writeln!(
                out,
                "counts only_a={} only_b={} changed={} mtime_drift={}",
                report.counts.only_a,
                report.counts.only_b,
                report.counts.changed,
                report.counts.mtime_drift
            )?;
        }
        Render::Json => {
            let body = serde_json::json!({
                "command": "diff",
                "a": report.a,
                "b": report.b,
                "only_a": report.only_a,
                "only_b": report.only_b,
                "changed": report.changed,
                "counts": report.counts,
                "partial": report.partial,
                "error_count": report.error_count,
            });
            serde_json::to_writer_pretty(&mut out, &body)?;
            writeln!(out)?;
        }
        Render::Ndjson => {
            for item in &report.only_a {
                write_nd(&mut out, "only_a", item)?;
            }
            for item in &report.only_b {
                write_nd(&mut out, "only_b", item)?;
            }
            for item in &report.changed {
                write_nd(&mut out, "changed", item)?;
            }
            let summary = serde_json::json!({
                "type": "summary",
                "a": report.a,
                "b": report.b,
                "counts": report.counts,
                "partial": report.partial,
                "error_count": report.error_count,
            });
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

fn write_nd(out: &mut impl Write, typ: &str, value: &impl Serialize) -> io::Result<()> {
    let mut v = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = v.as_object_mut() {
        obj.insert("type".into(), serde_json::json!(typ));
    }
    serde_json::to_writer(&mut *out, &v)?;
    writeln!(out)
}

fn format_only(item: &Only, sizes: bool, mtimes: bool) -> String {
    let mut s = format!("{} {}", kind_label(item.meta.kind), item.path);
    if let Some(t) = &item.meta.target {
        s.push_str(" -> ");
        s.push_str(t);
    }
    if sizes {
        if let Some(sz) = item.meta.size {
            s.push_str(&format!(" size={sz}"));
        }
    }
    if mtimes {
        if let Some(t) = item.meta.mtime {
            s.push_str(&format!(" mtime={t}"));
        }
    }
    s
}

fn format_changed(item: &Changed, sizes: bool, mtimes: bool) -> String {
    let mut why = Vec::new();
    if item.kind_changed {
        why.push(format!(
            "kind {} -> {}",
            kind_label(item.a.kind),
            kind_label(item.b.kind)
        ));
    }
    if item.target_changed {
        why.push(format!(
            "target {} -> {}",
            item.a.target.as_deref().unwrap_or("-"),
            item.b.target.as_deref().unwrap_or("-")
        ));
    }
    if item.size_changed {
        why.push(format!(
            "size {} -> {}",
            fmt_opt(item.a.size),
            fmt_opt(item.b.size)
        ));
    } else if sizes {
        if let Some(sz) = item.a.size {
            why.push(format!("size {sz}"));
        }
    }
    if item.mtime_changed {
        if mtimes {
            why.push(format!(
                "mtime {} -> {}",
                fmt_i(item.a.mtime),
                fmt_i(item.b.mtime)
            ));
        } else {
            why.push("mtime".into());
        }
    }
    if why.is_empty() {
        item.path.clone()
    } else {
        format!("{} ({})", item.path, why.join(", "))
    }
}

fn kind_label(k: EntryKind) -> &'static str {
    match k {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Symlink => "symlink",
    }
}

fn fmt_opt(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
}

fn fmt_i(v: Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
}
