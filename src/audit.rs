//! Classify each recorded worktree against its origin.
//!
//! Held paths are stated and then left alone. Denied paths are not stated.
//! Classification uses path and size, plus git's own modified/staged counts
//! so a same-size edit is still unique work. Directory mtimes and checkout
//! mtime drift do not change the class.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use globset::GlobSetBuilder;
use serde::Serialize;

use crate::conflicts::{self, ConflictKind};
use crate::deny::{is_under, lexical_absolute, normalize_lexical, DenyList};
use crate::diag::Diag;
use crate::diff::{self, DiffOpts};
use crate::git::{self, FindOpts};
use crate::grok::{self, WorktreeRow};
use crate::walk::{classify, EntryKind};
use crate::Render;

const SKIP_DIRS: &[&str] = &["node_modules", "target", ".venv"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Class {
    Identical,
    OriginHasEverything,
    WorktreeHasUniqueWork,
    OriginMissing,
    NeedsReview,
    OnHold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    Dir,
    Missing,
    Denied,
    Symlink,
    NotDir,
    Error,
}

#[derive(Clone, Debug)]
pub struct Signals {
    pub held: bool,
    pub worktree: Probe,
    pub origin: Probe,
    pub conflicts: u64,
    pub git_broken: bool,
    pub git_modified: u64,
    pub git_staged: u64,
    pub only_worktree: u64,
    pub only_origin: u64,
    pub size_changed: u64,
    /// Same-size files whose bytes differ. Used for non-git pairs.
    pub content_changed: u64,
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub class: Class,
    pub diverged: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditCounts {
    pub only_worktree: u64,
    pub only_origin: u64,
    pub size_changed: u64,
    pub content_changed: u64,
    pub mtime_drift: u64,
    pub conflicts: u64,
    pub git_modified: u64,
    pub git_staged: u64,
    pub git_untracked: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditRow {
    pub id: Option<String>,
    pub worktree: String,
    pub relative: Option<String>,
    pub origin: Option<String>,
    pub class: Class,
    pub reasons: Vec<String>,
    pub worktree_exists: Option<bool>,
    pub origin_exists: Option<bool>,
    pub counts: AuditCounts,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditSummary {
    pub identical: u64,
    pub origin_has_everything: u64,
    pub worktree_has_unique_work: u64,
    pub origin_missing: u64,
    pub needs_review: u64,
    pub on_hold: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditReport {
    pub home: String,
    pub summary: AuditSummary,
    pub rows: Vec<AuditRow>,
    pub partial: bool,
    pub error_count: u64,
}

pub fn decide(s: &Signals) -> Decision {
    if s.held {
        return Decision {
            class: Class::OnHold,
            diverged: false,
        };
    }
    if matches!(
        s.worktree,
        Probe::Denied | Probe::Missing | Probe::Symlink | Probe::NotDir | Probe::Error
    ) {
        return Decision {
            class: Class::NeedsReview,
            diverged: false,
        };
    }
    if s.origin == Probe::Denied
        || s.origin == Probe::Symlink
        || s.origin == Probe::NotDir
        || s.origin == Probe::Error
    {
        return Decision {
            class: Class::NeedsReview,
            diverged: false,
        };
    }
    if s.origin == Probe::Missing {
        return Decision {
            class: Class::OriginMissing,
            diverged: false,
        };
    }
    if s.conflicts > 0 || s.git_broken {
        return Decision {
            class: Class::NeedsReview,
            diverged: false,
        };
    }
    let content = s.git_modified + s.git_staged + s.content_changed;
    if s.only_worktree == 0 && s.only_origin == 0 && s.size_changed == 0 && content == 0 {
        return Decision {
            class: Class::Identical,
            diverged: false,
        };
    }
    if s.only_worktree == 0
        && s.size_changed == 0
        && s.content_changed == 0
        && s.git_modified + s.git_staged == 0
        && s.only_origin > 0
    {
        return Decision {
            class: Class::OriginHasEverything,
            diverged: false,
        };
    }
    if s.only_origin == 0 && (s.only_worktree > 0 || s.size_changed > 0 || content > 0) {
        return Decision {
            class: Class::WorktreeHasUniqueWork,
            diverged: false,
        };
    }
    Decision {
        class: Class::NeedsReview,
        diverged: true,
    }
}

pub fn run(home: &Path, holds: &[PathBuf], deny: &DenyList, diag: &Diag) -> AuditReport {
    let grok_report = grok::load(home, deny, diag);
    let hold_abs: Vec<PathBuf> = holds
        .iter()
        .filter_map(|p| lexical_absolute(p).ok())
        .collect();
    let mut rows = Vec::new();
    for wt in &grok_report.worktrees {
        rows.push(classify_row(wt, &hold_abs, deny, diag));
    }
    rows.sort_by(|a, b| a.worktree.cmp(&b.worktree).then(a.id.cmp(&b.id)));
    let summary = summarize(&rows);
    AuditReport {
        home: grok_report.home,
        summary,
        rows,
        partial: diag.partial() || grok_report.partial,
        error_count: diag.error_count(),
    }
}

fn classify_row(wt: &WorktreeRow, holds: &[PathBuf], deny: &DenyList, diag: &Diag) -> AuditRow {
    let worktree = PathBuf::from(&wt.folder);
    let origin = wt.origin.as_ref().map(PathBuf::from);
    let held = path_held(&worktree, holds) || origin.as_ref().is_some_and(|p| path_held(p, holds));
    let wt_probe = probe_exists_only(&worktree, deny);
    let origin_probe = if let Some(origin) = &origin {
        probe_exists_only(origin, deny)
    } else {
        Probe::Missing
    };

    let mut reasons = Vec::new();
    if held {
        reasons.push("held".into());
    }
    push_probe(&mut reasons, "worktree", wt_probe);
    push_probe(&mut reasons, "origin", origin_probe);

    let mut counts = AuditCounts {
        only_worktree: 0,
        only_origin: 0,
        size_changed: 0,
        content_changed: 0,
        mtime_drift: 0,
        conflicts: 0,
        git_modified: 0,
        git_staged: 0,
        git_untracked: 0,
    };

    let inspect =
        !held && wt_probe == Probe::Dir && matches!(origin_probe, Probe::Dir | Probe::Missing);

    if inspect && wt_probe == Probe::Dir && !deny.is_denied(&worktree) {
        let found = conflicts::scan(std::slice::from_ref(&worktree), deny, diag);
        counts.conflicts += record_conflicts(&mut reasons, &found.conflicts, "worktree");
        if origin_probe == Probe::Dir {
            if let Some(origin) = &origin {
                if !deny.is_denied(origin) {
                    let more = conflicts::scan(std::slice::from_ref(origin), deny, diag);
                    record_conflicts(&mut reasons, &more.conflicts, "origin");
                }
            }
        }
    }

    let mut git_broken = false;
    let mut git_modified = 0u64;
    let mut git_staged = 0u64;
    if inspect && wt_probe == Probe::Dir && !deny.is_denied(&worktree) {
        let (broken, modified, staged, untracked, git_reasons) =
            git_side("worktree", &worktree, deny, diag);
        git_broken |= broken;
        git_modified += modified;
        git_staged += staged;
        counts.git_modified = modified;
        counts.git_staged = staged;
        counts.git_untracked = untracked;
        reasons.extend(git_reasons);
    }
    if inspect && origin_probe == Probe::Dir {
        if let Some(origin) = &origin {
            if !deny.is_denied(origin) {
                let (broken, _, _, _, git_reasons) = git_side("origin", origin, deny, diag);
                git_broken |= broken;
                reasons.extend(git_reasons);
            }
        }
    }

    let mut only_worktree = 0u64;
    let mut only_origin = 0u64;
    let mut size_changed = 0u64;
    let mut content_changed = 0u64;
    let mut mtime_drift = 0u64;
    if inspect && wt_probe == Probe::Dir && origin_probe == Probe::Dir {
        if let Some(origin) = &origin {
            if !deny.is_denied(&worktree) && !deny.is_denied(origin) {
                let globs = GlobSetBuilder::new().build().expect("empty");
                let opts = DiffOpts {
                    globs: &globs,
                    compare_mtime: false,
                    skip_git: true,
                    skip_dir_names: SKIP_DIRS,
                };
                let diff = diff::compare(&worktree, origin, &opts, deny, diag);
                only_worktree = diff.counts.only_a;
                only_origin = diff.counts.only_b;
                size_changed = diff.counts.changed;
                mtime_drift = diff.counts.mtime_drift;
                if only_worktree > 0 {
                    reasons.push(format!("only_worktree:{only_worktree}"));
                    for item in diff.only_a.iter().take(10) {
                        reasons.push(format!("worktree_only:{}", item.path));
                    }
                }
                if only_origin > 0 {
                    reasons.push(format!("only_origin:{only_origin}"));
                    for item in diff.only_b.iter().take(10) {
                        reasons.push(format!("origin_only:{}", item.path));
                    }
                }
                if size_changed > 0 {
                    reasons.push(format!("size_changed:{size_changed}"));
                }
                let both_non_git = reasons.iter().any(|r| r == "git_not_a_repo:worktree")
                    && reasons.iter().any(|r| r == "git_not_a_repo:origin");
                if both_non_git {
                    content_changed = hash_drifted_files(
                        &worktree,
                        origin,
                        &diff.mtime_drift_paths,
                        deny,
                        diag,
                        &mut reasons,
                        &mut mtime_drift,
                    );
                }
            }
        }
    }
    if mtime_drift > 0 {
        reasons.push(format!("mtime_drift:{mtime_drift}"));
    }
    if content_changed > 0 {
        reasons.push(format!("content_changed:{content_changed}"));
    }
    if git_modified > 0 {
        reasons.push(format!("git_modified:{git_modified}"));
    }
    if git_staged > 0 {
        reasons.push(format!("git_staged:{git_staged}"));
    }
    counts.only_worktree = only_worktree;
    counts.only_origin = only_origin;
    counts.size_changed = size_changed;
    counts.content_changed = content_changed;
    counts.mtime_drift = mtime_drift;

    let decision = decide(&Signals {
        held,
        worktree: wt_probe,
        origin: origin_probe,
        conflicts: counts.conflicts,
        git_broken,
        git_modified,
        git_staged,
        only_worktree,
        only_origin,
        size_changed,
        content_changed,
    });
    if decision.diverged {
        reasons.push("diverged".into());
    }
    if git_broken && !reasons.iter().any(|r| r.starts_with("git_")) {
        reasons.push("git_broken".into());
    }

    AuditRow {
        id: wt.id.clone(),
        worktree: wt.folder.clone(),
        relative: wt.relative.clone(),
        origin: wt.origin.clone(),
        class: decision.class,
        reasons,
        worktree_exists: exists_flag(wt_probe),
        origin_exists: exists_flag(origin_probe),
        counts,
    }
}

/// Hash same-size files whose mtimes differ. Returns how many differ or
/// could not be read. Matching files stay in `mtime_drift`.
fn hash_drifted_files(
    worktree: &Path,
    origin: &Path,
    rels: &[String],
    deny: &DenyList,
    diag: &Diag,
    reasons: &mut Vec<String>,
    mtime_drift: &mut u64,
) -> u64 {
    let mut changed = 0u64;
    for rel in rels.iter().take(10_000) {
        let left = worktree.join(rel);
        let right = origin.join(rel);
        if deny.is_denied(&left) || deny.is_denied(&right) {
            diag.denied(if deny.is_denied(&left) { &left } else { &right });
            changed += 1;
            *mtime_drift = mtime_drift.saturating_sub(1);
            reasons.push(format!("content_unreadable:{rel}"));
            continue;
        }
        match diff::files_content_differ(&left, &right) {
            Ok(false) => {}
            Ok(true) => {
                changed += 1;
                *mtime_drift = mtime_drift.saturating_sub(1);
                reasons.push(format!("content_differs:{rel}"));
            }
            Err(err) => {
                diag.io_error(&left, &err);
                changed += 1;
                *mtime_drift = mtime_drift.saturating_sub(1);
                reasons.push(format!("content_unreadable:{rel}"));
            }
        }
    }
    changed
}

fn git_side(
    label: &str,
    path: &Path,
    deny: &DenyList,
    diag: &Diag,
) -> (bool, u64, u64, u64, Vec<String>) {
    let root = normalize_lexical(path);
    let repos = git::find_repos(
        path,
        &FindOpts {
            skip_dir_names: SKIP_DIRS,
        },
        deny,
        diag,
    );
    let mut reasons = Vec::new();
    if repos.is_empty() {
        reasons.push(format!("git_not_a_repo:{label}"));
        return (false, 0, 0, 0, reasons);
    }
    let mut broken = false;
    let mut modified = 0u64;
    let mut staged = 0u64;
    let mut untracked = 0u64;
    let root_is_repo = repos.iter().any(|r| normalize_lexical(r) == root);
    if !root_is_repo {
        reasons.push(format!("git_not_a_repo:{label}"));
    }
    for repo in &repos {
        let report = git::inspect_repo(repo, None, false, deny, diag);
        if normalize_lexical(repo) == root {
            modified = report.modified.unwrap_or(0);
            staged = report.staged.unwrap_or(0);
            untracked = report.untracked.unwrap_or(0);
        }
        if report.errors.iter().any(|e| e.contains("deny list")) {
            broken = true;
            reasons.push(format!("git_dir_denied:{label}"));
        }
        for missing in &report.critical_missing {
            broken = true;
            reasons.push(format!("git_missing:{label}:{missing}"));
        }
    }
    (broken, modified, staged, untracked, reasons)
}

/// Worktree conflicts outside `.git` affect the class. Origin conflicts and
/// anything inside a `.git` directory are reasons only.
fn record_conflicts(reasons: &mut Vec<String>, items: &[conflicts::Conflict], side: &str) -> u64 {
    let mut classifying = 0u64;
    let mut origin_n = 0u64;
    let mut git_n = 0u64;
    for c in items {
        let name = conflict_name(c.kind);
        if conflicts::is_git_metadata_conflict(&c.path) {
            git_n += 1;
            reasons.push(format!("git_conflict:{name}:{side}:{}", c.path));
        } else if side == "origin" {
            origin_n += 1;
            reasons.push(format!("origin_conflict:{name}:{}", c.path));
        } else {
            classifying += 1;
            reasons.push(format!("conflict:{name}:{}", c.path));
        }
    }
    if classifying > 0 {
        reasons.push(format!("conflicts:{classifying}"));
    }
    if origin_n > 0 {
        reasons.push(format!("origin_conflicts:{origin_n}"));
    }
    if git_n > 0 {
        reasons.push(format!("git_conflicts:{git_n}"));
    }
    classifying
}

fn conflict_name(k: ConflictKind) -> &'static str {
    match k {
        ConflictKind::Icloud => "icloud",
        ConflictKind::IcloudPlaceholder => "icloud_placeholder",
        ConflictKind::Dropbox => "dropbox",
        ConflictKind::Syncthing => "syncthing",
    }
}

fn push_probe(reasons: &mut Vec<String>, side: &str, probe: Probe) {
    let name = match probe {
        Probe::Dir => return,
        Probe::Missing => "missing",
        Probe::Denied => "denied",
        Probe::Symlink => "symlink",
        Probe::NotDir => "not_directory",
        Probe::Error => "stat_error",
    };
    reasons.push(format!("{side}_{name}"));
}

fn exists_flag(probe: Probe) -> Option<bool> {
    match probe {
        Probe::Dir | Probe::Symlink | Probe::NotDir => Some(true),
        Probe::Missing => Some(false),
        Probe::Denied | Probe::Error => None,
    }
}

fn probe_exists_only(path: &Path, deny: &DenyList) -> Probe {
    if deny.is_denied(path) {
        return Probe::Denied;
    }
    match classify(path) {
        Ok(c) => match c.kind {
            EntryKind::Dir => Probe::Dir,
            EntryKind::Symlink => Probe::Symlink,
            EntryKind::File => Probe::NotDir,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Probe::Missing,
        Err(_) => Probe::Error,
    }
}

fn path_held(path: &Path, holds: &[PathBuf]) -> bool {
    holds
        .iter()
        .any(|h| path == h || is_under(path, h) || is_under(h, path))
}

fn summarize(rows: &[AuditRow]) -> AuditSummary {
    let mut s = AuditSummary {
        identical: 0,
        origin_has_everything: 0,
        worktree_has_unique_work: 0,
        origin_missing: 0,
        needs_review: 0,
        on_hold: 0,
    };
    for row in rows {
        match row.class {
            Class::Identical => s.identical += 1,
            Class::OriginHasEverything => s.origin_has_everything += 1,
            Class::WorktreeHasUniqueWork => s.worktree_has_unique_work += 1,
            Class::OriginMissing => s.origin_missing += 1,
            Class::NeedsReview => s.needs_review += 1,
            Class::OnHold => s.on_hold += 1,
        }
    }
    s
}

pub fn problems(report: &AuditReport) -> bool {
    report.rows.iter().any(|r| {
        matches!(
            r.class,
            Class::WorktreeHasUniqueWork | Class::OriginMissing | Class::NeedsReview
        )
    })
}

pub fn render(report: &AuditReport, mode: Render, mut out: impl Write) -> io::Result<()> {
    match mode {
        Render::Human => {
            writeln!(out, "Identical              {}", report.summary.identical)?;
            writeln!(
                out,
                "OriginHasEverything    {}",
                report.summary.origin_has_everything
            )?;
            writeln!(
                out,
                "WorktreeHasUniqueWork  {}",
                report.summary.worktree_has_unique_work
            )?;
            writeln!(
                out,
                "OriginMissing          {}",
                report.summary.origin_missing
            )?;
            writeln!(
                out,
                "NeedsReview            {}",
                report.summary.needs_review
            )?;
            writeln!(out, "OnHold                 {}", report.summary.on_hold)?;
            writeln!(out)?;
            for row in &report.rows {
                writeln!(
                    out,
                    "{:?}  {}  origin={}",
                    row.class,
                    row.worktree,
                    row.origin.as_deref().unwrap_or("-")
                )?;
                for reason in &row.reasons {
                    writeln!(out, "  - {reason}")?;
                }
            }
        }
        Render::Json => {
            let body = serde_json::json!({
                "command": "audit",
                "home": report.home,
                "summary": report.summary,
                "rows": report.rows,
                "partial": report.partial,
                "error_count": report.error_count,
            });
            serde_json::to_writer_pretty(&mut out, &body)?;
            writeln!(out)?;
        }
        Render::Ndjson => {
            for row in &report.rows {
                let mut v = serde_json::to_value(row).unwrap_or(serde_json::Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("type".into(), serde_json::json!("row"));
                }
                serde_json::to_writer(&mut out, &v)?;
                writeln!(out)?;
            }
            let summary = serde_json::json!({
                "type": "summary",
                "summary": report.summary,
                "partial": report.partial,
                "error_count": report.error_count,
            });
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(over: impl FnOnce(&mut Signals)) -> Signals {
        let mut s = Signals {
            held: false,
            worktree: Probe::Dir,
            origin: Probe::Dir,
            conflicts: 0,
            git_broken: false,
            git_modified: 0,
            git_staged: 0,
            only_worktree: 0,
            only_origin: 0,
            size_changed: 0,
            content_changed: 0,
        };
        over(&mut s);
        s
    }

    #[test]
    fn classification_matrix() {
        assert_eq!(decide(&sig(|_| {})).class, Class::Identical);
        assert_eq!(
            decide(&sig(|s| s.only_origin = 2)).class,
            Class::OriginHasEverything
        );
        assert_eq!(
            decide(&sig(|s| s.only_worktree = 1)).class,
            Class::WorktreeHasUniqueWork
        );
        assert_eq!(
            decide(&sig(|s| s.size_changed = 1)).class,
            Class::WorktreeHasUniqueWork
        );
        assert_eq!(
            decide(&sig(|s| s.content_changed = 1)).class,
            Class::WorktreeHasUniqueWork
        );
        assert_ne!(
            decide(&sig(|s| s.content_changed = 1)).class,
            Class::Identical
        );
        assert_eq!(
            decide(&sig(|s| {
                s.content_changed = 1;
                s.only_origin = 1;
            }))
            .class,
            Class::NeedsReview
        );
        assert_eq!(
            decide(&sig(|s| s.git_modified = 1)).class,
            Class::WorktreeHasUniqueWork
        );
        assert_eq!(
            decide(&sig(|s| {
                s.only_worktree = 1;
                s.only_origin = 1;
            }))
            .class,
            Class::NeedsReview
        );
        assert!(
            decide(&sig(|s| {
                s.only_worktree = 1;
                s.only_origin = 1;
            }))
            .diverged
        );
        assert_eq!(decide(&sig(|s| s.conflicts = 1)).class, Class::NeedsReview);
        assert_eq!(
            decide(&sig(|s| s.git_broken = true)).class,
            Class::NeedsReview
        );
        assert_eq!(
            decide(&sig(|s| s.origin = Probe::Missing)).class,
            Class::OriginMissing
        );
        assert_eq!(
            decide(&sig(|s| {
                s.held = true;
                s.conflicts = 4;
            }))
            .class,
            Class::OnHold
        );
        assert_eq!(
            decide(&sig(|s| s.worktree = Probe::Missing)).class,
            Class::NeedsReview
        );
        assert_eq!(
            decide(&sig(|s| {
                s.size_changed = 1;
                s.only_origin = 3;
            }))
            .class,
            Class::NeedsReview
        );
    }
}
