//! Read-only git inspection. Every git subprocess is on an allowlist and
//! runs with `GIT_OPTIONAL_LOCKS=0` and `--no-optional-locks`. The index is
//! never refreshed. There is no `status`, `gc`, `fetch`, or `update-index`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde::Serialize;

use crate::deny::{lexical_absolute, normalize_lexical, DenyList};
use crate::diag::Diag;
use crate::redact::redact_git_url;
use crate::walk::{classify, lossy, read_names, skip_denied, EntryKind};
use crate::Render;

const CRITICAL: &[&str] = &["HEAD", "config", "objects", "refs"];
const SKELETON: &[(&str, bool)] = &[
    ("HEAD", false),
    ("config", false),
    ("index", false),
    ("objects", true),
    ("refs", true),
    ("packed-refs", false),
    ("info/exclude", false),
    ("hooks", true),
];

const ALLOWED_GIT: &[&str] = &[
    "rev-parse",
    "symbolic-ref",
    "remote",
    "diff-files",
    "diff-index",
    "ls-files",
    "cat-file",
    "rev-list",
    "fsck",
];

#[derive(Clone, Debug, Serialize)]
pub struct Remote {
    pub name: String,
    pub url: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SkeletonItem {
    pub name: String,
    pub present: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Against {
    pub repo: String,
    pub shared_history: bool,
    pub ahead: Option<u64>,
    pub behind: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FsckIssue {
    pub kind: String,
    pub oids: Vec<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FsckReport {
    pub issues: Vec<FsckIssue>,
    pub object_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GitRepoReport {
    pub path: String,
    pub is_repo: bool,
    pub bare: bool,
    pub git_dir: Option<String>,
    pub common_dir: Option<String>,
    pub branch: Option<String>,
    pub detached: bool,
    pub head: Option<String>,
    pub remotes: Vec<Remote>,
    pub skeleton: Vec<SkeletonItem>,
    pub missing: Vec<String>,
    pub critical_missing: Vec<String>,
    pub modified: Option<u64>,
    pub staged: Option<u64>,
    pub untracked: Option<u64>,
    pub against: Option<Against>,
    pub fsck: Option<FsckReport>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RepoHead {
    pub path: PathBuf,
    pub sha: Option<String>,
}

pub struct FindOpts<'a> {
    pub skip_dir_names: &'a [&'a str],
}

pub fn find_repos(root: &Path, opts: &FindOpts<'_>, deny: &DenyList, diag: &Diag) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(abs) = lexical_absolute(root) else {
        diag.error(root, "cannot resolve path");
        return found;
    };
    if deny.is_denied(&abs) {
        diag.denied(&abs);
        return found;
    }
    let mut stack = vec![abs];
    while let Some(dir) = stack.pop() {
        if skip_denied(&dir, deny, diag) {
            continue;
        }
        let classified = match classify(&dir) {
            Ok(c) => c,
            Err(e) => {
                diag.io_error(&dir, &e);
                continue;
            }
        };
        if classified.kind == EntryKind::Symlink {
            continue;
        }
        if classified.kind != EntryKind::Dir {
            continue;
        }
        if is_work_tree(&dir) || is_bare(&dir) {
            found.push(dir.clone());
            if is_bare(&dir) {
                continue;
            }
        }
        let names = match read_names(&dir) {
            Ok(n) => n,
            Err(e) => {
                diag.io_error(&dir, &e);
                continue;
            }
        };
        for ent in names.into_iter().rev() {
            let name = lossy(&ent.name);
            if name == ".git" {
                continue;
            }
            if opts.skip_dir_names.contains(&name.as_str()) {
                continue;
            }
            if skip_denied(&ent.path, deny, diag) {
                continue;
            }
            // Stat only after the deny check. Skip non-directories without
            // descending. `classify` does not follow symlinks.
            match classify(&ent.path) {
                Ok(c) if c.kind == EntryKind::Dir => stack.push(ent.path),
                Ok(_) => {}
                Err(e) => diag.io_error(&ent.path, &e),
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

pub fn is_work_tree(path: &Path) -> bool {
    classify(&path.join(".git"))
        .map(|c| {
            c.kind == EntryKind::Dir || c.kind == EntryKind::File || c.kind == EntryKind::Symlink
        })
        .unwrap_or(false)
}

pub fn is_bare(path: &Path) -> bool {
    if is_work_tree(path) {
        return false;
    }
    let head = classify(&path.join("HEAD"))
        .map(|c| c.kind == EntryKind::File)
        .unwrap_or(false);
    let objects = classify(&path.join("objects"))
        .map(|c| c.kind == EntryKind::Dir)
        .unwrap_or(false);
    head && objects
}

pub fn inspect_repo(
    repo: &Path,
    against: Option<&RepoHead>,
    fsck: bool,
    diag: &Diag,
) -> GitRepoReport {
    let mut errors = Vec::new();
    let bare = is_bare(repo);
    let git_dir = resolve_git_dir(repo);
    let is_repo = git_dir.is_some();
    let common = git_dir.as_ref().and_then(|g| read_common_dir(g));
    let skeleton = skeleton_of(git_dir.as_deref(), common.as_deref());
    let missing: Vec<String> = skeleton
        .iter()
        .filter(|s| !s.present)
        .map(|s| s.name.clone())
        .collect();
    let critical_missing: Vec<String> = missing
        .iter()
        .filter(|n| CRITICAL.contains(&n.as_str()))
        .cloned()
        .collect();

    let mut branch = None;
    let mut detached = false;
    let mut head = None;
    let mut remotes = Vec::new();
    let mut modified = None;
    let mut staged = None;
    let mut untracked = None;
    let mut fsck_report = None;

    if is_repo {
        match git(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]) {
            Ok(out) if out.status.success() => {
                branch = Some(stdout_trim(&out));
            }
            Ok(_) => {
                detached = true;
            }
            Err(e) => errors.push(format!("git: {e}")),
        }
        match git(repo, &["rev-parse", "--verify", "-q", "HEAD"]) {
            Ok(out) if out.status.success() => {
                let sha = stdout_trim(&out);
                if is_sha(&sha) {
                    head = Some(sha);
                }
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("git: {e}")),
        }
        match git(repo, &["remote", "-v"]) {
            Ok(out) if out.status.success() => {
                remotes = parse_remotes(&stdout_text(&out));
            }
            Ok(out) => errors.push(clip(&format!("remote: {}", stderr_text(&out)))),
            Err(e) => errors.push(format!("git: {e}")),
        }
        modified = count_paths(repo, &["diff-files", "--name-only", "-z"], &mut errors);
        if head.is_some() {
            staged = count_paths(
                repo,
                &["diff-index", "--cached", "--name-only", "-z", "HEAD"],
                &mut errors,
            );
        } else {
            staged = count_paths(repo, &["ls-files", "-z"], &mut errors);
        }
        untracked = count_paths(
            repo,
            &["ls-files", "--others", "--exclude-standard", "-z"],
            &mut errors,
        );
        if fsck {
            fsck_report = Some(run_fsck(repo, diag));
        }
    }

    let against_report = match (against, head.as_deref()) {
        (Some(other), _) => Some(compare_against(repo, head.as_deref(), other, &mut errors)),
        _ => None,
    };
    let _ = diag;

    GitRepoReport {
        path: repo.display().to_string(),
        is_repo,
        bare,
        git_dir: git_dir.map(|p| p.display().to_string()),
        common_dir: common.map(|p| p.display().to_string()),
        branch,
        detached,
        head,
        remotes,
        skeleton,
        missing,
        critical_missing,
        modified,
        staged,
        untracked,
        against: against_report,
        fsck: fsck_report,
        errors,
    }
}

pub fn load_head(repo: &Path) -> RepoHead {
    let sha = git(repo, &["rev-parse", "--verify", "-q", "HEAD"])
        .ok()
        .filter(|o| o.status.success())
        .map(|o| stdout_trim(&o))
        .filter(|s| is_sha(s));
    RepoHead {
        path: repo.to_path_buf(),
        sha,
    }
}

pub fn primary_repo(path: &Path, deny: &DenyList, diag: &Diag) -> Option<PathBuf> {
    if is_work_tree(path) || is_bare(path) {
        return Some(path.to_path_buf());
    }
    find_repos(
        path,
        &FindOpts {
            skip_dir_names: &[],
        },
        deny,
        diag,
    )
    .into_iter()
    .next()
}

fn compare_against(
    repo: &Path,
    our_sha: Option<&str>,
    other: &RepoHead,
    errors: &mut Vec<String>,
) -> Against {
    let Some(our) = our_sha else {
        return Against {
            repo: other.path.display().to_string(),
            shared_history: false,
            ahead: None,
            behind: None,
        };
    };
    let Some(their) = other.sha.as_deref() else {
        return Against {
            repo: other.path.display().to_string(),
            shared_history: false,
            ahead: None,
            behind: None,
        };
    };
    if !is_sha(our) || !is_sha(their) {
        errors.push("refusing non-hex object id".into());
        return Against {
            repo: other.path.display().to_string(),
            shared_history: false,
            ahead: None,
            behind: None,
        };
    }
    let our_in_other = object_exists(&other.path, our);
    let their_in_ours = object_exists(repo, their);
    // Prefer the repository that actually has both commits. A copy that
    // moved on still shares history with the side that holds both objects.
    let counts = if their_in_ours {
        rev_counts(repo, our, their)
    } else if our_in_other {
        rev_counts(&other.path, their, our).map(|(behind, ahead)| (ahead, behind))
    } else {
        None
    };
    match counts {
        Some((ahead, behind)) => Against {
            repo: other.path.display().to_string(),
            shared_history: true,
            ahead: Some(ahead),
            behind: Some(behind),
        },
        None if !their_in_ours && !our_in_other => Against {
            repo: other.path.display().to_string(),
            shared_history: false,
            ahead: None,
            behind: None,
        },
        None => {
            errors.push("rev-list failed".into());
            Against {
                repo: other.path.display().to_string(),
                shared_history: false,
                ahead: None,
                behind: None,
            }
        }
    }
}

fn rev_counts(repo: &Path, left: &str, right: &str) -> Option<(u64, u64)> {
    let spec = format!("{left}...{right}");
    let out = git(repo, &["rev-list", "--left-right", "--count", &spec]).ok()?;
    if !out.status.success() {
        return None;
    }
    let text = stdout_trim(&out);
    let mut parts = text.split_whitespace();
    let ahead = parts.next()?.parse().ok()?;
    let behind = parts.next()?.parse().ok()?;
    Some((ahead, behind))
}

fn object_exists(repo: &Path, sha: &str) -> bool {
    let spec = format!("{sha}^{{commit}}");
    git(repo, &["cat-file", "-e", &spec])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_fsck(repo: &Path, diag: &Diag) -> FsckReport {
    match git(repo, &["fsck", "--full", "--no-dangling"]) {
        Ok(out) => {
            let mut text = stdout_text(&out);
            if !stderr_text(&out).is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&stderr_text(&out));
            }
            parse_fsck(&text)
        }
        Err(e) => {
            diag.error(repo, format!("git fsck: {e}"));
            FsckReport {
                issues: Vec::new(),
                object_ids: Vec::new(),
            }
        }
    }
}

pub fn parse_fsck(text: &str) -> FsckReport {
    let mut issues = Vec::new();
    let mut object_ids = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let lower = l.to_ascii_lowercase();
        if lower.contains("dangling") {
            continue;
        }
        let interesting = lower.contains("missing")
            || lower.contains("corrupt")
            || lower.contains("broken")
            || lower.contains("error")
            || lower.contains("fatal")
            || lower.contains("empty");
        if !interesting {
            continue;
        }
        let oids = extract_oids(l);
        let kind = if lower.contains("missing") {
            "missing"
        } else if lower.contains("corrupt") || lower.contains("empty") {
            "corrupt"
        } else if lower.contains("broken") {
            "broken"
        } else {
            "error"
        };
        for oid in &oids {
            if !object_ids.contains(oid) {
                object_ids.push(oid.clone());
            }
        }
        issues.push(FsckIssue {
            kind: kind.into(),
            oids,
            message: l.to_string(),
        });
        if issues.len() >= 1000 {
            break;
        }
    }
    object_ids.sort();
    FsckReport { issues, object_ids }
}

fn extract_oids(s: &str) -> Vec<String> {
    let mut oids = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            cur.push(c);
        } else {
            push_oid(&mut oids, &cur);
            cur.clear();
        }
    }
    push_oid(&mut oids, &cur);
    oids
}

fn push_oid(oids: &mut Vec<String>, cur: &str) {
    if cur.len() == 40 || cur.len() == 64 {
        oids.push(cur.to_string());
    }
}

fn count_paths(repo: &Path, args: &[&str], errors: &mut Vec<String>) -> Option<u64> {
    match git(repo, args) {
        Ok(out) => Some(count_z(&out.stdout) as u64),
        Err(e) => {
            errors.push(format!("git {}: {e}", args.first().unwrap_or(&"?")));
            None
        }
    }
}

fn count_z(bytes: &[u8]) -> usize {
    bytes.split(|b| *b == 0).filter(|p| !p.is_empty()).count()
}

fn skeleton_of(git_dir: Option<&Path>, common: Option<&Path>) -> Vec<SkeletonItem> {
    SKELETON
        .iter()
        .map(|(name, is_dir)| {
            let present = [git_dir, common].into_iter().flatten().any(|base| {
                let p = base.join(name);
                match classify(&p) {
                    Ok(c) if *is_dir => c.kind == EntryKind::Dir,
                    Ok(c) if !*is_dir => c.kind == EntryKind::File || c.kind == EntryKind::Symlink,
                    _ => false,
                }
            });
            SkeletonItem {
                name: (*name).to_string(),
                present,
            }
        })
        .collect()
}

fn resolve_git_dir(repo: &Path) -> Option<PathBuf> {
    let dot = repo.join(".git");
    if let Ok(c) = classify(&dot) {
        match c.kind {
            EntryKind::Dir => return Some(dot),
            EntryKind::Symlink => {
                let target = fs::read_link(&dot).ok()?;
                let joined = if target.is_absolute() {
                    target
                } else {
                    repo.join(target)
                };
                return Some(normalize_lexical(&joined));
            }
            EntryKind::File => return read_gitdir_file(&dot, repo),
        }
    }
    if is_bare(repo) {
        return Some(repo.to_path_buf());
    }
    None
}

fn read_gitdir_file(dot: &Path, repo: &Path) -> Option<PathBuf> {
    // The gitdir pointer is git plumbing, not user content.
    let text = fs::read_to_string(dot).ok()?;
    let line = text.lines().next()?.trim();
    let rest = line.strip_prefix("gitdir:")?.trim();
    if rest.is_empty() {
        return None;
    }
    let p = PathBuf::from(rest);
    let joined = if p.is_absolute() { p } else { repo.join(p) };
    Some(normalize_lexical(&joined))
}

fn read_common_dir(git_dir: &Path) -> Option<PathBuf> {
    let path = git_dir.join("commondir");
    let Ok(c) = classify(&path) else {
        return Some(git_dir.to_path_buf());
    };
    if c.kind != EntryKind::File {
        return Some(git_dir.to_path_buf());
    }
    let text = fs::read_to_string(&path).ok()?;
    let line = text.trim();
    if line.is_empty() {
        return Some(git_dir.to_path_buf());
    }
    let p = PathBuf::from(line);
    let joined = if p.is_absolute() { p } else { git_dir.join(p) };
    Some(normalize_lexical(&joined))
}

fn git(repo: &Path, args: &[&str]) -> io::Result<Output> {
    let cmd_name = args.first().copied().unwrap_or("");
    if !ALLOWED_GIT.contains(&cmd_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("git subcommand not allowed: {cmd_name}"),
        ));
    }
    let mut cmd = Command::new("git");
    cmd.arg("--no-optional-locks")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_NAMESPACE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output()
}

fn stdout_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout_trim(out: &Output) -> String {
    stdout_text(out).trim().to_string()
}

fn is_sha(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_remotes(text: &str) -> Vec<Remote> {
    let mut remotes = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let Some(url) = parts.next() else { continue };
        let kind = parts
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '(' || c == ')')
            .to_string();
        remotes.push(Remote {
            name: name.to_string(),
            url: redact_git_url(url),
            kind,
        });
    }
    remotes
}

fn clip(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() > 300 {
        let clipped: String = t.chars().take(300).collect();
        format!("{clipped}…")
    } else {
        t.to_string()
    }
}

pub fn broken(report: &GitRepoReport) -> bool {
    !report.is_repo || !report.critical_missing.is_empty()
}

pub fn dirty(report: &GitRepoReport) -> bool {
    report.modified.unwrap_or(0) + report.staged.unwrap_or(0) + report.untracked.unwrap_or(0) > 0
}

pub fn problems(reports: &[GitRepoReport]) -> bool {
    if reports.is_empty() {
        return true;
    }
    reports
        .iter()
        .any(|r| broken(r) || dirty(r) || r.fsck.as_ref().is_some_and(|f| !f.issues.is_empty()))
}

pub fn render(
    reports: &[GitRepoReport],
    mode: Render,
    partial: bool,
    error_count: u64,
    mut out: impl Write,
) -> io::Result<()> {
    match mode {
        Render::Human => {
            if reports.is_empty() {
                writeln!(out, "repos: 0")?;
            }
            for r in reports {
                writeln!(out, "repo: {}", r.path)?;
                writeln!(out, "  is_repo: {}", yes(r.is_repo))?;
                writeln!(out, "  bare: {}", yes(r.bare))?;
                writeln!(
                    out,
                    "  branch: {}",
                    r.branch
                        .as_deref()
                        .unwrap_or(if r.detached { "detached" } else { "-" })
                )?;
                writeln!(out, "  head: {}", r.head.as_deref().unwrap_or("-"))?;
                if r.remotes.is_empty() {
                    writeln!(out, "  remotes: -")?;
                } else {
                    writeln!(out, "  remotes:")?;
                    for remote in &r.remotes {
                        writeln!(out, "    {} {} ({})", remote.name, remote.url, remote.kind)?;
                    }
                }
                if r.missing.is_empty() {
                    writeln!(out, "  skeleton missing: -")?;
                } else {
                    writeln!(out, "  skeleton missing: {}", r.missing.join(", "))?;
                }
                writeln!(
                    out,
                    "  modified: {} staged: {} untracked: {}",
                    fmt_u(r.modified),
                    fmt_u(r.staged),
                    fmt_u(r.untracked)
                )?;
                if let Some(a) = &r.against {
                    writeln!(
                        out,
                        "  against: {} shared={} ahead={} behind={}",
                        a.repo,
                        yes(a.shared_history),
                        fmt_u(a.ahead),
                        fmt_u(a.behind)
                    )?;
                }
                if let Some(fsck) = &r.fsck {
                    if fsck.object_ids.is_empty() {
                        writeln!(out, "  fsck: clean")?;
                    } else {
                        writeln!(out, "  fsck: {}", fsck.object_ids.join(", "))?;
                    }
                }
                for err in &r.errors {
                    writeln!(out, "  error: {err}")?;
                }
            }
        }
        Render::Json => {
            let body = serde_json::json!({
                "command": "git",
                "repos": reports,
                "partial": partial,
                "error_count": error_count,
            });
            serde_json::to_writer_pretty(&mut out, &body)?;
            writeln!(out)?;
        }
        Render::Ndjson => {
            for r in reports {
                let mut v = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("type".into(), serde_json::json!("repo"));
                }
                serde_json::to_writer(&mut out, &v)?;
                writeln!(out)?;
            }
            let summary = serde_json::json!({
                "type": "summary",
                "count": reports.len(),
                "partial": partial,
                "error_count": error_count,
            });
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

fn yes(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn fmt_u(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsck_parser_extracts_missing_blob() {
        let text = "missing blob deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n\
                    dangling blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                    error: object file .git/objects/ab/cd is empty\n";
        // The empty-object line has no 40-hex token in this sample.
        let report = parse_fsck(text);
        assert!(report
            .object_ids
            .iter()
            .any(|s| s == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(!report.object_ids.iter().any(|s| s.starts_with("aaaa")));
        assert!(report.issues.iter().any(|i| i.kind == "missing"));
    }
}
