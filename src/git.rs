//! Read-only git inspection. Every git subprocess is on an allowlist and
//! runs with `GIT_OPTIONAL_LOCKS=0`, `--no-optional-locks`,
//! `-c core.fsmonitor=false`, and `-c core.hooksPath=/dev/null`.
//! Change counts come from `status --porcelain=v2`, which compares content.
//! The index is not refreshed. There is no `gc`, `fetch`, or `update-index`.

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
    "status",
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
    deny: &DenyList,
    diag: &Diag,
) -> GitRepoReport {
    let mut errors = Vec::new();
    let bare = is_bare(repo);
    let resolved = resolve_git_dir(repo, deny);
    let (git_dir, denied_git_dir) = match resolved {
        ResolvedGitDir::Found(path) => (Some(path), false),
        ResolvedGitDir::Denied(path) => {
            errors.push(format!(
                "git dir is on the deny list and was not opened: {}",
                path.display()
            ));
            (None, true)
        }
        ResolvedGitDir::Missing => (None, false),
    };
    let is_repo = git_dir.is_some() || denied_git_dir || bare;
    let common = git_dir.as_ref().and_then(|g| read_common_dir(g));
    let skeleton = if denied_git_dir {
        Vec::new()
    } else {
        skeleton_of(git_dir.as_deref(), common.as_deref())
    };
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

    if git_dir.is_some() {
        let gd = git_dir.as_deref();
        match git(repo, gd, &["symbolic-ref", "--quiet", "--short", "HEAD"]) {
            Ok(out) if out.status.success() => {
                branch = Some(stdout_trim(&out));
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("git: {e}")),
        }
        match git(repo, gd, &["rev-parse", "--verify", "-q", "HEAD"]) {
            Ok(out) if out.status.success() => {
                let sha = stdout_trim(&out);
                if is_sha(&sha) {
                    head = Some(sha);
                    if branch.is_none() {
                        detached = true;
                    }
                }
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("git: {e}")),
        }
        match git(repo, gd, &["remote", "-v"]) {
            Ok(out) if out.status.success() => {
                remotes = parse_remotes(&stdout_text(&out));
            }
            Ok(out) => {
                if critical_missing.is_empty() {
                    errors.push(clip(&format!("remote: {}", stderr_text(&out))));
                }
            }
            Err(e) => errors.push(format!("git: {e}")),
        }
        match git(
            repo,
            gd,
            &["status", "--porcelain=v2", "-z", "--untracked-files=normal"],
        ) {
            Ok(out) if out.status.success() => {
                let counts = parse_status_v2_z(&out.stdout);
                modified = Some(counts.modified);
                staged = Some(counts.staged);
                untracked = Some(counts.untracked);
            }
            Ok(out) => {
                if critical_missing.is_empty() {
                    errors.push(clip(&format!("status: {}", stderr_text(&out))));
                }
            }
            Err(e) => errors.push(format!("git: {e}")),
        }
        if fsck {
            fsck_report = Some(run_fsck(repo, gd, diag));
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

pub fn load_head(repo: &Path, deny: &DenyList) -> RepoHead {
    let git_dir = match resolve_git_dir(repo, deny) {
        ResolvedGitDir::Found(path) => Some(path),
        _ => None,
    };
    let sha = git(
        repo,
        git_dir.as_deref(),
        &["rev-parse", "--verify", "-q", "HEAD"],
    )
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
    let git_dir = match resolve_git_dir(repo, &DenyList::from_allows(&[])) {
        ResolvedGitDir::Found(path) => Some(path),
        _ => None,
    };
    let out = git(
        repo,
        git_dir.as_deref(),
        &["rev-list", "--left-right", "--count", &spec],
    )
    .ok()?;
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
    let git_dir = match resolve_git_dir(repo, &DenyList::from_allows(&[])) {
        ResolvedGitDir::Found(path) => Some(path),
        _ => None,
    };
    git(repo, git_dir.as_deref(), &["cat-file", "-e", &spec])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_fsck(repo: &Path, git_dir: Option<&Path>, diag: &Diag) -> FsckReport {
    match git(repo, git_dir, &["fsck", "--full", "--no-dangling"]) {
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

enum ResolvedGitDir {
    Missing,
    Found(PathBuf),
    Denied(PathBuf),
}

fn resolve_git_dir(repo: &Path, deny: &DenyList) -> ResolvedGitDir {
    let dot = repo.join(".git");
    if let Ok(c) = classify(&dot) {
        match c.kind {
            EntryKind::Dir => return ResolvedGitDir::Found(dot),
            EntryKind::Symlink => {
                let Ok(target) = fs::read_link(&dot) else {
                    return ResolvedGitDir::Missing;
                };
                let joined = if target.is_absolute() {
                    target
                } else {
                    repo.join(target)
                };
                let abs = normalize_lexical(&joined);
                if deny.is_denied(&abs) {
                    return ResolvedGitDir::Denied(abs);
                }
                return ResolvedGitDir::Found(abs);
            }
            EntryKind::File => {
                let Some(path) = read_gitdir_file(&dot, repo) else {
                    return ResolvedGitDir::Missing;
                };
                if deny.is_denied(&path) {
                    return ResolvedGitDir::Denied(path);
                }
                return ResolvedGitDir::Found(path);
            }
        }
    }
    if is_bare(repo) {
        return ResolvedGitDir::Found(repo.to_path_buf());
    }
    ResolvedGitDir::Missing
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

fn git(repo: &Path, git_dir: Option<&Path>, args: &[&str]) -> io::Result<Output> {
    let cmd_name = args.first().copied().unwrap_or("");
    if !ALLOWED_GIT.contains(&cmd_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("git subcommand not allowed: {cmd_name}"),
        ));
    }
    let mut cmd = Command::new("git");
    cmd.arg("--no-optional-locks")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null");
    if let Some(dir) = git_dir {
        cmd.arg("--git-dir").arg(dir);
        if !is_bare(repo) {
            cmd.arg("--work-tree").arg(repo);
        }
    }
    cmd.arg("-C").arg(repo).args(args);
    if let Some(parent) = repo.parent() {
        if let Ok(ceiling) = lexical_absolute(parent) {
            // Stop git from walking into a parent repository when this repo
            // is missing HEAD or is otherwise not a complete git dir.
            cmd.env("GIT_CEILING_DIRECTORIES", ceiling);
        }
    }
    cmd.env("GIT_OPTIONAL_LOCKS", "0")
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusCounts {
    pub modified: u64,
    pub staged: u64,
    pub untracked: u64,
}

/// Parse `git status --porcelain=v2 -z` records.
/// The first XY column is the index (staged). The second is the worktree.
pub fn parse_status_v2_z(bytes: &[u8]) -> StatusCounts {
    let mut counts = StatusCounts::default();
    let mut i = 0;
    while i < bytes.len() {
        let rel = bytes[i..]
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(bytes.len() - i);
        let rec = &bytes[i..i + rel];
        i += rel + 1;
        if rec.is_empty() {
            continue;
        }
        match rec[0] {
            b'?' => counts.untracked += 1,
            b'!' | b'#' => {}
            b'1' | b'u' => tally_xy(rec, &mut counts),
            b'2' => {
                tally_xy(rec, &mut counts);
                if i < bytes.len() {
                    let rel = bytes[i..]
                        .iter()
                        .position(|b| *b == 0)
                        .unwrap_or(bytes.len() - i);
                    i += rel + 1;
                }
            }
            _ => {}
        }
    }
    counts
}

fn tally_xy(rec: &[u8], counts: &mut StatusCounts) {
    let text = String::from_utf8_lossy(rec);
    let mut fields = text.split_whitespace();
    let _kind = fields.next();
    let Some(xy) = fields.next() else {
        return;
    };
    let mut chars = xy.chars();
    let Some(index) = chars.next() else {
        return;
    };
    let Some(worktree) = chars.next() else {
        return;
    };
    if index != '.' && index != '?' {
        counts.staged += 1;
    }
    if worktree != '.' && worktree != '?' {
        counts.modified += 1;
    }
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
    report.modified.unwrap_or(0) + report.staged.unwrap_or(0) > 0
}

pub fn problems(reports: &[GitRepoReport]) -> bool {
    if reports.is_empty() {
        return true;
    }
    reports.iter().any(|r| {
        broken(r)
            || dirty(r)
            || r.fsck.as_ref().is_some_and(|f| !f.issues.is_empty())
            || r.errors.iter().any(|e| e.contains("deny list"))
    })
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

    #[test]
    fn status_parser_counts_real_changes_not_headers() {
        let sample = b"1 .M N... 100644 100644 100644 aaa bbb README\0? extra.txt\0";
        let counts = parse_status_v2_z(sample);
        assert_eq!(counts.modified, 1);
        assert_eq!(counts.staged, 0);
        assert_eq!(counts.untracked, 1);
        let both = b"1 MM N... 100644 100644 100644 aaa bbb README\0";
        let counts = parse_status_v2_z(both);
        assert_eq!(counts.modified, 1);
        assert_eq!(counts.staged, 1);
    }
}
