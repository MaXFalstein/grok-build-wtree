//! Tree view. `classic` matches `find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'`.
//! Entries are written as the walk discovers them. Only one directory listing
//! is held at a time.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use globset::GlobSet;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use serde::Serialize;

use crate::deny::DenyList;
use crate::diag::Diag;
use crate::walk::{
    classify, file_size, human_text, lossy, mtime_secs, read_names, rel_join, skip_denied,
    EntryKind,
};
use crate::Render;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Style {
    Classic,
    Unicode,
    Ascii,
}

pub struct ShowOpts<'a> {
    pub max_depth: Option<usize>,
    pub all: bool,
    pub dirs_only: bool,
    pub globs: &'a GlobSet,
    pub gitignore: bool,
    pub sizes: bool,
    pub style: Style,
    pub default_ignores: bool,
    pub display_root: String,
}

#[derive(Debug, Serialize)]
struct ShowEntry {
    path: String,
    name: String,
    depth: usize,
    kind: EntryKind,
    size: Option<u64>,
    mtime: Option<i64>,
    target: Option<String>,
}

struct GitStack {
    root: PathBuf,
    compiled: Vec<Gitignore>,
}

impl GitStack {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            compiled: Vec::new(),
        }
    }

    /// Push this directory's `.gitignore` if it is a regular file.
    fn push_dir(&mut self, dir: &Path, diag: &Diag) -> bool {
        let gi_path = dir.join(".gitignore");
        let meta = match fs::symlink_metadata(&gi_path) {
            Ok(m) => m,
            Err(_) => return false,
        };
        if !meta.file_type().is_file() {
            return false;
        }
        let mut b = GitignoreBuilder::new(&self.root);
        if let Some(err) = b.add(&gi_path) {
            diag.error(&gi_path, format!("gitignore: {err}"));
            return false;
        }
        match b.build() {
            Ok(g) => {
                self.compiled.push(g);
                true
            }
            Err(err) => {
                diag.error(&gi_path, format!("gitignore: {err}"));
                false
            }
        }
    }

    fn ignored(&self, rel: &str, is_dir: bool) -> bool {
        let path = Path::new(rel);
        for gi in self.compiled.iter().rev() {
            match gi.matched(path, is_dir) {
                Match::None => continue,
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
            }
        }
        false
    }
}

pub fn default_ignored(parent_name: Option<&str>, name: &str) -> bool {
    matches!(name, "node_modules" | "target" | ".venv")
        || (parent_name == Some(".git") && name == "objects")
}

fn glob_hit(globs: &GlobSet, name: &str, rel: &str) -> bool {
    !globs.is_empty() && (globs.is_match(name) || globs.is_match(rel))
}

struct Child {
    path: PathBuf,
    name: String,
    rel: String,
    kind: EntryKind,
    size: Option<u64>,
    mtime: Option<i64>,
    target: Option<String>,
}

pub fn run(
    root: &Path,
    opts: &ShowOpts<'_>,
    deny: &DenyList,
    diag: &Diag,
    render: Render,
    out: &mut dyn Write,
) -> io::Result<u64> {
    if render == Render::Json {
        writeln!(out, "{{")?;
        writeln!(out, "  \"command\": \"show\",")?;
        writeln!(
            out,
            "  \"path\": {},",
            serde_json::to_string(&root.display().to_string())?
        )?;
        writeln!(out, "  \"style\": {},", serde_json::to_string(&opts.style)?)?;
        writeln!(out, "  \"entries\": [")?;
    }
    let mut count = 0u64;
    let mut json_first = true;
    let meta = match fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) => {
            diag.io_error(root, &e);
            finish(render, diag, count, out)?;
            return Ok(0);
        }
    };
    let root_kind = if meta.file_type().is_symlink() {
        EntryKind::Symlink
    } else if meta.is_dir() {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    let target = if root_kind == EntryKind::Symlink {
        fs::read_link(root).ok().map(|p| p.display().to_string())
    } else {
        None
    };
    let root_name = if opts.style == Style::Classic && root_kind == EntryKind::Dir {
        ".".to_string()
    } else if root_kind == EntryKind::Dir {
        opts.display_root.clone()
    } else {
        root.file_name()
            .map(lossy)
            .unwrap_or_else(|| opts.display_root.clone())
    };
    emit(
        &ShowEntry {
            path: ".".into(),
            name: root_name,
            depth: 0,
            kind: root_kind,
            size: file_size(root_kind, &meta),
            mtime: mtime_secs(&meta),
            target,
        },
        &[],
        true,
        opts,
        render,
        &mut json_first,
        out,
    )?;
    count += 1;
    if root_kind == EntryKind::Dir {
        let mut git = GitStack::new(root.to_path_buf());
        if opts.gitignore {
            git.push_dir(root, diag);
        }
        let mut walk = Walk {
            opts,
            deny,
            diag,
            render,
            git: &mut git,
            json_first: &mut json_first,
            out,
        };
        count += walk.list(root, "", 0, &[])?;
    }
    finish(render, diag, count, out)?;
    Ok(count)
}

fn finish(render: Render, diag: &Diag, count: u64, out: &mut dyn Write) -> io::Result<()> {
    match render {
        Render::Json => {
            writeln!(out)?;
            writeln!(out, "  ],")?;
            writeln!(out, "  \"partial\": {},", diag.partial())?;
            writeln!(out, "  \"error_count\": {},", diag.error_count())?;
            writeln!(
                out,
                "  \"errors\": {},",
                serde_json::to_string(&diag.errors())?
            )?;
            writeln!(
                out,
                "  \"skipped_denied\": {}",
                serde_json::to_string(&diag.skipped_denied())?
            )?;
            writeln!(out, "}}")?;
        }
        Render::Ndjson => {
            let summary = serde_json::json!({
                "type": "summary",
                "partial": diag.partial(),
                "error_count": diag.error_count(),
                "errors": diag.errors(),
                "skipped_denied": diag.skipped_denied(),
                "count": count,
            });
            serde_json::to_writer(&mut *out, &summary)?;
            writeln!(out)?;
        }
        Render::Human => {}
    }
    Ok(())
}

struct Walk<'a> {
    opts: &'a ShowOpts<'a>,
    deny: &'a DenyList,
    diag: &'a Diag,
    render: Render,
    git: &'a mut GitStack,
    json_first: &'a mut bool,
    out: &'a mut dyn Write,
}

impl Walk<'_> {
    fn list(&mut self, dir: &Path, rel: &str, depth: usize, ancestors: &[bool]) -> io::Result<u64> {
        if depth > 4096 {
            self.diag.error(dir, "max depth exceeded");
            return Ok(0);
        }
        if let Some(max) = self.opts.max_depth {
            if depth >= max {
                return Ok(0);
            }
        }
        let names = match read_names(dir) {
            Ok(n) => n,
            Err(e) => {
                self.diag.io_error(dir, &e);
                return Ok(0);
            }
        };
        let parent_name = if rel.is_empty() {
            dir.file_name().map(lossy)
        } else {
            Path::new(rel).file_name().map(lossy)
        };
        let mut children = Vec::new();
        for ent in names {
            if skip_denied(&ent.path, self.deny, self.diag) {
                continue;
            }
            let name = lossy(&ent.name);
            let child_rel = rel_join(rel, &name);
            if self.opts.default_ignores && default_ignored(parent_name.as_deref(), &name) {
                continue;
            }
            if glob_hit(self.opts.globs, &name, &child_rel) {
                continue;
            }
            if !self.opts.all && name.starts_with('.') {
                continue;
            }
            let classified = match classify(&ent.path) {
                Ok(c) => c,
                Err(e) => {
                    self.diag.io_error(&ent.path, &e);
                    continue;
                }
            };
            if self.opts.gitignore
                && self
                    .git
                    .ignored(&child_rel, classified.kind == EntryKind::Dir)
            {
                continue;
            }
            if self.opts.dirs_only && classified.kind != EntryKind::Dir {
                continue;
            }
            children.push(Child {
                path: ent.path,
                name,
                rel: child_rel,
                kind: classified.kind,
                size: file_size(classified.kind, &classified.meta),
                mtime: mtime_secs(&classified.meta),
                target: classified.target,
            });
        }
        self.emit_children(&children, depth, ancestors)
    }

    fn emit_children(
        &mut self,
        children: &[Child],
        depth: usize,
        ancestors: &[bool],
    ) -> io::Result<u64> {
        let mut count = 0u64;
        let n = children.len();
        for (i, child) in children.iter().enumerate() {
            let is_last = i + 1 == n;
            let kind = child.kind;
            let path = child.path.clone();
            let rel = child.rel.clone();
            let mut prefix = ancestors.to_vec();
            emit(
                &ShowEntry {
                    path: rel.clone(),
                    name: child.name.clone(),
                    depth: depth + 1,
                    kind,
                    size: child.size,
                    mtime: child.mtime,
                    target: child.target.clone(),
                },
                &prefix,
                is_last,
                self.opts,
                self.render,
                self.json_first,
                self.out,
            )?;
            count += 1;
            if kind == EntryKind::Dir {
                let pushed = if self.opts.gitignore {
                    self.git.push_dir(&path, self.diag)
                } else {
                    false
                };
                prefix.push(is_last);
                count += self.list(&path, &rel, depth + 1, &prefix)?;
                if pushed {
                    self.git.compiled.pop();
                }
            }
        }
        Ok(count)
    }
}

fn emit(
    entry: &ShowEntry,
    ancestors: &[bool],
    is_last: bool,
    opts: &ShowOpts<'_>,
    render: Render,
    json_first: &mut bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    match render {
        Render::Human => write_human(entry, ancestors, is_last, opts, out),
        Render::Json => {
            if !*json_first {
                writeln!(out, ",")?;
            }
            *json_first = false;
            write!(out, "    ")?;
            serde_json::to_writer(&mut *out, entry)?;
            Ok(())
        }
        Render::Ndjson => {
            let mut v = serde_json::to_value(entry).unwrap_or(serde_json::Value::Null);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("type".into(), serde_json::json!("entry"));
            }
            serde_json::to_writer(&mut *out, &v)?;
            writeln!(out)
        }
    }
}

fn write_human(
    entry: &ShowEntry,
    ancestors: &[bool],
    is_last: bool,
    opts: &ShowOpts<'_>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let label = format_label(entry, opts.sizes);
    if entry.depth == 0 || opts.style == Style::Classic {
        if entry.depth == 0 {
            writeln!(out, "{label}")?;
        } else {
            writeln!(out, "{}{label}", classic_prefix(entry.depth))?;
        }
        return Ok(());
    }
    let (tee, last, bar, blank) = match opts.style {
        Style::Ascii => ("|-- ", "`-- ", "|   ", "    "),
        Style::Unicode => ("├── ", "└── ", "│   ", "    "),
        Style::Classic => unreachable!(),
    };
    for flag in ancestors {
        out.write_all(if *flag { blank } else { bar }.as_bytes())?;
    }
    out.write_all(if is_last { last } else { tee }.as_bytes())?;
    writeln!(out, "{label}")?;
    Ok(())
}

fn format_label(entry: &ShowEntry, sizes: bool) -> String {
    let mut s = human_text(&entry.name);
    if let Some(t) = &entry.target {
        s.push_str(" -> ");
        s.push_str(&human_text(t));
    }
    if sizes {
        if let Some(sz) = entry.size {
            s.push_str(&format!(" [{sz}]"));
        }
    }
    s
}

pub fn classic_prefix(depth: usize) -> String {
    if depth == 0 {
        return String::new();
    }
    let mut s = String::new();
    for i in 0..depth {
        if i + 1 == depth {
            s.push_str("|____");
        } else {
            s.push_str("| ");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_prefix_matches_sed() {
        assert_eq!(classic_prefix(0), "");
        assert_eq!(classic_prefix(1), "|____");
        assert_eq!(classic_prefix(2), "| |____");
        assert_eq!(classic_prefix(3), "| | |____");
    }
}
