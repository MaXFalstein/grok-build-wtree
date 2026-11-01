//! Built-in privacy deny list.
//!
//! macOS prompts the user the first time a process touches certain home
//! folders. `groktree` refuses those paths unless the caller passes `--allow`.
//! Paths are compared lexically. Symlinks are not resolved, so a link cannot
//! smuggle the walk into `~/Library`.

use std::env;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Folder names directly under `$HOME` that must not be scanned.
pub const DENY_NAMES: &[&str] = &[
    "Library",
    "Music",
    "Pictures",
    "Movies",
    "Desktop",
    "Downloads",
];

#[derive(Clone, Debug)]
pub struct DenyList {
    roots: Vec<PathBuf>,
    allows: Vec<PathBuf>,
}

impl DenyList {
    pub fn from_allows(allows: &[PathBuf]) -> Self {
        let mut roots = Vec::new();
        roots.push(PathBuf::from("/Volumes"));
        if let Some(home) = home_dir() {
            let home = normalize_lexical(&home);
            roots.push(home.join(".Trash"));
            for name in DENY_NAMES {
                roots.push(home.join(name));
            }
        }
        let allows = allows
            .iter()
            .filter_map(|p| lexical_absolute(p).ok())
            .collect();
        Self { roots, allows }
    }

    pub fn is_denied(&self, path: &Path) -> bool {
        let abs = match lexical_absolute(path) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if self.allows.iter().any(|a| is_under(&abs, a)) {
            return false;
        }
        self.roots.iter().any(|r| is_under(&abs, r))
    }
}

pub fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

pub fn expand_user(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" {
        return home_dir().unwrap_or_else(|| path.to_path_buf());
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    path.to_path_buf()
}

/// Absolute path with `.` and `..` removed. Does not touch the filesystem
/// except to read the current directory when `path` is relative, and does not
/// resolve symlinks.
pub fn lexical_absolute(path: &Path) -> io::Result<PathBuf> {
    let path = expand_user(path);
    let joined = if path.is_absolute() {
        path
    } else {
        env::current_dir()?.join(path)
    };
    Ok(normalize_lexical(&joined))
}

pub fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn is_under(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

/// Refuse to scan a user-supplied root that sits in the deny list.
/// Returns the lexical absolute path when the root may be used.
pub fn guard_root(path: &Path, deny: &DenyList) -> Result<PathBuf, String> {
    let abs = lexical_absolute(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if deny.is_denied(&abs) {
        return Err(format!(
            "refusing to scan {}: it is on the privacy deny list (~/Library, ~/Music, ~/Pictures, ~/Movies, ~/Desktop, ~/Downloads, ~/.Trash, /Volumes). Pass --allow {} to inspect it explicitly.",
            abs.display(),
            abs.display()
        ));
    }
    Ok(abs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_normalize_pops_parents() {
        assert_eq!(
            normalize_lexical(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(
            normalize_lexical(Path::new("/a/./b")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    fn library_is_denied_unless_allowed() {
        let home = PathBuf::from("/Users/ada");
        let roots = vec![home.join("Library"), home.join("Desktop")];
        let deny = DenyList {
            roots: roots.clone(),
            allows: vec![],
        };
        assert!(deny.is_denied(&home.join("Library/Caches")));
        assert!(deny.is_denied(&home.join("Desktop")));
        assert!(!deny.is_denied(&home.join("Projects/app")));
        assert!(!deny.is_denied(&home.join("LibraryFoo")));

        let allowed = DenyList {
            roots,
            allows: vec![home.join("Library/Caches")],
        };
        assert!(!allowed.is_denied(&home.join("Library/Caches/x")));
        assert!(allowed.is_denied(&home.join("Library/Mail")));
    }

    #[test]
    fn volumes_and_trash_are_denied() {
        let deny = DenyList::from_allows(&[]);
        assert!(deny.is_denied(Path::new("/Volumes/Secret")));
        if let Some(home) = home_dir() {
            assert!(deny.is_denied(&home.join(".Trash/file")));
            assert!(!deny.is_denied(&home.join("Projects/app")));
        }
    }
}
