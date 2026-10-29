#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static N: AtomicU64 = AtomicU64::new(0);

pub struct Temp {
    pub path: PathBuf,
}

impl Temp {
    pub fn new() -> Self {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("wtree-test-{}-{}-{n}", std::process::id(), nanos));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .args(["-R", "u+rwx"])
            .arg(&self.path)
            .status();
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wtree"))
        .args(args)
        .output()
        .expect("spawn wtree");
    decode(out)
}

pub fn run_with_home(home: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wtree"))
        .args(args)
        .env("HOME", home)
        .output()
        .expect("spawn wtree");
    decode(out)
}

fn decode(out: Output) -> (i32, String, String) {
    (
        out.status.code().unwrap_or(99),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

pub fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-c")
        .arg("user.email=wtree-test@example.com")
        .arg("-c")
        .arg("user.name=wtree-test")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("git")
}

pub fn git_ok(dir: &Path, args: &[&str]) -> String {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn init_repo(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    git_ok(dir, &["init", "-b", "main"]);
    fs::write(dir.join("README"), b"hello\n").unwrap();
    git_ok(dir, &["add", "README"]);
    git_ok(dir, &["commit", "-m", "init"]);
    let _ = git(dir, &["pack-refs", "--all"]);
    fs::create_dir_all(dir.join(".git/hooks")).unwrap();
    fs::create_dir_all(dir.join(".git/info")).unwrap();
    let exclude = dir.join(".git/info/exclude");
    if !exclude.exists() {
        fs::write(&exclude, b"").unwrap();
    }
    if !dir.join(".git/packed-refs").is_file() {
        fs::write(
            dir.join(".git/packed-refs"),
            b"# pack-refs with: peeled fully-peeled sorted\n",
        )
        .unwrap();
    }
}

pub fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).unwrap();
}
