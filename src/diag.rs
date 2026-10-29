//! Collected scan problems. Details go to stderr immediately. The JSON report
//! keeps a capped, path-sorted copy.

use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

const STORED_CAP: usize = 200;

#[derive(Clone, Debug, Serialize)]
pub struct Note {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Default)]
struct Inner {
    errors: Vec<Note>,
    error_count: u64,
    denied: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Diag {
    inner: Mutex<Inner>,
}

impl Diag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn io_error(&self, path: &Path, err: &io::Error) {
        let message = if err.kind() == io::ErrorKind::NotFound {
            "vanished".to_string()
        } else if err.kind() == io::ErrorKind::PermissionDenied {
            "permission denied".to_string()
        } else {
            err.to_string()
        };
        self.error(path, message);
    }

    pub fn error(&self, path: &Path, message: impl Into<String>) {
        let message = message.into();
        let path_s = path.display().to_string();
        eprintln!("wtree: {path_s}: {message}");
        let _ = io::stderr().flush();
        let mut g = self.inner.lock().expect("diag lock");
        g.error_count = g.error_count.saturating_add(1);
        if g.errors.len() < STORED_CAP {
            g.errors.push(Note {
                path: path_s,
                message,
            });
        }
    }

    pub fn denied(&self, path: &Path) {
        let path_s = path.display().to_string();
        eprintln!("wtree: skipped {path_s}: deny list (pass --allow {path_s} to inspect)");
        let _ = io::stderr().flush();
        let mut g = self.inner.lock().expect("diag lock");
        if !g.denied.iter().any(|d| d == &path_s) {
            g.denied.push(path_s);
        }
    }

    pub fn error_count(&self) -> u64 {
        self.inner.lock().expect("diag lock").error_count
    }

    pub fn partial(&self) -> bool {
        self.error_count() > 0
    }

    pub fn errors(&self) -> Vec<Note> {
        let mut notes = self.inner.lock().expect("diag lock").errors.clone();
        notes.sort_by(|a, b| a.path.cmp(&b.path).then(a.message.cmp(&b.message)));
        notes
    }

    pub fn skipped_denied(&self) -> Vec<String> {
        let mut d = self.inner.lock().expect("diag lock").denied.clone();
        d.sort();
        d.dedup();
        d
    }
}
