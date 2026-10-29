//! Read-only inspection of Grok Build worktrees, origins, and git repositories.
//!
//! `wtree` never writes, never follows symlinks, and never reads arbitrary file
//! contents. The only bytes it opens are git metadata, `.gitignore` files when
//! `--gitignore` is set, `worktrees.db`, `sessions/*/summary.json`, and
//! `trusted_folders.toml`.

#![forbid(unsafe_code)]

pub mod audit;
pub mod cli;
pub mod conflicts;
pub mod deny;
pub mod diag;
pub mod diff;
pub mod git;
pub mod grok;
pub mod redact;
pub mod show;
pub mod stats;
pub mod walk;

/// Process exit codes.
pub const EXIT_OK: i32 = 0;
pub const EXIT_PROBLEMS: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PARTIAL: i32 = 3;

/// Partial scans outrank findings so scripts do not treat an incomplete
/// result as a finished diagnosis.
pub fn exit_code(partial: bool, problems: bool) -> i32 {
    if partial {
        EXIT_PARTIAL
    } else if problems {
        EXIT_PROBLEMS
    } else {
        EXIT_OK
    }
}

/// How a command renders its report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Render {
    Human,
    Json,
    Ndjson,
}
