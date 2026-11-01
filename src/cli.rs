//! Command-line interface. `--json` and `--ndjson` are global. `--allow`
//! lifts a privacy deny-list entry for that path and its descendants.

use std::path::PathBuf;

use clap::{ColorChoice, Parser, Subcommand};

use crate::show::Style;

#[derive(Debug, Parser)]
#[command(
    name = "groktree",
    version,
    about = "Read-only inspector for Grok Build worktrees, origins, and git repos",
    color = ColorChoice::Never,
    disable_colored_help = true
)]
pub struct Cli {
    /// One JSON document on stdout.
    #[arg(long, global = true, conflicts_with = "ndjson")]
    pub json: bool,
    /// One JSON record per line on stdout.
    #[arg(long, global = true, conflicts_with = "json")]
    pub ndjson: bool,
    /// Inspect PATH even if it is under the privacy deny list.
    /// Repeat for more than one path.
    #[arg(long, global = true, value_name = "PATH")]
    pub allow: Vec<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print a tree. Classic style matches the legacy find | sed alias.
    Show {
        path: PathBuf,
        /// Maximum depth. 1 is the root's children. 0 is the root only.
        #[arg(short = 'L', long = "level", value_name = "N")]
        level: Option<usize>,
        /// Show names that start with a dot.
        #[arg(short = 'a')]
        all: bool,
        /// Show directories only.
        #[arg(short = 'd')]
        dirs_only: bool,
        /// Ignore entries whose name or relative path matches GLOB.
        #[arg(short = 'I', long = "ignore", value_name = "GLOB")]
        ignore: Vec<String>,
        /// Skip files matched by .gitignore files under PATH.
        #[arg(long)]
        gitignore: bool,
        /// Print byte sizes of regular files.
        #[arg(long)]
        sizes: bool,
        /// Connector style: classic, unicode, or ascii.
        #[arg(long, value_enum, default_value = "unicode")]
        style: Style,
        /// Do not hide node_modules, target, .venv, or .git/objects.
        #[arg(long)]
        no_default_ignores: bool,
    },
    /// Count files, directories, symlinks, and bytes.
    Stats {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Compare two trees by relative path.
    Diff {
        a: PathBuf,
        b: PathBuf,
        /// Show sizes in the human report.
        #[arg(long)]
        sizes: bool,
        /// Show mtimes in the human report.
        #[arg(long, conflicts_with = "no_mtimes")]
        mtimes: bool,
        /// Do not treat mtime differences as changes.
        #[arg(long, conflicts_with = "mtimes")]
        no_mtimes: bool,
        /// Ignore entries whose name or relative path matches GLOB.
        #[arg(short = 'I', long = "ignore", value_name = "GLOB")]
        ignore: Vec<String>,
    },
    /// Inspect git repositories, including nested ones.
    Git {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Compare ahead/behind with OTHER_REPO when the two share history.
        #[arg(long, value_name = "OTHER_REPO")]
        against: Option<PathBuf>,
        /// Run `git fsck --full --no-dangling` and list missing or corrupt ids.
        #[arg(long)]
        fsck: bool,
    },
    /// Find iCloud, Dropbox, and Syncthing conflict copies and iCloud placeholders.
    Conflicts {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Read ~/.grok worktree records, session summaries, and trusted folders.
    Grok {
        /// Grok home. Defaults to ~/.grok.
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
    },
    /// Classify every recorded worktree against its origin.
    Audit {
        /// Grok home. Defaults to ~/.grok.
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
        /// List PATH and do not inspect it beyond an existence check.
        #[arg(long, value_name = "PATH")]
        hold: Vec<PathBuf>,
    },
}
