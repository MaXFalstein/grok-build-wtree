//! `groktree` entry point. Scan roots on the privacy deny list are rejected
//! before any filesystem read of those roots.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use groktree::audit;
use groktree::cli::{Cli, Command};
use groktree::conflicts;
use groktree::deny::{guard_root, DenyList};
use groktree::diag::Diag;
use groktree::diff::{self, DiffOpts};
use groktree::git::{self, FindOpts};
use groktree::grok;
use groktree::show::{self, ShowOpts};
use groktree::stats;
use groktree::{exit_code, Render, EXIT_USAGE};

fn main() -> ExitCode {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
    match result {
        Ok(code) => code,
        Err(_) => {
            eprintln!("groktree: internal error");
            ExitCode::from(groktree::EXIT_PARTIAL as u8)
        }
    }
}

fn run() -> ExitCode {
    // Release builds ignore this. Debug and `cargo test` binaries still honor
    // it so the panic-to-exit-3 path can be regression tested.
    #[cfg(debug_assertions)]
    if std::env::var_os("GROKTREE_TEST_PANIC").is_some() {
        panic!("groktree test panic");
    }
    let cli = Cli::parse();
    let render = if cli.json {
        Render::Json
    } else if cli.ndjson {
        Render::Ndjson
    } else {
        Render::Human
    };
    let deny = DenyList::from_allows(&cli.allow);
    let code = match cli.command {
        Command::Show {
            path,
            level,
            all,
            dirs_only,
            ignore,
            gitignore,
            sizes,
            style,
            no_default_ignores,
        } => cmd_show(
            &ShowCmd {
                path: &path,
                level,
                all,
                dirs_only,
                ignore: &ignore,
                gitignore,
                sizes,
                style,
                no_default_ignores,
            },
            &deny,
            render,
        ),
        Command::Stats { paths } => cmd_stats(&paths, &deny, render),
        Command::Diff {
            a,
            b,
            sizes,
            mtimes,
            no_mtimes,
            ignore,
        } => cmd_diff(
            DiffCmd {
                a: &a,
                b: &b,
                sizes,
                mtimes,
                no_mtimes,
                ignore: &ignore,
            },
            &deny,
            render,
        ),
        Command::Git {
            paths,
            against,
            fsck,
        } => cmd_git(&paths, against.as_ref(), fsck, &deny, render),
        Command::Conflicts { paths } => cmd_conflicts(&paths, &deny, render),
        Command::Grok { home } => cmd_grok(home, &deny, render),
        Command::Audit { home, hold } => cmd_audit(home, &hold, &deny, render),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

struct ShowCmd<'a> {
    path: &'a std::path::Path,
    level: Option<usize>,
    all: bool,
    dirs_only: bool,
    ignore: &'a [String],
    gitignore: bool,
    sizes: bool,
    style: show::Style,
    no_default_ignores: bool,
}

fn cmd_show(cmd: &ShowCmd<'_>, deny: &DenyList, render: Render) -> i32 {
    let globs = match compile_globs(cmd.ignore) {
        Ok(g) => g,
        Err(msg) => {
            eprintln!("groktree: {msg}");
            return EXIT_USAGE;
        }
    };
    if let Err(msg) = guard_root(cmd.path, deny) {
        eprintln!("groktree: {msg}");
        return EXIT_USAGE;
    }
    let diag = Diag::new();
    let opts = ShowOpts {
        max_depth: cmd.level,
        all: cmd.all,
        dirs_only: cmd.dirs_only,
        globs: &globs,
        gitignore: cmd.gitignore,
        sizes: cmd.sizes,
        style: cmd.style,
        default_ignores: !cmd.no_default_ignores,
        display_root: display_root(cmd.path),
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = show::run(cmd.path, &opts, deny, &diag, render, &mut out) {
        eprintln!("groktree: write failed: {e}");
        return groktree::EXIT_PARTIAL;
    }
    let _ = out.flush();
    exit_code(diag.partial(), false)
}

fn cmd_stats(paths: &[PathBuf], deny: &DenyList, render: Render) -> i32 {
    if let Err(code) = preflight(paths, deny) {
        return code;
    }
    let diag = Diag::new();
    let rows = stats::scan_many(paths, deny, &diag);
    let partial = diag.partial() || stats::any_partial(&rows);
    if let Err(e) = stats::render(&rows, render, io::stdout().lock()) {
        eprintln!("groktree: write failed: {e}");
        return groktree::EXIT_PARTIAL;
    }
    exit_code(partial, false)
}

struct DiffCmd<'a> {
    a: &'a std::path::Path,
    b: &'a std::path::Path,
    sizes: bool,
    mtimes: bool,
    no_mtimes: bool,
    ignore: &'a [String],
}

fn cmd_diff(cmd: DiffCmd<'_>, deny: &DenyList, render: Render) -> i32 {
    let globs = match compile_globs(cmd.ignore) {
        Ok(g) => g,
        Err(msg) => {
            eprintln!("groktree: {msg}");
            return EXIT_USAGE;
        }
    };
    if let Err(code) = preflight(&[cmd.a.to_path_buf(), cmd.b.to_path_buf()], deny) {
        return code;
    }
    let diag = Diag::new();
    let opts = DiffOpts {
        globs: &globs,
        compare_mtime: !cmd.no_mtimes,
        skip_git: true,
        skip_dir_names: &[],
    };
    let report = diff::compare(cmd.a, cmd.b, &opts, deny, &diag);
    if let Err(e) = diff::render(&report, cmd.sizes, cmd.mtimes, render, io::stdout().lock()) {
        eprintln!("groktree: write failed: {e}");
        return groktree::EXIT_PARTIAL;
    }
    exit_code(report.partial || diag.partial(), diff::problems(&report))
}

fn cmd_git(
    paths: &[PathBuf],
    against: Option<&PathBuf>,
    fsck: bool,
    deny: &DenyList,
    render: Render,
) -> i32 {
    let mut check = paths.to_vec();
    if let Some(a) = against {
        check.push(a.clone());
    }
    if let Err(code) = preflight(&check, deny) {
        return code;
    }
    let diag = Diag::new();
    let against_repo = if let Some(path) = against {
        match git::primary_repo(path, deny, &diag) {
            Some(repo) => Some(git::load_head(&repo, deny)),
            None => {
                diag.error(path, "not a git repository");
                None
            }
        }
    } else {
        None
    };
    let mut reports = Vec::new();
    for path in paths {
        let repos = git::find_repos(
            path,
            &FindOpts {
                skip_dir_names: &[],
            },
            deny,
            &diag,
        );
        if repos.is_empty() {
            reports.push(git::inspect_repo(
                path,
                against_repo.as_ref(),
                fsck,
                deny,
                &diag,
            ));
        } else {
            for repo in repos {
                reports.push(git::inspect_repo(
                    &repo,
                    against_repo.as_ref(),
                    fsck,
                    deny,
                    &diag,
                ));
            }
        }
    }
    let partial = diag.partial();
    let problems = git::problems(&reports) || against.is_some() && against_repo.is_none();
    if let Err(e) = git::render(
        &reports,
        render,
        partial,
        diag.error_count(),
        io::stdout().lock(),
    ) {
        eprintln!("groktree: write failed: {e}");
        return groktree::EXIT_PARTIAL;
    }
    exit_code(partial, problems)
}

fn cmd_conflicts(paths: &[PathBuf], deny: &DenyList, render: Render) -> i32 {
    if let Err(code) = preflight(paths, deny) {
        return code;
    }
    let diag = Diag::new();
    let report = conflicts::scan(paths, deny, &diag);
    if let Err(e) = conflicts::render(&report, render, io::stdout().lock()) {
        eprintln!("groktree: write failed: {e}");
        return groktree::EXIT_PARTIAL;
    }
    exit_code(
        report.partial || diag.partial(),
        !report.conflicts.is_empty(),
    )
}

fn cmd_grok(home: Option<PathBuf>, deny: &DenyList, render: Render) -> i32 {
    let home = home.unwrap_or_else(grok::default_home);
    if let Err(msg) = guard_root(&home, deny) {
        eprintln!("groktree: {msg}");
        return EXIT_USAGE;
    }
    let diag = Diag::new();
    let report = grok::load(&home, deny, &diag);
    if let Err(e) = grok::render(&report, render, io::stdout().lock()) {
        eprintln!("groktree: write failed: {e}");
        return groktree::EXIT_PARTIAL;
    }
    exit_code(report.partial || diag.partial(), grok::problems(&report))
}

fn cmd_audit(home: Option<PathBuf>, hold: &[PathBuf], deny: &DenyList, render: Render) -> i32 {
    let home = home.unwrap_or_else(grok::default_home);
    if let Err(msg) = guard_root(&home, deny) {
        eprintln!("groktree: {msg}");
        return EXIT_USAGE;
    }
    let diag = Diag::new();
    let report = audit::run(&home, hold, deny, &diag);
    if let Err(e) = audit::render(&report, render, io::stdout().lock()) {
        eprintln!("groktree: write failed: {e}");
        return groktree::EXIT_PARTIAL;
    }
    exit_code(report.partial, audit::problems(&report))
}

fn preflight(paths: &[PathBuf], deny: &DenyList) -> Result<(), i32> {
    let mut failed = false;
    for path in paths {
        if let Err(msg) = guard_root(path, deny) {
            eprintln!("groktree: {msg}");
            failed = true;
        }
    }
    if failed {
        Err(EXIT_USAGE)
    } else {
        Ok(())
    }
}

fn compile_globs(patterns: &[String]) -> Result<GlobSet, String> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let g = GlobBuilder::new(p)
            .literal_separator(false)
            .backslash_escape(true)
            .build()
            .map_err(|e| format!("invalid ignore glob '{p}': {e}"))?;
        b.add(g);
    }
    b.build().map_err(|e| e.to_string())
}

fn display_root(path: &std::path::Path) -> String {
    let s = path.to_string_lossy();
    let t = s.trim_end_matches('/');
    if t.is_empty() {
        "/".into()
    } else {
        t.to_string()
    }
}
