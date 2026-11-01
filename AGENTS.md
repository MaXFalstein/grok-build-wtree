# groktree

Read-only inspector for Grok Build worktrees. Do not add writes, symlink follows, or scans of `~/Library`, `~/Music`, `~/Pictures`, `~/Movies`, `~/Desktop`, `~/Downloads`, `~/.Trash`, or `/Volumes` unless the user passed `--allow`.

## Commands an agent should run

```sh
groktree audit --json
groktree git --fsck --json PATH
groktree conflicts --json PATH
groktree diff --json --no-mtimes WORKTREE ORIGIN
groktree grok --json
```

Exit 0 is clean, 1 is findings, 2 is usage, 3 is a partial scan or an internal panic. `Identical` and `OriginHasEverything` have no unique worktree content. `git_not_a_repo` is a reason, not a failed class. Untracked files and a missing `packed-refs` are not failures.

Do not run plain `git status`, `git gc`, or `git update-index` against a tree `groktree` is inspecting. Those can write. `groktree git` already runs a locked-down `status --porcelain=v2`.

## Layout

`src/walk.rs` lists directories without following symlinks. `src/git.rs`, `src/diff.rs`, `src/conflicts.rs`, `src/grok.rs`, and `src/audit.rs` are the subcommands. `src/deny.rs` is the privacy list. `src/redact.rs` masks secret-named values and `http`/`https`/`ssh` userinfo.
