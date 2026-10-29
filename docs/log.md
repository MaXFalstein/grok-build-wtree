# Design log

## Read-only git

Change counts use `git status --porcelain=v2 -z` with `--no-optional-locks`, `GIT_OPTIONAL_LOCKS=0`, `-c core.fsmonitor=false`, and `-c core.hooksPath=/dev/null`. `git diff-files` treats a stat mismatch as a modification, so `cp -a` and iCloud copies looked dirty. Status compares content and, with optional locks off, does not write the index.

A nested directory whose `.git` has no `HEAD` must not inherit the parent repository. Each invocation passes `--git-dir`, `--work-tree`, and `GIT_CEILING_DIRECTORIES` set to the repo's parent. A `.git` symlink or `gitdir:` pointer into the deny list is not opened.

## Classification

A pair of ordinary folders is still `Identical`, `OriginHasEverything`, or `WorktreeHasUniqueWork` from the file diff. `git_not_a_repo` is a reason. A missing critical git file is `NeedsReview` and sets `broken` on that repo. For a non-git pair, same-size files with different mtimes are hashed. Equal bytes stay mtime drift. Different bytes are `WorktreeHasUniqueWork` or `NeedsReview`, never `Identical`. The digest is not printed.

Conflict copies on the origin, and conflict copies inside `.git`, are reported and do not by themselves force `NeedsReview`. Worktree conflicts outside `.git` do. iCloud ` N` copies (`N >= 2`) are reported even when the original file is gone.

## Records

`worktrees.db` is opened `mode=ro&immutable=1`. A sibling `worktrees.db-wal` produces a warning because those frames are invisible in immutable mode. Session cwd values match a worktree by prefix, so a session whose cwd is a subdirectory still belongs to that worktree.

URL userinfo in any grok string (`https://token@host`, `ssh://git@host`) is replaced with `***`.

## Panics

`percent_decode` works on bytes so a multibyte character after `%` cannot panic. Any panic that still escapes is caught in `main` and exits 3, not 101.
