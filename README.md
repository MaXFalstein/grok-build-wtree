# wtree

`wtree` is a read-only command for inspecting Grok Build worktrees, the origin folders they were cut from, and git repositories that live in cloud-synced directories such as iCloud Drive. It complements the system `tree` command. It does not replace it.

The tool is one binary. It links only the platform C library. SQLite is compiled in, so it does not need a system `libsqlite`. Git inspection shells out to the `git` on `PATH`.

## Install

Requires Rust 1.85 or newer (a dependency uses edition 2024). If the build fails with an edition2024 error, run `rustup update`.

From this checkout:

```sh
cargo install --path . --locked
```

`Cargo.lock` is part of the repo, so `--locked` reproduces the build that the tests ran against.

A Homebrew formula lives at [`packaging/homebrew/wtree.rb`](packaging/homebrew/wtree.rb). After the formula is in a tap and pointed at a release tarball:

```sh
brew install wtree
```

Until that tarball exists, install from a checkout with Cargo. `brew install --HEAD` works once the formula's `head` URL is the real git remote.

## Safety guarantees

`wtree` is safe to point at a synced worktree.

- It never writes, moves, deletes, or `chmod`s. It never refreshes a git index, runs `git gc`, or takes an optional lock. Every git subprocess is on an allowlist and is started with `--no-optional-locks` and `GIT_OPTIONAL_LOCKS=0`. `GIT_DIR` and `GIT_INDEX_FILE` from the environment are cleared so a parent shell cannot redirect the inspection.
- It never follows symlinks. A symlink is a single entry, `name -> target`. A symlink `.gitignore` is not read. `worktrees.db`, `trusted_folders.toml`, and `summary.json` are skipped when they are symlinks.
- It never reads arbitrary file contents. The only bytes it opens are git metadata (the `.git` gitdir pointer, `commondir`, and what the allowlisted git commands themselves read), `.gitignore` files when `--gitignore` is set, `worktrees.db`, `sessions/*/summary.json` and `sessions/*/*/summary.json`, and `trusted_folders.toml`.
- It only walks paths you pass, plus the git directory those paths point at. A linked worktree's `.git` file names a git dir that may sit outside the worktree. That git dir is read for the `git` command and for audit. Nothing else outside the requested path is opened.
- A built-in deny list refuses `~/Library` (which includes `CloudStorage` and iCloud's Mobile Documents), `~/Music`, `~/Pictures`, `~/Movies`, `~/Desktop`, `~/Downloads`, `~/.Trash`, and `/Volumes`. The check is lexical. A symlink `.git` whose target is on that list is not opened. Pass `--allow PATH` to inspect a denied path on purpose. A denied child of an allowed walk is skipped and named on stderr. It is not stated.
- Paths are sorted by raw bytes. Output does not depend on `LC_COLLATE`. There is no color and no prompt. The human tree is streamed one directory at a time.
- Errors (permission denied, a file that vanished mid-walk, an unreadable gitignore) go to stderr. The walk continues.
- Values whose keys contain `token`, `key`, `secret`, or `password` are printed as `***`. Git remote URLs lose embedded userinfo passwords. Blobs in SQLite are not printed. Session transcripts and `session_summary` text are not printed. Only session ids and working-directory paths are kept.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The scan finished and found nothing the command treats as a problem. |
| 1 | The scan finished and found a problem: a diff, a conflict, a dirty or broken repo, a stale or duplicate Grok record, an orphaned session, or an audit row that is `WorktreeHasUniqueWork`, `OriginMissing`, or `NeedsReview`. |
| 2 | Usage error. Bad flags, a bad glob, or a requested root that sits on the deny list. |
| 3 | Partial scan. A permission error, a vanished path, a missing `worktrees.db`, or git itself missing. A partial result outranks findings, so a script does not treat an incomplete report as a finished diagnosis. |

`show` and `stats` exit 0 when the walk completes. They exit 3 when it does not. Intentional deny-list skips are reported on stderr and in `skipped_denied`. They are not exit 3.

`Identical`, `OriginHasEverything`, and `OnHold` are not exit 1. Read the JSON if you need those classes. `OriginHasEverything` means the origin already has every worktree file at the same size.

## Privacy deny list

```text
~/Library      includes CloudStorage and Mobile Documents
~/Music
~/Pictures
~/Movies
~/Desktop
~/Downloads
~/.Trash
/Volumes
```

`~/Documents` is not on the list. `$HOME` comes from the environment. If it is unset, the list is empty and the tool says so by not denying anything.

```sh
wtree show ~/Library                 # exit 2, nothing is stated
wtree show ~/Library --allow ~/Library
wtree show ~                         # walks ~, skips ~/Library, exit 0
```

## Subcommands

Global flags, accepted before or after the subcommand: `--json`, `--ndjson`, `--allow PATH` (repeatable). `--json` and `--ndjson` cannot be combined.

### `wtree show PATH`

Tree view.

| Flag | Effect |
| --- | --- |
| `-L, --level N` | Depth. `1` is the root's children. `0` is the root only. |
| `-a` | Include names that start with `.` |
| `-d` | Directories only. Symlinks are not descended into. |
| `-I, --ignore GLOB` | Drop a name or relative path. Repeatable. |
| `--gitignore` | Honor `.gitignore` files under `PATH` only. Global excludes are not read. |
| `--sizes` | Append `[bytes]` for regular files. |
| `--style classic\|unicode\|ascii` | Default `unicode`. |
| `--no-default-ignores` | Also show `node_modules`, `target`, `.venv`, and `.git/objects`. |

`classic` matches this alias, with siblings sorted by bytes instead of directory order:

```sh
find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'
```

```text
.
|____b
| |____c
|____src
| |____main.rs
```

Without `-a`, dotfiles are hidden, which already hides `.git`. With `-a`, `.git` is shown and `.git/objects` is still pruned unless `--no-default-ignores` is set. A symlink prints as `link -> target` and its target is not walked.

### `wtree stats PATH...`

Counts every file, directory, and symlink under each path, including hidden and gitignored files. Bytes are the sum of regular-file lengths. Symlink targets are not added. The root directory is included in `dirs`.

```text
/path/to/tree
  files: 4
  dirs: 3
  symlinks: 0
  bytes: 26
  newest_mtime: 1793243955
  oldest_mtime: 1793243955
```

Several paths are counted in parallel. One wide tree is counted a directory level at a time, also in parallel. Exit 0 unless a directory cannot be read.

### `wtree diff A B`

Compares the two trees by relative path. Prints paths only in A, only in B, and paths whose kind, symlink target, size, or mtime differs. Directory mtimes are ignored, because creating a file bumps every parent.

`.git` (file or directory) is skipped. A linked worktree stores a gitdir file where the origin stores a gitdir directory, and that difference is not working-tree content. Use `wtree git` for the git directory.

`--sizes` and `--mtimes` add the numbers to the human report. JSON always has them. `--no-mtimes` keeps mtime differences out of `changed` (they are counted as `mtime_drift` instead). `-I GLOB` drops matching names. Default dependency directories are not skipped here. Audit skips them on its own.

```text
only in A: /tmp/a (1)
  file only.txt
only in B: /tmp/b (0)
changed (1):
  sized.txt (size 1 -> 2)
counts only_a=1 only_b=0 changed=1 mtime_drift=0
```

Exit 1 when there is any only-in or changed path.

### `wtree git PATH...`

Finds every repository under each path, including a nested repo such as `vulns/`. Does not follow symlinks and does not descend into a `.git` directory or into a bare repo's object store.

For each repo:

- whether it is a git repo, and whether it is bare
- skeleton check for `HEAD`, `config`, `index`, `objects`, `refs`, `packed-refs`, `info/exclude`, and `hooks`, looking in the git dir and, for a linked worktree, the common dir
- branch, full HEAD sha, remotes (passwords stripped)
- counts of modified and staged files from `git status --porcelain=v2` (content changes, not stat-only drift) and untracked files. Untracked files alone are not a problem. A missing `packed-refs` is listed and is not a problem.
- with `--against OTHER_REPO`, ahead/behind when either repository contains both commits
- with `--fsck`, `git fsck --full --no-dangling`, and the missing or corrupt object ids

`HEAD`, `config`, `objects`, and `refs` are critical. A missing `packed-refs`, `index`, `info/exclude`, or `hooks` is listed and does not by itself fail the command. Exit 1 when a requested path is not a repo, a critical file is missing, a file is modified or staged, or fsck reports an issue. Untracked files do not fail the command. A nested repo with no `HEAD` is reported as that repo, not as its parent: git is given `--git-dir`, `--work-tree`, and `GIT_CEILING_DIRECTORIES`. Every git invocation also passes `-c core.fsmonitor=false` and `-c core.hooksPath=/dev/null`.

```sh
wtree git --json --fsck ./repo
wtree git --against /path/to/origin /path/to/worktree
```

### `wtree conflicts PATH...`

Finds sync-conflict copies and iCloud placeholders.

| Kind | Pattern | Original |
| --- | --- | --- |
| `icloud` | `name N`, `name N.ext`, `.git 2`, `HEAD 2`, `archive.tar 3.gz` for any integer `N >= 2` | The name with ` N` removed from in front of the last extension. Reported even when that original is missing, including `.git/HEAD 2` with no `HEAD`. |
| `icloud_placeholder` | `.video.mov.icloud` | `video.mov`. The file is not downloaded. Reported even when the original is absent. |
| `dropbox` | `(conflicted copy ...)` | The name with the parenthetical removed. |
| `syncthing` | `.sync-conflict-DATE-TIME-DEVICE` | The name with that infix removed. |

The report has the conflict path, the original it shadows, whether the original exists, and both mtimes (unix seconds). The walk includes hidden names and `.git`, which is where `index 2` shows up. Exit 1 when any conflict is found.

### `wtree grok [--home ~/.grok]`

Reads Grok Build's records:

- `worktrees.db`, opened with SQLite `mode=ro&immutable=1` and `query_only`. The table and columns come from `sqlite_master` and `PRAGMA table_info`. A table named `worktrees` wins. Otherwise the tool picks a table that has both a path column (`path`, `folder`, `worktree_path`, `worktree`) and an origin column (`source_repo`, `origin`, `origin_path`, `repo_path`, `source`, `upstream`).
- `sessions/<id>/summary.json` and `sessions/<encoded-cwd>/<id>/summary.json`. Only `info.id`, `info.cwd`, and the encoded directory are kept. A session matches a worktree when its cwd is that folder or a path inside it.
- `trusted_folders.toml`, redacted.

Each row includes the folder, its path relative to `~/.grok/worktrees`, the recorded origin, whether that origin exists, and the session ids that reference it (the database `session_id`, a matching `info.cwd`, or a matching encoded session directory).

Flags:

- `stale_path` — the folder is not on disk
- `stale_origin` — the origin is missing or was not recorded
- `duplicate_path` — two rows share a folder
- `outside_worktrees_root` — the folder is not under `~/.grok/worktrees`
- `worktree_denied` / `origin_denied` — the path is on the deny list and was not stated
- `status_not_alive` — a status column is present and is not `alive` or `active`

An orphaned session is one whose cwd or encoded directory is under `~/.grok/worktrees` and either does not exist (`missing_on_disk`) or has no database row (`no_worktree_record`). Sessions for ordinary project directories are not orphans.

If `worktrees.db-wal` sits next to the database, `wtree` warns on stderr and sets `wal_present`. `immutable=1` does not read the WAL, so rows that have not been checkpointed can be missing. That warning does not by itself change the exit code.

Every string in the grok report is scanned for `http://`, `https://`, and `ssh://` userinfo. `https://ghp_xxx@github.com/...` becomes `https://***@github.com/...`.

Exit 1 when any row is flagged, any duplicate exists, or any session is orphaned.

### `wtree audit [--home ~/.grok] [--hold PATH]...`

Loads the same records as `grok`, then classifies every worktree against its origin. `--hold PATH` marks that path, anything inside it, and anything that contains it. A held pair is stated (existence only) and then left alone. A denied path is not stated at all.

| Class | Meaning |
| --- | --- |
| `Identical` | Same relative paths and the same bytes. For a git pair, `git status` supplies the content check. For a non-git pair, same-size files whose mtimes differ are hashed (the digest is not printed). Mtime drift with equal bytes is noted and does not change the class. A same-size edit is not Identical. If more than 10,000 such files need hashing, the rest are not read and the class is `NeedsReview` with `content_check_limit` and `content_unchecked`. |
| `OriginHasEverything` | Every worktree path is in the origin at the same size. The origin may have extra paths. |
| `WorktreeHasUniqueWork` | The worktree has a path the origin lacks, a shared path whose size or kind changed, or git reports a modified or staged file. The origin has no private paths. |
| `OriginMissing` | The worktree exists and the recorded origin does not. |
| `NeedsReview` | Worktree sync conflicts outside `.git`, a git repo that is missing a critical file, a denied git dir, a worktree that is missing or is itself a symlink, a denied side, or the trees diverged (each side has something the other does not). A folder that is not a git repo is still classified from the file diff. `git_not_a_repo` is a reason. Conflict copies that live only in the origin, and conflict copies inside `.git`, are reasons and do not by themselves select this class. |
| `OnHold` | The pair overlaps a `--hold` path. |

The working-tree diff used here skips `.git`, `node_modules`, `target`, and `.venv`. Conflict detection does not skip those, so `index 2` inside `.git` still forces `NeedsReview`. Git fsck is not run. Use `wtree git --fsck` for that.

```text
Identical              1
OriginHasEverything    1
WorktreeHasUniqueWork  2
OriginMissing          0
NeedsReview            1
OnHold                 1

WorktreeHasUniqueWork  /Users/me/.grok/worktrees/group/repo  origin=/Users/me/src/repo
  - only_worktree:1
  - worktree_only:NOTES
```

## JSON output

`--json` is one document. `--ndjson` is one record per line, then a `type: summary` line. Field order inside an object is not stable. Absence of a problem is `null` or an empty array, not a missing command.

`errors` on a JSON document keeps the first 200 notes, sorted by path. `error_count` is the full total. The same lines are printed to stderr as they happen. When several directories are scanned in parallel, stderr order can differ from the sorted JSON list.

### `show`

```json
{
  "command": "show",
  "path": "/absolute/or/as/given",
  "style": "classic",
  "entries": [
    {
      "path": "src/main.rs",
      "name": "main.rs",
      "depth": 2,
      "kind": "file",
      "size": 13,
      "mtime": 1793243983,
      "target": null
    }
  ],
  "partial": false,
  "error_count": 0,
  "errors": [{ "path": "/abs", "message": "permission denied" }],
  "skipped_denied": []
}
```

`kind` is `file`, `dir`, or `symlink`. `size` is null for directories and symlinks. `mtime` is unix seconds, or null. The root entry has `path` `"."`. NDJSON adds `"type": "entry"` on each line and a final `"type": "summary"` with `count`.

### `stats`

```json
{
  "command": "stats",
  "partial": false,
  "error_count": 0,
  "paths": [
    {
      "path": "/tree",
      "files": 1,
      "dirs": 2,
      "symlinks": 0,
      "bytes": 13,
      "newest_mtime": 1793243983,
      "oldest_mtime": 1793243983,
      "partial": false,
      "error_count": 0
    }
  ]
}
```

NDJSON emits one `"type": "path"` object per path, then `"type": "summary"`.

### `diff`

```json
{
  "command": "diff",
  "a": "/tree-a",
  "b": "/tree-b",
  "only_a": [{ "path": "only.txt", "kind": "file", "size": 4, "mtime": 100, "target": null }],
  "only_b": [],
  "changed": [
    {
      "path": "sized.txt",
      "kind_changed": false,
      "size_changed": true,
      "mtime_changed": true,
      "target_changed": false,
      "a": { "kind": "file", "size": 1, "mtime": 100, "target": null },
      "b": { "kind": "file", "size": 2, "mtime": 200, "target": null }
    }
  ],
  "counts": { "only_a": 1, "only_b": 0, "changed": 1, "mtime_drift": 0 },
  "partial": false,
  "error_count": 0
}
```

On the CLI, mtime differences are `changed`. `mtime_drift` is used by audit, which does not treat mtime as a change. NDJSON uses `"type": "only_a" | "only_b" | "changed" | "summary"`.

### `git`

```json
{
  "command": "git",
  "partial": false,
  "error_count": 0,
  "repos": [
    {
      "path": "/repo",
      "is_repo": true,
      "bare": false,
      "git_dir": "/repo/.git",
      "common_dir": "/repo/.git",
      "branch": "main",
      "detached": false,
      "head": "0123456789abcdef0123456789abcdef01234567",
      "remotes": [{ "name": "origin", "url": "https://user:***@example.com/repo.git", "kind": "fetch" }],
      "skeleton": [{ "name": "HEAD", "present": true }],
      "missing": [],
      "critical_missing": [],
      "modified": 0,
      "staged": 0,
      "untracked": 0,
      "against": { "repo": "/other", "shared_history": true, "ahead": 0, "behind": 1 },
      "fsck": { "issues": [{ "kind": "missing", "oids": ["..."], "message": "missing blob ..." }], "object_ids": ["..."] },
      "errors": []
    }
  ]
}
```

`against` is null unless `--against` was passed. `fsck` is null unless `--fsck` was passed. `branch` is null when HEAD is detached. NDJSON uses `"type": "repo"`.

### `conflicts`

```json
{
  "command": "conflicts",
  "roots": ["/tree"],
  "conflicts": [
    {
      "kind": "icloud",
      "path": "/tree/notes 2.txt",
      "original": "/tree/notes.txt",
      "original_exists": true,
      "mtime": 1793243955,
      "original_mtime": 1793243955
    }
  ],
  "count": 1,
  "partial": false,
  "error_count": 0
}
```

`kind` is `icloud`, `icloud_placeholder`, `dropbox`, or `syncthing`. NDJSON uses `"type": "conflict"`.

### `grok`

```json
{
  "command": "grok",
  "home": "/Users/me/.grok",
  "worktrees_root": "/Users/me/.grok/worktrees",
  "db_path": "/Users/me/.grok/worktrees.db",
  "schema": {
    "tables": ["meta", "worktrees"],
    "worktree_table": "worktrees",
    "columns": ["id", "path", "source_repo"]
  },
  "meta": { "schema_version": "1" },
  "trusted_folders": { "folders": { "/abs/path": { "trusted": true, "decided_at": 10 } } },
  "worktrees": [
    {
      "id": "wt-1",
      "folder": "/Users/me/.grok/worktrees/group/repo",
      "relative": "group/repo",
      "origin": "/Users/me/src/repo",
      "origin_exists": true,
      "session_ids": ["sess-1"],
      "status": "alive",
      "repo_name": "repo",
      "flags": [],
      "extra": {}
    }
  ],
  "duplicates": [{ "kind": "path", "key": "/same/folder", "ids": ["wt-1", "wt-2"] }],
  "orphaned_sessions": [
    {
      "session_id": "orphan-1",
      "cwd": "/Users/me/.grok/worktrees/missing/repo",
      "decoded_path": "/Users/me/.grok/worktrees/missing/repo",
      "reason": "missing_on_disk"
    }
  ],
  "partial": false,
  "error_count": 0
}
```

`extra` is every column that is not one of the recognised roles, with sensitive keys masked and JSON-looking text parsed and masked. `origin_exists` is null when the origin was on the deny list and was not stated. NDJSON emits `worktree`, `duplicate`, and `orphan` records, then a summary that carries `schema`, `meta`, and `trusted_folders`.

### `audit`

```json
{
  "command": "audit",
  "home": "/Users/me/.grok",
  "summary": {
    "identical": 1,
    "origin_has_everything": 1,
    "worktree_has_unique_work": 2,
    "origin_missing": 0,
    "needs_review": 1,
    "on_hold": 1
  },
  "rows": [
    {
      "id": "unique",
      "worktree": "/Users/me/.grok/worktrees/unique/wt",
      "relative": "unique/wt",
      "origin": "/Users/me/src/unique",
      "class": "WorktreeHasUniqueWork",
      "reasons": ["only_worktree:1", "worktree_only:NOTES"],
      "worktree_exists": true,
      "origin_exists": true,
      "counts": {
        "only_worktree": 1,
        "only_origin": 0,
        "size_changed": 0,
        "mtime_drift": 4,
        "conflicts": 0,
        "git_modified": 0,
        "git_staged": 0,
        "git_untracked": 0
      }
    }
  ],
  "partial": false,
  "error_count": 0
}
```

`class` is `Identical`, `OriginHasEverything`, `WorktreeHasUniqueWork`, `OriginMissing`, `NeedsReview`, or `OnHold`. Reason strings are stable tokens such as `held`, `origin_missing`, `worktree_symlink`, `conflicts:1`, `conflict:icloud:/path/notes 2.txt`, `git_missing:worktree:HEAD`, `git_not_a_repo:origin`, `diverged`, `only_worktree:N`, `size_changed:N`, `content_changed:N`, `content_differs:PATH` (first 20 paths), `content_differs_total:N`, `content_check_limit:10000`, `content_unchecked:N`, `mtime_drift:N`, and `git_modified:N`. Example paths are capped at 10, conflict lines and `content_differs` paths at 20. Hitting the 10,000-file hash cap also prints one warning line on stderr. NDJSON uses `"type": "row"` and a summary that repeats `summary`.

## Using wtree from AI assistant skills

Run these from a non-interactive shell. Do not alias them. Prefer `--json` and branch on the exit code: 0 clean, 1 findings, 2 bad invocation, 3 incomplete.

Audit every recorded worktree:

```sh
wtree audit --json
```

A row of `WorktreeHasUniqueWork` or `NeedsReview` is not safe to delete. `Identical` and `OriginHasEverything` have no unique worktree content. `OnHold` was not inspected. Add `--hold PATH` for a tree you already know you must keep. The command will not open it.

Diagnose one repo, including a nested repo and a linked worktree:

```sh
wtree git --fsck --json PATH
wtree conflicts --json PATH
```

`critical_missing`, a non-empty `fsck.object_ids`, or a worktree conflict outside `.git` is the thing to report. `modified` and `staged` are content changes. `untracked` is informational. Do not run a plain `git status` or `git gc` to confirm: a normal `git status` refreshes the index. `wtree git` runs status with optional locks disabled.

Compare a worktree with the origin recorded for it:

```sh
wtree diff --json WORKTREE ORIGIN
```

`only_a` is only in the worktree. `only_b` is only in the origin. `.git` is already excluded.

Find leftovers after a cleanup:

```sh
wtree grok --json
wtree conflicts --json ~/.grok/worktrees
wtree stats ~/.grok/worktrees
```

`stale_path`, `duplicates`, and `orphaned_sessions` are the records that no longer match disk. Conflict copies are the files a sync left behind. `stats` is the size of whatever is still there, including hidden files and git objects.

## Design trade-offs

Streaming versus a random-access tree. `show` writes each entry as soon as its directory listing is sorted, so a million files do not have to sit in memory. Unicode and ASCII connectors need to know which sibling is last, and that is known once the directory has been read. `diff` and `audit` keep a map of relative paths because classification needs both trees at once. That map, not the walker, is the memory ceiling.

`wtree` does not hash file contents. `diff` compares size and, unless `--no-mtimes`, mtime. A same-size edit is invisible to `diff`. Audit also asks `git status --porcelain=v2` with `GIT_OPTIONAL_LOCKS=0`. That command compares content and does not write a stat refresh, so a byte-identical copy (`cp -a`, ditto, iCloud) is not "modified", while a real edit is. Mtime drift does not change an audit class. Directory mtimes are ignored because creating a file bumps every parent.

`.git` is left out of `diff` and out of the audit file compare. A linked worktree and its origin will never have the same `.git` shape. The skeleton check and `git fsck` cover that metadata instead. Audit also skips `node_modules`, `target`, and `.venv` so a dependency install does not look like source work. `diff` itself does not skip those. Pass `-I` if you want to.

The iCloud `" 2"` pattern is only a finding when the reconstructed original exists. Dropbox, Syncthing, and `.icloud` placeholders are specific enough to report on their own.

SQLite is opened `immutable=1`, as required. That does not take a lock and it does not see frames that exist only in a WAL. A database that has been checkpointed is complete. One mid-write can look a generation behind. `query_only` is set on top so a bug in this program cannot commit.

Git is a subprocess, not libgit2 or gitoxide. `git fsck --full --no-dangling` is the behavior people already know, and the allowlist is short enough to audit. The cost is a `git` binary on `PATH` and a process per repository. Ahead/behind is computed only when one of the two repositories actually has both commits, so the tool never fetches.

Parallelism is level by level for `stats`, and across the top-level path list. Nested rayon joins deadlock, so the walk does not do that. `show`, `diff`, `conflicts`, and `audit` stay single-threaded so their output order stays deterministic.

The deny list is `/Volumes` plus a hard prefix of `$HOME` (including `~/.Trash`). It will miss a privacy folder that lives somewhere else, and it will refuse a legitimate project that someone put on the Desktop. `--allow` is the explicit override. The tool would rather skip a directory than raise a macOS privacy prompt.

Tests build SQLite fixtures with `rusqlite` (bundled). They do not need the `sqlite3` CLI. They do need `git` on `PATH`. An internal panic is caught and exits 3 instead of 101.
