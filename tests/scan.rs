#[path = "common/mod.rs"]
mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::{init_repo, run, run_with_home, set_mode, Temp};

fn show(dir: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["show", "--style", "classic"];
    args.extend(extra);
    args.push(dir.to_str().unwrap());
    run(&args)
}

#[test]
fn classic_tree_is_sorted_and_matches_the_sed_alias() {
    let t = Temp::new();
    let root = t.path.join("demo");
    fs::create_dir_all(root.join("b")).unwrap();
    fs::write(root.join("a"), b"a").unwrap();
    fs::write(root.join("0"), b"0").unwrap();
    fs::write(root.join("b/c"), b"c").unwrap();
    let (code, out, err) = show(&root, &[]);
    assert_eq!(code, 0, "{err}\n{out}");
    // Byte order, not a locale collation: '0' (0x30) before 'a' before 'b'.
    assert_eq!(out, ".\n|____0\n|____a\n|____b\n| |____c\n");
    assert!(err.is_empty(), "{err}");
}

#[test]
fn unicode_and_ascii_connectors() {
    let t = Temp::new();
    let root = t.path.join("demo");
    fs::create_dir_all(root.join("b")).unwrap();
    fs::write(root.join("a"), b"a").unwrap();
    fs::write(root.join("b/c"), b"c").unwrap();
    let (code, out, err) = run(&["show", "--style", "unicode", root.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.starts_with(&format!("{}\n", root.display())), "{out}");
    assert!(out.contains("├── a\n"), "{out}");
    assert!(out.contains("└── b\n"), "{out}");
    assert!(out.contains("    └── c\n"), "{out}");

    let (code, out, err) = run(&["show", "--style", "ascii", root.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("|-- a\n"), "{out}");
    assert!(out.contains("`-- b\n"), "{out}");
    assert!(out.contains("    `-- c\n"), "{out}");
}

#[test]
fn depth_dirs_only_hidden_ignore_and_gitignore() {
    let t = Temp::new();
    let root = t.path.join("tree");
    fs::create_dir_all(root.join("sub/nested")).unwrap();
    fs::create_dir_all(root.join("node_modules")).unwrap();
    fs::create_dir_all(root.join(".git/objects")).unwrap();
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("file.txt"), b"f").unwrap();
    fs::write(root.join(".hidden"), b"h").unwrap();
    fs::write(root.join("sub/nested/deep.txt"), b"d").unwrap();
    fs::write(root.join("node_modules/pkg.js"), b"p").unwrap();
    fs::write(root.join("target/out"), b"o").unwrap();
    fs::write(root.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join(".git/objects/pack"), b"x").unwrap();
    fs::write(root.join("noise.log"), b"n").unwrap();
    fs::write(root.join("secret.txt"), b"s").unwrap();
    fs::write(root.join(".gitignore"), b"secret.txt\n").unwrap();

    let (code, out, err) = show(&root, &[]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("file.txt"), "{out}");
    assert!(out.contains("sub"), "{out}");
    assert!(out.contains("deep.txt"), "{out}");
    assert!(!out.contains("node_modules"), "{out}");
    assert!(!out.contains("pkg.js"), "{out}");
    assert!(!out.contains(".hidden"), "{out}");
    assert!(!out.contains("target"), "{out}");

    let (code, out, _) = show(&root, &["-L", "1"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("sub"), "{out}");
    assert!(!out.contains("deep.txt"), "{out}");

    let (code, out, _) = show(&root, &["-d"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("sub"), "{out}");
    assert!(out.contains("nested"), "{out}");
    assert!(!out.contains("file.txt"), "{out}");
    assert!(!out.contains("deep.txt"), "{out}");

    let (code, out, _) = show(&root, &["-a"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains(".hidden"), "{out}");
    assert!(out.contains(".git"), "{out}");
    assert!(out.contains("HEAD"), "{out}");
    assert!(!out.contains("objects"), "{out}");

    let (code, out, _) = show(&root, &["-a", "--no-default-ignores"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("objects"), "{out}");
    assert!(out.contains("node_modules"), "{out}");

    let (code, out, err) = show(&root, &["--ignore", "*.log"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(!out.contains("noise.log"), "{out}");

    let (code, out, err) = show(&root, &["--gitignore"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(!out.contains("secret.txt"), "{out}");
    assert!(out.contains("file.txt"), "{out}");

    let (code, out, _) = show(&root, &["--sizes"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("file.txt [1]"), "{out}");
}

#[test]
fn symlinks_are_reported_and_not_followed() {
    let t = Temp::new();
    let outside = t.path.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"secret-bytes").unwrap();
    let root = t.path.join("root");
    fs::create_dir_all(&root).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    fs::write(root.join("keep.txt"), b"k").unwrap();
    let (code, out, err) = show(&root, &[]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("link -> "), "{out}");
    assert!(out.contains("keep.txt"), "{out}");
    assert!(!out.contains("secret.txt"), "{out}");
    assert!(!out.contains("secret-bytes"), "{out}");
}

#[test]
fn deny_list_skips_without_touching_and_allow_opts_in() {
    let t = Temp::new();
    let home = t.path.join("home");
    fs::create_dir_all(home.join("Library/secret")).unwrap();
    fs::write(home.join("Library/secret/nope.txt"), b"private").unwrap();
    fs::create_dir_all(home.join("Projects")).unwrap();
    fs::write(home.join("Projects/a.txt"), b"yes").unwrap();
    set_mode(&home.join("Library"), 0o000);

    let (code, out, err) = run_with_home(
        &home,
        &["show", "--style", "classic", home.to_str().unwrap()],
    );
    assert_eq!(code, 0, "deny skip is not a partial failure\n{err}\n{out}");
    assert!(out.contains("a.txt"), "{out}");
    assert!(!out.contains("nope.txt"), "{out}");
    assert!(!out.contains("secret"), "{out}");
    assert!(err.contains("deny list"), "{err}");
    assert!(!err.to_ascii_lowercase().contains("permission"), "{err}");

    let lib = home.join("Library");
    let (code, out, err) = run_with_home(&home, &["show", lib.to_str().unwrap()]);
    assert_eq!(code, 2, "{err}\n{out}");
    assert!(err.contains("deny list"), "{err}");
    assert!(!err.to_ascii_lowercase().contains("permission"), "{err}");
    assert!(!out.contains("nope"), "{out}");

    set_mode(&lib, 0o755);
    let (code, out, err) = run_with_home(
        &home,
        &[
            "show",
            "--style",
            "classic",
            "--allow",
            lib.to_str().unwrap(),
            lib.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("nope.txt"), "{out}");
}

#[test]
fn permission_denied_is_partial_and_continues() {
    let t = Temp::new();
    let root = t.path.join("root");
    fs::create_dir_all(root.join("ok")).unwrap();
    fs::write(root.join("ok/a.txt"), b"a").unwrap();
    fs::create_dir_all(root.join("locked")).unwrap();
    fs::write(root.join("locked/x.txt"), b"x").unwrap();
    set_mode(&root.join("locked"), 0o000);
    let (code, out, err) = show(&root, &[]);
    assert_eq!(code, 3, "{err}\n{out}");
    assert!(out.contains("a.txt"), "{out}");
    assert!(err.contains("locked"), "{err}");
    assert!(
        err.contains("permission denied") || err.contains("Permission denied"),
        "{err}"
    );
}

#[test]
fn missing_root_is_partial() {
    let t = Temp::new();
    let missing = t.path.join("nope");
    let (code, _out, err) = run(&["show", missing.to_str().unwrap()]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("nope"), "{err}");
}

#[test]
fn bad_glob_is_usage() {
    let t = Temp::new();
    let (code, _, err) = run(&["show", "--ignore", "[", t.path.to_str().unwrap()]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("glob") || err.contains("ignore"), "{err}");
}

#[test]
fn stats_counts_hidden_and_does_not_follow_links() {
    let t = Temp::new();
    let root = t.path.join("s");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("a.txt"), b"abcd").unwrap();
    fs::write(root.join(".hid"), b"z").unwrap();
    fs::write(root.join("sub/b.txt"), b"xy").unwrap();
    std::os::unix::fs::symlink(root.join("a.txt"), root.join("link")).unwrap();
    let (code, out, err) = run(&["stats", "--json", root.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let row = &v["paths"][0];
    assert_eq!(row["files"], 3);
    assert_eq!(row["dirs"], 2);
    assert_eq!(row["symlinks"], 1);
    assert_eq!(row["bytes"], 4 + 1 + 2);
    assert!(row["newest_mtime"].as_i64().unwrap() >= row["oldest_mtime"].as_i64().unwrap());
}

#[test]
fn diff_reports_only_and_mtime_and_honors_ignore() {
    let t = Temp::new();
    let a = t.path.join("a");
    let b = t.path.join("b");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    fs::write(a.join("same.txt"), b"same").unwrap();
    fs::write(b.join("same.txt"), b"same").unwrap();
    fs::write(a.join("only.txt"), b"only").unwrap();
    fs::write(a.join("skip.log"), b"log").unwrap();
    fs::write(a.join("sized.txt"), b"a").unwrap();
    fs::write(b.join("sized.txt"), b"aa").unwrap();
    let (code, out, err) = run(&[
        "diff",
        "--json",
        "--ignore",
        "*.log",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "{err}\n{out}");
    let (hcode, human, herr) = run(&["diff", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(hcode, 1, "{herr}\n{human}");
    assert!(
        human.contains(&format!("only in A: {} (", a.display())),
        "{human}"
    );
    assert!(
        !human.lines().any(|line| line.starts_with("only in A (")),
        "{human}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let only_a: Vec<&str> = v["only_a"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(only_a.contains(&"only.txt"), "{only_a:?}");
    assert!(!only_a.iter().any(|p| p.contains("skip.log")), "{only_a:?}");
    let changed = v["changed"].as_array().unwrap();
    assert!(
        changed
            .iter()
            .any(|c| c["path"] == "sized.txt" && c["size_changed"] == true),
        "{changed:?}"
    );

    fs::write(a.join("time.txt"), b"tt").unwrap();
    fs::write(b.join("time.txt"), b"tt").unwrap();
    let _ = Command::new("touch")
        .args([
            "-t",
            "202001010101.00",
            a.join("time.txt").to_str().unwrap(),
        ])
        .status();
    let _ = Command::new("touch")
        .args([
            "-t",
            "202202020202.00",
            b.join("time.txt").to_str().unwrap(),
        ])
        .status();
    let (code, out, err) = run(&[
        "diff",
        "--mtimes",
        "--ignore",
        "*.log",
        "--ignore",
        "only.txt",
        "--ignore",
        "sized.txt",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "{err}\n{out}");
    assert!(out.contains("time.txt"), "{out}");
    assert!(out.contains("mtime"), "{out}");
}

#[test]
fn json_and_ndjson_are_distinct_documents() {
    let t = Temp::new();
    fs::write(t.path.join("a"), b"a").unwrap();
    let (code, out, err) = run(&["show", "--json", t.path.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect(&out);
    assert_eq!(v["command"], "show");
    assert!(v["entries"].as_array().unwrap().len() >= 2);

    let (code, out, err) = run(&["show", "--ndjson", t.path.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let lines: Vec<_> = out.lines().collect();
    assert!(lines.len() >= 2, "{out}");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect(line);
        assert!(v.get("type").is_some(), "{line}");
    }
    assert!(lines.last().unwrap().contains("summary"));

    let (code, _, _) = run(&["show", "--json", "--ndjson", t.path.to_str().unwrap()]);
    assert_eq!(code, 2);
}

#[test]
fn conflicts_report_numbered_copies_even_without_the_original() {
    let t = Temp::new();
    let root = &t.path;
    fs::write(root.join("notes.txt"), b"n").unwrap();
    fs::write(root.join("notes 2.txt"), b"n2").unwrap();
    fs::write(root.join(".git"), b"gitdir: /tmp/example\n").unwrap();
    fs::write(root.join(".git 2"), b"copy").unwrap();
    fs::create_dir_all(root.join("repo/.git")).unwrap();
    fs::write(root.join("repo/.git/index"), b"idx").unwrap();
    fs::write(root.join("repo/.git/index 2"), b"idx2").unwrap();
    fs::write(root.join("Getting Started.md"), b"g").unwrap();
    fs::write(
        root.join("Getting Started (conflicted copy 2015-03-26).md"),
        b"g2",
    )
    .unwrap();
    fs::write(root.join("photo.jpg"), b"p").unwrap();
    fs::write(
        root.join("photo.sync-conflict-20240101-120000-ABCDEF.jpg"),
        b"p2",
    )
    .unwrap();
    fs::write(root.join(".video.mov.icloud"), b"placeholder").unwrap();
    fs::write(root.join("Chapter 2.txt"), b"numbered copy").unwrap();
    fs::write(root.join("notes 3.txt"), b"third").unwrap();
    fs::create_dir_all(root.join("repo/.git")).unwrap();
    fs::write(root.join("repo/.git/HEAD 2"), b"leftover").unwrap();

    let (code, out, err) = run(&["conflicts", "--json", root.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}\n{out}");
    assert!(out.contains("Chapter 2.txt"), "{out}");
    assert!(out.contains("notes 3.txt"), "{out}");
    assert!(out.contains("HEAD 2"), "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let head = v["conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["path"].as_str().unwrap().ends_with("HEAD 2"));
    let head = head.expect("HEAD 2");
    assert_eq!(head["original_exists"], false, "{head}");
    let kinds: Vec<&str> = v["conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"icloud"), "{kinds:?} {out}");
    assert!(kinds.contains(&"icloud_placeholder"), "{kinds:?}");
    assert!(kinds.contains(&"dropbox"), "{kinds:?}");
    assert!(kinds.contains(&"syncthing"), "{kinds:?}");
    assert!(out.contains("index 2"), "{out}");
    assert!(out.contains(".git 2"), "{out}");
    let notes = v["conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["path"].as_str().unwrap().ends_with("notes 2.txt"));
    let notes = notes.expect("notes conflict");
    assert!(notes["original"].as_str().unwrap().ends_with("notes.txt"));
    assert_eq!(notes["original_exists"], true);
    assert!(notes["mtime"].is_number());
    assert!(notes["original_mtime"].is_number());
}

#[test]
fn git_healthy_missing_head_missing_blob_nested_and_ahead() {
    let t = Temp::new();
    let healthy = t.path.join("healthy");
    init_repo(&healthy);
    let index_before = fs::read(healthy.join(".git/index")).unwrap();
    let names_before = git_names(&healthy.join(".git"));

    let (code, out, err) = run(&["git", "--json", healthy.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let repo = &v["repos"][0];
    assert_eq!(repo["is_repo"], true);
    assert_eq!(repo["branch"], "main");
    assert!(repo["head"].as_str().unwrap().len() >= 40, "{repo}");
    assert_eq!(repo["modified"], 0);
    assert_eq!(repo["staged"], 0);
    assert_eq!(repo["untracked"], 0);
    assert!(repo["missing"].as_array().unwrap().is_empty(), "{repo}");
    assert_eq!(fs::read(healthy.join(".git/index")).unwrap(), index_before);
    assert_eq!(
        git_names(&healthy.join(".git")),
        names_before,
        "git wrote into .git"
    );

    let broken = t.path.join("nohead");
    init_repo(&broken);
    fs::remove_file(broken.join(".git/HEAD")).unwrap();
    let (code, out, err) = run(&["git", "--json", broken.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let missing = v["repos"][0]["critical_missing"].to_string();
    assert!(missing.contains("HEAD"), "{missing}");

    let blobbed = t.path.join("blob");
    init_repo(&blobbed);
    let sha = common::git_ok(&blobbed, &["rev-parse", "HEAD:README"]);
    let obj = blobbed.join(format!(".git/objects/{}/{}", &sha[..2], &sha[2..]));
    assert!(obj.is_file(), "loose object missing at {}", obj.display());
    fs::remove_file(&obj).unwrap();
    let (code, out, err) = run(&["git", "--fsck", "--json", blobbed.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}\n{out}");
    assert!(out.contains(&sha), "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let ids = v["repos"][0]["fsck"]["object_ids"].to_string();
    assert!(ids.contains(&sha), "{ids}\n{out}");

    let nested = t.path.join("nest");
    init_repo(&nested);
    let vulns = nested.join("vulns");
    init_repo(&vulns);
    let (code, out, err) = run(&["git", "--json", nested.to_str().unwrap()]);
    // Untracked files alone are not a problem. The nested repo is untracked in the parent.
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["repos"].as_array().unwrap().len(), 2, "{out}");
    let nested_repo = v["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"].as_str().unwrap().ends_with("/vulns"))
        .unwrap();
    assert_eq!(nested_repo["untracked"], 0, "{nested_repo}");
    assert!(nested_repo["critical_missing"]
        .as_array()
        .unwrap()
        .is_empty());

    let older = t.path.join("older");
    let newer = t.path.join("newer");
    init_repo(&older);
    // Copy the object store by cloning the file tree after a second commit,
    // then move `older` back one commit so both commits remain in both repos.
    fs::write(older.join("second.txt"), b"two\n").unwrap();
    common::git_ok(&older, &["add", "second.txt"]);
    common::git_ok(&older, &["commit", "-m", "second"]);
    copy_dir(&older, &newer);
    common::git_ok(&older, &["reset", "--hard", "HEAD~1"]);
    let (code, out, err) = run(&[
        "git",
        "--json",
        "--against",
        newer.to_str().unwrap(),
        older.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let against = &v["repos"][0]["against"];
    assert_eq!(against["shared_history"], true, "{against}");
    assert_eq!(against["ahead"], 0, "{against}");
    assert_eq!(against["behind"], 1, "{against}");

    let other = t.path.join("unrelated");
    fs::create_dir_all(&other).unwrap();
    common::git_ok(&other, &["init", "-b", "main"]);
    fs::write(other.join("README"), b"completely-different\n").unwrap();
    common::git_ok(&other, &["add", "README"]);
    common::git_ok(&other, &["commit", "-m", "other-history"]);
    let (code, out, err) = run(&[
        "git",
        "--json",
        "--against",
        other.to_str().unwrap(),
        healthy.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["repos"][0]["against"]["shared_history"], false, "{out}");

    common::git_ok(
        &healthy,
        &[
            "remote",
            "add",
            "origin",
            "https://user:SUPERSECRETTOKENVALUE@example.com/repo.git",
        ],
    );
    let (code, out, err) = run(&["git", "--json", healthy.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(!out.contains("SUPERSECRETTOKENVALUE"), "{out}");
    assert!(out.contains("***"), "{out}");
    assert!(!err.contains("SUPERSECRETTOKENVALUE"), "{err}");
}

#[test]
fn linked_worktree_skeleton_is_complete() {
    let t = Temp::new();
    let main = t.path.join("main");
    init_repo(&main);
    let wt = t.path.join("wt");
    common::git_ok(&main, &["worktree", "add", wt.to_str().unwrap(), "HEAD"]);
    let (code, out, err) = run(&["git", "--json", wt.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let repo = &v["repos"][0];
    assert_eq!(repo["is_repo"], true, "{repo}");
    assert!(repo["head"].as_str().unwrap().len() >= 40, "{repo}");
    assert!(
        repo["critical_missing"].as_array().unwrap().is_empty(),
        "{repo}"
    );
    assert!(repo["missing"].as_array().unwrap().is_empty(), "{repo}");
}

fn git_names(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for ent in fs::read_dir(dir).unwrap() {
        names.push(ent.unwrap().file_name().to_string_lossy().into_owned());
    }
    names.sort();
    names
}

fn copy_dir(src: &Path, dst: &Path) {
    let status = Command::new("cp")
        .arg("-R")
        .arg(src)
        .arg(dst)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn stat_only_copy_is_not_modified_and_untracked_is_not_a_problem() {
    let t = Temp::new();
    let src = t.path.join("src");
    init_repo(&src);
    // pack-refs may be the only copy of the branch. Capture the sha, drop
    // packed-refs, then write a loose ref so HEAD still resolves.
    let sha = common::git_ok(&src, &["rev-parse", "HEAD"]);
    let _ = fs::remove_file(src.join(".git/packed-refs"));
    common::git_ok(&src, &["update-ref", "refs/heads/main", &sha]);
    let copied = t.path.join("copied");
    let status = Command::new("cp")
        .args(["-a", src.to_str().unwrap(), copied.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let index_before = fs::read(copied.join(".git/index")).unwrap();
    let (code, out, err) = run(&["git", "--json", copied.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert_eq!(fs::read(copied.join(".git/index")).unwrap(), index_before);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let repo = &v["repos"][0];
    assert_eq!(repo["modified"], 0, "{repo}");
    assert_eq!(repo["staged"], 0, "{repo}");
    let missing = repo["missing"].to_string();
    assert!(missing.contains("packed-refs"), "{missing}");
    assert!(repo["critical_missing"].as_array().unwrap().is_empty());

    fs::write(src.join("extra.txt"), b"x").unwrap();
    let (code, out, err) = run(&["git", "--json", src.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["repos"][0]["modified"], 0);
    assert!(v["repos"][0]["untracked"].as_u64().unwrap() >= 1);
}

#[test]
fn nested_repo_missing_head_does_not_inherit_parent() {
    let t = Temp::new();
    let parent = t.path.join("parent");
    init_repo(&parent);
    let child = parent.join("vulns");
    fs::create_dir_all(child.join(".git")).unwrap();
    fs::write(
        child.join(".git/config"),
        b"[core]\n\trepositoryformatversion = 0\n",
    )
    .unwrap();
    let (code, out, err) = run(&["git", "--json", parent.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let parent_head = v["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"] == parent.display().to_string())
        .unwrap()["head"]
        .as_str()
        .unwrap()
        .to_string();
    let nested = v["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"].as_str().unwrap().ends_with("/vulns"))
        .expect("nested repo");
    assert!(nested["head"].is_null(), "{nested}");
    assert_ne!(nested["head"].as_str().unwrap_or(""), parent_head);
    assert!(
        nested["critical_missing"].to_string().contains("HEAD"),
        "{nested}"
    );
    assert!(nested["branch"].is_null(), "{nested}");
    assert_eq!(nested["broken"], true, "{nested}");
    let parent_row = v["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"] == parent.display().to_string())
        .unwrap();
    assert_eq!(parent_row["broken"], false, "{parent_row}");
}

#[test]
fn diff_no_mtimes_ignores_timestamp_drift() {
    let t = Temp::new();
    let a = t.path.join("a");
    let b = t.path.join("b");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    fs::write(a.join("f.txt"), b"same").unwrap();
    fs::write(b.join("f.txt"), b"same").unwrap();
    let _ = Command::new("touch")
        .args(["-t", "202001010101.00", a.join("f.txt").to_str().unwrap()])
        .status();
    let _ = Command::new("touch")
        .args(["-t", "202202020202.00", b.join("f.txt").to_str().unwrap()])
        .status();
    let (code, out, err) = run(&[
        "diff",
        "--no-mtimes",
        "--json",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["counts"]["changed"], 0);
    assert!(v["counts"]["mtime_drift"].as_u64().unwrap() >= 1);

    let (code, _, _) = run(&["diff", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(code, 1);
}

#[test]
fn volumes_trash_and_denied_gitdir_symlink_are_not_opened() {
    let (code, out, err) = run(&["show", "/Volumes"]);
    assert_eq!(code, 2, "{err}\n{out}");
    assert!(err.contains("deny list"), "{err}");

    let t = Temp::new();
    let home = t.path.join("home");
    fs::create_dir_all(home.join(".Trash")).unwrap();
    fs::write(home.join(".Trash/secret.txt"), b"TRASHSECRET").unwrap();
    let (code, out, err) = run_with_home(&home, &["show", home.join(".Trash").to_str().unwrap()]);
    assert_eq!(code, 2, "{err}\n{out}");
    assert!(!out.contains("TRASHSECRET"), "{out}");
    assert!(!err.contains("TRASHSECRET"), "{err}");

    let repo = t.path.join("repo");
    fs::create_dir_all(&repo).unwrap();
    let hidden = home.join("Library/secret.git");
    fs::create_dir_all(&hidden).unwrap();
    fs::write(hidden.join("HEAD"), b"GITDIRSECRET").unwrap();
    std::os::unix::fs::symlink(&hidden, repo.join(".git")).unwrap();
    let (code, out, err) = run_with_home(&home, &["git", "--json", repo.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}\n{out}");
    assert!(!out.contains("GITDIRSECRET"), "{out}{err}");
    assert!(!err.contains("GITDIRSECRET"), "{err}");
    assert!(
        err.contains("deny list") || out.contains("deny list"),
        "{out}\n{err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["repos"][0]["head"].is_null(), "{v}");
}

#[test]
fn fsmonitor_and_hooks_are_not_run() {
    let t = Temp::new();
    let repo = t.path.join("repo");
    init_repo(&repo);
    let marker = t.path.join("hook-ran");
    let script = t.path.join("fsmonitor.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display()),
    )
    .unwrap();
    let _ = Command::new("chmod")
        .args(["+x", script.to_str().unwrap()])
        .status();
    common::git_ok(
        &repo,
        &["config", "core.fsmonitor", script.to_str().unwrap()],
    );
    let (code, out, err) = run(&["git", "--json", repo.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(!marker.exists(), "fsmonitor hook ran");
}

#[test]
fn internal_panic_exits_3() {
    let t = Temp::new();
    let out = Command::new(env!("CARGO_BIN_EXE_groktree"))
        .arg("show")
        .arg(t.path.to_str().unwrap())
        .env("GROKTREE_TEST_PANIC", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}
