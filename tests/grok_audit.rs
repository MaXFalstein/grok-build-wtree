#[path = "common/mod.rs"]
mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::{git_ok, init_repo, percent_encode, run, Temp};

fn sqlite(db: &Path, sql: &str) {
    let out = Command::new("sqlite3")
        .arg(db)
        .arg(sql)
        .output()
        .expect("sqlite3");
    assert!(
        out.status.success(),
        "sqlite: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn grok_discovers_schema_masks_secrets_and_flags_records() {
    let t = Temp::new();
    let home = t.path.join("grokhome");
    let wt_root = home.join("worktrees");
    let folder = wt_root.join("group/repo");
    let origin = t.path.join("origin");
    fs::create_dir_all(&folder).unwrap();
    fs::create_dir_all(&origin).unwrap();
    fs::write(folder.join("README"), b"hello\n").unwrap();
    fs::write(origin.join("README"), b"hello\n").unwrap();

    let db = home.join("worktrees.db");
    fs::create_dir_all(&home).unwrap();
    sqlite(
        &db,
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         INSERT INTO meta (key, value) VALUES ('schema_version', '1');
         CREATE TABLE worktrees (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            source_repo TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'alive',
            session_id TEXT,
            metadata TEXT,
            api_token TEXT
         );",
    );
    let folder_s = folder.display().to_string().replace('\'', "''");
    let origin_s = origin.display().to_string().replace('\'', "''");
    let stale = "/tmp/wtree-stale-does-not-exist";
    sqlite(
        &db,
        &format!(
            "INSERT INTO worktrees (id, path, source_repo, repo_name, status, session_id, metadata, api_token)
             VALUES
             ('wt-1', '{folder_s}', '{origin_s}', 'repo', 'alive', 'sess-1', '{{\"label\":\"ok\",\"api_token\":\"METATOKENSECRET\"}}', 'DBTOKENSECRET'),
             ('wt-2', '{folder_s}', '{origin_s}', 'repo', 'alive', NULL, NULL, NULL),
             ('wt-3', '{stale}', '{origin_s}', 'gone', 'alive', NULL, NULL, NULL);"
        ),
    );

    let encoded = percent_encode(&folder.display().to_string());
    let session_dir = home.join("sessions").join(&encoded).join("sess-1");
    fs::create_dir_all(&session_dir).unwrap();
    fs::write(
        session_dir.join("summary.json"),
        format!(
            r#"{{"info":{{"id":"sess-1","cwd":"{}"}},"session_summary":"SESSIONPRIVATE","api_token":"SUPERSECRETTOKENVALUE"}}"#,
            folder.display()
        ),
    )
    .unwrap();

    let missing = wt_root.join("missing/repo");
    let orphan_dir = home
        .join("sessions")
        .join(percent_encode(&missing.display().to_string()))
        .join("orphan-1");
    fs::create_dir_all(&orphan_dir).unwrap();
    fs::write(
        orphan_dir.join("summary.json"),
        format!(
            r#"{{"info":{{"id":"orphan-1","cwd":"{}"}}}}"#,
            missing.display()
        ),
    )
    .unwrap();

    let outside = t.path.join("plain-project");
    fs::create_dir_all(
        home.join("sessions")
            .join(percent_encode(&outside.display().to_string()))
            .join("plain-1"),
    )
    .unwrap();
    fs::write(
        home.join("sessions")
            .join(percent_encode(&outside.display().to_string()))
            .join("plain-1")
            .join("summary.json"),
        format!(
            r#"{{"info":{{"id":"plain-1","cwd":"{}"}}}}"#,
            outside.display()
        ),
    )
    .unwrap();

    fs::write(
        home.join("trusted_folders.toml"),
        format!(
            "[folders.\"{}\"]\ntrusted = true\ndecided_at = 10\n\n[credentials]\npassword = \"HUNTER2PASSWORD\"\napi_token = \"SUPERSECRETTOKENVALUE\"\n",
            folder.display()
        ),
    )
    .unwrap();

    let (code, out, err) = run(&["grok", "--json", "--home", home.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}\n{out}");
    for secret in [
        "SESSIONPRIVATE",
        "SUPERSECRETTOKENVALUE",
        "HUNTER2PASSWORD",
        "METATOKENSECRET",
        "DBTOKENSECRET",
    ] {
        assert!(!out.contains(secret), "{secret} leaked in stdout\n{out}");
        assert!(!err.contains(secret), "{secret} leaked in stderr\n{err}");
    }
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["schema"]["worktree_table"], "worktrees");
    let cols = v["schema"]["columns"].to_string();
    assert!(
        cols.contains("path") && cols.contains("source_repo"),
        "{cols}"
    );
    assert_eq!(v["meta"]["schema_version"], "1");
    assert!(out.contains("***"), "{out}");
    let rows = v["worktrees"].as_array().unwrap();
    let live = rows.iter().find(|r| r["id"] == "wt-1").unwrap();
    assert_eq!(live["relative"], "group/repo");
    assert_eq!(live["origin_exists"], true);
    assert!(live["session_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "sess-1"));
    assert!(rows
        .iter()
        .any(|r| r["id"] == "wt-3" && r["flags"].to_string().contains("stale_path")));
    assert!(!v["duplicates"].as_array().unwrap().is_empty(), "{out}");
    let orphans = v["orphaned_sessions"].to_string();
    assert!(orphans.contains("orphan-1"), "{orphans}");
    assert!(!orphans.contains("plain-1"), "{orphans}");
    assert_eq!(
        v["trusted_folders"]["folders"][&folder.display().to_string()]["trusted"],
        true
    );
}

#[test]
fn grok_accepts_an_unknown_table_shape() {
    let t = Temp::new();
    let home = t.path.join("home");
    let folder = home.join("worktrees/a/b");
    let origin = t.path.join("src");
    fs::create_dir_all(&folder).unwrap();
    fs::create_dir_all(&origin).unwrap();
    let db = home.join("worktrees.db");
    fs::create_dir_all(&home).unwrap();
    sqlite(
        &db,
        "CREATE TABLE projects (id TEXT, folder TEXT, origin TEXT, note TEXT);",
    );
    sqlite(
        &db,
        &format!(
            "INSERT INTO projects (id, folder, origin, note) VALUES ('p1', '{}', '{}', 'plain');",
            folder.display(),
            origin.display()
        ),
    );
    let (code, out, err) = run(&["grok", "--json", "--home", home.to_str().unwrap()]);
    assert!(code == 0 || code == 1, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["schema"]["worktree_table"], "projects");
    assert_eq!(v["worktrees"][0]["folder"], folder.display().to_string());
    assert_eq!(v["worktrees"][0]["origin"], origin.display().to_string());
    assert_eq!(v["worktrees"][0]["origin_exists"], true);
    assert_eq!(v["worktrees"][0]["relative"], "a/b");
}

#[test]
fn audit_classifies_pairs_and_does_not_walk_holds() {
    let t = Temp::new();
    let home = t.path.join("home");
    let wt_root = home.join("worktrees");
    fs::create_dir_all(&home).unwrap();

    let identical_wt = wt_root.join("ident/wt");
    let identical_or = t.path.join("origins/ident");
    init_repo(&identical_wt);
    init_repo(&identical_or);
    // Same committed bytes. mtime may differ; class must stay Identical.
    fs::write(identical_wt.join("README"), b"hello\n").unwrap();
    fs::write(identical_or.join("README"), b"hello\n").unwrap();
    git_ok(&identical_wt, &["add", "README"]);
    git_ok(&identical_wt, &["commit", "--allow-empty", "-m", "touch"]);
    // Revert the commit content if the rewrite was a no-op. README is still hello.
    // If the second write matched the commit, the commit may be empty. That's fine.

    let superset_wt = wt_root.join("super/wt");
    let superset_or = t.path.join("origins/super");
    init_repo(&superset_wt);
    init_repo(&superset_or);
    fs::write(superset_or.join("EXTRA"), b"extra\n").unwrap();
    git_ok(&superset_or, &["add", "EXTRA"]);
    git_ok(&superset_or, &["commit", "-m", "extra"]);

    let unique_wt = wt_root.join("unique/wt");
    let unique_or = t.path.join("origins/unique");
    init_repo(&unique_wt);
    init_repo(&unique_or);
    fs::write(unique_wt.join("NOTES"), b"notes\n").unwrap();
    git_ok(&unique_wt, &["add", "NOTES"]);
    git_ok(&unique_wt, &["commit", "-m", "notes"]);

    let same_size_wt = wt_root.join("samesize/wt");
    let same_size_or = t.path.join("origins/samesize");
    init_repo(&same_size_wt);
    init_repo(&same_size_or);
    fs::write(same_size_wt.join("README"), b"HELLO\n").unwrap();

    let diverged_wt = wt_root.join("div/wt");
    let diverged_or = t.path.join("origins/div");
    init_repo(&diverged_wt);
    init_repo(&diverged_or);
    fs::write(diverged_wt.join("NOTES"), b"notes\n").unwrap();
    git_ok(&diverged_wt, &["add", "NOTES"]);
    git_ok(&diverged_wt, &["commit", "-m", "notes"]);
    fs::write(diverged_or.join("EXTRA"), b"extra\n").unwrap();
    git_ok(&diverged_or, &["add", "EXTRA"]);
    git_ok(&diverged_or, &["commit", "-m", "extra"]);

    let missing_wt = wt_root.join("missing/wt");
    init_repo(&missing_wt);
    let missing_or = t.path.join("origins/does-not-exist");

    let headless_wt = wt_root.join("headless/wt");
    let headless_or = t.path.join("origins/headless");
    init_repo(&headless_wt);
    init_repo(&headless_or);
    fs::remove_file(headless_wt.join(".git/HEAD")).unwrap();

    let held_wt = wt_root.join("held/wt");
    let held_or = t.path.join("origins/held");
    init_repo(&held_wt);
    init_repo(&held_or);
    fs::write(held_wt.join("zz-conflict-marker.txt"), b"orig").unwrap();
    fs::write(held_wt.join("zz-conflict-marker 2.txt"), b"copy").unwrap();

    let rows = [
        ("ident", &identical_wt, identical_or.display().to_string()),
        ("super", &superset_wt, superset_or.display().to_string()),
        ("unique", &unique_wt, unique_or.display().to_string()),
        (
            "samesize",
            &same_size_wt,
            same_size_or.display().to_string(),
        ),
        ("div", &diverged_wt, diverged_or.display().to_string()),
        ("missing", &missing_wt, missing_or.display().to_string()),
        ("headless", &headless_wt, headless_or.display().to_string()),
        ("held", &held_wt, held_or.display().to_string()),
    ];
    let mut sql = String::from(
        "CREATE TABLE worktrees (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            source_repo TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'alive',
            session_id TEXT
        );",
    );
    for (id, path, origin) in &rows {
        sql.push_str(&format!(
            "INSERT INTO worktrees (id, path, source_repo, repo_name) VALUES ('{id}', '{}', '{}', '{id}');",
            path.display().to_string().replace('\'', "''"),
            origin.replace('\'', "''")
        ));
    }
    sqlite(&home.join("worktrees.db"), &sql);

    let (code, out, err) = run(&[
        "audit",
        "--json",
        "--home",
        home.to_str().unwrap(),
        "--hold",
        held_wt.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "{err}\n{out}");
    assert!(
        !out.contains("zz-conflict-marker"),
        "held path was inspected\n{out}"
    );
    assert!(!err.contains("zz-conflict-marker"), "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let class = |id: &str| -> String {
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("missing {id} in {out}"))["class"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(class("ident"), "Identical", "{out}");
    assert_eq!(class("super"), "OriginHasEverything", "{out}");
    assert_eq!(class("unique"), "WorktreeHasUniqueWork", "{out}");
    assert_eq!(class("samesize"), "WorktreeHasUniqueWork", "{out}");
    assert_eq!(class("div"), "NeedsReview", "{out}");
    assert_eq!(class("missing"), "OriginMissing", "{out}");
    assert_eq!(class("headless"), "NeedsReview", "{out}");
    assert_eq!(class("held"), "OnHold", "{out}");
    let div = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "div")
        .unwrap();
    assert!(div["reasons"].to_string().contains("diverged"), "{div}");
    let headless = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "headless")
        .unwrap();
    assert!(
        headless["reasons"].to_string().contains("HEAD"),
        "{headless}"
    );
    let summary = &v["summary"];
    assert_eq!(summary["identical"], 1);
    assert_eq!(summary["origin_has_everything"], 1);
    assert_eq!(summary["worktree_has_unique_work"], 2);
    assert_eq!(summary["origin_missing"], 1);
    assert_eq!(summary["needs_review"], 2);
    assert_eq!(summary["on_hold"], 1);
}

#[test]
fn audit_identical_only_exits_clean() {
    let t = Temp::new();
    let home = t.path.join("home");
    let wt = home.join("worktrees/only/wt");
    let origin = t.path.join("origin");
    init_repo(&wt);
    init_repo(&origin);
    fs::create_dir_all(&home).unwrap();
    sqlite(
        &home.join("worktrees.db"),
        &format!(
            "CREATE TABLE worktrees (id TEXT, path TEXT, source_repo TEXT, repo_name TEXT, status TEXT);
             INSERT INTO worktrees VALUES ('only', '{}', '{}', 'only', 'alive');",
            wt.display(),
            origin.display()
        ),
    );
    let (code, out, err) = run(&["audit", "--json", "--home", home.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["rows"][0]["class"], "Identical");
}
