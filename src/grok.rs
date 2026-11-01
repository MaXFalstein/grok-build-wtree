//! Read Grok Build's records without writing and without printing secrets.
//!
//! `worktrees.db` is opened with SQLite's read-only and immutable flags.
//! The column list comes from `sqlite_master` and `PRAGMA table_info`, not
//! from a hard-coded `SELECT`. Session transcripts are not opened; only
//! `summary.json` files are, and only a whitelist of path fields is kept.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::deny::{lexical_absolute, normalize_lexical, DenyList};
use crate::diag::Diag;
use crate::redact::{key_is_sensitive, toml_to_json_redacted, MASK};
use crate::walk::{classify, lossy, EntryKind};
use crate::Render;

#[derive(Clone, Debug, Serialize)]
pub struct WorktreeRow {
    pub id: Option<String>,
    pub folder: String,
    pub relative: Option<String>,
    pub origin: Option<String>,
    pub origin_exists: Option<bool>,
    pub session_ids: Vec<String>,
    pub status: Option<String>,
    pub repo_name: Option<String>,
    pub flags: Vec<String>,
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Duplicate {
    pub kind: String,
    pub key: String,
    pub ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OrphanSession {
    pub session_id: String,
    pub cwd: Option<String>,
    pub decoded_path: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GrokReport {
    pub home: String,
    pub worktrees_root: String,
    pub db_path: String,
    pub schema: SchemaInfo,
    pub meta: Map<String, Value>,
    pub trusted_folders: Option<Value>,
    pub worktrees: Vec<WorktreeRow>,
    pub duplicates: Vec<Duplicate>,
    pub orphaned_sessions: Vec<OrphanSession>,
    /// `worktrees.db-wal` exists. `immutable=1` does not read it.
    pub wal_present: bool,
    pub partial: bool,
    pub error_count: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct SchemaInfo {
    pub tables: Vec<String>,
    pub worktree_table: Option<String>,
    pub columns: Vec<String>,
}

#[derive(Clone, Debug)]
struct RawRow {
    values: BTreeMap<String, Value>,
}

#[derive(Clone, Debug)]
struct SessionHit {
    id: String,
    cwd: Option<PathBuf>,
    decoded_path: Option<PathBuf>,
}

pub fn default_home() -> PathBuf {
    crate::deny::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".grok")
}

pub fn load(home: &Path, deny: &DenyList, diag: &Diag) -> GrokReport {
    let before = diag.error_count();
    let home = match lexical_absolute(home) {
        Ok(p) => p,
        Err(e) => {
            diag.error(home, e.to_string());
            return empty(home, diag, before);
        }
    };
    if deny.is_denied(&home) {
        diag.error(
            &home,
            "refusing to read grok home: privacy deny list. Pass --allow to inspect it.",
        );
        return empty(&home, diag, before);
    }
    let db_path = home.join("worktrees.db");
    let wal_path = wal_sibling(&db_path);
    let wal_present = classify(&wal_path).is_ok();
    if wal_present {
        eprintln!(
            "groktree: {}: a WAL file is present; immutable=1 may miss rows that are only in the WAL",
            wal_path.display()
        );
    }
    let worktrees_root = home.join("worktrees");
    let mut schema = SchemaInfo::default();
    let mut meta = Map::new();
    let mut raw_rows = Vec::new();

    if let Some(conn) = open_db(&db_path, diag) {
        match discover(&conn) {
            Ok(found) => {
                schema = found.schema;
                meta = found.meta;
                raw_rows = found.rows;
            }
            Err(e) => diag.error(&db_path, e),
        }
    }

    let sessions = scan_sessions(&home, diag);
    let trusted = read_trusted(&home.join("trusted_folders.toml"), diag);
    let mut worktrees = Vec::new();
    for row in &raw_rows {
        if let Some(wt) = project_row(row, &home, &worktrees_root, &sessions, deny, diag) {
            worktrees.push(wt);
        }
    }
    worktrees.sort_by(|a, b| a.folder.cmp(&b.folder).then(a.id.cmp(&b.id)));
    let duplicates = find_duplicates(&worktrees);
    for dup in &duplicates {
        if dup.kind == "path" {
            for wt in &mut worktrees {
                if dup
                    .ids
                    .iter()
                    .any(|id| wt.id.as_deref() == Some(id.as_str()))
                    || (wt.id.is_none() && dup.key == wt.folder)
                {
                    push_flag(&mut wt.flags, "duplicate_path");
                }
            }
        }
    }
    let orphans = orphan_sessions(&sessions, &worktrees, &worktrees_root, deny);
    let errors = diag.error_count().saturating_sub(before);
    GrokReport {
        home: home.display().to_string(),
        worktrees_root: worktrees_root.display().to_string(),
        db_path: db_path.display().to_string(),
        schema,
        meta,
        trusted_folders: trusted,
        worktrees,
        duplicates,
        orphaned_sessions: orphans,
        wal_present,
        partial: errors > 0,
        error_count: errors,
    }
}

fn empty(home: &Path, diag: &Diag, before: u64) -> GrokReport {
    let errors = diag.error_count().saturating_sub(before);
    GrokReport {
        home: home.display().to_string(),
        worktrees_root: home.join("worktrees").display().to_string(),
        db_path: home.join("worktrees.db").display().to_string(),
        schema: SchemaInfo::default(),
        meta: Map::new(),
        trusted_folders: None,
        worktrees: Vec::new(),
        duplicates: Vec::new(),
        orphaned_sessions: Vec::new(),
        wal_present: false,
        partial: true,
        error_count: errors.max(1),
    }
}

struct Discovered {
    schema: SchemaInfo,
    meta: Map<String, Value>,
    rows: Vec<RawRow>,
}

fn open_db(path: &Path, diag: &Diag) -> Option<Connection> {
    match classify(path) {
        Ok(c) if c.kind == EntryKind::Symlink => {
            diag.error(path, "refusing to open symlink worktrees.db");
            return None;
        }
        Ok(c) if c.kind == EntryKind::File => {}
        Ok(_) => {
            diag.error(path, "worktrees.db is not a regular file");
            return None;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            diag.error(path, "worktrees.db not found");
            return None;
        }
        Err(e) => {
            diag.io_error(path, &e);
            return None;
        }
    }
    let uri = sqlite_uri(path);
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    match Connection::open_with_flags(&uri, flags) {
        Ok(conn) => {
            let _ = conn.pragma_update(None, "query_only", "ON");
            Some(conn)
        }
        Err(e) => {
            diag.error(path, format!("sqlite: {e}"));
            None
        }
    }
}

fn sqlite_uri(path: &Path) -> String {
    let abs = lexical_absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let s = abs.to_string_lossy();
    let mut enc = String::from("file:");
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'_' | b'-' => {
                enc.push(b as char);
            }
            _ => enc.push_str(&format!("%{b:02X}")),
        }
    }
    enc.push_str("?mode=ro&immutable=1");
    enc
}

fn discover(conn: &Connection) -> Result<Discovered, String> {
    let mut tables = Vec::new();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| e.to_string())?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    for name in names {
        let name = name.map_err(|e| e.to_string())?;
        if is_ident(&name) {
            tables.push(name);
        }
    }
    drop(stmt);
    let mut schema = SchemaInfo {
        tables: tables.clone(),
        worktree_table: None,
        columns: Vec::new(),
    };
    let mut meta = Map::new();
    if tables.iter().any(|t| t == "meta") {
        meta = read_meta(conn).unwrap_or_default();
    }
    let infos: Vec<(String, Vec<String>)> = tables
        .iter()
        .map(|t| (t.clone(), table_columns(conn, t).unwrap_or_default()))
        .collect();
    let chosen = choose_table(&infos);
    let mut rows = Vec::new();
    if let Some(table) = chosen {
        schema.worktree_table = Some(table.clone());
        schema.columns = table_columns(conn, &table).unwrap_or_default();
        rows = read_rows(conn, &table)?;
    }
    Ok(Discovered { schema, meta, rows })
}

fn choose_table(infos: &[(String, Vec<String>)]) -> Option<String> {
    if let Some((name, _)) = infos
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("worktrees"))
    {
        return Some(name.clone());
    }
    infos
        .iter()
        .find(|(_, cols)| {
            cols.iter().any(|c| is_path_col(c)) && cols.iter().any(|c| is_origin_col(c))
        })
        .map(|(n, _)| n.clone())
}

fn is_path_col(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "path" | "worktree_path" | "folder" | "worktree"
    )
}

fn is_origin_col(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "source_repo" | "origin" | "origin_path" | "repo_path" | "source" | "upstream"
    )
}

fn is_ident(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, String> {
    if !is_ident(table) {
        return Err("unsafe table name".into());
    }
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| e.to_string())?;
    let mut cols = Vec::new();
    for row in rows {
        cols.push(row.map_err(|e| e.to_string())?);
    }
    Ok(cols)
}

fn read_rows(conn: &Connection, table: &str) -> Result<Vec<RawRow>, String> {
    if !is_ident(table) {
        return Err("unsafe table name".into());
    }
    let sql = format!("SELECT * FROM {table}");
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let col_count = stmt.column_count();
    let mut names = Vec::with_capacity(col_count);
    for i in 0..col_count {
        names.push(stmt.column_name(i).unwrap_or("").to_string());
    }
    let mut sql_rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    while let Some(row) = sql_rows.next().map_err(|e| e.to_string())? {
        let mut values = BTreeMap::new();
        for (i, name) in names.iter().enumerate() {
            let value = row.get_ref(i).map(value_ref_to_json).unwrap_or(Value::Null);
            let value = maybe_parse_json(name, value);
            let value = if key_is_sensitive(name) {
                Value::String(MASK.to_string())
            } else {
                crate::redact::redact_json(value)
            };
            values.insert(name.clone(), value);
        }
        out.push(RawRow { values });
    }
    Ok(out)
}

fn value_ref_to_json(v: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::Number(i.into()),
        ValueRef::Real(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        ValueRef::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(_) => Value::String(MASK.to_string()),
    }
}

fn maybe_parse_json(column: &str, value: Value) -> Value {
    let looks_named =
        column.eq_ignore_ascii_case("metadata") || column.eq_ignore_ascii_case("json");
    let Value::String(s) = &value else {
        return value;
    };
    let trimmed = s.trim_start();
    if looks_named || trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return parsed;
        }
    }
    value
}

fn read_meta(conn: &Connection) -> Result<Map<String, Value>, String> {
    let cols = table_columns(conn, "meta")?;
    let key_col = cols.iter().find(|c| c.eq_ignore_ascii_case("key"));
    let val_col = cols.iter().find(|c| c.eq_ignore_ascii_case("value"));
    let (Some(k), Some(v)) = (key_col, val_col) else {
        return Ok(Map::new());
    };
    if !is_ident(k) || !is_ident(v) {
        return Ok(Map::new());
    }
    let sql = format!("SELECT {k}, {v} FROM meta ORDER BY {k}");
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, rusqlite::types::Value>(1)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut map = Map::new();
    for row in rows {
        let (key, value) = row.map_err(|e| e.to_string())?;
        let json = sqlite_owned_to_json(value);
        if key_is_sensitive(&key) {
            map.insert(key, Value::String(MASK.to_string()));
        } else {
            map.insert(key, json);
        }
    }
    Ok(map)
}

fn sqlite_owned_to_json(v: rusqlite::types::Value) -> Value {
    use rusqlite::types::Value as Sv;
    match v {
        Sv::Null => Value::Null,
        Sv::Integer(i) => Value::Number(i.into()),
        Sv::Real(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Sv::Text(s) => Value::String(s),
        Sv::Blob(_) => Value::String(MASK.to_string()),
    }
}

fn project_row(
    row: &RawRow,
    home: &Path,
    worktrees_root: &Path,
    sessions: &[SessionHit],
    deny: &DenyList,
    diag: &Diag,
) -> Option<WorktreeRow> {
    let folder_raw = first_col(
        &row.values,
        &["path", "worktree_path", "folder", "worktree"],
    )?;
    let folder = resolve_recorded_path(home, &folder_raw);
    let origin_raw = first_col(
        &row.values,
        &[
            "source_repo",
            "origin",
            "origin_path",
            "repo_path",
            "source",
            "upstream",
        ],
    );
    let origin = origin_raw
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| resolve_recorded_path(home, s));
    let id = first_col(&row.values, &["id"]);
    let status = first_col(&row.values, &["status"]);
    let repo_name = first_col(&row.values, &["repo_name", "name"]);
    let db_session = first_col(&row.values, &["session_id", "session"]);
    let relative = folder
        .strip_prefix(worktrees_root)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"));

    let mut flags = Vec::new();
    let folder_exists = probe_exists(&folder, deny, diag, &mut flags, "worktree");
    if folder_exists == Some(false) {
        push_flag(&mut flags, "stale_path");
    }
    let origin_exists = if let Some(origin) = &origin {
        let exists = probe_exists(origin, deny, diag, &mut flags, "origin");
        if exists == Some(false) {
            push_flag(&mut flags, "stale_origin");
        }
        exists
    } else {
        push_flag(&mut flags, "stale_origin");
        Some(false)
    };
    if let Some(status) = &status {
        if !status.is_empty()
            && !status.eq_ignore_ascii_case("alive")
            && !status.eq_ignore_ascii_case("active")
        {
            push_flag(&mut flags, "status_not_alive");
        }
    }
    if relative.is_none() {
        push_flag(&mut flags, "outside_worktrees_root");
    }

    let mut session_ids = BTreeSet::new();
    if let Some(s) = db_session {
        if !s.is_empty() {
            session_ids.insert(redact_out(&s));
        }
    }
    for session in sessions {
        let cwd_hit = session
            .cwd
            .as_ref()
            .is_some_and(|c| path_within(c, &folder));
        let dec_hit = session
            .decoded_path
            .as_ref()
            .is_some_and(|c| path_within(c, &folder));
        if cwd_hit || dec_hit {
            session_ids.insert(redact_out(&session.id));
        }
    }

    let consumed = [
        "path",
        "worktree_path",
        "folder",
        "worktree",
        "source_repo",
        "origin",
        "origin_path",
        "repo_path",
        "source",
        "upstream",
        "id",
        "status",
        "repo_name",
        "name",
        "session_id",
        "session",
    ];
    let mut extra = Map::new();
    for (k, v) in &row.values {
        if consumed.iter().any(|c| k.eq_ignore_ascii_case(c)) {
            continue;
        }
        extra.insert(k.clone(), v.clone());
    }

    Some(WorktreeRow {
        id: id.map(|s| redact_out(&s)),
        folder: redact_out(&folder.display().to_string()),
        relative: relative.map(|s| redact_out(&s)),
        origin: origin.map(|p| redact_out(&p.display().to_string())),
        origin_exists,
        session_ids: session_ids.into_iter().collect(),
        status: status.map(|s| redact_out(&s)),
        repo_name: repo_name.map(|s| redact_out(&s)),
        flags,
        extra,
    })
}

fn redact_out(s: &str) -> String {
    crate::redact::redact_urls_in_text(s)
}

fn path_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn wal_sibling(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push("-wal");
    PathBuf::from(name)
}

fn first_col(values: &BTreeMap<String, Value>, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(v) = values.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
            return json_string(v.1);
        }
    }
    None
}

fn json_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn resolve_recorded_path(home: &Path, raw: &str) -> PathBuf {
    let expanded = crate::deny::expand_user(Path::new(raw.trim()));
    if expanded.is_absolute() {
        normalize_lexical(&expanded)
    } else {
        normalize_lexical(&home.join(expanded))
    }
}

fn probe_exists(
    path: &Path,
    deny: &DenyList,
    diag: &Diag,
    flags: &mut Vec<String>,
    side: &str,
) -> Option<bool> {
    if deny.is_denied(path) {
        push_flag(flags, &format!("{side}_denied"));
        diag.denied(path);
        return None;
    }
    match classify(path) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
        Err(e) => {
            diag.io_error(path, &e);
            None
        }
    }
}

fn push_flag(flags: &mut Vec<String>, flag: &str) {
    if !flags.iter().any(|f| f == flag) {
        flags.push(flag.to_string());
    }
}

fn find_duplicates(rows: &[WorktreeRow]) -> Vec<Duplicate> {
    let mut by_path: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (i, row) in rows.iter().enumerate() {
        let id = row.id.clone().unwrap_or_else(|| format!("row-{i}"));
        by_path.entry(row.folder.clone()).or_default().push(id);
    }
    let mut dups = Vec::new();
    for (key, ids) in by_path {
        if ids.len() > 1 {
            dups.push(Duplicate {
                kind: "path".into(),
                key,
                ids,
            });
        }
    }
    dups
}

fn scan_sessions(home: &Path, diag: &Diag) -> Vec<SessionHit> {
    let root = home.join("sessions");
    let Ok(top) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    let mut entries = Vec::new();
    for ent in top.flatten() {
        entries.push(ent.path());
    }
    entries.sort();
    for path in entries {
        let classified = match classify(&path) {
            Ok(c) => c,
            Err(e) => {
                diag.io_error(&path, &e);
                continue;
            }
        };
        if classified.kind != EntryKind::Dir {
            continue;
        }
        let direct = path.join("summary.json");
        if is_regular_file(&direct) {
            if let Some(hit) = read_summary(&direct, None, diag) {
                hits.push(hit);
            }
        }
        let Ok(inner) = fs::read_dir(&path) else {
            continue;
        };
        let mut children = Vec::new();
        for ent in inner.flatten() {
            children.push(ent.path());
        }
        children.sort();
        let name = path.file_name().unwrap_or_default();
        let text = name.to_string_lossy();
        let decoded = percent_decode(&text);
        let decoded_path = if decoded.starts_with('/') {
            Some(PathBuf::from(decoded))
        } else {
            None
        };
        for child in children {
            if !is_dir_nofollow(&child) {
                continue;
            }
            let summary = child.join("summary.json");
            if is_regular_file(&summary) {
                if let Some(hit) = read_summary(&summary, decoded_path.clone(), diag) {
                    hits.push(hit);
                }
            }
        }
    }
    hits
}

fn is_regular_file(path: &Path) -> bool {
    classify(path)
        .map(|c| c.kind == EntryKind::File)
        .unwrap_or(false)
}

fn is_dir_nofollow(path: &Path) -> bool {
    classify(path)
        .map(|c| c.kind == EntryKind::Dir)
        .unwrap_or(false)
}

fn read_summary(path: &Path, decoded_path: Option<PathBuf>, diag: &Diag) -> Option<SessionHit> {
    if !is_regular_file(path) {
        return None;
    }
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            diag.io_error(path, &e);
            return None;
        }
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            diag.error(path, format!("summary.json: {e}"));
            return None;
        }
    };
    let info = value.get("info");
    let id = info
        .and_then(|i| i.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| path.parent().and_then(|p| p.file_name()).map(lossy))?;
    let cwd = info
        .and_then(|i| i.get("cwd"))
        .and_then(|v| v.as_str())
        .map(|s| normalize_lexical(Path::new(s)));
    Some(SessionHit {
        id,
        cwd,
        decoded_path,
    })
}

fn orphan_sessions(
    sessions: &[SessionHit],
    rows: &[WorktreeRow],
    worktrees_root: &Path,
    deny: &DenyList,
) -> Vec<OrphanSession> {
    let known: Vec<PathBuf> = rows.iter().map(|r| PathBuf::from(&r.folder)).collect();
    let mut orphans = Vec::new();
    for session in sessions {
        let candidates = [session.cwd.clone(), session.decoded_path.clone()];
        let mut referenced = false;
        let mut orphan: Option<(&str, PathBuf)> = None;
        for cand in candidates.into_iter().flatten() {
            if !cand.starts_with(worktrees_root) || deny.is_denied(&cand) {
                continue;
            }
            if known.iter().any(|root| path_within(&cand, root)) {
                referenced = true;
                break;
            }
            let reason = if classify(&cand).is_ok() {
                "no_worktree_record"
            } else {
                "missing_on_disk"
            };
            orphan = Some((reason, cand));
        }
        if referenced {
            continue;
        }
        if let Some((reason, _)) = orphan {
            orphans.push(OrphanSession {
                session_id: redact_out(&session.id),
                cwd: session
                    .cwd
                    .as_ref()
                    .map(|p| redact_out(&p.display().to_string())),
                decoded_path: session
                    .decoded_path
                    .as_ref()
                    .map(|p| redact_out(&p.display().to_string())),
                reason: reason.into(),
            });
        }
    }
    orphans.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    orphans.dedup_by(|a, b| a.session_id == b.session_id && a.reason == b.reason);
    orphans
}

fn read_trusted(path: &Path, diag: &Diag) -> Option<Value> {
    match classify(path) {
        Ok(c) if c.kind == EntryKind::Symlink => {
            diag.error(path, "refusing to read symlink trusted_folders.toml");
            return None;
        }
        Ok(c) if c.kind == EntryKind::File => {}
        Ok(_) => return None,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            diag.io_error(path, &e);
            return None;
        }
    }
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            diag.io_error(path, &e);
            return None;
        }
    };
    match toml::from_str::<toml::Value>(&text) {
        Ok(v) => Some(toml_to_json_redacted(&v)),
        Err(e) => {
            diag.error(path, format!("trusted_folders.toml: {e}"));
            None
        }
    }
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            let hex = [b[i + 1], b[i + 2]];
            let digits = std::str::from_utf8(&hex).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(digits, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn problems(report: &GrokReport) -> bool {
    report.worktrees.iter().any(|w| !w.flags.is_empty())
        || !report.duplicates.is_empty()
        || !report.orphaned_sessions.is_empty()
}

pub fn render(report: &GrokReport, mode: Render, mut out: impl Write) -> io::Result<()> {
    match mode {
        Render::Human => {
            writeln!(out, "home: {}", report.home)?;
            writeln!(
                out,
                "worktree table: {} columns: {}",
                report.schema.worktree_table.as_deref().unwrap_or("-"),
                report.schema.columns.join(", ")
            )?;
            for wt in &report.worktrees {
                writeln!(out, "worktree: {}", wt.folder)?;
                writeln!(out, "  id: {}", wt.id.as_deref().unwrap_or("-"))?;
                writeln!(out, "  relative: {}", wt.relative.as_deref().unwrap_or("-"))?;
                writeln!(
                    out,
                    "  origin: {} (exists={})",
                    wt.origin.as_deref().unwrap_or("-"),
                    fmt_bool(wt.origin_exists)
                )?;
                writeln!(out, "  sessions: {}", wt.session_ids.join(", "))?;
                writeln!(
                    out,
                    "  flags: {}",
                    if wt.flags.is_empty() {
                        "-".into()
                    } else {
                        wt.flags.join(", ")
                    }
                )?;
            }
            if !report.duplicates.is_empty() {
                writeln!(out, "duplicates:")?;
                for d in &report.duplicates {
                    writeln!(out, "  {} {} -> {}", d.kind, d.key, d.ids.join(", "))?;
                }
            }
            if !report.orphaned_sessions.is_empty() {
                writeln!(out, "orphaned sessions:")?;
                for o in &report.orphaned_sessions {
                    writeln!(
                        out,
                        "  {} {} {}",
                        o.session_id,
                        o.reason,
                        o.decoded_path
                            .as_deref()
                            .or(o.cwd.as_deref())
                            .unwrap_or("-")
                    )?;
                }
            }
            if report.wal_present {
                writeln!(
                    out,
                    "warning: worktrees.db-wal is present; immutable=1 may miss uncheckpointed rows"
                )?;
            }
            writeln!(
                out,
                "counts worktrees={} duplicates={} orphans={}",
                report.worktrees.len(),
                report.duplicates.len(),
                report.orphaned_sessions.len()
            )?;
        }
        Render::Json => {
            serde_json::to_writer_pretty(&mut out, &json_doc(report))?;
            writeln!(out)?;
        }
        Render::Ndjson => {
            for wt in &report.worktrees {
                let mut v = serde_json::to_value(wt).unwrap_or(Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("type".into(), Value::String("worktree".into()));
                }
                serde_json::to_writer(&mut out, &v)?;
                writeln!(out)?;
            }
            for d in &report.duplicates {
                let mut v = serde_json::to_value(d).unwrap_or(Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("type".into(), Value::String("duplicate".into()));
                }
                serde_json::to_writer(&mut out, &v)?;
                writeln!(out)?;
            }
            for o in &report.orphaned_sessions {
                let mut v = serde_json::to_value(o).unwrap_or(Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("type".into(), Value::String("orphan".into()));
                }
                serde_json::to_writer(&mut out, &v)?;
                writeln!(out)?;
            }
            let summary = serde_json::json!({
                "type": "summary",
                "home": report.home,
                "schema": report.schema,
                "meta": report.meta,
                "trusted_folders": report.trusted_folders,
                "wal_present": report.wal_present,
                "partial": report.partial,
                "error_count": report.error_count,
                "counts": {
                    "worktrees": report.worktrees.len(),
                    "duplicates": report.duplicates.len(),
                    "orphans": report.orphaned_sessions.len(),
                }
            });
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

fn json_doc(report: &GrokReport) -> Value {
    serde_json::json!({
        "command": "grok",
        "home": report.home,
        "worktrees_root": report.worktrees_root,
        "db_path": report.db_path,
        "schema": report.schema,
        "meta": report.meta,
        "trusted_folders": report.trusted_folders,
        "worktrees": report.worktrees,
        "duplicates": report.duplicates,
        "orphaned_sessions": report.orphaned_sessions,
        "wal_present": report.wal_present,
        "partial": report.partial,
        "error_count": report.error_count,
    })
}

fn fmt_bool(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decodes_slashes() {
        assert_eq!(percent_decode("%2FUsers%2Fada%2F.grok"), "/Users/ada/.grok");
    }

    #[test]
    fn percent_decode_non_ascii_does_not_panic() {
        let fancy = format!("pre-%{}-post", "é");
        let decoded = percent_decode(&fancy);
        assert!(decoded.contains('é'), "{decoded}");
    }
}
