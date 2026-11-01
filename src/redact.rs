//! Mask configuration values whose keys look like credentials.
//! Matching is a case-insensitive substring search for `token`, `key`,
//! `secret`, or `password`, as required by the tool contract.

use serde_json::{Map, Value};

pub fn key_is_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("token") || k.contains("key") || k.contains("secret") || k.contains("password")
}

pub const MASK: &str = "***";

pub fn redact_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(redact_map(map)),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_json).collect()),
        Value::String(s) => Value::String(redact_urls_in_text(&s)),
        other => other,
    }
}

fn redact_map(map: Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in map {
        let key = redact_urls_in_text(&k);
        let value = if key_is_sensitive(&k) {
            Value::String(MASK.to_string())
        } else {
            redact_json(v)
        };
        insert_distinct(&mut out, key, value);
    }
    out
}

/// Two different keys can redact to the same text. Keep both rows.
fn insert_distinct(map: &mut Map<String, Value>, key: String, value: Value) {
    if !map.contains_key(&key) {
        map.insert(key, value);
        return;
    }
    let mut n = 2u64;
    loop {
        let candidate = format!("{key}#{n}");
        if !map.contains_key(&candidate) {
            map.insert(candidate, value);
            return;
        }
        n += 1;
    }
}

/// Mask every `http://`, `https://`, and `ssh://` userinfo, including a token
/// with no password (`https://ghp_xxx@github.com`).
pub fn redact_git_url(url: &str) -> String {
    redact_urls_in_text(url)
}

pub fn redact_urls_in_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if let Some(len) = scheme_at(input, i) {
            let scheme = &input[i..i + len];
            let after = &input[i + len..];
            if let Some(at) = userinfo_end(after) {
                out.push_str(scheme);
                out.push_str(MASK);
                i += len + at;
                continue;
            }
            out.push_str(scheme);
            i += len;
            continue;
        }
        let ch = input[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Length of `http://`, `https://`, or `ssh://` at `i`, ignoring scheme case.
fn scheme_at(s: &str, i: usize) -> Option<usize> {
    let rest = s.get(i..)?;
    for scheme in ["https://", "http://", "ssh://"] {
        if rest.len() >= scheme.len()
            && rest.is_char_boundary(scheme.len())
            && rest[..scheme.len()].eq_ignore_ascii_case(scheme)
        {
            return Some(scheme.len());
        }
    }
    None
}

/// Byte offset of `@` that ends userinfo, if the prefix has no separator.
fn userinfo_end(rest: &str) -> Option<usize> {
    let mut saw_user = false;
    for (off, ch) in rest.char_indices() {
        if ch == '@' {
            return if saw_user { Some(off) } else { None };
        }
        if ch == '/' || ch == '?' || ch == '#' || ch.is_whitespace() {
            return None;
        }
        saw_user = true;
    }
    None
}

pub fn toml_to_json_redacted(value: &toml::Value) -> Value {
    match value {
        toml::Value::String(s) => Value::String(redact_urls_in_text(s)),
        toml::Value::Integer(i) => Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(f.to_string())),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a) => Value::Array(a.iter().map(toml_to_json_redacted).collect()),
        toml::Value::Table(t) => {
            let mut map = Map::new();
            for (k, v) in t {
                let key = redact_urls_in_text(k);
                let value = if key_is_sensitive(k) {
                    Value::String(MASK.to_string())
                } else {
                    toml_to_json_redacted(v)
                };
                insert_distinct(&mut map, key, value);
            }
            Value::Object(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_nested_secrets_and_urls() {
        let v: Value = serde_json::json!({
            "path": "/tmp/proj",
            "api_token": "super-secret",
            "nested": {"password": "hunter2", "name": "ok"}
        });
        let red = redact_json(v);
        let s = red.to_string();
        assert!(!s.contains("super-secret"));
        assert!(!s.contains("hunter2"));
        assert!(s.contains("/tmp/proj"));
        assert!(s.contains("ok"));
        assert_eq!(
            redact_git_url("https://user:ghp_abc@github.com/org/repo.git"),
            "https://***@github.com/org/repo.git"
        );
        assert_eq!(
            redact_git_url("https://ghp_xxx@github.com/org/repo"),
            "https://***@github.com/org/repo"
        );
        assert_eq!(
            redact_git_url("ssh://git@github.com/org/repo.git"),
            "ssh://***@github.com/org/repo.git"
        );
        assert!(
            redact_urls_in_text("see https://ghp_xxx@github.com/org/repo now")
                .contains("https://***@github.com/org/repo")
        );
        assert!(!redact_urls_in_text("https://github.com/org/repo").contains("***"));
        let keyed = redact_json(serde_json::json!({
            "https://ghp_xxx@github.com/org": "keep-me"
        }));
        let keyed_s = keyed.to_string();
        assert!(!keyed_s.contains("ghp_xxx"), "{keyed_s}");
        assert!(keyed_s.contains("https://***@github.com/org"), "{keyed_s}");
        assert!(keyed_s.contains("keep-me"), "{keyed_s}");
        assert_eq!(
            redact_git_url("HTTPS://Token@github.com/org/repo"),
            "HTTPS://***@github.com/org/repo"
        );
        assert_eq!(
            redact_urls_in_text("see HtTpS://ghp_xxx@github.com/org now"),
            "see HtTpS://***@github.com/org now"
        );
        let collided = redact_json(serde_json::json!({
            "https://aaa@github.com/x": "one",
            "https://bbb@github.com/x": "two"
        }));
        let obj = collided.as_object().unwrap();
        assert_eq!(obj.len(), 2, "{collided}");
        let values: Vec<&str> = obj.values().filter_map(|v| v.as_str()).collect();
        assert!(
            values.contains(&"one") && values.contains(&"two"),
            "{collided}"
        );
        assert!(!collided.to_string().contains("aaa"), "{collided}");
        assert!(!collided.to_string().contains("bbb"), "{collided}");
    }
}
