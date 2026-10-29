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
    map.into_iter()
        .map(|(k, v)| {
            let key = redact_urls_in_text(&k);
            if key_is_sensitive(&k) {
                (key, Value::String(MASK.to_string()))
            } else {
                (key, redact_json(v))
            }
        })
        .collect()
}

/// Mask every `http://`, `https://`, and `ssh://` userinfo, including a token
/// with no password (`https://ghp_xxx@github.com`).
pub fn redact_git_url(url: &str) -> String {
    redact_urls_in_text(url)
}

pub fn redact_urls_in_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        let found = ["https://", "http://", "ssh://"]
            .iter()
            .filter_map(|scheme| rest.find(scheme).map(|at| (at, *scheme)))
            .min_by_key(|(at, _)| *at);
        let Some((at, scheme)) = found else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..at]);
        let after = &rest[at + scheme.len()..];
        if let Some(userinfo_end) = userinfo_end(after) {
            out.push_str(scheme);
            out.push_str(MASK);
            rest = &after[userinfo_end..];
        } else {
            out.push_str(scheme);
            rest = after;
        }
    }
    out
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
                if key_is_sensitive(k) {
                    map.insert(key, Value::String(MASK.to_string()));
                } else {
                    map.insert(key, toml_to_json_redacted(v));
                }
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
    }
}
