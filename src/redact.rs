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
        other => other,
    }
}

fn redact_map(map: Map<String, Value>) -> Map<String, Value> {
    map.into_iter()
        .map(|(k, v)| {
            if key_is_sensitive(&k) {
                (k, Value::String(MASK.to_string()))
            } else {
                (k, redact_json(v))
            }
        })
        .collect()
}

pub fn redact_git_url(url: &str) -> String {
    let Some(scheme) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme + 3..];
    let Some(at) = rest.find('@') else {
        return url.to_string();
    };
    let userinfo = &rest[..at];
    let host = &rest[at..];
    if let Some((user, _)) = userinfo.split_once(':') {
        format!("{}://{user}:{}{host}", &url[..scheme], MASK)
    } else {
        url.to_string()
    }
}

pub fn toml_to_json_redacted(value: &toml::Value) -> Value {
    match value {
        toml::Value::String(s) => Value::String(s.clone()),
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
                if key_is_sensitive(k) {
                    map.insert(k.clone(), Value::String(MASK.to_string()));
                } else {
                    map.insert(k.clone(), toml_to_json_redacted(v));
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
            "https://user:***@github.com/org/repo.git"
        );
    }
}
