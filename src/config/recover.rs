//! Second pass over a config that failed typed parsing: one problem per bad key or entry.

use std::path::Path;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use toml::{Table, Value};
use toml_edit::Document;

use super::{Credential, Problem, RepoConfig, Server, validate};

const FIX_TYPE: &str = "correct the value type or format at this line";
const FIX_UNKNOWN: &str = "remove the field or correct its spelling";

struct Found {
    key: String,
    message: String,
}

struct Collector<'a> {
    file: &'a Path,
    text: &'a str,
    doc: Option<Document<&'a str>>,
    out: Vec<Problem>,
}

impl Collector<'_> {
    fn push(&mut self, key: String, message: String) {
        let unknown = message.starts_with("unknown field");
        let line = self
            .doc
            .as_ref()
            .and_then(|d| validate::line_of(d, self.text, &key));
        self.out.push(Problem {
            file: self.file.to_path_buf(),
            line,
            key,
            message,
            fix: if unknown { FIX_UNKNOWN } else { FIX_TYPE }.to_string(),
            fatal: true,
        });
    }

    fn push_all(&mut self, found: Vec<Found>) {
        for f in found {
            self.push(f.key, f.message);
        }
    }
}

fn message(e: &toml::de::Error) -> String {
    e.message().to_string()
}

fn nest(path: &[&str], leaf: Table) -> Value {
    path.iter().rev().fold(Value::Table(leaf), |inner, key| {
        let mut t = Table::new();
        t.insert((*key).to_string(), inner);
        Value::Table(t)
    })
}

/// Finds the keys of a defaulted section that fail on their own, descending into sub-tables.
fn blame<T: DeserializeOwned>(
    prefix: &str,
    path: &mut Vec<String>,
    table: &Table,
    out: &mut Vec<Found>,
) {
    for (k, v) in table {
        let mut leaf = Table::new();
        leaf.insert(k.clone(), v.clone());
        let segs: Vec<&str> = path.iter().map(String::as_str).collect();
        let Err(e) = T::deserialize(nest(&segs, leaf)) else {
            continue;
        };
        let key = format!(
            "{prefix}.{}{k}",
            path.iter().map(|p| format!("{p}.")).collect::<String>()
        );
        let before = out.len();
        if let Value::Table(sub) = v {
            path.push(k.clone());
            blame::<T>(prefix, path, sub, out);
            path.pop();
        }
        if out.len() == before {
            out.push(Found {
                key,
                message: message(&e),
            });
        }
    }
}

fn section<T: DeserializeOwned>(c: &mut Collector, name: &str, value: &Value) {
    if T::deserialize(value.clone()).is_ok() {
        return;
    }
    let Value::Table(table) = value else {
        if let Err(e) = T::deserialize(value.clone()) {
            c.push(name.to_string(), message(&e));
        }
        return;
    };
    let mut found = Vec::new();
    blame::<T>(name, &mut Vec::new(), table, &mut found);
    if found.is_empty()
        && let Err(e) = T::deserialize(value.clone())
    {
        found.push(Found {
            key: name.to_string(),
            message: message(&e),
        });
    }
    c.push_all(found);
}

fn repo_entry(c: &mut Collector, index: usize, value: &Value) {
    if RepoConfig::deserialize(value.clone()).is_ok() {
        return;
    }
    let base = format!("repo[{index}]");
    let Value::Table(entry) = value else {
        c.push(base, "expected a table".into());
        return;
    };
    let mut culprits = Vec::new();
    for (k, v) in entry {
        let mut probe = Table::new();
        for (bk, bv) in [
            ("id", "x"),
            ("host", "github"),
            ("path", "x"),
            ("branch", "x"),
        ] {
            probe.insert(bk.into(), Value::String(bv.into()));
        }
        probe.insert(k.clone(), v.clone());
        if let Err(e) = RepoConfig::deserialize(Value::Table(probe)) {
            culprits.push(Found {
                key: format!("{base}.{k}"),
                message: message(&e),
            });
        }
    }
    if culprits.is_empty()
        && let Err(e) = RepoConfig::deserialize(value.clone())
    {
        culprits.push(Found {
            key: base,
            message: message(&e),
        });
    }
    c.push_all(culprits);
}

fn credential_entry(c: &mut Collector, name: &str, value: &Value) {
    if let Err(e) = Credential::deserialize(value.clone()) {
        c.push(format!("credentials.{name}"), message(&e));
    }
}

/// Re-checks `text` section by section after `first` (the typed parse error) stopped at one problem.
/// Returns every problem found, or just `first` when the text is not valid TOML or nothing else is found.
pub(super) fn collect(text: &str, file: &Path, first: Problem) -> Vec<Problem> {
    let Ok(root) = text.parse::<Table>() else {
        return vec![first];
    };
    let mut c = Collector {
        file,
        text,
        doc: Document::parse(text).ok(),
        out: Vec::new(),
    };
    for required in ["version", "server", "auth", "repo"] {
        if !root.contains_key(required) {
            c.push(required.to_string(), format!("missing field `{required}`"));
        }
    }
    for (name, value) in &root {
        match name.as_str() {
            "version" => {
                if let Err(e) = u32::deserialize(value.clone()) {
                    c.push("version".into(), message(&e));
                }
            }
            "server" => section::<Server>(&mut c, name, value),
            "auth" => section::<super::Auth>(&mut c, name, value),
            "limits" => section::<super::Limits>(&mut c, name, value),
            "pull" => section::<super::Pull>(&mut c, name, value),
            "scan" => section::<super::Scan>(&mut c, name, value),
            "deny" => section::<super::Deny>(&mut c, name, value),
            "features" => section::<super::Features>(&mut c, name, value),
            "logging" => section::<super::Logging>(&mut c, name, value),
            "metrics" => section::<super::Metrics>(&mut c, name, value),
            "credentials" => match value {
                Value::Table(entries) => {
                    for (cname, cvalue) in entries {
                        credential_entry(&mut c, cname, cvalue);
                    }
                }
                _ => c.push(
                    "credentials".into(),
                    "expected a table of credentials".into(),
                ),
            },
            "repo" => match value {
                Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        repo_entry(&mut c, i, item);
                    }
                }
                _ => c.push("repo".into(), "expected an array of [[repo]] tables".into()),
            },
            other => c.push(other.to_string(), format!("unknown field `{other}`")),
        }
    }
    if c.out.is_empty() { vec![first] } else { c.out }
}
