//! `keygen`: creates a bearer key and stores only its argon2id hash.

use std::path::Path;

use chrono::{NaiveDate, Utc};

use super::{EXIT_FAILURE, EXIT_USAGE, load_lenient};
use crate::keys::{self, KeySet};

pub(super) fn run(
    config_path: &Path,
    name: &str,
    repos: Option<Vec<String>>,
    expires: Option<NaiveDate>,
    print_only: bool,
) -> u8 {
    let cfg = match load_lenient(config_path) {
        Ok(c) => c,
        Err(code) => return code,
    };
    if name.trim().is_empty() {
        eprintln!("--name must not be empty");
        return EXIT_USAGE;
    }
    if let Some(list) = &repos {
        let unknown: Vec<&str> = list
            .iter()
            .map(String::as_str)
            .filter(|id| cfg.repo(id).is_none())
            .collect();
        if list.is_empty() || !unknown.is_empty() {
            eprintln!(
                "--repos names unknown repo ids: {}; configured ids are: {}",
                unknown.join(", "),
                cfg.repo
                    .iter()
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return EXIT_USAGE;
        }
    }
    if let Some(date) = expires
        && date < Utc::now().date_naive()
    {
        eprintln!("--expires {date} is in the past");
        return EXIT_USAGE;
    }

    let keys_file = &cfg.auth.keys_file;
    let ids: Vec<String> = cfg.repo.iter().map(|r| r.id.clone()).collect();
    if let Ok(existing) = KeySet::load(keys_file, &ids)
        && existing.keys.iter().any(|k| k.name == name)
    {
        eprintln!(
            "{}: a key named {name:?} already exists; pick another name",
            keys_file.display()
        );
        return EXIT_USAGE;
    }

    let (plaintext, entry) = keys::keygen(name, repos, expires);
    if print_only {
        println!("{}", entry.to_toml_table());
    } else if let Err(e) = keys::append_entry(keys_file, &entry) {
        eprintln!("cannot append to {}: {e}", keys_file.display());
        return EXIT_FAILURE;
    }
    if print_only {
        eprintln!("key: {plaintext}");
        eprintln!(
            "This key will not be shown again. Append the [[key]] block from stdout to the keys file."
        );
    } else {
        println!("key: {plaintext}");
        eprintln!(
            "Added key {} ({name}) to {}. This key will not be shown again.",
            entry.id,
            keys_file.display()
        );
    }
    0
}
