//! `check-config [--probe]`: validates everything `serve` would, without starting it.

use std::path::Path;

use super::{EXIT_USAGE, git_runner, print_problems};
use crate::config::Config;
use crate::git;
use crate::keys::KeySet;
use crate::puller::ResolvedCreds;
use crate::snapshot::ErrorClass;

pub(super) async fn run(path: &Path, probe: bool) -> u8 {
    let mut problems = 0usize;
    let cfg = match Config::load(path) {
        Ok(loaded) => {
            print_problems(&loaded.warnings);
            loaded.config
        }
        Err(found) => {
            problems += print_problems(&found.0);
            let text = std::fs::read_to_string(path).unwrap_or_default();
            if let Ok(cfg) = Config::parse_unvalidated(&text, path) {
                problems += print_problems(&cfg.validate_binaries());
            }
            return finish(problems, None);
        }
    };

    problems += print_problems(&cfg.validate_binaries());

    let repo_ids: Vec<String> = cfg.repo.iter().map(|r| r.id.clone()).collect();
    let key_count = match KeySet::load(&cfg.auth.keys_file, &repo_ids) {
        Ok(set) => Some(set.len()),
        Err(found) => {
            for p in &found.0 {
                eprintln!("{p}");
            }
            problems += found.0.len();
            None
        }
    };

    if probe {
        problems += probe_repos(&cfg).await;
    }
    finish(
        problems,
        key_count.map(|k| (cfg.repo.len(), cfg.credentials.len(), k)),
    )
}

fn finish(problems: usize, ok: Option<(usize, usize, usize)>) -> u8 {
    match ok {
        Some((repos, creds, keys)) if problems == 0 => {
            println!("config ok: {repos} repos, {creds} credentials, {keys} keys");
            0
        }
        _ => {
            println!("config has {} problem(s)", problems.max(1));
            EXIT_USAGE
        }
    }
}

async fn probe_repos(cfg: &Config) -> usize {
    let creds = match ResolvedCreds::prepare(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot prepare credentials for the probe: {e}");
            return 1;
        }
    };
    let git = git_runner(cfg);
    let mut failures = 0;
    for repo in &cfg.repo {
        let url = repo.remote_url(cfg.credential_for(repo));
        let cred = creds.get(repo.credential.as_deref());
        match git.ls_remote(&url, &repo.branch, cred).await {
            Ok(oid) => println!("repo {}: ok {}", repo.id, oid.short()),
            Err(e) => {
                failures += 1;
                let class = ErrorClass::from(e.class()).as_str();
                println!(
                    "repo {}: {class}: {}",
                    repo.id,
                    git::scrub_stderr(&e.to_string())
                );
            }
        }
    }
    failures
}
