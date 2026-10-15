//! `check-config [--probe]`: validates everything `serve` would, without starting it.

use std::path::Path;

use super::{EXIT_USAGE, git_runner, print_problems};
use crate::config::{Config, Problem};
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
    if let Some(w) = admin_exposure_warning(&cfg) {
        print_problems(&[w]);
    }

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

/// The admin listener has no authentication, so a non-loopback bind deserves a reminder.
fn admin_exposure_warning(cfg: &Config) -> Option<Problem> {
    let addr = cfg.server.admin_listen;
    if addr.ip().is_loopback() {
        return None;
    }
    Some(Problem {
        file: cfg.source.clone(),
        line: None,
        key: "server.admin_listen".into(),
        message: format!(
            "admin endpoints (/readyz, /metrics) are unauthenticated and {addr} is not loopback; never publish this port"
        ),
        fix: "bind 127.0.0.1 or keep the port off every public interface and published Docker port"
            .into(),
        fatal: false,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(admin: &str) -> Config {
        let text = format!(
            "version = 1\n[server]\nadmin_listen = \"{admin}\"\n[auth]\n[[repo]]\nid = \"a\"\nhost = \"github\"\npath = \"example-org/a\"\nbranch = \"main\"\n"
        );
        Config::parse_unvalidated(&text, Path::new("config.toml")).expect("parses")
    }

    #[test]
    fn non_loopback_admin_listener_warns() {
        for addr in ["0.0.0.0:9090", "192.0.2.10:9090", "[::]:9090"] {
            let w = admin_exposure_warning(&cfg_with(addr)).expect(addr);
            assert!(!w.fatal);
            assert!(
                w.message.contains("never publish this port"),
                "{}",
                w.message
            );
        }
        for addr in ["127.0.0.1:9090", "[::1]:9090"] {
            assert!(admin_exposure_warning(&cfg_with(addr)).is_none(), "{addr}");
        }
    }
}
