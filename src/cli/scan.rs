//! `scan --repo <id>`: onboarding scan of a fresh clone through the serving scan path, printing masked findings.

use std::path::Path;

use super::{EXIT_FAILURE, EXIT_FINDINGS, EXIT_USAGE, git_runner, load_validated, print_problems};
use crate::git;
use crate::puller::{ResolvedCreds, prepare_scan_inputs};
use crate::scan::{self, GitleaksScanner};

pub(super) async fn run(config_path: &Path, repo_id: &str) -> u8 {
    let cfg = match load_validated(config_path) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Some(repo) = cfg.repo(repo_id) else {
        eprintln!(
            "unknown repo {repo_id:?}; configured ids are: {}",
            cfg.repo
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return EXIT_USAGE;
    };
    if print_problems(&cfg.validate_binaries()) > 0 {
        return EXIT_USAGE;
    }
    match scan_repo(&cfg, repo).await {
        Ok(code) => code,
        Err(message) => {
            eprintln!("scan of {repo_id} failed: {}", git::scrub_stderr(&message));
            EXIT_FAILURE
        }
    }
}

async fn scan_repo(
    cfg: &crate::config::Config,
    repo: &crate::config::RepoConfig,
) -> Result<u8, String> {
    let creds =
        ResolvedCreds::prepare(cfg).map_err(|e| format!("cannot prepare credentials: {e}"))?;
    let git = git_runner(cfg);
    let url = repo.remote_url(cfg.credential_for(repo));
    let cred = creds.get(repo.credential.as_deref());
    let depth = cfg.pull.depth;

    let tmp = tempfile::Builder::new()
        .prefix("cex-scan-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let bare = tmp.path().join("git");
    git.clone_bare(&url, &repo.branch, depth, &bare, cred)
        .await
        .map_err(|e| e.to_string())?;
    let tip = git
        .rev_parse(&bare, &format!("refs/heads/{}", repo.branch))
        .await
        .map_err(|e| e.to_string())?;
    let inputs = prepare_scan_inputs(&git, &bare, &tip, depth, &tmp.path().join("worktree"))
        .await
        .map_err(|e| e.to_string())?;

    let scanner = GitleaksScanner::new(cfg.scanner_bin(), cfg.scan.timeout);
    let history = cfg
        .features
        .file_at_commit
        .then_some((bare.as_path(), &tip));
    let findings = scan::scan_snapshot(
        &scanner,
        &inputs.worktree,
        &inputs.messages.file,
        history,
        &cfg.scan.allowlist,
    )
    .await
    .map_err(|e| e.to_string())?;

    if findings.is_empty() {
        println!("repo {}: no findings at {}", repo.id, tip.short());
        return Ok(0);
    }
    println!("{}", scan::onboarding_report(&findings));
    println!(
        "repo {}: {} finding(s) at {}; add fingerprints judged false positives to [scan] allowlist",
        repo.id,
        findings.len(),
        tip.short()
    );
    Ok(EXIT_FINDINGS)
}
