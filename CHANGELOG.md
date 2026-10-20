# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project follows semantic versioning.

## Unreleased

### Fixed
- The puller removes stale git lock files (`config.lock`, `shallow.lock`, `packed-refs.lock`, `FETCH_HEAD.lock`, `HEAD.lock` and `*.lock` under `refs/`) before each pull. A git process killed by the subprocess timeout could leave one behind and block every later pull of that repo with `could not lock config file`.

### Added
- Six read-only MCP tools over local shallow clones: `list_repos`, `list_tree`, `glob`, `read_file`, `grep`, `log`. Optional `blame` and `read_file.commit` behind feature flags.
- Streamable HTTP transport, MCP 2026-07-28 stateless, with legacy clients served without sessions.
- TOML configuration with full startup validation and `check-config`.
- Per-user hashed keys with `keygen`, hot reload on change and `SIGHUP`, optional repo allow-lists.
- Failed-auth throttling per client IP with trusted proxy CIDRs.
- Shallow single-branch clones refreshed on a timer, atomic snapshot swap, stale notices.
- gitleaks scanning on onboarding and every pull with `redact`, `warn` and `block` policies, plus a path deny-list.
- JSON request logs per key, `/healthz`, `/readyz`, Prometheus metrics.
- Docker image and compose files with a Caddy profile and a gateway mode.
- Redaction at rest: under the `redact` policy, found secret values are replaced inside the snapshot files before anything is served.
- Bitbucket SSH remotes use `ssh.bitbucket.org`, the host Bitbucket Cloud serves Git over SSH from as of November 12, 2026; the shipped `known_hosts` covers it.
