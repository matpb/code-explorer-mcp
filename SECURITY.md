# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" button on the Security tab of this repository. Do not open a public issue for a vulnerability. You will get an acknowledgement, and a fix or a mitigation plan, before any public disclosure.

## Scope

Code Explorer is a read-only server. Reports we care most about:

- Any way for a client to write to a repository or a host, or to make the server call out anywhere but the configured Git remotes.
- Path traversal, symlink escape, or any read outside the current snapshot of a configured repo.
- Deny-list or redaction bypass (serving a path or a value the configuration says to hide).
- Authentication bypass, key recovery from `keys.toml`, or throttle bypass.
- Credential leakage into logs, errors, process arguments or the data directory.
- Resource exhaustion that the worker cap, timeouts and output caps should have prevented.

## Design notes for reviewers

The threat model is in the README under "Security model". In short: clients are authenticated but only semi-trusted, repository content is untrusted data, the hosts are trusted for transport only, and the operator and the config files are trusted.

## Supported versions

Only the latest release receives fixes.
