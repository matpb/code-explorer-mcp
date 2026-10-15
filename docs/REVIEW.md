# Review log

Findings from reviews of this codebase and what was done about them. Newest first.

## Lead review of milestone 3 (compose profiles)

| Finding | Severity | Outcome |
|---|---|---|
| The README told operators to make `keys.toml` writable by the server's uid so `keygen` could run inside the container. A compromised server could then mint itself a key that survives restarts. | High | Fixed. `keys.toml` is mounted `:ro`, the server never writes it (verified: `append_entry` is called only from the `keygen` command), `keygen --print-only` now prints the entry on stdout and the key on stderr so `>> keys.toml` on the host is the documented flow. README, compose and DECISIONS updated. |
