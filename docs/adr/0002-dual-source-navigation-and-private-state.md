# ADR 0002: dual-source navigation and private state

- Status: Accepted
- Date: 2026-08-28
- Issue: https://github.com/arykai031/bit-secret-manager/issues/3

## Context

Schema 1 stored non-secret BWS mappings beside the private Machine Account
Token. Test-only credentials needed an execution-time source that can remain
on one device without putting values in the Vault or Git.

## Decision

Schema 1 stays read-only compatible when selected explicitly with `--config`.
Schema 2 is a regular, non-symlinked navigation file with a top-level
`[[entries]]` table. Each entry declares its profile, target environment and
source. BWS entries carry an ID and expected key; local entries carry a logical
key only.

`init --config PATH` validates schema 2 and atomically writes a private
`device.toml` pointer. It obtains a hidden BWS Token only when at least one BWS
entry exists. Local values are written one at a time through `set-local KEY` to
private `local-secrets.toml`. Both private files require a current-user-owned
`0700` directory and `0600` regular files without symbolic links.

## Consequences

Local-only profiles run without `bws` or a Token. Mixed profiles resolve all
entries before the target starts. The target process receives only resolved
profile variables and cannot inherit BWS material, manager private-path
variables or stale managed values. `doctor [PROFILE]` scopes provider checks to
the requested profile while retaining full-device validation with no argument.
