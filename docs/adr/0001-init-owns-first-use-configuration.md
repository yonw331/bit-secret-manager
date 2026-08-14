# ADR 0001: init owns first-use configuration

- Status: Accepted
- Date: 2026-08-14
- Issue: https://github.com/arykai031/bit-secret-manager/issues/1

## Context

Version 0.1 required a valid configuration before `init`, but the user-facing
guidance treated `init` as the first setup step. A new machine therefore failed
before it could reach hidden Token input and required an undocumented manual
configuration step.

## Decision

Keep the public surface at `init`, `doctor`, and `run`. Interactive `init`
branches on local state:

- Without a configuration, collect and validate all non-secret profile
  mappings, then read the Token using hidden input and create private files.
- With a valid configuration, preserve its bytes and initialize or rotate only
  the Token.
- `init --token-stdin` remains non-interactive and requires an existing valid
  configuration.

The first-use write is transactional at the CLI boundary: cancellation before
commit writes nothing, and a Token write failure removes the configuration
created by that invocation.

## Consequences

First use has one documented entry point and no provider-specific defaults.
Automation must provision configuration separately before using
`--token-stdin`. Tests continue to target public CLI behavior and filesystem
results rather than prompt helper implementation.
