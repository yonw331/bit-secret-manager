# bit-secret-hub Prototype

Read the Vault project entry before changing this prototype:
`/mnt/e/WY/400_Code/Remote/ob-garden/01-Projects/bit-secret-hub/Project.md`.

This repository is a throwaway security prototype. It answers whether BWS
secret retrieval, profile caching, TTL enforcement, isolated process injection,
and the GitHub credential helper can work without leaking secret values through
arguments, output, audit logs, or GitHub CLI authentication files.

Run `python3 -m unittest discover -s tests -v` after every behavior change.
Passing means all tests succeed without real credentials. Use only fake secrets
by default; optional E2E work may use a dedicated low-privilege test account.

Keep the public test seams at the CLI and persisted-state boundaries. Preserve
strict schema validation, fail-closed permission checks, atomic file writes,
profile-wide consistency, stable exit classifications, and value-free logs.
Never print secret values or accept a BWS token as a command argument.

The source of truth for requirements and decisions is the Vault design note.
Code and tests are authoritative only for the behavior this prototype proves.

