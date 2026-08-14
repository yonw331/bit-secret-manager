# Repository Context

`bit-secret-manager` is a Linux/WSL execution boundary for Bitwarden Secrets
Manager. `bit_secret_manager/cli.py` owns the three public commands: `init`,
`doctor`, and `run`. `install.sh` installs a launcher under `~/.local/bin` and
the package under `~/.local/lib/bit-secret-manager`.

The CLI stores non-secret profile mappings in a private TOML file and a Machine
Account Token in a separate private file. BWS remains authoritative for secret
values. `run` retrieves and identity-checks a complete profile before starting
the target process; it never writes retrieved values to disk.

Behavior is specified through the CLI seam in `tests/test_cli.py`. Tests may
observe argv, exit status, redacted output, and private filesystem results. A
fake `bws` executable is the only external adapter. Internal prompt and
serialization helpers are implementation details.

Architecture decisions live in `docs/adr/`. Repository execution constraints
and validation commands live in `AGENTS.md`.
