# bit-secret-manager

`bit-secret-manager` is a small WSL/Linux execution boundary for BWS and
device-local credentials. It resolves a complete profile immediately before
launching an argv process. Values are never written to `.env`, command-line
arguments, stdout, stderr, logs, or the navigation configuration.

Schema 1 private BWS configurations remain supported through explicit
`--config`. Schema 2 separates a Vault-safe navigation file from device-private
state and supports BWS-only, local-only, and mixed profiles.

## Requirements

- Linux or WSL
- Python 3.11 or newer
- The official `bws` executable on `PATH` only for profiles that use BWS
- A separate read-only BWS Machine Account for each machine that uses BWS

## Install

```bash
./install.sh
bit-secret-manager --version
bsm --version
```

The installer writes `~/.local/bin/bit-secret-manager`, plus a `bsm` symbolic
link to the same command, and its Python package under
`~/.local/lib/bit-secret-manager`. It does not install `bws`, alter shell
startup, or create credentials. Installation refuses to replace an existing
non-symlink `~/.local/bin/bsm` command.

## Schema 2 Navigation

Keep a non-sensitive navigation file in the Vault. It must be a regular file,
not a symbolic link; it contains profile names, environment names, BWS IDs and
logical local keys, never values.

```toml
schema_version = 2

[[entries]]
profile = "github"
source = "bws"
id = "<BWS Secret UUID>"
expected_key = "GITHUB_PAT"
env = "GH_TOKEN"

[[entries]]
profile = "test-service"
source = "local"
key = "test-service-password"
env = "TEST_SERVICE_PASSWORD"
```

Every entry must have `profile`, `source`, and `env`. BWS entries require only
`id` and `expected_key`; local entries require only `key`. Unknown, missing,
conflicting, unsafe, or duplicate per-profile environment mappings are rejected
before a target process can start.

Initialize the device pointer from that file:

```bash
bit-secret-manager --config /absolute/path/to/config.toml init
```

This writes `~/.config/bit-secret-manager/device.toml` with mode `0600` and
records an absolute navigation path. For a configuration with BWS entries it
also prompts for the BWS Machine Account Token using hidden input and writes
`access-token` with mode `0600`. A local-only configuration does not need
`bws` or a Token.

Set or rotate a local value on the device using hidden input:

```bash
bit-secret-manager set-local test-service-password
```

The value is atomically stored in
`~/.config/bit-secret-manager/local-secrets.toml`. The private directory is
`0700`; `device.toml`, `access-token`, and `local-secrets.toml` are
current-user-owned `0600` regular files and may not be symbolic links. There
is deliberately no command to print, export, or delete a local value.

## Run And Verify

After initialization, commands read the private device pointer:

```bash
bsm doctor
bsm doctor github
bsm run github -- gh api user
bsm run test-service -- ./test-client
```

`doctor PROFILE` checks only that profile; `doctor` checks all profiles. BWS
output and values are never reported. A profile is fully resolved before the
target starts, so a missing local key or failed BWS lookup cannot leak partial
credentials to a process. The child receives only resolved variables; BWS
Token material, manager-private path variables, and stale managed variables
are cleared.

Use `--config PATH` to select a schema 2 navigation file directly or a legacy
schema 1 private configuration. Schema 1 is not rewritten or migrated.

## Verify Changes

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 -m compileall -q bit_secret_manager tests
bash -n install.sh bin/bit-secret-manager
```

Tests use a fake `bws` and fake values. They do not require or accept real
credentials.
