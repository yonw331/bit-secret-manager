# bit-secret-manager

`bit-secret-manager` is a small WSL/Linux command-line tool that retrieves a
configured Bitwarden Secrets Manager profile immediately before launching a
process. BWS remains the only authority for business secret values. The manager
does not cache values, create `.env` files, or contain provider-specific logic
for GitHub or other consumers.

## Requirements

- Linux or WSL
- Python 3.11 or newer
- The official `bws` executable on `PATH`
- A separate read-only BWS Machine Account for each machine

The accepted first-release risk is that machines may still read the same
high-privilege, non-expiring GitHub PAT. This tool does not reduce that PAT's
scope or remove its single-compromise blast radius.

## Install

```bash
./install.sh
bit-secret-manager --version
```

The installer only copies the manager into `~/.local`. It does not install
Python, `bws`, edit shell startup files, or create credentials.

## Configure

Create `~/.config/bit-secret-manager/config.toml` with directory mode `0700`
and file mode `0600`:

```toml
schema_version = 1

[[profiles.github]]
id = "<BWS Secret UUID>"
expected_key = "GITHUB_PAT"
env = "GH_TOKEN"
```

Only Secret IDs, expected BWS keys, and target environment names belong in the
configuration. Initialize this machine without putting its Token in argv:

```bash
bit-secret-manager init
bit-secret-manager doctor
```

For a trusted pipe, `init --token-stdin` reads exactly one line. The Token is
stored as raw text in `access-token`; it is not a shell-sourceable file.

Run consumers with an argv, not a shell string:

```bash
bit-secret-manager run github -- gh api user
bit-secret-manager run github -- git push
```

Every mapping in the profile must be retrieved and identity-checked before the
target starts. The target receives only the selected profile. It never receives
`BWS_ACCESS_TOKEN`, and all managed variables are cleared before injection.

Use `--config PATH` before the subcommand to select another private TOML file.

## Verify

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 -m compileall -q bit_secret_manager tests
bash -n install.sh bin/bit-secret-manager
```

Tests use a fake `bws` and fake values; real credentials are neither needed nor
accepted in fixtures.
