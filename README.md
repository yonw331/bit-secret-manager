# bit-secret-hub security prototype

> PROTOTYPE: this repository answers a security and state-model question. It is
> not production-ready and is expected to be replaced after the model is proven.

The question is whether a personal secret manager can retrieve explicitly
registered Bitwarden Secrets Manager values by ID, cache them per profile for
seven days, and inject only the selected profile into a child process without
placing values in command arguments, output, audit logs, or `gh` auth files.

## Proven surface

- Strict YAML configuration and explicit Secret ID mappings.
- `refresh PROFILE` with per-file atomic replacement and `0600` cache files.
- Base64 JSON cache with SHA-256 integrity metadata. Base64 is not encryption.
- `status PROFILE --json` with no secret values.
- `exec PROFILE [--offline] -- executable arg...` with managed-variable cleanup.
- Optional GitHub validation through `gh api user`.
- `setup-git --hostname github.com` using `gh auth setup-git --force`.
- Value-free JSONL audit records.

## Run

Requirements: Linux or WSL2, Python 3.11+, PyYAML, `bws`, `gh`, and `git`.

```bash
python3 -m unittest discover -s tests -v
./install.sh
bit-secret-hub --config ~/configs/config.yaml status github --json
```

Use `config.example.yaml` only as a shape reference. `bw.env` must be a regular
`0600` file containing exactly one line:

```dotenv
BWS_ACCESS_TOKEN=replace-interactively-or-via-stdin
```

Never commit `bw.env`, caches, audit output, device state, or real Secret IDs.
The prototype intentionally does not implement `init`, `register`, `render`,
`doctor`, `purge`, `decommission`, locking, release upgrade, Windows support, or
Kubernetes delivery.

Open `prototype-cache-state.html` directly to exercise the state model without
credentials or installation.

