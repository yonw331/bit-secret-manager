# bit-secret-manager

This repository contains the long-lived WSL/Linux manager. The active Vault
iteration is `01-Projects/260827-bit-secret-manager双源凭证升级/Project.md` in
the `ob-garden` repository; its PRD is the requirement source, GitHub Issue #3
is the task source, and this repository is the code source. The stable system
entry is `03-Areas/技术成长/系统-bit-secret-manager.md`.

Keep the public surface limited to `init`, `set-local`, `doctor`, and `run`.
BWS remains the authority for BWS entries; local entries are device-private
values used only at execution time. Preserve whole-profile success before
launch, minimal BWS environment, child environment cleanup, strict TOML
validation, value-free output, and fail-closed `0700`/`0600` ownership checks
for private state. Never add caches, `.env` generation, shell evaluation,
Token arguments, value-reading interfaces, or consumer-specific validation.

Schema 1 private configurations remain readable only through explicit
`--config`. Schema 2 navigation configuration contains no values and is read
from the Vault; `init --config PATH` records its private device pointer and
initializes a Token only when the configuration contains BWS entries.
`set-local KEY` writes one hidden-input local value atomically. Do not add a
value export, deletion, or migration command.

After behavior changes run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 -m compileall -q bit_secret_manager tests
bash -n install.sh bin/bit-secret-manager
```

The CI entry is `.github/workflows/ci.yml`. A change passes only when behavior
tests, Python compilation, installer syntax, and installation smoke coverage
all succeed without real BWS credentials. Tests observe the public CLI seam;
the fake `bws` process is the only external adapter.
