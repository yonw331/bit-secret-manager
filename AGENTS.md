# bit-secret-manager

> [!warning] Project suspended
> As of 2026-08-31 this repository is suspended. Do not implement, install,
> execute, validate, publish, deploy, or configure this project or its Agent
> Skill. The suspension is intentional because the project is obstructing the
> user's primary work. Preserve the source and historical evidence. Resuming
> requires explicit re-audit and updated approval in the Vault; this notice
> does not close GitHub Issue #3 or authorize remote changes.

This repository contains the suspended WSL/Linux manager. The Vault project
and system entry remain historical records only; they are not active work
instructions. The PRD, GitHub Issue #3, and this repository remain preserved as
historical sources, but no implementation or delivery work may start from them
while the project is suspended.

The following contract is historical reference only and must not be executed
while the repository is suspended. It previously kept the public surface
limited to `init`, `set-local`, `doctor`, and `run`.
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

If the project is explicitly resumed, re-audit before running the historical
validation commands below:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 -m compileall -q bit_secret_manager tests
bash -n install.sh bin/bit-secret-manager
```

The CI entry is `.github/workflows/ci.yml`. A change passes only when behavior
tests, Python compilation, installer syntax, and installation smoke coverage
all succeed without real BWS credentials. Tests observe the public CLI seam;
the fake `bws` process is the only external adapter.
