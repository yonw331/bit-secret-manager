# bit-secret-manager

This repository contains the long-lived WSL/Linux manager. The active Vault
iteration is `01-Projects/bit-secret-manager-init-wizard/Project.md` in the
`ob-garden` repository; its PRD is the requirement source, GitHub Issue #1 is
the task source, and this repository is the code source. The stable system
entry is `03-Areas/技术成长/运维工程/系统-bit-secret-manager.md`.

Keep the public surface limited to `init`, `doctor`, and `run`. BWS is the only
authority for secret values. Preserve execution-time retrieval, whole-profile
success before launch, minimal BWS environment, child environment cleanup,
strict TOML validation, value-free output, and fail-closed `0700`/`0600`
ownership checks. Never add caches, `.env` generation, shell evaluation, Token
arguments, or consumer-specific validation.

`init` owns first-use configuration. With no configuration, interactive `init`
collects all non-secret mappings before hidden Token input and commits private
files only after validation. With an existing configuration, it only rotates
the Token. `init --token-stdin` requires an existing configuration.

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
