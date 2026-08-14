# bit-secret-manager

This repository contains the long-lived WSL/Linux manager. The Vault project
entry at `/mnt/e/WY/400_Code/Remote/ob-garden/01-Projects/bit-secret-hub/Project.md`
is the planning and acceptance source; this repository is the code source.

Keep the public surface limited to `init`, `doctor`, and `run`. BWS is the only
authority for secret values. Preserve execution-time retrieval, whole-profile
success before launch, minimal BWS environment, child environment cleanup,
strict TOML validation, value-free output, and fail-closed `0700`/`0600`
ownership checks. Never add caches, `.env` generation, shell evaluation, Token
arguments, or consumer-specific validation.

After behavior changes run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 -m compileall -q bit_secret_manager tests
bash -n install.sh bin/bit-secret-manager
```
