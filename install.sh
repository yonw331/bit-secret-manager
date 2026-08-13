#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE installer: installs a tested copy into the current user's home.
project_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
install_root="${BIT_SECRET_HUB_INSTALL_ROOT:-$HOME/.local/lib/bit-secret-hub-prototype}"
bin_root="${BIT_SECRET_HUB_BIN_ROOT:-$HOME/.local/bin}"

for dependency in python3 bws gh git; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "missing dependency: $dependency" >&2
    exit 1
  fi
done

python3 -c 'import sys, yaml; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'

mkdir -p "$install_root" "$bin_root"
chmod 700 "$install_root"
cp -R "$project_root/bit_secret_hub" "$install_root/"

launcher="$bin_root/bit-secret-hub"
temporary="${launcher}.tmp.$$"
printf '%s\n' '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  "export PYTHONPATH=\"$install_root\"" \
  'exec python3 -m bit_secret_hub "$@"' >"$temporary"
chmod 700 "$temporary"
mv -f "$temporary" "$launcher"

echo "installed prototype launcher: $launcher"

