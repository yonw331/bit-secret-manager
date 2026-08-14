#!/usr/bin/env bash
set -euo pipefail

PREFIX="$HOME/.local"
if [[ "${1:-}" == "--prefix" && -n "${2:-}" && -z "${3:-}" ]]; then
  PREFIX="$2"
elif [[ $# -ne 0 ]]; then
  echo "usage: ./install.sh [--prefix PATH]" >&2
  exit 2
fi

python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' || {
  echo "error: Python 3.11 or newer is required" >&2
  exit 1
}

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$PREFIX/lib/bit-secret-manager"
BIN_DIR="$PREFIX/bin"

install -d -m 0755 "$LIB_DIR" "$BIN_DIR"
rm -rf "$LIB_DIR/bit_secret_manager"
install -d -m 0755 "$LIB_DIR/bit_secret_manager"
install -m 0644 "$SOURCE_DIR"/bit_secret_manager/*.py "$LIB_DIR/bit_secret_manager/"
install -m 0755 "$SOURCE_DIR/bin/bit-secret-manager" "$BIN_DIR/bit-secret-manager"

echo "installed: $BIN_DIR/bit-secret-manager"
echo "required separately: official bws CLI"
