from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any
from uuid import UUID


EXIT_CONFIG = 2
EXIT_REMOTE = 4
EXIT_PERMISSION = 6
EXIT_LAUNCH = 126

DEFAULT_DIR = Path("~/.config/bit-secret-manager")
PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ENV_NAME_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]*$")
RESERVED_ENV_NAMES = {
    "BWS_ACCESS_TOKEN",
    "HOME",
    "LD_LIBRARY_PATH",
    "PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "SHELL",
}


class ManagerError(Exception):
    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def reject_unknown(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ManagerError(f"unknown {label} field(s): {', '.join(unknown)}", EXIT_CONFIG)


def private_stat(path: Path, kind: str, mode: int) -> os.stat_result:
    if path.is_symlink():
        raise ManagerError(f"{kind} may not be a symbolic link", EXIT_PERMISSION)
    try:
        info = path.stat()
    except OSError as exc:
        raise ManagerError(f"cannot access {kind}", EXIT_PERMISSION) from exc
    if kind == "configuration directory" and not stat.S_ISDIR(info.st_mode):
        raise ManagerError(f"{kind} must be a directory", EXIT_PERMISSION)
    if kind != "configuration directory" and not stat.S_ISREG(info.st_mode):
        raise ManagerError(f"{kind} must be a regular file", EXIT_PERMISSION)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
        raise ManagerError(f"{kind} must be owned by the current user with mode {mode:04o}", EXIT_PERMISSION)
    return info


def ensure_private_directory(path: Path, create: bool = False) -> None:
    if path.is_symlink():
        raise ManagerError("configuration directory may not be a symbolic link", EXIT_PERMISSION)
    if not path.exists() and create:
        try:
            path.mkdir(parents=True, mode=0o700)
        except OSError as exc:
            raise ManagerError("cannot create configuration directory", EXIT_PERMISSION) from exc
    private_stat(path, "configuration directory", 0o700)


def ensure_private_file(path: Path, kind: str) -> None:
    private_stat(path, kind, 0o600)


def load_config(path: Path) -> dict[str, Any]:
    ensure_private_directory(path.parent)
    ensure_private_file(path, "configuration file")
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManagerError("cannot load configuration", EXIT_CONFIG) from exc
    if not isinstance(raw, dict):
        raise ManagerError("configuration must be a table", EXIT_CONFIG)
    reject_unknown(raw, {"schema_version", "profiles"}, "configuration")
    if raw.get("schema_version") != 1:
        raise ManagerError("unsupported schema_version", EXIT_CONFIG)
    profiles = raw.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ManagerError("configuration must define profiles", EXIT_CONFIG)

    managed_envs: set[str] = set()
    normalized: dict[str, list[dict[str, str]]] = {}
    for profile_name, entries in profiles.items():
        if not isinstance(profile_name, str) or not PROFILE_NAME_PATTERN.fullmatch(profile_name):
            raise ManagerError("profile name is not a safe identifier", EXIT_CONFIG)
        if not isinstance(entries, list) or not entries:
            raise ManagerError(f"profile {profile_name} must define secret mappings", EXIT_CONFIG)
        profile_envs: set[str] = set()
        normalized_entries: list[dict[str, str]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ManagerError(f"profile {profile_name} mapping must be a table", EXIT_CONFIG)
            reject_unknown(entry, {"id", "expected_key", "env"}, f"profile {profile_name}")
            if set(entry) != {"id", "expected_key", "env"}:
                raise ManagerError(f"profile {profile_name} has an incomplete mapping", EXIT_CONFIG)
            if not all(isinstance(entry[key], str) and entry[key] for key in entry):
                raise ManagerError(f"profile {profile_name} has an invalid mapping", EXIT_CONFIG)
            try:
                UUID(entry["id"])
            except ValueError as exc:
                raise ManagerError(f"profile {profile_name} has an invalid Secret ID", EXIT_CONFIG) from exc
            env_name = entry["env"]
            if not ENV_NAME_PATTERN.fullmatch(env_name) or env_name in RESERVED_ENV_NAMES:
                raise ManagerError(f"profile {profile_name} has an unsafe environment variable", EXIT_CONFIG)
            if env_name in profile_envs:
                raise ManagerError(f"profile {profile_name} has a duplicate environment variable", EXIT_CONFIG)
            profile_envs.add(env_name)
            managed_envs.add(env_name)
            normalized_entries.append(dict(entry))
        normalized[profile_name] = normalized_entries
    return {"profiles": normalized, "managed_envs": managed_envs}


def token_path_for(config_path: Path) -> Path:
    return config_path.parent / "access-token"


def read_token(path: Path) -> str:
    ensure_private_file(path, "Token file")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManagerError("cannot read Token file", EXIT_PERMISSION) from exc
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ManagerError("Token file must contain one non-empty line", EXIT_CONFIG)
    return lines[0]


def atomic_write_token(path: Path, token: str) -> None:
    ensure_private_directory(path.parent, create=True)
    if path.is_symlink():
        raise ManagerError("Token file may not be a symbolic link", EXIT_PERMISSION)
    if path.exists():
        ensure_private_file(path, "Token file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".access-token.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(token)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def minimal_bws_environment(token: str) -> dict[str, str]:
    allowed = {"HOME", "LANG", "LC_ALL", "PATH", "SSL_CERT_DIR", "SSL_CERT_FILE"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment["BWS_ACCESS_TOKEN"] = token
    return environment


def find_bws() -> str:
    executable = shutil.which("bws")
    if executable is None:
        raise ManagerError("bws: missing", EXIT_REMOTE)
    return executable


def invoke_bws(executable: str, token: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [executable, *arguments],
            env=minimal_bws_environment(token),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ManagerError("bws: unavailable", EXIT_REMOTE) from exc


def fetch_secret(executable: str, token: str, mapping: dict[str, str]) -> str:
    result = invoke_bws(executable, token, ["secret", "get", mapping["id"]])
    if result.returncode != 0:
        raise ManagerError("secret retrieval failed", EXIT_REMOTE)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ManagerError("bws returned invalid data", EXIT_REMOTE) from exc
    if payload.get("id") != mapping["id"] or payload.get("key") != mapping["expected_key"]:
        raise ManagerError("secret identity check failed", EXIT_REMOTE)
    value = payload.get("value")
    if not isinstance(value, str) or not value:
        raise ManagerError("secret value is empty", EXIT_REMOTE)
    return value


def init_command(config_path: Path, token_stdin: bool) -> int:
    load_config(config_path)
    if token_stdin:
        token = sys.stdin.readline().rstrip("\n")
        if sys.stdin.readline() != "":
            raise ManagerError("stdin must contain exactly one Token line", EXIT_CONFIG)
    else:
        token = getpass.getpass("BWS Machine Account Token: ")
    if not token or "\n" in token or "\r" in token:
        raise ManagerError("Token must be one non-empty line", EXIT_CONFIG)
    atomic_write_token(token_path_for(config_path), token)
    print("credentials: initialized")
    return 0


def doctor_command(config_path: Path) -> int:
    config = load_config(config_path)
    token = read_token(token_path_for(config_path))
    print("config: ok")
    print("permissions: ok")
    executable = find_bws()
    print("bws: ok")
    auth = invoke_bws(executable, token, ["secret", "list"])
    if auth.returncode != 0:
        raise ManagerError("authentication: failed", EXIT_REMOTE)
    print("authentication: ok")
    for profile_name, mappings in config["profiles"].items():
        for mapping in mappings:
            fetch_secret(executable, token, mapping)
            print(f"profile.{profile_name}.{mapping['expected_key']}: ok")
    return 0


def run_command(config_path: Path, profile_name: str, command: list[str]) -> int:
    if not command:
        raise ManagerError("run requires a command after --", EXIT_CONFIG)
    config = load_config(config_path)
    try:
        mappings = config["profiles"][profile_name]
    except KeyError as exc:
        raise ManagerError(f"unknown profile: {profile_name}", EXIT_CONFIG) from exc
    token = read_token(token_path_for(config_path))
    executable = find_bws()

    values: dict[str, str] = {}
    for mapping in mappings:
        values[mapping["env"]] = fetch_secret(executable, token, mapping)

    environment = os.environ.copy()
    environment.pop("BWS_ACCESS_TOKEN", None)
    for name in config["managed_envs"]:
        environment.pop(name, None)
    environment.update(values)
    try:
        result = subprocess.run(command, env=environment, check=False)
    except OSError as exc:
        raise ManagerError("cannot execute target program", EXIT_LAUNCH) from exc
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bit-secret-manager")
    parser.add_argument("--config", type=Path, default=DEFAULT_DIR / "config.toml")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    subparsers = parser.add_subparsers(dest="action", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--token-stdin", action="store_true")
    subparsers.add_parser("doctor")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("profile")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_argv)
    config_path = args.config.expanduser().absolute()
    try:
        if args.action == "init":
            return init_command(config_path, args.token_stdin)
        if args.action == "doctor":
            return doctor_command(config_path)
        try:
            delimiter_index = raw_argv.index("--")
        except ValueError:
            raise ManagerError("run requires -- before the target command", EXIT_CONFIG)
        if delimiter_index < 2 or raw_argv[delimiter_index - 2 : delimiter_index] != ["run", args.profile]:
            raise ManagerError("run requires -- immediately after PROFILE", EXIT_CONFIG)
        return run_command(config_path, args.profile, args.command)
    except ManagerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
