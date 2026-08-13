from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any
from uuid import UUID

import yaml


EXIT_CONFIG = 2
EXIT_REMOTE = 4
EXIT_CACHE = 5
EXIT_PERMISSION = 6
EXIT_VALIDATION = 7

TOP_LEVEL_KEYS = {
    "schema_version",
    "project_id",
    "state_dir",
    "token_file",
    "bws_path",
    "gh_path",
    "profiles",
}
PROFILE_KEYS = {"ttl_seconds", "validator", "secrets"}
SECRET_KEYS = {"id", "expected_key", "env", "encoding"}
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


class HubError(Exception):
    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class RemoteMissingError(HubError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat()


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HubError(f"{label} must be a mapping", EXIT_CONFIG)
    return value


def reject_unknown(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise HubError(f"unknown {label} field(s): {', '.join(unknown)}", EXIT_CONFIG)


def load_config(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise HubError(f"cannot load configuration: {exc}", EXIT_CONFIG) from exc
    config = require_mapping(raw, "configuration")
    reject_unknown(config, TOP_LEVEL_KEYS, "configuration")
    required = TOP_LEVEL_KEYS - {"gh_path"}
    missing = sorted(required - set(config))
    if missing:
        raise HubError(f"missing configuration field(s): {', '.join(missing)}", EXIT_CONFIG)
    if config["schema_version"] != 1:
        raise HubError("unsupported schema_version", EXIT_CONFIG)
    profiles = require_mapping(config["profiles"], "profiles")
    managed_envs: set[str] = set()
    for profile_name, profile_value in profiles.items():
        if not isinstance(profile_name, str) or not PROFILE_NAME_PATTERN.fullmatch(profile_name):
            raise HubError("profile name is not a safe identifier", EXIT_CONFIG)
        profile = require_mapping(profile_value, f"profile {profile_name}")
        reject_unknown(profile, PROFILE_KEYS, f"profile {profile_name}")
        missing_profile = PROFILE_KEYS - set(profile)
        if missing_profile:
            raise HubError(f"profile {profile_name} is incomplete", EXIT_CONFIG)
        if not isinstance(profile["ttl_seconds"], int) or profile["ttl_seconds"] <= 0:
            raise HubError(f"profile {profile_name} has invalid ttl_seconds", EXIT_CONFIG)
        if profile["validator"] not in {"none", "github"}:
            raise HubError(f"profile {profile_name} has unsupported validator", EXIT_CONFIG)
        secrets = profile["secrets"]
        if not isinstance(secrets, list) or not secrets:
            raise HubError(f"profile {profile_name} must define secrets", EXIT_CONFIG)
        profile_envs: set[str] = set()
        for index, secret_value in enumerate(secrets):
            secret = require_mapping(secret_value, f"profile {profile_name} secret {index}")
            reject_unknown(secret, SECRET_KEYS, f"profile {profile_name} secret")
            if SECRET_KEYS - set(secret):
                raise HubError(f"profile {profile_name} has incomplete secret mapping", EXIT_CONFIG)
            if secret["encoding"] not in {"text", "base64"}:
                raise HubError(f"profile {profile_name} has unsupported encoding", EXIT_CONFIG)
            if not all(isinstance(secret[key], str) and secret[key] for key in ("id", "expected_key", "env")):
                raise HubError(f"profile {profile_name} has invalid secret mapping", EXIT_CONFIG)
            try:
                UUID(secret["id"])
            except ValueError as exc:
                raise HubError(f"profile {profile_name} has invalid BWS Secret ID", EXIT_CONFIG) from exc
            if not ENV_NAME_PATTERN.fullmatch(secret["env"]) or secret["env"] in RESERVED_ENV_NAMES:
                raise HubError(f"profile {profile_name} has unsafe target environment variable", EXIT_CONFIG)
            if secret["env"] in profile_envs:
                raise HubError(f"profile {profile_name} has duplicate target environment variable", EXIT_CONFIG)
            profile_envs.add(secret["env"])
            managed_envs.add(secret["env"])
    config["_managed_envs"] = managed_envs
    return config


def ensure_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise HubError(f"state directory may not be a symbolic link: {path}", EXIT_PERMISSION)
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
    if not path.is_dir():
        raise HubError(f"expected a private directory: {path}", EXIT_PERMISSION)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o700 or path.stat().st_uid != os.getuid():
        raise HubError(f"state directory permissions are not private: {path}", EXIT_PERMISSION)


def ensure_private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise HubError(f"expected a regular private file: {path}", EXIT_PERMISSION)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600 or path.stat().st_uid != os.getuid():
        raise HubError(f"file permissions are not private: {path}", EXIT_PERMISSION)


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_private_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and path.is_symlink():
            raise HubError(f"refusing to replace symbolic link: {path}", EXIT_PERMISSION)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def load_token(path: Path) -> str:
    ensure_private_file(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1 or not lines[0].startswith("BWS_ACCESS_TOKEN="):
        raise HubError("bw.env must contain only BWS_ACCESS_TOKEN", EXIT_CONFIG)
    token = lines[0].partition("=")[2]
    if not token:
        raise HubError("BWS_ACCESS_TOKEN is empty", EXIT_CONFIG)
    return token


def cache_path_for(config: dict[str, Any], profile_name: str) -> Path:
    cache_dir = Path(config["state_dir"]).expanduser() / "cache"
    return cache_dir / f"{profile_name}.json"


def snapshot_hash(snapshot: dict[str, Any]) -> str:
    hashable = {key: value for key, value in snapshot.items() if key != "content_sha256"}
    encoded = json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def audit(config: dict[str, Any], profile: str, action: str, result: str, executable: str | None = None) -> None:
    audit_dir = Path(config["state_dir"]).expanduser() / "audit"
    ensure_private_dir(audit_dir)
    audit_file = audit_dir / "audit.jsonl"
    if audit_file.exists():
        ensure_private_file(audit_file)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    descriptor = os.open(audit_file, flags, 0o600)
    try:
        payload = {
            "action": action,
            "executable": executable,
            "profile": profile,
            "result": result,
            "time": isoformat(utc_now()),
        }
        os.write(descriptor, (json.dumps(payload, sort_keys=True) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remove_profile_cache(config: dict[str, Any], profile_name: str) -> None:
    path = cache_path_for(config, profile_name)
    if path.exists():
        if path.is_symlink():
            raise HubError(f"refusing to delete symbolic link: {path}", EXIT_PERMISSION)
        path.unlink()


def fetch_secret(config: dict[str, Any], token: str, mapping: dict[str, str]) -> dict[str, str]:
    child_env = {
        key: value
        for key, value in os.environ.items()
        if key in {"HOME", "LANG", "LC_ALL", "PATH", "SSL_CERT_DIR", "SSL_CERT_FILE"}
    }
    child_env["BWS_ACCESS_TOKEN"] = token
    command = [str(Path(config["bws_path"]).expanduser()), "secret", "get", mapping["id"]]
    try:
        result = subprocess.run(command, env=child_env, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise HubError("cannot execute bws", EXIT_REMOTE) from exc
    if result.returncode == 5:
        raise RemoteMissingError("remote secret is missing", EXIT_REMOTE)
    if result.returncode != 0:
        raise HubError("remote secret is unavailable", EXIT_REMOTE)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise HubError("bws returned invalid data", EXIT_REMOTE) from exc
    if payload.get("id") != mapping["id"] or payload.get("key") != mapping["expected_key"]:
        raise HubError("remote secret identity does not match configuration", EXIT_REMOTE)
    value = payload.get("value")
    if not isinstance(value, str) or not value:
        raise HubError("remote secret value is empty", EXIT_REMOTE)
    return {"value": value, "revision": str(payload.get("revisionDate", ""))}


def refresh(config: dict[str, Any], profile_name: str) -> None:
    profile = get_profile(config, profile_name)
    state_dir = Path(config["state_dir"]).expanduser()
    ensure_private_dir(state_dir)
    token = load_token(Path(config["token_file"]).expanduser())
    values: dict[str, str] = {}
    revisions: list[dict[str, str]] = []
    try:
        for mapping in profile["secrets"]:
            fetched = fetch_secret(config, token, mapping)
            raw = fetched["value"].encode("utf-8")
            if mapping["encoding"] == "base64":
                try:
                    raw = base64.b64decode(raw, validate=True)
                except ValueError as exc:
                    raise HubError("remote secret is not valid base64", EXIT_REMOTE) from exc
            values[mapping["env"]] = base64.b64encode(raw).decode("ascii")
            revisions.append({"id": mapping["id"], "revision": fetched["revision"]})
    except RemoteMissingError:
        remove_profile_cache(config, profile_name)
        audit(config, profile_name, "refresh", "remote_missing")
        raise
    except HubError:
        audit(config, profile_name, "refresh", "remote_unavailable")
        raise

    refreshed_at = utc_now()
    validation_status = validate_profile(config, profile_name, values)
    snapshot = {
        "expires_at": isoformat(refreshed_at + timedelta(seconds=profile["ttl_seconds"])),
        "profile": profile_name,
        "refreshed_at": isoformat(refreshed_at),
        "revisions": revisions,
        "schema_version": 1,
        "status": validation_status,
        "values": values,
    }
    snapshot["content_sha256"] = snapshot_hash(snapshot)
    cache_file = cache_path_for(config, profile_name)
    atomic_json(cache_file, snapshot)
    if validation_status != "verified":
        audit(config, profile_name, "refresh", "validation_failed")
        raise HubError("provider validation failed", EXIT_VALIDATION)
    audit(config, profile_name, "refresh", "success")


def clean_child_environment(config: dict[str, Any]) -> dict[str, str]:
    child_env = os.environ.copy()
    child_env.pop("BWS_ACCESS_TOKEN", None)
    for variable in config["_managed_envs"]:
        child_env.pop(variable, None)
    return child_env


def validate_profile(
    config: dict[str, Any], profile_name: str, encoded_values: dict[str, str]
) -> str:
    profile = get_profile(config, profile_name)
    if profile["validator"] == "none":
        return "verified"
    gh_path = config.get("gh_path")
    if not isinstance(gh_path, str) or not gh_path:
        raise HubError("github validator requires gh_path", EXIT_CONFIG)
    if "GH_TOKEN" not in encoded_values:
        raise HubError("github validator requires GH_TOKEN", EXIT_CONFIG)
    try:
        token = base64.b64decode(encoded_values["GH_TOKEN"], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HubError("github token encoding is invalid", EXIT_CACHE) from exc
    child_env = clean_child_environment(config)
    child_env["GH_TOKEN"] = token
    try:
        result = subprocess.run(
            [str(Path(gh_path).expanduser()), "api", "user"],
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return "unverified"
    return "verified" if result.returncode == 0 else "unverified"


def get_profile(config: dict[str, Any], profile_name: str) -> dict[str, Any]:
    try:
        return config["profiles"][profile_name]
    except KeyError as exc:
        raise HubError(f"unknown profile: {profile_name}", EXIT_CONFIG) from exc


def cache_status(config: dict[str, Any], profile_name: str) -> dict[str, Any]:
    get_profile(config, profile_name)
    cache_file = cache_path_for(config, profile_name)
    if not cache_file.exists():
        return {"profile": profile_name, "status": "missing"}
    ensure_private_file(cache_file)
    try:
        snapshot = json.loads(cache_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HubError("cache snapshot is invalid", EXIT_CACHE) from exc
    if snapshot.get("schema_version") != 1:
        raise HubError("cache schema is invalid", EXIT_CACHE)
    if snapshot.get("content_sha256") != snapshot_hash(snapshot):
        raise HubError("cache integrity check failed", EXIT_CACHE)
    if snapshot.get("profile") != profile_name or snapshot.get("status") != "verified":
        return {"profile": profile_name, "status": "unverified", "expires_at": snapshot.get("expires_at")}
    expires_at = parse_time(snapshot["expires_at"])
    status = "expired" if utc_now() >= expires_at else "ready"
    return {"profile": profile_name, "status": status, "expires_at": snapshot["expires_at"]}


def load_cache_values(config: dict[str, Any], profile_name: str) -> dict[str, str]:
    status = cache_status(config, profile_name)
    if status["status"] != "ready":
        raise HubError(f"profile cache is {status['status']}", EXIT_CACHE)
    cache_file = cache_path_for(config, profile_name)
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
        return {
            key: base64.b64decode(value, validate=True).decode("utf-8")
            for key, value in cache["values"].items()
        }
    except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError) as exc:
        raise HubError("profile cache is invalid", EXIT_CACHE) from exc


def execute(config: dict[str, Any], profile_name: str, command: list[str], offline: bool) -> int:
    if not command:
        raise HubError("exec requires a command after --", EXIT_CONFIG)
    status = cache_status(config, profile_name)
    if status["status"] != "ready":
        if offline:
            raise HubError(f"profile cache is {status['status']}", EXIT_CACHE)
        refresh(config, profile_name)
    values = load_cache_values(config, profile_name)
    child_env = clean_child_environment(config)
    child_env.update(values)
    executable = Path(command[0]).name
    try:
        result = subprocess.run(command, env=child_env, check=False)
    except OSError as exc:
        audit(config, profile_name, "exec", "launch_error", executable)
        raise HubError(f"cannot execute target program: {executable}", EXIT_CACHE) from exc
    audit(config, profile_name, "exec", f"exit_{result.returncode}", executable)
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bit-secret-hub")
    parser.add_argument("--config", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    refresh_parser = subparsers.add_parser("refresh")
    refresh_parser.add_argument("profile")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("profile")
    status_parser.add_argument("--json", action="store_true")
    exec_parser = subparsers.add_parser("exec")
    exec_parser.add_argument("profile")
    exec_parser.add_argument("--offline", action="store_true")
    setup_git_parser = subparsers.add_parser("setup-git")
    setup_git_parser.add_argument("--hostname", required=True)
    return parser


def run(arguments: argparse.Namespace) -> int:
    config = load_config(arguments.config)
    if arguments.command == "refresh":
        refresh(config, arguments.profile)
        print(f"profile {arguments.profile}: refreshed")
        return 0
    if arguments.command == "status":
        payload = cache_status(config, arguments.profile)
        if arguments.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"profile {arguments.profile}: {payload['status']}")
        return 0
    if arguments.command == "exec":
        return execute(config, arguments.profile, arguments.target, arguments.offline)
    if arguments.command == "setup-git":
        gh_path = config.get("gh_path")
        if not isinstance(gh_path, str) or not gh_path:
            raise HubError("setup-git requires gh_path", EXIT_CONFIG)
        child_env = clean_child_environment(config)
        result = subprocess.run(
            [
                str(Path(gh_path).expanduser()),
                "auth",
                "setup-git",
                "--hostname",
                arguments.hostname,
                "--force",
            ],
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise HubError("gh credential helper setup failed", EXIT_VALIDATION)
        print(f"git credential helper configured for {arguments.hostname}")
        return 0
    raise HubError("unsupported command", EXIT_CONFIG)


def main(argv: list[str] | None = None) -> int:
    try:
        raw_arguments = list(sys.argv[1:] if argv is None else argv)
        target: list[str] = []
        if "exec" in raw_arguments and "--" in raw_arguments:
            separator = raw_arguments.index("--")
            target = raw_arguments[separator + 1 :]
            raw_arguments = raw_arguments[:separator]
        arguments = build_parser().parse_args(raw_arguments)
        if arguments.command == "exec":
            arguments.target = target
        return run(arguments)
    except HubError as exc:
        print(f"bit-secret-hub: {exc}", file=sys.stderr)
        return exc.exit_code
