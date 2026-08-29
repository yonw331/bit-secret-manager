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
from typing import Any, Callable
from uuid import UUID

from . import __version__


EXIT_CONFIG = 2
EXIT_REMOTE = 4
EXIT_PERMISSION = 6
EXIT_LAUNCH = 126

DEFAULT_DIR = Path("~/.config/bit-secret-manager")
PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ENV_NAME_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]*$")
LOCAL_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
RESERVED_ENV_NAMES = {
    "BWS_ACCESS_TOKEN", "HOME", "LD_LIBRARY_PATH", "PATH", "PYTHONHOME", "PYTHONPATH", "SHELL",
}
PRIVATE_ENV_NAMES = {
    "BWS_ACCESS_TOKEN", "BIT_SECRET_MANAGER_CONFIG", "BIT_SECRET_MANAGER_DEVICE", "BIT_SECRET_MANAGER_LOCAL_SECRETS",
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
    is_directory = kind == "configuration directory"
    if not (stat.S_ISDIR(info.st_mode) if is_directory else stat.S_ISREG(info.st_mode)):
        expected = "directory" if is_directory else "regular file"
        raise ManagerError(f"{kind} must be a {expected}", EXIT_PERMISSION)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
        raise ManagerError(f"{kind} must be owned by the current user with mode {mode:04o}", EXIT_PERMISSION)
    return info


def private_dir() -> Path:
    return DEFAULT_DIR.expanduser().absolute()


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


def ensure_navigation_file(path: Path) -> None:
    if path.is_symlink():
        raise ManagerError("navigation configuration may not be a symbolic link", EXIT_PERMISSION)
    try:
        info = path.stat()
    except OSError as exc:
        raise ManagerError("cannot access navigation configuration", EXIT_CONFIG) from exc
    if not stat.S_ISREG(info.st_mode):
        raise ManagerError("navigation configuration must be a regular file", EXIT_PERMISSION)


def load_toml(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManagerError(f"cannot load {label}", EXIT_CONFIG) from exc
    if not isinstance(raw, dict):
        raise ManagerError(f"{label} must be a table", EXIT_CONFIG)
    return raw


def validate_entry(profile_name: str, entry: Any, profile_envs: set[str]) -> dict[str, str]:
    if not isinstance(entry, dict):
        raise ManagerError(f"profile {profile_name} mapping must be a table", EXIT_CONFIG)
    source = entry.get("source")
    required = {"source", "id", "expected_key", "env"} if source == "bws" else {"source", "key", "env"} if source == "local" else set()
    if not required:
        raise ManagerError(f"profile {profile_name} has an unknown source", EXIT_CONFIG)
    reject_unknown(entry, required, f"profile {profile_name}")
    if set(entry) != required or not all(isinstance(entry[key], str) and entry[key] for key in required):
        raise ManagerError(f"profile {profile_name} has an incomplete mapping", EXIT_CONFIG)
    env_name = entry["env"]
    if not ENV_NAME_PATTERN.fullmatch(env_name) or env_name in RESERVED_ENV_NAMES:
        raise ManagerError(f"profile {profile_name} has an unsafe environment variable", EXIT_CONFIG)
    if env_name in profile_envs:
        raise ManagerError(f"profile {profile_name} has a duplicate environment variable", EXIT_CONFIG)
    profile_envs.add(env_name)
    if source == "bws":
        try:
            UUID(entry["id"])
        except ValueError as exc:
            raise ManagerError(f"profile {profile_name} has an invalid Secret ID", EXIT_CONFIG) from exc
    elif not LOCAL_KEY_PATTERN.fullmatch(entry["key"]):
        raise ManagerError(f"profile {profile_name} has an unsafe local key", EXIT_CONFIG)
    return {key: entry[key] for key in required}


def normalize_schema_one(raw: dict[str, Any]) -> dict[str, Any]:
    reject_unknown(raw, {"schema_version", "profiles"}, "configuration")
    if raw.get("schema_version") != 1:
        raise ManagerError("unsupported schema_version", EXIT_CONFIG)
    profiles = raw.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ManagerError("configuration must define profiles", EXIT_CONFIG)
    normalized: dict[str, list[dict[str, str]]] = {}
    managed_envs: set[str] = set()
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
            legacy_entry = dict(entry)
            legacy_entry["source"] = "bws"
            normalized_entries.append(validate_entry(profile_name, legacy_entry, profile_envs))
        normalized[profile_name] = normalized_entries
        managed_envs.update(profile_envs)
    return {"schema_version": 1, "profiles": normalized, "managed_envs": managed_envs}


def normalize_schema_two(raw: dict[str, Any]) -> dict[str, Any]:
    reject_unknown(raw, {"schema_version", "entries"}, "navigation configuration")
    if raw.get("schema_version") != 2:
        raise ManagerError("unsupported schema_version", EXIT_CONFIG)
    entries = raw.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ManagerError("navigation configuration must define entries", EXIT_CONFIG)
    profiles: dict[str, list[dict[str, str]]] = {}
    profile_envs: dict[str, set[str]] = {}
    managed_envs: set[str] = set()
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ManagerError("navigation entry must be a table", EXIT_CONFIG)
        profile_name = raw_entry.get("profile")
        if not isinstance(profile_name, str) or not PROFILE_NAME_PATTERN.fullmatch(profile_name):
            raise ManagerError("profile name is not a safe identifier", EXIT_CONFIG)
        entry = dict(raw_entry)
        entry.pop("profile", None)
        normalized = validate_entry(profile_name, entry, profile_envs.setdefault(profile_name, set()))
        profiles.setdefault(profile_name, []).append(normalized)
        managed_envs.add(normalized["env"])
    return {"schema_version": 2, "profiles": profiles, "managed_envs": managed_envs}


def normalize_config(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ManagerError("configuration must be a table", EXIT_CONFIG)
    if raw.get("schema_version") == 1:
        return normalize_schema_one(raw)
    if raw.get("schema_version") == 2:
        return normalize_schema_two(raw)
    raise ManagerError("unsupported schema_version", EXIT_CONFIG)


def load_config(path: Path) -> dict[str, Any]:
    """Load a schema 1 private configuration for backwards compatibility."""
    ensure_private_directory(path.parent)
    ensure_private_file(path, "configuration file")
    config = normalize_config(load_toml(path, "configuration"))
    if config["schema_version"] != 1:
        raise ManagerError("schema 2 configuration is a navigation file, not a private configuration", EXIT_CONFIG)
    return config


def load_navigation_config(path: Path) -> dict[str, Any]:
    ensure_navigation_file(path)
    config = normalize_config(load_toml(path, "navigation configuration"))
    if config["schema_version"] != 2:
        raise ManagerError("schema 1 configuration requires explicit private --config", EXIT_CONFIG)
    return config


def device_path() -> Path:
    return private_dir() / "device.toml"


def token_path_for(config_path: Path | None = None) -> Path:
    return (config_path.parent if config_path is not None else private_dir()) / "access-token"


def local_secrets_path() -> Path:
    return private_dir() / "local-secrets.toml"


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


def atomic_write_private(path: Path, content: str, prefix: str, kind: str) -> None:
    ensure_private_directory(path.parent, create=True)
    if path.is_symlink():
        raise ManagerError(f"{kind} may not be a symbolic link", EXIT_PERMISSION)
    if path.exists():
        ensure_private_file(path, kind)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=prefix, dir=path.parent)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ManagerError(f"cannot write {kind}", EXIT_PERMISSION) from exc
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def atomic_write_token(path: Path, token: str) -> None:
    atomic_write_private(path, token + "\n", ".access-token.", "Token file")


def atomic_write_config(path: Path, content: str) -> None:
    atomic_write_private(path, content, ".config.toml.", "configuration file")


def atomic_write_device(path: Path, navigation_path: Path) -> None:
    content = "schema_version = 1\nconfig = " + json.dumps(str(navigation_path), ensure_ascii=False) + "\n"
    atomic_write_private(path, content, ".device.toml.", "device file")


def load_device_config_path() -> Path:
    path = device_path()
    ensure_private_directory(path.parent)
    ensure_private_file(path, "device file")
    raw = load_toml(path, "device file")
    reject_unknown(raw, {"schema_version", "config"}, "device file")
    if raw.get("schema_version") != 1 or not isinstance(raw.get("config"), str) or not raw["config"]:
        raise ManagerError("device file has an invalid navigation pointer", EXIT_CONFIG)
    navigation = Path(raw["config"]).expanduser()
    if not navigation.is_absolute():
        raise ManagerError("device file navigation pointer must be absolute", EXIT_CONFIG)
    return navigation


def ensure_safe_missing_config_path(path: Path) -> None:
    for directory in (path.parent, *path.parent.parents):
        if directory.is_symlink():
            raise ManagerError("configuration directory may not be a symbolic link", EXIT_PERMISSION)
    if path.parent.exists():
        ensure_private_directory(path.parent)


def load_selected_config(explicit_path: Path | None) -> tuple[dict[str, Any], Path | None]:
    if explicit_path is not None:
        path = explicit_path.expanduser().absolute()
        if path.exists() and not path.is_symlink() and load_toml(path, "configuration").get("schema_version") == 1:
            return load_config(path), path
        return load_navigation_config(path), None
    navigation = load_device_config_path()
    return load_navigation_config(navigation), None


def prompt_value(prompt: str, validator: Callable[[str], bool], error: str) -> str:
    while True:
        try:
            value = input(prompt)
        except (EOFError, KeyboardInterrupt) as exc:
            raise ManagerError("initialization cancelled", EXIT_CONFIG) from exc
        if not valid_utf8(value):
            print("error: input must be valid UTF-8", file=sys.stderr)
            continue
        if validator(value):
            return value
        print(f"error: {error}", file=sys.stderr)


def prompt_yes_no(prompt: str) -> bool:
    while True:
        answer = prompt_value(prompt, lambda value: value.lower() in {"", "y", "yes", "n", "no"}, "answer must be yes or no").lower()
        return answer not in {"", "n", "no"}


def valid_uuid(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def valid_utf8(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def token_appears_duplicated(token: str) -> bool:
    midpoint, remainder = divmod(len(token), 2)
    return remainder == 0 and token[:midpoint] == token[midpoint:]


def prompt_initial_config() -> dict[str, list[dict[str, str]]]:
    profiles = {}
    while True:
        profile_name = prompt_value("Profile name: ", lambda value: PROFILE_NAME_PATTERN.fullmatch(value) is not None and value not in profiles, "profile name is unsafe or already exists")
        mappings = []
        while True:
            secret_id = prompt_value("BWS Secret UUID: ", valid_uuid, "Secret ID must be a UUID")
            expected_key = prompt_value("BWS Secret key (the Key field, not the UUID): ", lambda value: bool(value) and value != secret_id, "expected key must differ from the Secret UUID and not be empty")
            mappings.append({"id": secret_id, "expected_key": expected_key, "env": prompt_value("Target environment variable: ", lambda value: ENV_NAME_PATTERN.fullmatch(value) is not None and value not in RESERVED_ENV_NAMES and value not in {mapping["env"] for mapping in mappings}, "environment variable is unsafe or already used")})
            if not prompt_yes_no("Add another mapping to this profile? [y/N]: "):
                break
        profiles[profile_name] = mappings
        if not prompt_yes_no("Add another profile? [y/N]: "):
            break
    return profiles


def serialize_config(profiles: dict[str, list[dict[str, str]]]) -> str:
    lines = ["schema_version = 1", ""]
    for profile_name, mappings in profiles.items():
        for mapping in mappings:
            lines.extend([f"[[profiles.{json.dumps(profile_name, ensure_ascii=False)}]]", f"id = {json.dumps(mapping['id'], ensure_ascii=False)}", f"expected_key = {json.dumps(mapping['expected_key'], ensure_ascii=False)}", f"env = {json.dumps(mapping['env'], ensure_ascii=False)}", ""])
    content = "\n".join(lines)
    normalize_schema_one(tomllib.loads(content))
    return content


def read_initial_token(token_stdin: bool) -> str:
    if token_stdin:
        token = sys.stdin.readline().rstrip("\n")
        if sys.stdin.readline() != "":
            raise ManagerError("stdin must contain exactly one Token line", EXIT_CONFIG)
    else:
        try:
            token = getpass.getpass("BWS Machine Account Token: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise ManagerError("initialization cancelled", EXIT_CONFIG) from exc
    if not token or "\n" in token or "\r" in token:
        raise ManagerError("Token must be one non-empty line", EXIT_CONFIG)
    if not valid_utf8(token):
        raise ManagerError("Token must be valid UTF-8", EXIT_CONFIG)
    if token_appears_duplicated(token):
        raise ManagerError("Token appears to be duplicated; paste it once", EXIT_CONFIG)
    return token


def init_schema_one(config_path: Path, token_stdin: bool) -> int:
    config_exists = config_path.exists() or config_path.is_symlink()
    if not config_exists:
        ensure_safe_missing_config_path(config_path)
    if token_stdin and not config_exists:
        raise ManagerError("non-interactive init requires an existing configuration", EXIT_CONFIG)
    profiles = None
    if config_exists:
        load_config(config_path)
    else:
        profiles = prompt_initial_config()
    token = read_initial_token(token_stdin)
    if profiles is not None:
        config_written = False
        try:
            atomic_write_config(config_path, serialize_config(profiles))
            config_written = True
            atomic_write_token(token_path_for(config_path), token)
        except Exception:
            if config_written:
                try:
                    config_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
    else:
        atomic_write_token(token_path_for(config_path), token)
    print("credentials: initialized")
    return 0


def has_bws_entries(config: dict[str, Any]) -> bool:
    return any(entry["source"] == "bws" for entries in config["profiles"].values() for entry in entries)


def init_schema_two(navigation_path: Path, config: dict[str, Any], token_stdin: bool) -> int:
    if token_stdin and not has_bws_entries(config):
        raise ManagerError("configuration does not use BWS", EXIT_CONFIG)
    token = read_initial_token(token_stdin) if has_bws_entries(config) else None
    pointer = device_path()
    original = pointer.read_bytes() if pointer.exists() and not pointer.is_symlink() else None
    original_exists = pointer.exists() or pointer.is_symlink()
    if original_exists:
        ensure_private_directory(pointer.parent)
        ensure_private_file(pointer, "device file")
    try:
        atomic_write_device(pointer, navigation_path)
        if token is not None:
            atomic_write_token(token_path_for(), token)
    except Exception:
        if original is not None:
            atomic_write_private(pointer, original.decode("utf-8"), ".device.toml.", "device file")
        elif not original_exists:
            try:
                pointer.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    print("credentials: initialized")
    return 0


def init_command(explicit_path: Path | None, token_stdin: bool) -> int:
    if explicit_path is None:
        navigation = load_device_config_path()
        return init_schema_two(navigation, load_navigation_config(navigation), token_stdin)
    config_path = explicit_path.expanduser().absolute()
    if not config_path.exists() and not config_path.is_symlink():
        return init_schema_one(config_path, token_stdin)
    if config_path.is_symlink():
        return init_schema_one(config_path, token_stdin)
    if load_toml(config_path, "configuration").get("schema_version") == 1:
        return init_schema_one(config_path, token_stdin)
    return init_schema_two(config_path, load_navigation_config(config_path), token_stdin)


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
        return subprocess.run([executable, *arguments], env=minimal_bws_environment(token), capture_output=True, text=True, check=False)
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


def normalize_local_secrets(raw: dict[str, Any]) -> dict[str, str]:
    reject_unknown(raw, {"schema_version", "secrets"}, "local secrets")
    if raw.get("schema_version") != 1 or not isinstance(raw.get("secrets"), dict):
        raise ManagerError("local secrets have an invalid schema", EXIT_CONFIG)
    secrets: dict[str, str] = {}
    for key, value in raw["secrets"].items():
        if not isinstance(key, str) or not LOCAL_KEY_PATTERN.fullmatch(key):
            raise ManagerError("local secrets have an unsafe key", EXIT_CONFIG)
        if not isinstance(value, str) or not value or "\n" in value or "\r" in value or not valid_utf8(value):
            raise ManagerError("local secrets have an invalid value", EXIT_CONFIG)
        secrets[key] = value
    return secrets


def load_local_secrets(path: Path | None = None) -> dict[str, str]:
    path = path or local_secrets_path()
    ensure_private_directory(path.parent)
    ensure_private_file(path, "local secrets file")
    return normalize_local_secrets(load_toml(path, "local secrets"))


def serialize_local_secrets(secrets: dict[str, str]) -> str:
    normalize_local_secrets({"schema_version": 1, "secrets": secrets})
    lines = ["schema_version = 1", "", "[secrets]"]
    lines.extend(f"{json.dumps(key, ensure_ascii=False)} = {json.dumps(value, ensure_ascii=False)}" for key, value in sorted(secrets.items()))
    return "\n".join(lines) + "\n"


def set_local_command(key: str) -> int:
    if not LOCAL_KEY_PATTERN.fullmatch(key):
        raise ManagerError("local key is not a safe identifier", EXIT_CONFIG)
    try:
        value = getpass.getpass("Local secret value: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ManagerError("local secret input cancelled", EXIT_CONFIG) from exc
    if not value or "\n" in value or "\r" in value or not valid_utf8(value):
        raise ManagerError("local secret must be one non-empty UTF-8 line", EXIT_CONFIG)
    path = local_secrets_path()
    if path.exists() or path.is_symlink():
        secrets = load_local_secrets(path)
    else:
        ensure_private_directory(path.parent, create=True)
        secrets = {}
    secrets[key] = value
    atomic_write_private(path, serialize_local_secrets(secrets), ".local-secrets.toml.", "local secrets file")
    print("local secret: updated")
    return 0


def selected_profile(config: dict[str, Any], profile_name: str) -> list[dict[str, str]]:
    try:
        return config["profiles"][profile_name]
    except KeyError as exc:
        raise ManagerError(f"unknown profile: {profile_name}", EXIT_CONFIG) from exc


def resolve_profile(config: dict[str, Any], private_config_path: Path | None, profile_name: str) -> dict[str, str]:
    entries = selected_profile(config, profile_name)
    bws_entries = [entry for entry in entries if entry["source"] == "bws"]
    local_entries = [entry for entry in entries if entry["source"] == "local"]
    values: dict[str, str] = {}
    if bws_entries:
        token = read_token(token_path_for(private_config_path))
        executable = find_bws()
        for entry in bws_entries:
            values[entry["env"]] = fetch_secret(executable, token, entry)
    if local_entries:
        local_values = load_local_secrets()
        for entry in local_entries:
            try:
                values[entry["env"]] = local_values[entry["key"]]
            except KeyError as exc:
                raise ManagerError(f"local key missing: {entry['key']}", EXIT_CONFIG) from exc
    return values


def doctor_command(explicit_path: Path | None, profile_name: str | None) -> int:
    config, private_config_path = load_selected_config(explicit_path)
    profiles = [profile_name] if profile_name is not None else list(config["profiles"])
    for name in profiles:
        selected_profile(config, name)
    print("config: ok")
    print("permissions: ok")
    bws_entries = [entry for name in profiles for entry in selected_profile(config, name) if entry["source"] == "bws"]
    if bws_entries:
        token = read_token(token_path_for(private_config_path))
        executable = find_bws()
        print("bws: ok")
        if invoke_bws(executable, token, ["secret", "list"]).returncode != 0:
            raise ManagerError("authentication: failed", EXIT_REMOTE)
        print("authentication: ok")
        for name in profiles:
            for entry in selected_profile(config, name):
                if entry["source"] == "bws":
                    fetch_secret(executable, token, entry)
                    print(f"profile.{name}.{entry['expected_key']}: ok")
    local_entries = [entry for name in profiles for entry in selected_profile(config, name) if entry["source"] == "local"]
    if local_entries:
        local_values = load_local_secrets()
        for name in profiles:
            for entry in selected_profile(config, name):
                if entry["source"] == "local":
                    if entry["key"] not in local_values:
                        raise ManagerError(f"local key missing: {entry['key']}", EXIT_CONFIG)
                    print(f"profile.{name}.{entry['key']}: ok")
    return 0


def run_command(explicit_path: Path | None, profile_name: str, command: list[str]) -> int:
    if not command:
        raise ManagerError("run requires a command after --", EXIT_CONFIG)
    config, private_config_path = load_selected_config(explicit_path)
    values = resolve_profile(config, private_config_path, profile_name)
    environment = os.environ.copy()
    for name in PRIVATE_ENV_NAMES | config["managed_envs"]:
        environment.pop(name, None)
    environment.update(values)
    try:
        result = subprocess.run(command, env=environment, check=False)
    except OSError as exc:
        raise ManagerError("cannot execute target program", EXIT_LAUNCH) from exc
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bit-secret-manager")
    parser.add_argument("--config", type=Path, help="schema 1 private config or schema 2 navigation config")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="action", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--token-stdin", action="store_true")
    subparsers.add_parser("set-local").add_argument("key")
    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("profile", nargs="?")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("profile")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_argv)
    try:
        if args.action == "init":
            return init_command(args.config, args.token_stdin)
        if args.action == "set-local":
            return set_local_command(args.key)
        if args.action == "doctor":
            return doctor_command(args.config, args.profile)
        try:
            delimiter_index = raw_argv.index("--")
        except ValueError:
            raise ManagerError("run requires -- before the target command", EXIT_CONFIG)
        if raw_argv[delimiter_index - 2 : delimiter_index] != ["run", args.profile]:
            raise ManagerError("run requires -- immediately after PROFILE", EXIT_CONFIG)
        return run_command(args.config, args.profile, args.command)
    except ManagerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
