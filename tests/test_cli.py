from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
from unittest import mock

from bit_secret_manager import cli


ID_ONE = "11111111-1111-4111-8111-111111111111"
ID_TWO = "22222222-2222-4222-8222-222222222222"
TOKEN = "test-machine-token"
SECRET_ONE = "value-never-print-one"
SECRET_TWO = "value-never-print-two"


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp.name)
        self.config_dir = self.root / "config"
        self.config_dir.mkdir(mode=0o700)
        self.config = self.config_dir / "config.toml"
        self.write_config()
        self.token = self.config_dir / "access-token"
        self.write_private(self.token, TOKEN + "\n")
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.bws = self.bin_dir / "bws"
        self.state = self.bin_dir / "fake-bws.json"
        self.log = self.bin_dir / "calls.jsonl"
        self.write_fake_bws()
        self.write_state()
        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.bin_dir}{os.pathsep}{self.env.get('PATH', '')}"
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_private(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    def write_config(self, content: str | None = None) -> None:
        if content is None:
            content = textwrap.dedent(
                f"""\
                schema_version = 1

                [[profiles.github]]
                id = "{ID_ONE}"
                expected_key = "GITHUB_PAT"
                env = "GH_TOKEN"

                [[profiles.github]]
                id = "{ID_TWO}"
                expected_key = "SECOND_PAT"
                env = "SECOND_TOKEN"

                [[profiles.other]]
                id = "{ID_TWO}"
                expected_key = "SECOND_PAT"
                env = "OTHER_TOKEN"
                """
            )
        self.write_private(self.config, content)

    def write_state(self, *, token: str = TOKEN, records: dict[str, dict[str, str]] | None = None) -> None:
        if records is None:
            records = {
                ID_ONE: {"id": ID_ONE, "key": "GITHUB_PAT", "value": SECRET_ONE},
                ID_TWO: {"id": ID_TWO, "key": "SECOND_PAT", "value": SECRET_TWO},
            }
        self.state.write_text(json.dumps({"token": token, "records": records}), encoding="utf-8")

    def write_fake_bws(self) -> None:
        script = textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            root = Path(__file__).resolve().parent
            state = json.loads((root / "fake-bws.json").read_text())
            with (root / "calls.jsonl").open("a") as handle:
                handle.write(json.dumps({"argv": sys.argv[1:], "env_names": sorted(os.environ)}) + "\\n")
            if os.environ.get("BWS_ACCESS_TOKEN") != state["token"]:
                sys.exit(1)
            if sys.argv[1:] == ["secret", "list"]:
                print("[]")
                sys.exit(0)
            if len(sys.argv) == 4 and sys.argv[1:3] == ["secret", "get"]:
                record = state["records"].get(sys.argv[3])
                if record is None:
                    sys.exit(5)
                print(json.dumps(record))
                sys.exit(0)
            sys.exit(2)
            """
        )
        self.bws.write_text(script, encoding="utf-8")
        self.bws.chmod(0o755)

    def run_cli(self, *args: str, input_text: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "bit_secret_manager", "--config", str(self.config), *args],
            input=input_text,
            env=env or self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> list[dict[str, object]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_version_is_0_2_0(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "bit_secret_manager", "--version"],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "bit-secret-manager 0.2.0")

    def test_init_from_stdin_writes_raw_token_atomically(self) -> None:
        self.token.unlink()
        result = self.run_cli("init", "--token-stdin", input_text=TOKEN + "\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.token.read_text(encoding="utf-8"), TOKEN + "\n")
        self.assertEqual(stat.S_IMODE(self.token.stat().st_mode), 0o600)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertEqual(list(self.config_dir.glob(".access-token.*")), [])

    def test_init_from_stdin_requires_existing_config(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()

        result = self.run_cli("init", "--token-stdin", input_text=TOKEN + "\n")

        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertIn("non-interactive init requires an existing configuration", result.stderr)
        self.assertFalse(self.config_dir.exists())
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_interactive_init_bootstraps_single_mapping(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            [
                "github",
                ID_ONE,
                "GITHUB_PAT",
                "GH_TOKEN",
                "n",
                "n",
                TOKEN,
            ]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(
            config,
            {
                "schema_version": 1,
                "profiles": {
                    "github": [{"id": ID_ONE, "expected_key": "GITHUB_PAT", "env": "GH_TOKEN"}]
                },
            },
        )
        self.assertEqual(stat.S_IMODE(self.config_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.token.stat().st_mode), 0o600)
        self.assertEqual(self.token.read_text(encoding="utf-8"), TOKEN + "\n")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_interactive_init_reprompts_invalid_uuid(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            ["github", "not-a-uuid", ID_ONE, "GITHUB_PAT", "GH_TOKEN", "n", "n", TOKEN]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Secret ID must be a UUID", result.stderr)
        self.assertNotIn("not-a-uuid", result.stdout + result.stderr)

    def test_interactive_init_reprompts_expected_key_equal_to_uuid(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            ["github", ID_ONE, ID_ONE, "GITHUB_PAT", "GH_TOKEN", "n", "n", TOKEN]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("expected key must differ from the Secret UUID", result.stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(config["profiles"]["github"][0]["expected_key"], "GITHUB_PAT")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_interactive_init_reprompts_non_utf8_expected_key(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = b"\n".join(
            [
                b"github",
                ID_ONE.encode(),
                b"GITHUB_TOKEN\xe2",
                b"GITHUB_TOKEN",
                b"GITHUB_TOKEN",
                b"n",
                b"n",
                TOKEN.encode(),
            ]
        )

        result = subprocess.run(
            [sys.executable, "-m", "bit_secret_manager", "--config", str(self.config), "init"],
            input=answers + b"\n",
            env=self.env,
            capture_output=True,
            check=False,
        )

        stderr = result.stderr.decode("utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, stderr)
        self.assertIn("input must be valid UTF-8", stderr)
        self.assertNotIn("Traceback", stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(config["profiles"]["github"][0]["expected_key"], "GITHUB_TOKEN")

    def test_interactive_init_cancellation_before_token_keeps_zero_state(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(["github", ID_ONE, "GITHUB_PAT", "GH_TOKEN", "n", "n"])

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertIn("initialization cancelled", result.stderr)
        self.assertFalse(self.config_dir.exists())
        self.assertNotIn("Traceback", result.stderr)

    def test_interactive_init_serializes_dotted_profile_name(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            ["team.github", ID_ONE, "GITHUB_PAT", "GH_TOKEN", "n", "n", TOKEN]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(set(config["profiles"]), {"team.github"})

    def test_interactive_init_adds_multiple_mappings_to_one_profile(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            [
                "github",
                ID_ONE,
                "GITHUB_PAT",
                "GH_TOKEN",
                "y",
                ID_TWO,
                "SECOND_PAT",
                "SECOND_TOKEN",
                "n",
                "n",
                TOKEN,
            ]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(
            config["profiles"]["github"],
            [
                {"id": ID_ONE, "expected_key": "GITHUB_PAT", "env": "GH_TOKEN"},
                {"id": ID_TWO, "expected_key": "SECOND_PAT", "env": "SECOND_TOKEN"},
            ],
        )
        self.assertEqual(self.token.read_text(encoding="utf-8"), TOKEN + "\n")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_interactive_init_reprompts_duplicate_profile_environment(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            [
                "github",
                ID_ONE,
                "GITHUB_PAT",
                "GH_TOKEN",
                "y",
                ID_TWO,
                "SECOND_PAT",
                "GH_TOKEN",
                "SECOND_TOKEN",
                "n",
                "n",
                TOKEN,
            ]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("environment variable is unsafe or already used", result.stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(
            [mapping["env"] for mapping in config["profiles"]["github"]],
            ["GH_TOKEN", "SECOND_TOKEN"],
        )
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_interactive_init_adds_multiple_profiles(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            [
                "github",
                ID_ONE,
                "GITHUB_PAT",
                "GH_TOKEN",
                "n",
                "y",
                "other",
                ID_TWO,
                "SECOND_PAT",
                "OTHER_TOKEN",
                "n",
                "n",
                TOKEN,
            ]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(
            config["profiles"],
            {
                "github": [{"id": ID_ONE, "expected_key": "GITHUB_PAT", "env": "GH_TOKEN"}],
                "other": [{"id": ID_TWO, "expected_key": "SECOND_PAT", "env": "OTHER_TOKEN"}],
            },
        )
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_interactive_init_reprompts_duplicate_profile_name(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        answers = "\n".join(
            [
                "github",
                ID_ONE,
                "GITHUB_PAT",
                "GH_TOKEN",
                "n",
                "y",
                "github",
                "other",
                ID_TWO,
                "SECOND_PAT",
                "OTHER_TOKEN",
                "n",
                "n",
                TOKEN,
            ]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("profile name is unsafe or already exists", result.stderr)
        with self.config.open("rb") as handle:
            config = tomllib.load(handle)
        self.assertEqual(set(config["profiles"]), {"github", "other"})
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_interactive_init_rejects_symlinked_missing_config_directory_before_prompt(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.config_dir.rmdir()
        target = self.root / "outside-config"
        target.mkdir(mode=0o700)
        self.config_dir.symlink_to(target, target_is_directory=True)

        result = self.run_cli("init", input_text="")

        self.assertEqual(result.returncode, cli.EXIT_PERMISSION)
        self.assertIn("configuration directory may not be a symbolic link", result.stderr)
        self.assertNotIn("Profile name", result.stdout + result.stderr)
        self.assertEqual(list(target.iterdir()), [])

    def test_interactive_init_rolls_back_config_when_token_write_fails(self) -> None:
        self.config.unlink()
        self.token.unlink()
        self.token.mkdir(mode=0o700)
        answers = "\n".join(
            ["github", ID_ONE, "GITHUB_PAT", "GH_TOKEN", "n", "n", TOKEN]
        )

        result = self.run_cli("init", input_text=answers + "\n")

        self.assertEqual(result.returncode, cli.EXIT_PERMISSION)
        self.assertFalse(self.config.exists())
        self.assertTrue(self.token.is_dir())
        self.assertEqual(list(self.config_dir.glob(".config.toml.*")), [])
        self.assertEqual(list(self.config_dir.glob(".access-token.*")), [])
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_init_rejects_multiple_stdin_lines_without_writing(self) -> None:
        self.token.unlink()
        result = self.run_cli("init", "--token-stdin", input_text="one\ntwo\n")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertFalse(self.token.exists())

    def test_init_rejects_a_token_pasted_twice_without_overwriting(self) -> None:
        original = self.token.read_bytes()

        result = self.run_cli("init", "--token-stdin", input_text=TOKEN + TOKEN + "\n")

        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertIn("Token appears to be duplicated", result.stderr)
        self.assertEqual(self.token.read_bytes(), original)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_init_rejects_non_utf8_token_without_overwriting(self) -> None:
        original = self.token.read_bytes()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bit_secret_manager",
                "--config",
                str(self.config),
                "init",
            ],
            input=b"invalid-token-\xe2\n",
            env=self.env,
            capture_output=True,
            check=False,
        )

        stderr = result.stderr.decode("utf-8", errors="replace")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertIn("Token must be valid UTF-8", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(self.token.read_bytes(), original)

    def test_init_uses_hidden_input(self) -> None:
        self.token.unlink()
        with mock.patch.object(getpass, "getpass", return_value=TOKEN):
            result = cli.main(["--config", str(self.config), "init"])
        self.assertEqual(result, 0)
        self.assertEqual(self.token.read_text(encoding="utf-8"), TOKEN + "\n")

    def test_interactive_init_with_existing_config_preserves_config_bytes(self) -> None:
        original = self.config.read_bytes()
        self.token.unlink()

        result = self.run_cli("init", input_text=TOKEN + "\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(self.token.read_text(encoding="utf-8"), TOKEN + "\n")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_init_refuses_token_symlink(self) -> None:
        self.token.unlink()
        target = self.root / "outside"
        target.write_text("unchanged", encoding="utf-8")
        self.token.symlink_to(target)
        result = self.run_cli("init", "--token-stdin", input_text=TOKEN + "\n")
        self.assertEqual(result.returncode, cli.EXIT_PERMISSION)
        self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

    def test_doctor_checks_authentication_and_every_identity(self) -> None:
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("authentication: ok", result.stdout)
        self.assertIn("profile.github.GITHUB_PAT: ok", result.stdout)
        self.assertIn("profile.other.SECOND_PAT: ok", result.stdout)
        combined = result.stdout + result.stderr
        for forbidden in (TOKEN, SECRET_ONE, SECRET_TWO, ID_ONE, ID_TWO):
            self.assertNotIn(forbidden, combined)

    def test_doctor_reports_auth_failure_without_provider_output(self) -> None:
        self.write_state(token="different-token")
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_REMOTE)
        self.assertIn("authentication: failed", result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_doctor_reports_missing_bws(self) -> None:
        env = self.env.copy()
        env["PATH"] = "/nonexistent"
        result = self.run_cli("doctor", env=env)
        self.assertEqual(result.returncode, cli.EXIT_REMOTE)
        self.assertIn("bws: missing", result.stderr)

    def test_run_fetches_profile_then_preserves_argv_and_exit_code(self) -> None:
        target = self.root / "target.py"
        output = self.root / "target.json"
        target.write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "Path(sys.argv[1]).write_text(json.dumps({'argv': sys.argv[2:], 'gh': os.getenv('GH_TOKEN'), "
            "'second': os.getenv('SECOND_TOKEN'), 'other': os.getenv('OTHER_TOKEN'), "
            "'bws': os.getenv('BWS_ACCESS_TOKEN')}))\n"
            "raise SystemExit(37)\n",
            encoding="utf-8",
        )
        env = self.env.copy()
        env.update({"BWS_ACCESS_TOKEN": "parent-token", "GH_TOKEN": "stale", "OTHER_TOKEN": "stale-other"})
        result = self.run_cli(
            "run", "github", "--", sys.executable, str(target), str(output), "space value", "$(literal)", env=env
        )
        self.assertEqual(result.returncode, 37, result.stderr)
        observed = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(observed["argv"], ["space value", "$(literal)"])
        self.assertEqual(observed["gh"], SECRET_ONE)
        self.assertEqual(observed["second"], SECRET_TWO)
        self.assertIsNone(observed["other"])
        self.assertIsNone(observed["bws"])
        self.assertNotIn(SECRET_ONE, result.stdout + result.stderr)

    def test_run_is_profile_atomic_when_later_secret_fails(self) -> None:
        marker = self.root / "started"
        records = {ID_ONE: {"id": ID_ONE, "key": "GITHUB_PAT", "value": SECRET_ONE}}
        self.write_state(records=records)
        result = self.run_cli("run", "github", "--", sys.executable, "-c", f"open({str(marker)!r}, 'w').close()")
        self.assertEqual(result.returncode, cli.EXIT_REMOTE)
        self.assertFalse(marker.exists())
        self.assertNotIn(SECRET_ONE, result.stdout + result.stderr)

    def test_run_rejects_identity_mismatch_before_launch(self) -> None:
        marker = self.root / "started"
        records = {
            ID_ONE: {"id": ID_ONE, "key": "WRONG", "value": SECRET_ONE},
            ID_TWO: {"id": ID_TWO, "key": "SECOND_PAT", "value": SECRET_TWO},
        }
        self.write_state(records=records)
        result = self.run_cli("run", "github", "--", sys.executable, "-c", f"open({str(marker)!r}, 'w').close()")
        self.assertEqual(result.returncode, cli.EXIT_REMOTE)
        self.assertFalse(marker.exists())

    def test_bws_receives_only_minimal_environment(self) -> None:
        env = self.env.copy()
        env["UNRELATED_SECRET"] = "must-not-reach-provider"
        result = self.run_cli("doctor", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            self.assertNotIn("UNRELATED_SECRET", call["env_names"])
            self.assertIn("BWS_ACCESS_TOKEN", call["env_names"])

    def test_unknown_profile_fails_before_provider_call(self) -> None:
        result = self.run_cli("run", "missing", "--", "true")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertEqual(self.calls(), [])

    def test_run_requires_argv_separator(self) -> None:
        result = self.run_cli("run", "github", "true")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertEqual(self.calls(), [])

    def test_unknown_field_is_rejected(self) -> None:
        self.write_config("schema_version = 1\nunknown = true\n[profiles]\n")
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)

    def test_invalid_uuid_is_rejected(self) -> None:
        self.write_config(
            'schema_version = 1\n[[profiles.bad]]\nid = "not-a-uuid"\nexpected_key = "KEY"\nenv = "TOKEN"\n'
        )
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)
        self.assertEqual(self.calls(), [])

    def test_duplicate_environment_is_rejected(self) -> None:
        self.write_config(
            f'schema_version = 1\n[[profiles.bad]]\nid = "{ID_ONE}"\nexpected_key = "A"\nenv = "TOKEN"\n'
            f'[[profiles.bad]]\nid = "{ID_TWO}"\nexpected_key = "B"\nenv = "TOKEN"\n'
        )
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)

    def test_reserved_environment_is_rejected(self) -> None:
        self.write_config(
            f'schema_version = 1\n[[profiles.bad]]\nid = "{ID_ONE}"\nexpected_key = "A"\nenv = "PATH"\n'
        )
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_CONFIG)

    def test_unsafe_config_permissions_are_rejected(self) -> None:
        self.config.chmod(0o644)
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_PERMISSION)

    def test_unsafe_directory_permissions_are_rejected(self) -> None:
        self.config_dir.chmod(0o755)
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_PERMISSION)

    def test_non_current_user_ownership_is_rejected(self) -> None:
        with mock.patch.object(cli.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(cli.ManagerError) as caught:
                cli.load_config(self.config)
        self.assertEqual(caught.exception.exit_code, cli.EXIT_PERMISSION)

    def test_config_symlink_is_rejected(self) -> None:
        real_config = self.root / "real.toml"
        real_config.write_text(self.config.read_text(encoding="utf-8"), encoding="utf-8")
        real_config.chmod(0o600)
        self.config.unlink()
        self.config.symlink_to(real_config)
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, cli.EXIT_PERMISSION)


class InstallerTestCase(unittest.TestCase):
    def test_installer_produces_working_cli_without_installing_dependencies(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir="/tmp") as temp:
            prefix = Path(temp) / "prefix"
            result = subprocess.run(
                ["bash", str(repo / "install.sh"), "--prefix", str(prefix)],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            smoke = subprocess.run(
                [str(prefix / "bin" / "bit-secret-manager"), "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(smoke.stdout.strip(), "bit-secret-manager 0.2.0")


if __name__ == "__main__":
    unittest.main()
