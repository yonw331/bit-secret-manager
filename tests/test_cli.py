from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SECRET = "prototype-secret-value"
BWS_TOKEN = "prototype-bws-access-token"


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.state_dir = self.root / "state"
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.token_file = self.root / "bw.env"
        self.token_file.write_text(
            f"BWS_ACCESS_TOKEN={BWS_TOKEN}\n", encoding="utf-8"
        )
        self.token_file.chmod(0o600)
        self.bws_data = self.root / "bws-data.json"
        self.bws_data.write_text(
            json.dumps(
                {
                    "486c3235-2cb1-465d-9971-6997efdceb43": {
                        "id": "486c3235-2cb1-465d-9971-6997efdceb43",
                        "key": "GITHUB_PAT",
                        "value": SECRET,
                        "revisionDate": "2026-08-12T00:00:00Z",
                    },
                    "11111111-1111-4111-8111-111111111111": {
                        "id": "11111111-1111-4111-8111-111111111111",
                        "key": "OTHER_SECRET",
                        "value": "other-profile-secret",
                        "revisionDate": "2026-08-12T00:00:00Z",
                    },
                }
            ),
            encoding="utf-8",
        )
        self.bws_unavailable = self.root / "bws-unavailable"
        self.fake_bws = self.bin_dir / "bws"
        self.fake_bws.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path
                import sys

                if os.environ.get("BWS_ACCESS_TOKEN") != {BWS_TOKEN!r}:
                    print("authentication failed", file=sys.stderr)
                    raise SystemExit(4)
                if "OTHER_SECRET" in os.environ:
                    print("managed secret leaked into provider", file=sys.stderr)
                    raise SystemExit(8)
                if Path({str(self.bws_unavailable)!r}).exists():
                    print("service unavailable", file=sys.stderr)
                    raise SystemExit(9)
                secret_id = sys.argv[3]
                data = json.loads(Path({str(self.bws_data)!r}).read_text())
                if secret_id not in data:
                    print("secret not found", file=sys.stderr)
                    raise SystemExit(5)
                print(json.dumps(data[secret_id]))
                """
            ),
            encoding="utf-8",
        )
        self.fake_bws.chmod(0o700)
        self.config = self.root / "config.yaml"
        self.config.write_text(
            textwrap.dedent(
                f"""\
                schema_version: 1
                project_id: prototype-project
                state_dir: {self.state_dir}
                token_file: {self.token_file}
                bws_path: {self.fake_bws}
                profiles:
                  github:
                    ttl_seconds: 604800
                    validator: none
                    secrets:
                      - id: 486c3235-2cb1-465d-9971-6997efdceb43
                        expected_key: GITHUB_PAT
                        env: GH_TOKEN
                        encoding: text
                  other:
                    ttl_seconds: 604800
                    validator: none
                    secrets:
                      - id: 11111111-1111-4111-8111-111111111111
                        expected_key: OTHER_SECRET
                        env: OTHER_SECRET
                        encoding: text
                """
            ),
            encoding="utf-8",
        )
        self.fake_gh_log = self.root / "fake-gh-argv.json"
        self.fake_gh = self.bin_dir / "gh"
        self.fake_gh.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path
                import sys

                Path(os.environ["FAKE_GH_LOG"]).write_text(json.dumps(sys.argv[1:]))
                if sys.argv[1:3] == ["api", "user"]:
                    if os.environ.get("GH_TOKEN") == "prototype-secret-value":
                        print('{"login":"prototype-user"}')
                        raise SystemExit(0)
                    raise SystemExit(4)
                if sys.argv[1:3] == ["auth", "setup-git"]:
                    raise SystemExit(0)
                raise SystemExit(3)
                """
            ),
            encoding="utf-8",
        )
        self.fake_gh.chmod(0o700)
        self.base_env = os.environ.copy()
        self.base_env.update(
            {
                "PYTHONPATH": str(PROJECT_ROOT),
                "FAKE_GH_LOG": str(self.fake_gh_log),
            }
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_cli(self, *args: str, env: dict[str, str] | None = None):
        command = [
            sys.executable,
            "-m",
            "bit_secret_hub",
            "--config",
            str(self.config),
            *args,
        ]
        return subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=env or self.base_env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_secret_absent(self, result: subprocess.CompletedProcess[str]) -> None:
        combined = result.stdout + result.stderr
        self.assertNotIn(SECRET, combined)
        self.assertNotIn(BWS_TOKEN, combined)

    def test_refresh_writes_private_profile_cache_without_printing_secrets(self):
        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_absent(result)
        cache_file = self.state_dir / "cache" / "github.json"
        self.assertTrue(cache_file.exists())
        self.assertEqual(stat.S_IMODE(cache_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)

        cache = json.loads(cache_file.read_text(encoding="utf-8"))
        self.assertNotIn(SECRET, cache_file.read_text(encoding="utf-8"))
        self.assertEqual(cache["values"]["GH_TOKEN"], "cHJvdG90eXBlLXNlY3JldC12YWx1ZQ==")
        self.assertRegex(cache["content_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(cache["status"], "verified")

    def test_status_json_contains_metadata_but_no_secret(self):
        self.assertEqual(self.run_cli("refresh", "github").returncode, 0)

        result = self.run_cli("status", "github", "--json")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_absent(result)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["profile"], "github")
        self.assertEqual(payload["status"], "ready")
        self.assertIn("expires_at", payload)

    def test_exec_injects_selected_profile_and_removes_managed_and_bootstrap_values(self):
        self.assertEqual(self.run_cli("refresh", "github").returncode, 0)
        self.assertEqual(self.run_cli("refresh", "other").returncode, 0)
        observation = self.root / "child.json"
        child = self.root / "observe.py"
        child.write_text(
            textwrap.dedent(
                """\
                import hashlib
                import json
                import os
                from pathlib import Path
                import sys

                payload = {
                    "gh_hash": hashlib.sha256(os.environ["GH_TOKEN"].encode()).hexdigest(),
                    "has_other": "OTHER_SECRET" in os.environ,
                    "has_bws": "BWS_ACCESS_TOKEN" in os.environ,
                }
                Path(sys.argv[1]).write_text(json.dumps(payload))
                """
            ),
            encoding="utf-8",
        )
        env = self.base_env.copy()
        env.update(
            {
                "GH_TOKEN": "stale-value",
                "OTHER_SECRET": "stale-other",
                "BWS_ACCESS_TOKEN": "stale-bootstrap",
            }
        )

        result = self.run_cli(
            "exec", "github", "--offline", "--", sys.executable, str(child), str(observation), env=env
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_absent(result)
        payload = json.loads(observation.read_text(encoding="utf-8"))
        self.assertEqual(payload["gh_hash"], hashlib.sha256(SECRET.encode()).hexdigest())
        self.assertFalse(payload["has_other"])
        self.assertFalse(payload["has_bws"])

        audit_text = (self.state_dir / "audit" / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn(Path(sys.executable).name, audit_text)
        self.assertNotIn(str(child), audit_text)
        self.assertNotIn(SECRET, audit_text)
        self.assertNotIn(BWS_TOKEN, audit_text)

    def test_remote_missing_deletes_whole_profile_cache(self):
        self.assertEqual(self.run_cli("refresh", "github").returncode, 0)
        self.bws_data.write_text("{}", encoding="utf-8")

        result = self.run_cli("refresh", "github")

        self.assertNotEqual(result.returncode, 0)
        self.assert_secret_absent(result)
        self.assertFalse((self.state_dir / "cache" / "github.json").exists())

    def test_remote_unavailable_preserves_unexpired_profile_cache(self):
        self.assertEqual(self.run_cli("refresh", "github").returncode, 0)
        self.bws_unavailable.touch()

        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 4)
        self.assert_secret_absent(result)
        self.assertTrue((self.state_dir / "cache" / "github.json").exists())
        offline = self.run_cli("exec", "github", "--offline", "--", "/bin/true")
        self.assertEqual(offline.returncode, 0, offline.stderr)

    def test_expired_cache_cannot_be_used_offline(self):
        self.assertEqual(self.run_cli("refresh", "github").returncode, 0)
        cache_file = self.state_dir / "cache" / "github.json"
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
        cache["expires_at"] = "2000-01-01T00:00:00+00:00"
        hashable = {key: value for key, value in cache.items() if key != "content_sha256"}
        encoded = json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode()
        cache["content_sha256"] = hashlib.sha256(encoded).hexdigest()
        cache_file.write_text(json.dumps(cache), encoding="utf-8")
        cache_file.chmod(0o600)

        result = self.run_cli("exec", "github", "--offline", "--", "/bin/true")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expired", result.stderr.lower())
        self.assert_secret_absent(result)

    def test_unknown_config_field_fails_closed(self):
        with self.config.open("a", encoding="utf-8") as handle:
            handle.write("unknown_field: true\n")

        result = self.run_cli("status", "github", "--json")

        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown", result.stderr.lower())
        self.assert_secret_absent(result)

    def test_profile_name_cannot_escape_cache_directory(self):
        config_text = self.config.read_text(encoding="utf-8")
        config_text = config_text.replace("  github:\n", "  ../escape:\n", 1)
        self.config.write_text(config_text, encoding="utf-8")

        result = self.run_cli("status", "../escape", "--json")

        self.assertEqual(result.returncode, 2)
        self.assertIn("profile name", result.stderr.lower())
        self.assert_secret_absent(result)

    def test_target_environment_variable_must_be_a_safe_identifier(self):
        config_text = self.config.read_text(encoding="utf-8")
        config_text = config_text.replace("env: GH_TOKEN", "env: PATH", 1)
        self.config.write_text(config_text, encoding="utf-8")

        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 2)
        self.assertIn("environment variable", result.stderr.lower())
        self.assert_secret_absent(result)

    def test_bws_secret_id_must_be_a_uuid(self):
        config_text = self.config.read_text(encoding="utf-8")
        config_text = config_text.replace(
            "id: 486c3235-2cb1-465d-9971-6997efdceb43",
            "id: bitwarden-server",
            1,
        )
        self.config.write_text(config_text, encoding="utf-8")

        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 2)
        self.assertIn("secret id", result.stderr.lower())
        self.assert_secret_absent(result)

    def test_bws_provider_receives_bootstrap_token_but_not_other_managed_secrets(self):
        env = self.base_env.copy()
        env["OTHER_SECRET"] = "stale-other-secret"

        result = self.run_cli("refresh", "github", env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_absent(result)

    def test_cache_integrity_failure_blocks_execution(self):
        self.assertEqual(self.run_cli("refresh", "github").returncode, 0)
        cache_file = self.state_dir / "cache" / "github.json"
        cache_file.write_text('{"tampered":true}\n', encoding="utf-8")
        cache_file.chmod(0o600)

        result = self.run_cli("exec", "github", "--offline", "--", "/bin/true")

        self.assertEqual(result.returncode, 5)
        self.assertIn("cache", result.stderr.lower())
        self.assert_secret_absent(result)

    def test_insecure_token_permissions_fail_closed(self):
        self.token_file.chmod(0o644)

        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 6)
        self.assertIn("permissions", result.stderr.lower())
        self.assert_secret_absent(result)

    def test_insecure_existing_state_directory_fails_closed(self):
        self.state_dir.mkdir(mode=0o755)
        self.state_dir.chmod(0o755)

        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 6)
        self.assertIn("permissions", result.stderr.lower())
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o755)
        self.assert_secret_absent(result)

    def test_github_validator_marks_refreshed_cache_verified_without_leaking_token(self):
        config_text = self.config.read_text(encoding="utf-8")
        config_text = config_text.replace("validator: none", "validator: github", 1)
        config_text += f"gh_path: {self.fake_gh}\n"
        self.config.write_text(config_text, encoding="utf-8")

        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_absent(result)
        snapshot = json.loads(
            (self.state_dir / "cache" / "github.json").read_text(encoding="utf-8")
        )
        self.assertEqual(snapshot["status"], "verified")
        self.assertNotIn(SECRET, self.fake_gh_log.read_text(encoding="utf-8"))

    def test_github_validator_failure_keeps_cache_but_blocks_exec(self):
        config_text = self.config.read_text(encoding="utf-8")
        config_text = config_text.replace("validator: none", "validator: github", 1)
        config_text += f"gh_path: {self.fake_gh}\n"
        self.config.write_text(config_text, encoding="utf-8")
        self.fake_gh.write_text("#!/bin/sh\nexit 4\n", encoding="utf-8")
        self.fake_gh.chmod(0o700)

        result = self.run_cli("refresh", "github")

        self.assertEqual(result.returncode, 7)
        self.assert_secret_absent(result)
        self.assertTrue((self.state_dir / "cache" / "github.json").exists())
        snapshot = json.loads(
            (self.state_dir / "cache" / "github.json").read_text(encoding="utf-8")
        )
        self.assertEqual(snapshot["status"], "unverified")
        blocked = self.run_cli("exec", "github", "--offline", "--", "/bin/true")
        self.assertEqual(blocked.returncode, 5)

    def test_setup_git_passes_only_host_and_force_to_gh(self):
        config_text = self.config.read_text(encoding="utf-8")
        config_text += f"gh_path: {self.fake_gh}\n"
        self.config.write_text(config_text, encoding="utf-8")

        result = self.run_cli("setup-git", "--hostname", "github.com")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_absent(result)
        self.assertEqual(
            json.loads(self.fake_gh_log.read_text(encoding="utf-8")),
            ["auth", "setup-git", "--hostname", "github.com", "--force"],
        )

    @unittest.skipUnless(shutil.which("gh") and shutil.which("git"), "gh and git required")
    def test_real_gh_credential_helper_uses_environment_token_without_persisting_it(self):
        gh_path = shutil.which("gh")
        isolated_home = self.root / "isolated-home"
        gh_config = isolated_home / "gh"
        isolated_home.mkdir(mode=0o700)
        env = self.base_env.copy()
        env.update(
            {
                "GH_CONFIG_DIR": str(gh_config),
                "GH_TOKEN": SECRET,
                "HOME": str(isolated_home),
                "GIT_CONFIG_GLOBAL": str(isolated_home / ".gitconfig"),
            }
        )

        credential = subprocess.run(
            [gh_path, "auth", "git-credential", "get"],
            input="protocol=https\nhost=github.com\n\n",
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(credential.returncode, 0, credential.stderr)
        fields = dict(
            line.split("=", 1)
            for line in credential.stdout.splitlines()
            if "=" in line
        )
        self.assertEqual(fields["username"], "x-access-token")
        self.assertEqual(hashlib.sha256(fields["password"].encode()).hexdigest(), hashlib.sha256(SECRET.encode()).hexdigest())
        self.assertFalse((gh_config / "hosts.yml").exists())

        setup = subprocess.run(
            [gh_path, "auth", "setup-git", "--hostname", "github.com", "--force"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(setup.returncode, 0, setup.stderr)
        git_config = (isolated_home / ".gitconfig").read_text(encoding="utf-8")
        self.assertIn("auth git-credential", git_config)
        self.assertNotIn(SECRET, git_config)
        self.assertFalse((gh_config / "hosts.yml").exists())


if __name__ == "__main__":
    unittest.main()
