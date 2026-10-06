"""Local-source installer: no download, safe URL wiring, native-tool parity."""

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import attacca
import install as local_install


ROOT = Path(__file__).resolve().parents[1]


class PythonInstallerUnitTests(unittest.TestCase):
    def test_canonical_origins(self):
        for value, expected in (
                ("http://127.0.0.1:4173/", "http://127.0.0.1:4173"),
                ("https://Example.COM:443", "https://example.com"),
                ("http://[::1]:4173", "http://[::1]:4173")):
            with self.subTest(value=value):
                self.assertEqual(local_install.server_origin(value), expected)

    def test_unsafe_or_ambiguous_origins_rejected(self):
        for value in ("", "ftp://example.com", "http://user:secret@example.com",
                      "http://example.com/path", "http://example.com/?query=1",
                      "http://example.com/#fragment", "http://bad$host:4173",
                      "http://`id`:4173", "http://$(id):4173",
                      'http://host";id:4173', "http://example.com:99999",
                      "http://example.com\n", " http://example.com",
                      "http://exa\tmple.com", "http://[broken" ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    local_install.server_origin(value)

    def test_payload_uses_local_snapshot_and_neutral_cwd(self):
        observed = {}

        def run(command, **kwargs):
            observed.update(kwargs)
            self.assertEqual(command, ["/test/sh"])
            archive_path = Path(kwargs["env"]["ATTACCA_INSTALL_ARCHIVE"])
            self.assertEqual(archive_path.parent, Path(kwargs["cwd"]))
            self.assertNotEqual(Path(kwargs["cwd"]), ROOT)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.read("install.py"),
                                 (ROOT / "install.py").read_bytes())
                self.assertEqual(archive.read("attacca.py"),
                                 (ROOT / "attacca.py").read_bytes())
                for name in ("plugin-mcp.json", ".codex-plugin/plugin.json"):
                    config = json.loads(archive.read(name))
                    for server in config["mcpServers"].values():
                        self.assertEqual(server["env"]["ATTACCA_URL"],
                                         "https://example.com:8443")
                self.assertFalse(set(archive.namelist()) & {
                    "AGENTS.md", "CLAUDE.md", ".attacca/project.json",
                    ".mcp.json", "attacca.db"})
            self.assertIn('BASE="https://example.com:8443"', kwargs["input"])
            self.assertIn("ATTACCA_INSTALL_ARCHIVE", kwargs["input"])
            return subprocess.CompletedProcess(command, 7)

        with mock.patch.object(local_install.shutil, "which", return_value="/test/sh"), \
                mock.patch.object(local_install.subprocess, "run", side_effect=run):
            self.assertEqual(local_install.main(["--url", "https://example.com:8443"]), 7)
        self.assertFalse(Path(observed["cwd"]).exists())

    def test_missing_shell_fails_before_preparing_payload(self):
        with mock.patch.object(local_install.shutil, "which", return_value=None), \
                mock.patch.object(attacca, "_capture_distribution_snapshot") as snapshot, \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:
                local_install.main([])
            self.assertEqual(error.exception.code, 2)
            snapshot.assert_not_called()

    def test_runtime_only_mode_is_explicit_not_inherited(self):
        observed = []

        def run(command, **kwargs):
            observed.append(kwargs["env"])
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.dict(os.environ, {"ATTACCA_INSTALL_RUNTIME_ONLY": "1"}), \
                mock.patch.object(attacca, "_read_machine_config"), \
                mock.patch.object(local_install.shutil, "which", return_value="/test/sh"), \
                mock.patch.object(local_install.subprocess, "run", side_effect=run):
            self.assertEqual(local_install.main([
                "--runtime-only", "--url", "http://127.0.0.1:9"]), 0)
            self.assertEqual(local_install.main(["--url", "http://127.0.0.1:9"]), 0)
        self.assertEqual(observed[0]["ATTACCA_INSTALL_RUNTIME_ONLY"], "1")
        self.assertNotIn("ATTACCA_INSTALL_RUNTIME_ONLY", observed[1])

    def test_runtime_only_preflights_invalid_machine_config(self):
        with mock.patch.object(attacca, "_read_machine_config",
                               side_effect=attacca.AttaccaError("invalid machine config")), \
                mock.patch.object(attacca, "_capture_distribution_snapshot") as snapshot, \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:
                local_install.main(["--runtime-only", "--url", "http://127.0.0.1:9"])
            self.assertEqual(error.exception.code, 2)
            snapshot.assert_not_called()

    def test_normal_default_origin_remains_4173_without_machine_or_env_lookup(self):
        def run(command, **kwargs):
            self.assertIn('BASE="http://127.0.0.1:4173"', kwargs["input"])
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.dict(os.environ, {"ATTACCA_URL": "https://ignored.example.invalid"}), \
                mock.patch.object(attacca, "_read_machine_config") as machine, \
                mock.patch.object(attacca, "configured_server_url") as configured, \
                mock.patch.object(local_install.shutil, "which", return_value="/test/sh"), \
                mock.patch.object(local_install.subprocess, "run", side_effect=run):
            self.assertEqual(local_install.main([]), 0)
        machine.assert_not_called()
        configured.assert_not_called()

    def test_readme_keeps_short_start_and_separate_advanced_reference(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quick = readme.split("## Quick start (local server)", 1)[1].split(
            "## Everyday commands", 1)[0]
        self.assertLess(len(quick.split()), 300)
        self.assertIn("python3 install.py --url http://127.0.0.1:4173", quick)
        self.assertIn("curl -fsSL http://127.0.0.1:4173/install.sh | sh", quick)
        self.assertIn("python3 attacca.py auth reset-password USERNAME", readme)
        self.assertIn("attacca server set http://NEW_HOST:4173 --same-server", readme)
        self.assertEqual(readme.count("<details>"), 1)
        self.assertEqual(readme.count("</details>"), 1)
        self.assertLess(readme.index("<details>"), readme.index("## Architecture"))
        self.assertLess(readme.index("## REST API"), readme.index("</details>"))


@unittest.skipUnless(shutil.which("sh"), "POSIX shell required")
class PythonInstallerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-python-install-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for command in ("sh", "mktemp", "cp", "rm", "chmod", "mkdir", "ln", "sed"):
            path = shutil.which(command)
            if not path:
                self.skipTest("missing shell utility: " + command)
            (self.bin / command).symlink_to(path)
        (self.bin / "python3").symlink_to(sys.executable)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("ATTACCA_", "CODEX_", "CLAUDE_", "KIMI_"))}
        self.env.update({
            "HOME": str(self.home), "USERPROFILE": str(self.home),
            "PATH": str(self.bin), "PYTHONDONTWRITEBYTECODE": "1",
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_DATA_HOME": str(self.home / ".local/share"),
            "ATTACCA_DISABLE_WATCHER": "1", "ATTACCA_AUTOSTART": "0",
            "ATTACCA_DISABLE_SESSION_WAKE": "1",
            "TASK_TEST_COMMAND_LOG": str(self.root / "commands.txt"),
        })

    def run_install(self, extra_args=None, url="http://127.0.0.1:9"):
        # No server listens here. No curl/wget/native client from the real
        # machine is on PATH; all configuration belongs to this test's home.
        command = [sys.executable, "-B", str(ROOT / "install.py")]
        if url is not None:
            command.extend(["--url", url])
        command.extend(extra_args or [])
        result = subprocess.run(
            command,
            cwd=str(ROOT), env=self.env, capture_output=True, text=True,
            timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("local Attacca " + attacca.VERSION, result.stdout)
        self.assertNotIn("downloading attacca", result.stdout)
        installed = self.home / ".attacca/plugin/attacca"
        self.assertEqual((installed / "install.py").read_bytes(),
                         (ROOT / "install.py").read_bytes())
        self.assertEqual((installed / "attacca.py").read_bytes(),
                         (ROOT / "attacca.py").read_bytes())
        self.assertEqual((self.home / ".local/bin/attacca").resolve(),
                         installed / "attacca.py")
        return result

    def test_real_source_install_twice_without_curl_or_server(self):
        self.run_install()
        self.run_install()
        self.assertTrue((self.home / ".attacca/plugin-data/rollback/attacca/attacca.py").is_file())
        self.assertFalse((self.home / ".attacca/attacca.db").exists())

    def test_existing_database_is_neither_opened_nor_changed(self):
        database = self.home / ".attacca/attacca.db"
        database.parent.mkdir()
        sentinel = b"Installer must not even try to open this database.\n"
        database.write_bytes(sentinel)
        self.run_install()
        self.assertEqual(database.read_bytes(), sentinel)
        self.assertFalse(database.with_name("attacca.db-wal").exists())

    def test_same_installer_drives_native_clients(self):
        for client in ("claude", "codex", "kimi"):
            path = self.bin / client
            path.write_text('#!/bin/sh\nprintf "%s\\n" "' + client +
                            ' $*" >> "$TASK_TEST_COMMAND_LOG"\nexit 0\n')
            path.chmod(0o755)
        result = self.run_install()
        commands = (self.root / "commands.txt").read_text()
        self.assertIn("claude plugin install attacca@agentg --scope user", commands)
        self.assertIn("codex plugin add attacca@attacca-local", commands)
        self.assertIn("codex mcp get attacca", commands)
        self.assertIn("kimi code: native plugin installed/updated", result.stdout)
        self.assertTrue((self.home / ".codex/config.toml").is_file())

    def test_runtime_only_twice_preserves_clients_identities_and_private_state(self):
        sentinels = (
            ".codex/config.toml", ".codex/attacca-client.json",
            ".codex/plugins/cache/attacca-local/attacca/old/plugin.json",
            ".claude/settings.json", ".claude/attacca-client.json",
            ".claude/plugins/installed_plugins.json",
            ".kimi-code/plugins/installed.json", ".kimi-code/mcp.json",
            ".cursor/mcp.json", ".attacca/credentials.json",
            ".attacca/identity.json", ".attacca/client-instance.json",
            ".attacca/watcher/watcher-state.json",
            ".attacca/watcher/offline/scope/outboxes/device/records/one.json",
            ".attacca/watcher/wake/session/receipt.json", ".attacca/attacca.db",
        )
        before = {}
        for relative in sentinels:
            path = self.home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("Keep these bytes: " + relative + "\n").encode())
            before[path] = (path.read_bytes(), path.stat().st_mtime_ns)
        machine_path = self.home / ".attacca/config.json"
        machine = {
            "version": 1, "server_url": "https://old.example.invalid",
            "actor_bindings": {"saved": {"actor_id": "example.director.codex.newton"}},
            "other_setting": {"keep": True},
        }
        machine_path.write_text(json.dumps(machine))
        for client in ("claude", "codex", "kimi"):
            path = self.bin / client
            path.write_text('#!/bin/sh\nprintf "%s\\n" "' + client +
                            ' $*" >> "$TASK_TEST_COMMAND_LOG"\nexit 0\n')
            path.chmod(0o755)
        # Prove the branch itself skips watcher startup, not a test-only
        # environment switch. All other client code is isolated in this HOME.
        self.env.pop("ATTACCA_DISABLE_WATCHER")
        self.env.pop("ATTACCA_DISABLE_SESSION_WAKE")
        result = self.run_install(["--runtime-only"])
        machine_after = json.loads(machine_path.read_text())
        self.assertEqual(machine_after["server_url"], "http://127.0.0.1:9")
        self.assertEqual(machine_after["actor_bindings"], machine["actor_bindings"])
        self.assertEqual(machine_after["other_setting"], machine["other_setting"])
        self.assertEqual(machine_path.stat().st_mode & 0o777, 0o600)
        machine_bytes = machine_path.read_bytes()
        machine_mtime = machine_path.stat().st_mtime_ns
        self.run_install(["--runtime-only"])
        self.assertEqual(machine_path.read_bytes(), machine_bytes)
        self.assertEqual(machine_path.stat().st_mtime_ns, machine_mtime)
        for path, (data, modified) in before.items():
            self.assertEqual(path.read_bytes(), data, str(path))
            self.assertEqual(path.stat().st_mtime_ns, modified, str(path))
        self.assertFalse((self.root / "commands.txt").exists())
        self.assertNotIn("attacca watcher:", result.stdout)
        self.assertIn("runtime-only", result.stdout)
        self.assertTrue((self.home / ".attacca/plugin/attacca/hooks/session_start.py").is_file())
        self.assertTrue((self.home / ".attacca/plugin-data/rollback/attacca/attacca.py").is_file())
        self.assertFalse((self.home / ".attacca/attacca.db-wal").exists())

    def test_runtime_only_creates_no_database_or_client_registration(self):
        self.run_install(["--runtime-only"])
        for relative in (".attacca/attacca.db", ".attacca/credentials.json",
                         ".attacca/watcher", ".codex", ".claude", ".kimi-code"):
            self.assertFalse((self.home / relative).exists(), relative)
        machine = json.loads((self.home / ".attacca/config.json").read_text())
        self.assertEqual(machine["server_url"], "http://127.0.0.1:9")
        # The GitHub-cache runtime retains a localhost packaged/environment
        # default. The one machine origin must still win without editing it.
        env = dict(self.env, ATTACCA_URL="http://127.0.0.1:4173")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "attacca.py"), "--json", "server", "show"],
            cwd=str(self.root), env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads(result.stdout)
        self.assertEqual(status["server_url"], "http://127.0.0.1:9")
        self.assertEqual(status["source"], "machine")

    def test_runtime_only_without_url_preserves_existing_machine_origin(self):
        path = self.home / ".attacca/config.json"
        path.parent.mkdir()
        original = b'{"version":1,"server_url":"https://saved.example.invalid","actor_bindings":{}}\n'
        path.write_bytes(original)
        modified = path.stat().st_mtime_ns
        result = self.run_install(["--runtime-only"], url=None)
        self.assertIn("https://saved.example.invalid", result.stdout)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.stat().st_mtime_ns, modified)

    def test_runtime_only_rejects_unsafe_machine_config_before_install(self):
        path = self.home / ".attacca/config.json"
        path.parent.mkdir()
        target = self.root / "do-not-change.json"
        target.write_text('{"server_url":"https://saved.example.invalid"}')
        path.symlink_to(target)
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "install.py"), "--runtime-only"],
            cwd=str(self.root), env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertIn("safe regular file", result.stderr)
        self.assertFalse((self.home / ".attacca/plugin").exists())
        self.assertEqual(target.read_text(), '{"server_url":"https://saved.example.invalid"}')

    def test_inherited_runtime_only_environment_does_not_skip_normal_install(self):
        self.env["ATTACCA_INSTALL_RUNTIME_ONLY"] = "1"
        self.test_same_installer_drives_native_clients()


if __name__ == "__main__":
    unittest.main()
