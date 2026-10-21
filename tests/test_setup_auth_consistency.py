"""Real CLI setup must honor the server's effective authentication policy.

Only disposable loopback servers, databases, homes and checkouts are used. A
failed apply must never force pairing after allocating a permanent persona or
writing a link that the same installation cannot use.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import unittest
import zipfile
from unittest import mock

from tests import test_local_first_setup as fixture
from tests import test_auth_setup as auth_fixture


class SetupAuthenticationConsistencyTests(unittest.TestCase):
    # Share the isolated subprocess harness, not its test methods. The child
    # environment excludes installed clients, browser launchers and credentials.
    setUp = fixture.LocalFirstSetupCLITests.setUp
    start_server = fixture.LocalFirstSetupCLITests.start_server
    stop_server = fixture.LocalFirstSetupCLITests.stop_server
    restart_server = fixture.LocalFirstSetupCLITests.restart_server
    request = fixture.LocalFirstSetupCLITests.request
    auth_status = fixture.LocalFirstSetupCLITests.auth_status
    session_headers = staticmethod(fixture.LocalFirstSetupCLITests.session_headers)

    def cli(self, *args, extra_env=None):
        return subprocess.run(
            [sys.executable, "-B", str(fixture.SCRIPT), "--db",
             str(self.root / "client.sqlite"), "--actor", "codex",
             "--actor-type", "agent", "--json", "setup", "--url", self.url,
             *args], cwd=str(self.checkout),
            env={**self.env, **(extra_env or {})}, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=45)

    def apply(self, *args, extra_env=None):
        return self.cli(*args, "--role", "director", "--lead", "current",
                        "--skip-tools", "all", "--no-server",
                        extra_env=extra_env)

    def assert_cli_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def rows(self, query, parameters=()):
        with sqlite3.connect(str(self.db)) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(query, parameters)]

    def legacy(self):
        status, result, headers = self.request("POST", "/v1/auth/bootstrap", {
            "username": "operator", "password": "test-operator-password"})
        self.assertEqual(status, 201, result)
        self.browser = self.session_headers(headers)
        self.restart_server()
        access = self.auth_status()
        self.assertEqual(access["access_mode"], "legacy")
        self.assertFalse(access["authentication_required"])

    def local(self):
        status, result, _ = self.request("POST", "/v1/setup", {
            "mode": "local", "confirmed": True})
        self.assertEqual(status, 200, result)
        self.assertFalse(result["authentication_required"])
        self.assertTrue(result["anonymous_access"])

    def protected(self):
        status, result, headers = self.request("POST", "/v1/setup", {
            "mode": "protected", "confirmed": True,
            "username": "operator", "password": "test-operator-password"})
        self.assertEqual(status, 201, result)
        self.browser = self.session_headers(headers)
        self.assertTrue(result["authentication_required"])

    def assert_no_setup_side_effects(self):
        self.assertEqual(self.rows("SELECT project_id FROM projects"), [])
        self.assertEqual(self.rows("SELECT agent_id FROM agents"), [])
        self.assertFalse((self.checkout / ".attacca" / "project.json").exists())
        self.assertFalse((self.checkout / "AGENTS.md").exists())
        self.assertFalse((self.checkout / "CLAUDE.md").exists())
        self.assertFalse((self.checkout / ".mcp.json").exists())

    def assert_no_pairing(self):
        for table in ("auth_client_pairings", "auth_client_authorizations"):
            self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM " + table), [{"n": 0}])

    def assert_registered_and_linked(self, project_id):
        link = json.loads((self.checkout / ".attacca" / "project.json").read_text())
        self.assertEqual(link["project_id"], project_id)
        self.assertTrue((self.checkout / "AGENTS.md").is_file())
        actors = self.rows("SELECT agent_id FROM agents WHERE project_id=?", (project_id,))
        self.assertEqual(len(actors), 1, actors)
        self.assertTrue(actors[0]["agent_id"].startswith(project_id + ".director.codex."))
        return actors[0]["agent_id"]

    @contextlib.contextmanager
    def direct_cli_context(self):
        c = auth_fixture.c
        try:
            with mock.patch.dict(os.environ, self.env, clear=True), \
                    mock.patch.object(c.os, "getcwd", return_value=str(self.checkout)), \
                    mock.patch.object(c, "CREDENTIALS_FILE", self.home / "credentials.json"), \
                    mock.patch.object(c, "IDENTITY_FILE", self.home / "identity.json"), \
                    mock.patch.object(c._remote_setup_auth, "context", None, create=True), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                yield c
        finally:
            c.set_current_owner(None)
            c.set_current_git_context(None, None)

    def direct_apply_args(self, *extra):
        return ["--db", str(self.root / "client.sqlite"), "--actor", "codex",
                "--actor-type", "agent", "setup", "--url", self.url,
                "--create", "Partial Example", "--role", "director",
                "--identity-mode", "new", "--lead", "current",
                "--skip-tools", "all", "--no-server", *extra]

    def failed_final_verification(self):
        """Run the real CLI path with one final hosted-verification failure."""
        c = auth_fixture.c
        called = []

        def reject_verification(url, project_id, actor_id):
            called.append((project_id, actor_id))
            raise c.AuthenticationError("injected setup verification failure")

        with self.direct_cli_context(), \
                mock.patch.object(c, "provision_setup_agent_token", side_effect=reject_verification):
            with self.assertRaisesRegex(c.AttaccaError, "injected setup verification failure") as failed:
                c.cli_main(self.direct_apply_args())
        self.last_setup_error = str(failed.exception)
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0][0], "partial-example")
        self.assertEqual(self.rows(
            "SELECT agent_id FROM agents WHERE project_id='partial-example'"),
            [{"agent_id": called[0][1]}])
        return called[0][1]

    def test_legacy_optional_discovery_and_apply_agree_without_browser_pairing(self):
        self.legacy()
        discovery = self.cli("--discover")
        self.assert_cli_ok(discovery)
        discovered = json.loads(discovery.stdout)
        self.assertEqual(discovered["action"], "create_first_workspace")
        self.assertFalse(discovered["credential_required"])
        self.assertFalse(discovered["access"]["authentication_required"])
        self.assertEqual(discovered["access"]["access_mode"], "legacy")
        self.assertNotIn("principal", discovered["access"])
        self.assertNotIn("user", discovered["access"])
        applied = self.apply("--create", "Optional Example")
        self.assert_cli_ok(applied)
        self.assert_registered_and_linked("optional-example")
        self.assert_no_pairing()
        self.assertFalse(self.auth_status()["authentication_required"])
        self.assertEqual(self.auth_status()["access_mode"], "legacy")

    def test_explicit_local_discovery_and_apply_need_no_key_or_browser_pairing(self):
        self.local()
        discovery = self.cli("--discover")
        self.assert_cli_ok(discovery)
        discovered = json.loads(discovery.stdout)
        self.assertFalse(discovered["credential_required"])
        self.assertTrue(discovered["access"]["anonymous_access"])
        self.assertEqual(discovered["access"]["access_mode"], "local")
        applied = self.apply("--create", "Local Example")
        self.assert_cli_ok(applied)
        self.assert_registered_and_linked("local-example")
        self.assert_no_pairing()

    def test_optional_successful_rerun_keeps_one_permanent_persona(self):
        self.legacy()
        first = self.apply("--create", "Repeat Example")
        self.assert_cli_ok(first)
        actor = self.assert_registered_and_linked("repeat-example")
        second = self.apply("--attach", "repeat-example")
        self.assert_cli_ok(second)
        self.assertEqual(self.assert_registered_and_linked("repeat-example"), actor)
        self.assert_no_pairing()

    def test_interactive_optional_setup_does_not_start_pairing_without_explicit_login(self):
        self.legacy()
        c = auth_fixture.c
        flow = c._terminal_flow_runtime()
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(c, "CREDENTIALS_FILE", self.home / "credentials.json"), \
                mock.patch.object(c, "IDENTITY_FILE", self.home / "identity.json"), \
                mock.patch.object(c, "load_client_instance_id", return_value="client-interactive-test"), \
                mock.patch.object(c, "find_project_link", return_value=None), \
                mock.patch.object(c._remote_setup_auth, "context", None, create=True), \
                mock.patch.object(flow, "authorize_client", side_effect=AssertionError(
                    "optional setup must not request browser authorization")):
            checked = c.ensure_remote_setup_auth(self.url, "codex", interactive=True)
        self.assertFalse(checked["required"])
        self.assertFalse(checked["authenticated"])
        self.assert_no_setup_side_effects()
        self.assert_no_pairing()

    def test_protected_server_requires_authorization_before_any_setup_writes(self):
        self.protected()
        applied = self.apply("--create", "Protected Example")
        self.assertNotEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertIn("client_authorization_required", applied.stdout + applied.stderr)
        self.assert_no_setup_side_effects()

    def test_failed_final_verification_creates_no_checkout_files(self):
        self.legacy()
        self.failed_final_verification()
        for relative in (".attacca/project.json", "AGENTS.md", "CLAUDE.md", ".mcp.json"):
            self.assertFalse((self.checkout / relative).exists(), relative)

    def test_failed_final_verification_preserves_existing_checkout_bytes(self):
        self.legacy()
        existing = {
            "AGENTS.md": b"Local agent policy remains intact.\r\n",
            "CLAUDE.md": b"Local Claude policy remains intact.\n",
            ".attacca/project.json": b'{"schema_version":1,"project_id":"keep-existing"}\n',
            ".mcp.json": b'{"mcpServers":{"unrelated":{"command":"keep-me"}}}\n',
        }
        for relative, content in existing.items():
            target = self.checkout / relative
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(content)
        self.failed_final_verification()
        for relative, content in existing.items():
            self.assertEqual((self.checkout / relative).read_bytes(), content, relative)

    def test_retry_after_final_verification_failure_reuses_exact_allocated_actor(self):
        self.legacy()
        actor = self.failed_final_verification()
        self.assertIn("setup_partial_progress:", self.last_setup_error)
        self.assertIn("project=partial-example", self.last_setup_error)
        self.assertIn("actor=" + actor, self.last_setup_error)
        self.assertFalse((self.checkout / ".attacca" / "project.json").exists())
        self.assertFalse((self.checkout / "AGENTS.md").exists())
        with self.direct_cli_context() as c:
            self.assertEqual(c.cli_main(self.direct_apply_args()), 0)
        self.assertEqual(self.assert_registered_and_linked("partial-example"), actor)
        self.assertEqual(len(self.rows("SELECT project_id FROM projects")), 1)
        self.assert_no_pairing()

    def test_retry_after_binding_write_failure_restores_same_actor_and_default(self):
        self.local()
        with self.direct_cli_context() as c, \
                mock.patch.object(c, "machine_actor_binding_set", side_effect=OSError(
                    "injected binding write failure")):
            with self.assertRaisesRegex(c.AttaccaError, "setup_partial_progress:") as failed:
                c.cli_main(self.direct_apply_args())
            self.assertIn("injected binding write failure", str(failed.exception))
            self.assertIsNone(c.machine_actor_binding_get(self.url, "partial-example", "codex"))
        actors = self.rows("SELECT agent_id FROM agents WHERE project_id='partial-example'")
        self.assertEqual(len(actors), 1)
        actor = actors[0]["agent_id"]
        self.assertIn("actor=" + actor, str(failed.exception))
        self.assertFalse((self.checkout / ".attacca" / "project.json").exists())
        with self.direct_cli_context() as c:
            self.assertEqual(c.cli_main(self.direct_apply_args()), 0)
            binding = c.machine_actor_binding_get(self.url, "partial-example", "codex")
            self.assertEqual(binding["actor_id"], actor)
        self.assertEqual(self.assert_registered_and_linked("partial-example"), actor)

    def test_unfinished_setup_rejects_changed_choices_without_new_allocation(self):
        self.local()
        actor = self.failed_final_verification()
        before = self.rows("SELECT * FROM events")
        with self.direct_cli_context() as c:
            with self.assertRaisesRegex(c.AttaccaError, "setup_request_conflict"):
                c.cli_main(self.direct_apply_args("--role", "worker"))
        self.assertEqual(self.rows("SELECT * FROM events"), before)
        self.assertEqual(self.rows("SELECT agent_id FROM agents"), [{"agent_id": actor}])
        self.assertEqual(len(self.rows("SELECT project_id FROM projects")), 1)
        self.assertFalse((self.checkout / ".attacca" / "project.json").exists())

    def test_completed_explicit_new_request_can_intentionally_create_another_identity(self):
        self.local()
        self.assert_cli_ok(self.apply("--create", "Intentional Example", "--identity-mode", "new"))
        first = self.assert_registered_and_linked("intentional-example")
        self.assert_cli_ok(self.apply("--create", "Intentional Example", "--identity-mode", "new"))
        actors = self.rows("SELECT agent_id FROM agents WHERE project_id='intentional-example'")
        self.assertEqual(len(actors), 2)
        self.assertIn({"agent_id": first}, actors)
        self.assertEqual(len({actor["agent_id"] for actor in actors}), 2)
        self.assertEqual(len(self.rows("SELECT project_id FROM projects")), 1)
        self.assert_no_pairing()

    def test_lost_registration_response_never_blindly_allocates_another_persona(self):
        self.local()
        c = auth_fixture.c
        original_remote = c.remote_json
        allocated = []

        def lose_registration_response(url, method, path, *args, **kwargs):
            result = original_remote(url, method, path, *args, **kwargs)
            if method == "POST" and path == "/v1/projects/partial-example/agents":
                allocated.append(result["agent_id"])
                raise c.AttaccaError("injected lost registration response")
            return result

        with self.direct_cli_context(), mock.patch.object(c, "remote_json", side_effect=lose_registration_response):
            with self.assertRaisesRegex(c.AttaccaError, "setup_partial_progress:"):
                c.cli_main(self.direct_apply_args())
        self.assertEqual(len(allocated), 1)
        with self.direct_cli_context():
            with self.assertRaisesRegex(c.AttaccaError, "setup_outcome_unknown"):
                c.cli_main(self.direct_apply_args())
        self.assertEqual(self.rows("SELECT agent_id FROM agents"), [{"agent_id": allocated[0]}])
        self.assertFalse((self.checkout / ".attacca" / "project.json").exists())
        self.assertFalse((self.checkout / "AGENTS.md").exists())

    def test_packaged_and_stable_installed_runtime_support_optional_setup_and_recovery(self):
        self.legacy()
        c = auth_fixture.c
        extracted = self.root / "extracted-plugin"
        payload = c.build_plugin_zip(self.url)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertIn("setup_progress.py", archive.namelist())
            self.assertEqual(archive.read("setup_progress.py"),
                             (fixture.ROOT / "setup_progress.py").read_bytes())
            self.artifact_evidence = {
                "archive_sha256": hashlib.sha256(payload).hexdigest(),
                "runtime_sha256": hashlib.sha256(archive.read("attacca.py")).hexdigest(),
                "setup_progress_sha256": hashlib.sha256(archive.read("setup_progress.py")).hexdigest(),
                "entry_count": len(archive.namelist()),
            }
            archive.extractall(extracted)
        with mock.patch.object(fixture, "SCRIPT", extracted / "attacca.py"):
            discovery = self.cli("--discover")
            self.assert_cli_ok(discovery)
            self.assertFalse(json.loads(discovery.stdout)["credential_required"])
            self.assert_cli_ok(self.apply("--create", "Artifact Example"))
        actor = self.assert_registered_and_linked("artifact-example")
        for command in ("sh", "mktemp", "cp", "rm", "chmod", "mkdir", "ln", "sed"):
            executable = shutil.which(command)
            if not executable:
                self.skipTest("missing isolated installer utility: " + command)
            (self.bin / command).symlink_to(executable)
        (self.bin / "python3").symlink_to(sys.executable)
        installed = subprocess.run([
            sys.executable, "-B", str(extracted / "install.py"),
            "--runtime-only", "--url", self.url], cwd=str(self.root),
            env=self.env, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=60)
        self.assert_cli_ok(installed)
        stable = self.home / ".attacca" / "plugin" / "attacca"
        self.assertEqual((stable / "setup_progress.py").read_bytes(),
                         (extracted / "setup_progress.py").read_bytes())
        self.assertEqual((stable / "attacca.py").read_bytes(),
                         (extracted / "attacca.py").read_bytes())
        imported = subprocess.run([
            sys.executable, "-B", "-c",
            "import attacca, setup_progress; print(setup_progress.__file__)"],
            cwd=str(stable), env=self.env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=15)
        self.assert_cli_ok(imported)
        self.assertEqual(imported.stdout.strip(), str(stable / "setup_progress.py"))
        with mock.patch.object(fixture, "SCRIPT", stable / "attacca.py"):
            self.assert_cli_ok(self.apply("--attach", "artifact-example"))
        self.assertEqual(self.assert_registered_and_linked("artifact-example"), actor)
        self.assert_no_pairing()
        for relative in (".codex/config.toml", ".codex/plugins/installed_plugins.json",
                         ".claude/settings.json", ".claude/plugins/installed_plugins.json",
                         ".kimi-code/plugins/installed.json"):
            self.assertFalse((self.home / relative).exists(), relative)

    def test_rejected_key_is_not_silently_retried_anonymously_in_local_mode(self):
        self.local()
        applied = self.apply("--create", "Rejected Example", extra_env={
            "ATTACCA_API_TOKEN": "atkey_invalid.rejected-test-secret",
            "ATTACCA_CLIENT_INSTANCE": "client-rejected-test"})
        self.assertNotEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assert_no_setup_side_effects()
        self.assert_no_pairing()

    def test_rejected_key_is_not_silently_retried_anonymously_in_legacy_mode(self):
        self.legacy()
        applied = self.apply("--create", "Rejected Example", extra_env={
            "ATTACCA_API_TOKEN": "atkey_invalid.rejected-test-secret",
            "ATTACCA_CLIENT_INSTANCE": "client-rejected-test"})
        self.assertNotEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assert_no_setup_side_effects()
        self.assert_no_pairing()

    def test_explicit_local_does_not_expand_a_valid_keys_workspace_membership(self):
        self.local()
        c = auth_fixture.c
        connection = c.connect(self.db)
        try:
            c.auth_create_user(connection, "other", "test-other-password", "Other")
            user = connection.execute(
                "SELECT * FROM auth_users WHERE username='other'").fetchone()
            principal = c._auth_principal(connection, user, "session")
            key = c.auth_client_key_create(
                connection, principal, "Unscoped fixture client", "client-no-membership")
            c.project_init(connection, "anonymous", "human", path=self.root / "server-checkout",
                           project_id="existing-example", name="Existing Example")
        finally:
            c.set_current_owner(None)
            connection.close()
        before_projects = self.rows("SELECT * FROM projects")
        before_events = self.rows("SELECT * FROM events")
        headers = {"Authorization": "Bearer " + key["token"],
                   "X-Attacca-Client-Instance": "client-no-membership"}
        status, access, _ = self.request("GET", "/v1/auth/status", headers=headers)
        self.assertEqual(status, 200, access)
        self.assertTrue(access["authenticated"])
        self.assertFalse(access["authentication_required"])
        applied = self.apply("--create", "Existing Example", extra_env={
            "ATTACCA_API_TOKEN": key["token"],
            "ATTACCA_CLIENT_INSTANCE": "client-no-membership"})
        self.assertNotEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertIn("project_membership_required", applied.stdout + applied.stderr)
        self.assertEqual(self.rows("SELECT * FROM projects"), before_projects)
        self.assertEqual(self.rows("SELECT * FROM events"), before_events)
        self.assertEqual(self.rows("SELECT agent_id FROM agents"), [])
        self.assertEqual(self.rows("SELECT * FROM auth_project_memberships"), [])
        self.assertFalse((self.checkout / ".attacca" / "project.json").exists())
        self.assertFalse((self.checkout / "AGENTS.md").exists())
        self.assertFalse((self.checkout / "CLAUDE.md").exists())
        self.assert_no_pairing()


if __name__ == "__main__":
    unittest.main()
