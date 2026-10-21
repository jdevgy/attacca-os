"""Independent setup/auth boundary checks using only disposable HTTP servers.

Optional login must not start pairing for a healthy anonymous installation.
A credential that is actually supplied still keeps its normal scope and may
never silently become an anonymous request after rejection.
"""

import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import terminal_flow as flow
import setup_progress


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "attacca_setup_auth_security_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class SetupAuthBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-setup-security-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "server.sqlite"
        self.credentials = self.root / "credentials.json"
        self.instance = "isolated-client-installation"
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("ATTACCA_", "CODEX_", "CLAUDE_", "KIMI_"))}
        environment.update(HOME=str(self.root), USERPROFILE=str(self.root),
                           ATTACCA_DISABLE_WATCHER="1", ATTACCA_AUTOSTART="0")
        patcher = mock.patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, value in (("CREDENTIALS_FILE", self.credentials),
                            ("IDENTITY_FILE", self.root / "identity.json")):
            patcher = mock.patch.object(c, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, value in (("find_project_link", None),
                            ("load_client_instance_id", self.instance),
                            ("load_device_id", "isolated-device"),
                            ("load_owner", None),
                            ("_terminal_flow_runtime", flow)):
            patcher = mock.patch.object(c, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        c._remote_setup_auth.context = None
        self.addCleanup(setattr, c._remote_setup_auth, "context", None)
        self.server = c.AttaccaServer(("127.0.0.1", 0), self.db)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.port = self.server.server_address[1]
        self.assertNotEqual(self.port, 4173)
        self.url = "http://127.0.0.1:%d" % self.port
        conn = c.connect(self.db)
        try:
            c.auth_create_user(conn, "owner", "isolated-owner-password", bootstrap=True)
            c.auth_create_user(conn, "member", "isolated-member-password")
            self.owner = self._principal(conn, "owner")
            self.member = self._principal(conn, "member")
            for project in ("alpha", "beta"):
                c.set_current_owner("member")
                c.project_init(conn, "web.member", "human", path=self.root / project,
                               project_id=project, name=project.title())
                c.auth_grant_project_membership(conn, self.member, project)
                c.agent_register(conn, project, "web.member", "human",
                                 agent_id=project + ".director.codex", role="director",
                                 runtime="codex", canonical_identity=False,
                                 registration_username="member")
            self.key = c.auth_client_key_create(
                conn, self.member, "Isolated test key", self.instance,
                memberships=["alpha"])
        finally:
            c.set_current_owner(None)
            conn.close()

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    @staticmethod
    def _principal(conn, username):
        user = conn.execute("SELECT * FROM auth_users WHERE username=?", (username,)).fetchone()
        return c._auth_principal(conn, user, "session", session_hash="isolated-fixture")

    def _mode(self, mode):
        conn = c.connect(self.db)
        try:
            if mode == "legacy":
                for key in ("server.setup_mode", "auth.activated", "auth.deactivated_by",
                            "auth.deactivated_at"):
                    conn.execute("DELETE FROM server_settings WHERE setting_key=?", (key,))
            else:
                c.auth_activate(conn, self.owner, confirmed=True, server=self.server,
                                enabled=mode == "protected")
        finally:
            conn.close()
        self.assertEqual(self.request("/v1/auth/status")[1]["access_mode"], mode)
        c._remote_setup_auth.context = None

    def request(self, path, token=None, actor=None, instance=None):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
            headers[c.CLIENT_INSTANCE_HEADER] = instance or self.instance
        if actor:
            headers["X-Attacca-Actor"] = actor
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def durable_counts(self):
        conn = c.connect(self.db)
        try:
            return {table: conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                    for table in ("projects", "agents", "events", "auth_project_memberships",
                                  "auth_client_authorizations")}
        finally:
            conn.close()

    def test_optional_anonymous_setup_and_provision_never_start_pairing(self):
        for mode in ("legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), mock.patch.object(
                    flow, "authorize_client", side_effect=AssertionError("unexpected pairing")):
                for interactive in (False, True):
                    result = c._ensure_client_setup_auth(
                        self.url, "codex", interactive=interactive)
                    self.assertFalse(result["required"])
                    self.assertFalse(result["authenticated"])
                provision = c.provision_setup_agent_token(
                    self.url, "alpha", "alpha.director.codex")
                self.assertEqual(provision["status"], "ready")
                self.assertFalse(provision["credential_saved"])
                self.assertFalse(provision["authentication_required"])
            self.assertEqual(self.durable_counts(), before)

    def test_optional_provision_still_requires_the_exact_registered_agent(self):
        for mode in ("legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), mock.patch.object(
                    flow, "authorize_client", side_effect=AssertionError("unexpected pairing")):
                with self.assertRaisesRegex(c.AttaccaError, "exact registered agent"):
                    c.provision_setup_agent_token(
                        self.url, "alpha", "alpha.director.codex.missing")
            self.assertEqual(self.durable_counts(), before)

    def test_selected_key_project_allowlist_is_not_broadened_by_optional_login(self):
        for mode in ("protected", "legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            with self.subTest(mode=mode):
                status, body = self.request("/v1/projects/beta/status", self.key["token"],
                                            "beta.director.codex")
                self.assertEqual(status, 403, body)
                self.assertIn("outside key scope", body["error"])
                self.assertEqual(self.request("/v1/projects/alpha/status", self.key["token"],
                                              "alpha.director.codex")[0], 200)
            self.assertEqual(self.durable_counts(), before)

    def test_selected_key_membership_revocation_is_not_bypassed_in_any_mode(self):
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE auth_project_memberships SET revoked_at=? WHERE user_id=?",
                         (c.now_iso(), self.member["user_id"]))
        finally:
            conn.close()
        for mode in ("protected", "legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            with self.subTest(mode=mode):
                status, body = self.request("/v1/projects/alpha/status", self.key["token"],
                                            "alpha.director.codex")
                self.assertEqual(status, 403, body)
                self.assertIn("no workspace membership", body["error"])
            self.assertEqual(self.durable_counts(), before)

    def test_invalid_or_revoked_credentials_never_downgrade_to_anonymous(self):
        conn = c.connect(self.db)
        try:
            c.auth_client_key_revoke(conn, self.member, self.key["record"]["token_id"])
        finally:
            conn.close()
        for mode in ("protected", "legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            for token in ("atkey_nonexistent.test-secret", self.key["token"]):
                with self.subTest(mode=mode, revoked=token == self.key["token"]):
                    status, body = self.request("/v1/projects/alpha/status", token,
                                                "alpha.director.codex")
                    self.assertEqual(status, 401, body)
                    self.assertEqual(body["code"], "invalid_credential")
                    self.assertNotIn(token, json.dumps(body))
            self.assertEqual(self.durable_counts(), before)

    def test_wrong_installation_is_rejected_without_anonymous_fallback(self):
        for mode in ("protected", "legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            with self.subTest(mode=mode):
                status, body = self.request("/v1/projects/alpha/status", self.key["token"],
                                            "alpha.director.codex", instance="another-installation")
                self.assertEqual(status, 403, body)
                self.assertIn("client_instance_mismatch", body["error"])
            self.assertEqual(self.durable_counts(), before)

    def test_optional_setup_does_not_swallow_a_rejected_environment_key(self):
        for mode in ("legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            for token, instance, expected in (
                    ("atkey_invalid.environment-key", self.instance, "invalid_credential"),
                    (self.key["token"], "wrong-installation", "client_instance_mismatch")):
                with self.subTest(mode=mode, expected=expected), \
                        mock.patch.dict(os.environ, {c.ENV_API_TOKEN: token}), \
                        mock.patch.object(c, "load_client_instance_id", return_value=instance), \
                        mock.patch.object(flow, "authorize_client",
                                          side_effect=AssertionError("unexpected pairing")):
                    with self.assertRaisesRegex(c.AttaccaError, expected) as error:
                        c._ensure_client_setup_auth(self.url, "codex")
                    self.assertNotIn(token, str(error.exception))
                    self.assertIsNone(c._remote_setup_auth.context)
            self.assertEqual(self.durable_counts(), before)

    def test_selected_environment_key_scope_is_checked_before_provisioning(self):
        for mode in ("protected", "legacy", "local"):
            self._mode(mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), \
                    mock.patch.dict(os.environ, {c.ENV_API_TOKEN: self.key["token"]}), \
                    mock.patch.object(flow, "authorize_client",
                                      side_effect=AssertionError("unexpected pairing")):
                verified = c._ensure_client_setup_auth(self.url, "codex")
                self.assertTrue(verified["authenticated"])
                with self.assertRaisesRegex(c.AttaccaError, "outside key scope"):
                    c.provision_setup_agent_token(self.url, "beta", "beta.director.codex")
            self.assertEqual(self.durable_counts(), before)

    def test_active_environment_key_verifies_older_actor_beyond_first_page(self):
        self._mode("protected")
        conn = c.connect(self.db)
        try:
            for number in range(65):
                c.agent_register(
                    conn, "alpha", "web.member", "human",
                    agent_id="alpha.worker.codex.fixture%d" % number,
                    role="worker", runtime="codex", canonical_identity=False,
                    registration_username="member")
            conn.execute(
                "UPDATE agents SET registered_at='2000-01-01T00:00:00Z' "
                "WHERE project_id='alpha' AND agent_id='alpha.director.codex'")
        finally:
            conn.close()
        status, page = self.request(
            "/v1/projects/alpha/agents", self.key["token"], "alpha.director.codex")
        self.assertEqual(status, 200, page)
        self.assertEqual(len(page["agents"]), 60)
        self.assertNotIn("alpha.director.codex", [row["agent_id"] for row in page["agents"]])
        before = self.durable_counts()
        with mock.patch.dict(os.environ, {c.ENV_API_TOKEN: self.key["token"]}), \
                mock.patch.object(flow, "authorize_client",
                                  side_effect=AssertionError("unexpected pairing")):
            verified = c._ensure_client_setup_auth(self.url, "codex")
            self.assertTrue(verified["authenticated"])
            self.assertEqual(verified["credential_source"], "environment")
            provision = c.provision_setup_agent_token(
                self.url, "alpha", "alpha.director.codex")
            self.assertEqual(provision["status"], "ready")
            self.assertEqual(provision["credential_source"], "active_process")
            self.assertFalse(provision["credential_saved"])
        self.assertEqual(self.durable_counts(), before)

    def _checkpoint_identity(self, label):
        arguments = {
            "url": self.url, "root_path": self.root / "checkout", "runtime": "codex",
            "client_instance": self.instance, "storage_root": self.root / label,
            "request": {"attach_project": "alpha", "role": "director", "identity_mode": "new"},
        }
        with setup_progress.operation(**arguments) as progress:
            progress.project_created("alpha")
            progress.identity_registered("alpha.director.codex", identity_mode="new",
                                         make_default=True)
        return arguments

    def test_resumed_actor_revalidates_ownership_before_saving_default(self):
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE agents SET owner='owner' WHERE agent_id='alpha.director.codex'")
        finally:
            conn.close()
        for mode in ("protected", "legacy", "local"):
            self._mode(mode)
            checkpoint = self._checkpoint_identity("ownership-" + mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), \
                    mock.patch.dict(os.environ, {c.ENV_API_TOKEN: self.key["token"]}), \
                    mock.patch.object(c, "machine_actor_binding_set") as save_binding, \
                    setup_progress.operation(**checkpoint) as progress:
                self.assertTrue(progress.resumed)
                with self.assertRaisesRegex(c.AttaccaError, "client_actor_denied"):
                    c.apply_remote_network_setup(
                        self.url, "alpha", "codex", "agent", role="director",
                        identity_mode="new", home=self.root, client_instance=self.instance,
                        progress=progress)
                save_binding.assert_not_called()
                self.assertEqual(progress.state, "identity_registered")
            self.assertEqual(self.durable_counts(), before)

    def test_resumed_workspace_revalidates_membership_before_any_new_allocation(self):
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE auth_project_memberships SET revoked_at=? WHERE user_id=?",
                         (c.now_iso(), self.member["user_id"]))
        finally:
            conn.close()
        for mode in ("protected", "legacy", "local"):
            self._mode(mode)
            checkpoint = self._checkpoint_identity("membership-" + mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), \
                    mock.patch.dict(os.environ, {c.ENV_API_TOKEN: self.key["token"]}), \
                    setup_progress.operation(**checkpoint) as progress:
                with self.assertRaisesRegex(c.AttaccaError, "setup_recovery_access_required"):
                    c.one_shot_remote_setup(
                        "codex", "agent", self.root / "unused.sqlite", url=self.url,
                        path=self.root / "checkout", home=self.root,
                        attach_project="alpha", manage_server=False, manage_tools=False,
                        defer_checkout=True, progress=progress)
                self.assertFalse((self.root / "checkout" / ".attacca" / "project.json").exists())
            self.assertEqual(self.durable_counts(), before)

    def test_anonymous_recovery_revalidates_registered_role(self):
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE agents SET role='worker' WHERE agent_id='alpha.director.codex'")
        finally:
            conn.close()
        for mode in ("legacy", "local"):
            self._mode(mode)
            checkpoint = self._checkpoint_identity("role-" + mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), \
                    mock.patch.object(c, "machine_actor_binding_set") as save_binding, \
                    setup_progress.operation(**checkpoint) as progress:
                with self.assertRaisesRegex(c.AttaccaError, "setup_recovery_identity_changed"):
                    c.apply_remote_network_setup(
                        self.url, "alpha", "codex", "agent", role="director",
                        identity_mode="new", home=self.root, client_instance=self.instance,
                        progress=progress)
                save_binding.assert_not_called()
            self.assertEqual(self.durable_counts(), before)

    def test_anonymous_recovery_revalidates_registered_runtime(self):
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE agents SET runtime='claude' WHERE agent_id='alpha.director.codex'")
        finally:
            conn.close()
        for mode in ("legacy", "local"):
            self._mode(mode)
            checkpoint = self._checkpoint_identity("runtime-" + mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), \
                    mock.patch.object(c, "machine_actor_binding_set") as save_binding, \
                    setup_progress.operation(**checkpoint) as progress:
                with self.assertRaisesRegex(c.AttaccaError, "setup_recovery_identity_changed"):
                    c.apply_remote_network_setup(
                        self.url, "alpha", "codex", "agent", role="director",
                        identity_mode="new", home=self.root, client_instance=self.instance,
                        progress=progress)
                save_binding.assert_not_called()
            self.assertEqual(self.durable_counts(), before)

    def test_recovery_uses_complete_authorized_workspace_directory(self):
        conn = c.connect(self.db)
        try:
            for index in range(65):
                project = "z-newer-%02d" % index
                c.project_init(conn, "fixture", "agent", path=self.root / project,
                               project_id=project, name=project)
        finally:
            conn.close()
        for mode in ("legacy", "local"):
            self._mode(mode)
            first_page = self.request("/v1/projects")[1]
            self.assertNotIn("alpha", [item["project_id"] for item in first_page["projects"]])
            checkpoint = self._checkpoint_identity("pagination-" + mode)
            before = self.durable_counts()
            with self.subTest(mode=mode), setup_progress.operation(**checkpoint) as progress:
                result = c.one_shot_remote_setup(
                    "codex", "agent", self.root / "unused.sqlite", url=self.url,
                    path=self.root / "checkout", home=self.root, attach_project="alpha",
                    manage_server=False, manage_tools=False, write_instructions=False,
                    defer_checkout=True, progress=progress)
                self.assertEqual(result["project_id"], "alpha")
                self.assertEqual(result["matched_by"], "setup_recovery")
                self.assertFalse((self.root / "checkout" / ".attacca" / "project.json").exists())
            self.assertEqual(self.durable_counts(), before)


if __name__ == "__main__":
    unittest.main()
