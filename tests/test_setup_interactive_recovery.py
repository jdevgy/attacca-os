"""Independent real-HTTP/CLI recovery checks in disposable client homes."""

import io
import json
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock


class InteractiveSetupRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Reuse fixture helpers, not inherited tests. Every server listens on
        # an ephemeral loopback port and all state lives in TemporaryDirectory.
        from tests.test_setup_auth_consistency import SetupAuthenticationConsistencyTests
        self.fixture = SetupAuthenticationConsistencyTests(
            "test_explicit_local_discovery_and_apply_need_no_key_or_browser_pairing")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.local()

    def test_interactive_partial_create_resumes_before_workspace_picker(self):
        fixture = self.fixture
        argv = ["--db", str(fixture.root / "client.sqlite"), "--actor", "codex",
                "--actor-type", "agent", "setup", "--url", fixture.url,
                "--interactive", "--skip-tools", "all", "--no-server"]
        first_prompts = []

        def first_answer(prompt):
            first_prompts.append(prompt)
            if "create the first workspace" in prompt:
                return "checkout"
            if "tools to SKIP" in prompt:
                return "all"
            return ""

        with fixture.direct_cli_context() as core, \
                mock.patch("builtins.input", side_effect=first_answer), \
                mock.patch.object(core, "_finish_remote_checkout", side_effect=core.AttaccaError(
                    "injected local publication failure")):
            with self.assertRaisesRegex(core.AttaccaError, "setup_partial_progress"):
                core.cli_main(argv)
        actors = fixture.rows("SELECT agent_id FROM agents WHERE project_id='checkout'")
        self.assertEqual(len(actors), 1)
        self.assertFalse((fixture.checkout / ".attacca" / "project.json").exists())

        retry_prompts = []

        def retry_answer(prompt):
            retry_prompts.append(prompt)
            return "all" if "tools to SKIP" in prompt else ""

        with fixture.direct_cli_context() as core, mock.patch("builtins.input", side_effect=retry_answer):
            self.assertEqual(core.cli_main(argv), 0)
        self.assertEqual(fixture.rows("SELECT agent_id FROM agents"), actors)
        self.assertEqual(len(fixture.rows("SELECT project_id FROM projects")), 1)
        self.assertEqual(fixture.assert_registered_and_linked("checkout"), actors[0]["agent_id"])
        self.assertTrue(any("resum" in prompt.lower() for prompt in retry_prompts), retry_prompts)
        self.assertFalse(any("matches workspace" in prompt or "choose identity" in prompt
                             or "choose this AI's role" in prompt for prompt in retry_prompts), retry_prompts)

    def _check_definitive_rejection_retry(self, rejected_path, status):
        fixture = self.fixture
        original_open = urllib.request.urlopen
        intercepted = []

        def reject_allocation(request, *args, **kwargs):
            if getattr(request, "method", None) == "POST" and \
                    urllib.parse.urlsplit(request.full_url).path == rejected_path:
                intercepted.append(request.full_url)
                raise urllib.error.HTTPError(
                    request.full_url, status, "injected explicit rejection", {},
                    io.BytesIO(b'{"error":"injected explicit authorization rejection"}'))
            return original_open(request, *args, **kwargs)

        with fixture.direct_cli_context() as core, \
                mock.patch.object(urllib.request, "urlopen", side_effect=reject_allocation):
            with self.assertRaises(core.AttaccaError) as captured:
                core.cli_main(fixture.direct_apply_args())
        self.assertIn("injected explicit authorization rejection", str(captured.exception))
        self.assertEqual(len(intercepted), 1)
        journals = list((fixture.home / ".attacca" / "setup-progress").glob("*.json"))
        self.assertEqual(len(journals), 1)
        self.assertIsNone(json.loads(journals[0].read_text())["in_flight"])
        self.assertEqual(fixture.rows("SELECT agent_id FROM agents"), [])
        with fixture.direct_cli_context() as core:
            self.assertEqual(core.cli_main(fixture.direct_apply_args()), 0)
        fixture.assert_registered_and_linked("partial-example")
        self.assertEqual(len(fixture.rows("SELECT project_id FROM projects")), 1)

    def test_actual_http401_project_rejection_clears_inflight_for_retry(self):
        self._check_definitive_rejection_retry("/v1/projects", 401)

    def test_actual_http403_identity_rejection_clears_inflight_for_retry(self):
        self._check_definitive_rejection_retry("/v1/projects/partial-example/agents", 403)


if __name__ == "__main__":
    unittest.main()
