"""Private operation-journal tests; no installed profile or server is used."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import setup_progress as progress


class SetupProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-setup-progress-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.storage = self.root / "private"
        self.args = {"url": "https://example.test:443/attacca/", "root_path": self.root / "repo",
                     "runtime": "codex", "client_instance": "client-one",
                     "request": {"create_project": "Example", "role": "director", "identity_mode": "new"},
                     "storage_root": self.storage}

    def operation(self, **changes):
        return progress.operation(**dict(self.args, **changes))

    def test_resume_exact_identity_without_mutating_request_or_defaults(self):
        with self.operation() as first:
            first.before_mutation("project_create")
            first.project_created("example")
            first.before_mutation("identity_register")
            first.identity_registered("example.director.codex.gibbs")
            operation_id = first.record["operation_id"]
        with self.operation() as resumed:
            self.assertTrue(resumed.resumed)
            self.assertEqual(resumed.state, "identity_registered")
            self.assertEqual(resumed.actor_id, "example.director.codex.gibbs")
            self.assertEqual(resumed.record["operation_id"], operation_id)
            resumed.complete()

    def test_pending_project_resumes_without_new_workspace(self):
        with self.operation() as first:
            first.project_created("example")
        with self.operation() as resumed:
            self.assertTrue(resumed.resumed)
            self.assertEqual(resumed.project_id, "example")
            self.assertIsNone(resumed.actor_id)

    def test_unchanged_retry_after_started_is_safe(self):
        with self.operation():
            pass
        with self.operation() as resumed:
            self.assertTrue(resumed.resumed)
            self.assertEqual(resumed.state, "started")

    def test_changed_unfinished_request_refuses_even_when_same_project(self):
        with self.operation() as first:
            first.project_created("example")
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_request_conflict"):
            with self.operation(request={"create_project": "Example", "role": "worker"}):
                self.fail("different request resumed")

    def test_lost_workspace_response_stops_instead_of_allocating_again(self):
        with self.operation() as first:
            first.before_mutation("project_create")
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_outcome_unknown.*project_create"):
            with self.operation():
                self.fail("ambiguous allocation resumed")

    def test_lost_persona_response_stops_instead_of_allocating_again(self):
        with self.operation() as first:
            first.project_created("example")
            first.before_mutation("identity_register")
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_outcome_unknown.*identity_register"):
            with self.operation():
                self.fail("ambiguous allocation resumed")

    def test_exception_keeps_acknowledged_identity_for_retry(self):
        with self.assertRaisesRegex(RuntimeError, "later failure"):
            with self.operation() as first:
                first.project_created("example")
                first.identity_registered("example.director.codex.gibbs")
                raise RuntimeError("later failure")
        with self.operation() as resumed:
            self.assertEqual(resumed.actor_id, "example.director.codex.gibbs")

    def test_completed_operation_allows_deliberate_new_identity(self):
        with self.operation() as first:
            first.project_created("example")
            first.identity_registered("example.director.codex.gibbs")
            previous_id = first.record["operation_id"]
            first.complete()
        with self.operation() as new:
            self.assertFalse(new.resumed)
            self.assertEqual(new.state, "started")
            self.assertIsNone(new.actor_id)
            self.assertNotEqual(new.record["operation_id"], previous_id)

    def test_every_scope_dimension_is_isolated(self):
        with self.operation() as first:
            first.project_created("example")
        for replacement in ({"url": "https://elsewhere.test/attacca"},
                            {"url": "https://example.test/another"},
                            {"root_path": self.root / "other-repo"},
                            {"runtime": "claude"}, {"client_instance": "client-two"}):
            with self.subTest(replacement=replacement), self.operation(**replacement) as different:
                self.assertFalse(different.resumed)
                self.assertIsNone(different.project_id)

    def test_equivalent_origin_uses_same_record(self):
        with self.operation() as first:
            first.project_created("example")
        with self.operation(url="https://EXAMPLE.test/attacca") as resumed:
            self.assertTrue(resumed.resumed)

    def test_private_permissions_and_only_validated_request_fields_stored(self):
        request = dict(self.args["request"], identity_actor="example.director.codex.gibbs")
        with self.operation(request=request) as first:
            record = json.loads(first.path.read_text())
            self.assertEqual(record["request"], request)
            self.assertEqual(record["request_sha256"], progress._digest(request))
            self.assertEqual(stat.S_IMODE(first.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.storage.stat().st_mode), 0o700)
        with self.assertRaisesRegex(progress.SetupProgressError, "unknown setup request fields"):
            with self.operation(request={"password": "not-allowed"}):
                self.fail("accepted credential field")

    def test_simultaneous_apply_is_rejected(self):
        with self.operation():
            with self.assertRaisesRegex(progress.SetupProgressError, "setup_in_progress"):
                with self.operation():
                    self.fail("concurrent setup entered")

    def test_record_cannot_be_changed_after_lock_released(self):
        with self.operation() as first:
            pass
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_progress_closed"):
            first.project_created("example")

    def test_bad_transitions_and_changed_identity_are_refused(self):
        with self.operation() as first:
            with self.assertRaises(progress.SetupProgressError):
                first.identity_registered("example.director.codex.gibbs")
            with self.assertRaises(progress.SetupProgressError):
                first.complete()
            first.project_created("example")
            with self.assertRaises(progress.SetupProgressError):
                first.project_created("elsewhere")
            with self.assertRaises(progress.SetupProgressError):
                first.identity_registered("elsewhere.director.codex.gibbs")
            first.identity_registered("example.director.codex.gibbs")
            with self.assertRaises(progress.SetupProgressError):
                first.identity_registered("example.director.codex.turing")

    def test_corrupt_record_does_not_start_another_operation(self):
        with self.operation() as first:
            path = first.path
        path.write_text("{not json")
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_progress_invalid"):
            with self.operation():
                self.fail("corrupt state ignored")

    def test_world_readable_record_is_rejected(self):
        with self.operation() as first:
            path = first.path
        path.chmod(0o644)
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_progress_unsafe"):
            with self.operation():
                self.fail("unsafe file accepted")

    def test_symlink_record_or_directory_is_rejected(self):
        with self.operation() as first:
            path = first.path
        saved = self.root / "saved.json"
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_progress_unsafe"):
            with self.operation():
                self.fail("symlink followed")
        alias = self.root / "alias"
        alias.symlink_to(self.storage)
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_progress_unsafe"):
            with self.operation(storage_root=alias):
                self.fail("symlink directory followed")

    def test_scope_tampering_and_oversized_record_are_rejected(self):
        with self.operation() as first:
            path = first.path
            record = first.record
        record["scope"]["client_instance"] = "another-client"
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(progress.SetupProgressError, "scope or schema mismatch"):
            with self.operation():
                self.fail("wrong scope accepted")
        path.write_text(" " * (progress.MAX_BYTES + 1))
        with self.assertRaisesRegex(progress.SetupProgressError, "too large"):
            with self.operation():
                self.fail("oversized record accepted")

    def test_atomic_write_failure_does_not_advance_in_memory_checkpoint(self):
        with self.operation() as first:
            with mock.patch.object(progress.os, "replace", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    first.project_created("example")
            self.assertEqual(first.state, "started")
            self.assertEqual(json.loads(first.path.read_text())["state"], "started")

    def test_explicit_rejection_can_retry_but_does_not_advance(self):
        with self.operation() as first:
            first.before_mutation("project_create")
            first.mutation_rejected("project_create")
            self.assertEqual(first.state, "started")
        with self.operation() as retry:
            self.assertTrue(retry.resumed)
            retry.before_mutation("project_create")
            retry.project_created("example")
            retry.before_mutation("identity_register")
            with self.assertRaises(progress.SetupProgressError):
                retry.mutation_rejected("project_create")
            retry.mutation_rejected("identity_register")
            retry.before_mutation("identity_register")
            retry.identity_registered("example.director.codex.gibbs")

    def test_interactive_choices_survive_and_cannot_change_on_retry(self):
        choices = {"role": "director", "lead": "current", "identity_mode": "new",
                   "identity_actor": None, "make_default": True, "bridge": None,
                   "relationship": None, "principal": "other"}
        with self.operation() as first:
            first.project_created("example")
            first.network_requested(choices)
        with self.operation() as retry:
            self.assertEqual(retry.record["network_requested"], choices)
            retry.network_requested(choices)
            with self.assertRaisesRegex(progress.SetupProgressError, "setup_request_conflict"):
                retry.network_requested(dict(choices, lead="clear"))
            retry.identity_registered("example.director.codex.gibbs")

    def test_saved_identity_requires_exact_runtime_and_confirmed_role(self):
        with self.operation() as first:
            first.project_created("example")
            first.network_requested({"role": "worker"})
            for actor in ("example.worker.claude.gibbs", "example.director.codex.gibbs",
                          "example.human.codex.gibbs", "example.worker.codex.gibbs.extra"):
                with self.subTest(actor=actor), self.assertRaises(progress.SetupProgressError):
                    first.identity_registered(actor)
            first.identity_registered("example.worker.codex.gibbs")

    def test_network_checkpoint_never_accepts_arbitrary_fields_or_secret_values(self):
        with self.operation() as first:
            for choices in ({"password": "secret"}, {"lead": "secret"},
                            {"make_default": "secret"}, {"identity_actor": "value with spaces"}):
                with self.subTest(choices=choices), self.assertRaises(progress.SetupProgressError):
                    first.network_requested(choices)

    def test_non_regular_record_is_rejected_without_blocking(self):
        with self.operation() as first:
            path = first.path
        path.unlink()
        os.mkfifo(path, mode=0o600)
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_progress_unsafe"):
            with self.operation():
                self.fail("FIFO accepted")

    def test_symlinked_lock_is_not_followed_or_repaired(self):
        with self.operation() as first:
            lock = first.path.with_suffix(".lock")
        target = self.root / "target"
        target.write_text("preserve")
        target.chmod(0o644)
        lock.unlink()
        lock.symlink_to(target)
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_progress_unsafe"):
            with self.operation():
                self.fail("lock symlink accepted")
        self.assertEqual(target.read_text(), "preserve")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_read_copy_cannot_change_journal_or_saved_identity(self):
        with self.operation() as first:
            copy = first.record
            copy["state"] = "completed"
            copy["scope"]["runtime"] = "claude"
            self.assertEqual(first.state, "started")
            self.assertEqual(first.record["scope"]["runtime"], "codex")

    def test_corrected_unallocated_request_is_not_permanently_blocked(self):
        with self.operation() as first:
            old_id = first.record["operation_id"]
        with self.operation(request={"create_project": "Changed", "role": "director"}) as corrected:
            self.assertFalse(corrected.resumed)
            self.assertNotEqual(corrected.record["operation_id"], old_id)
            self.assertEqual(corrected.state, "started")

    def test_recovery_errors_expose_exact_non_secret_inspection_metadata(self):
        with self.operation() as first:
            first.project_created("example")
            first.before_mutation("identity_register")
            path = first.path
            operation_id = first.record["operation_id"]
        with self.assertRaises(progress.SetupProgressError) as captured:
            with self.operation():
                self.fail("ambiguous retry entered")
        self.assertEqual(captured.exception.journal_path, str(path))
        self.assertEqual(captured.exception.project_id, "example")
        self.assertEqual(captured.exception.operation_id, operation_id)
        self.assertIn(str(path), str(captured.exception))

    def test_explicit_verified_recovery_retains_original_request_and_resumes(self):
        with self.operation() as first:
            first.before_mutation("project_create")
            fingerprint = first.record["request_sha256"]
        recovery_args = {key: value for key, value in self.args.items() if key != "request"}
        recovered = progress.recover(**recovery_args, project_id="example")
        self.assertEqual(recovered["request_sha256"], fingerprint)
        with self.operation() as retry:
            retry.before_mutation("identity_register")
        with self.assertRaises(progress.SetupProgressError):
            progress.recover(**recovery_args, project_id="different", actor_id="different.director.codex.gibbs")
        recovered = progress.recover(**recovery_args, project_id="example", actor_id="example.director.codex.gibbs")
        self.assertEqual(recovered["state"], "identity_registered")
        with self.operation() as retry:
            self.assertEqual(retry.actor_id, "example.director.codex.gibbs")

    def test_windows_byte_lock_fallback_and_unlock(self):
        fallback = mock.Mock(LK_NBLCK=2, LK_UNLCK=0)
        with mock.patch.object(progress, "fcntl", None), mock.patch.object(progress, "msvcrt", fallback):
            with self.operation() as first:
                first.project_created("example")
        self.assertEqual([call.args[1:] for call in fallback.locking.call_args_list], [(2, 1), (0, 1)])

    def test_windows_lock_contention_does_not_unlock_someone_else(self):
        fallback = mock.Mock(LK_NBLCK=2, LK_UNLCK=0)
        fallback.locking.side_effect = OSError("locked")
        with mock.patch.object(progress, "fcntl", None), mock.patch.object(progress, "msvcrt", fallback):
            with self.assertRaisesRegex(progress.SetupProgressError, "setup_in_progress"):
                with self.operation():
                    self.fail("contended Windows lock entered")
        self.assertEqual(fallback.locking.call_count, 1)

    def test_effective_auto_identity_choice_round_trips_unchanged(self):
        with self.operation() as first:
            first.project_created("example")
            first.network_requested({"role": "director", "identity_mode": "auto", "make_default": None})
            first.identity_registered("example.director.codex.gibbs", identity_mode="new", make_default=True)
        with self.operation() as retry:
            self.assertEqual(retry.record["network_requested"]["identity_mode"], "auto")
            self.assertEqual(retry.record["identity_mode"], "new")
            self.assertIs(retry.record["make_default"], True)
            with self.assertRaises(progress.SetupProgressError):
                retry.identity_registered(retry.actor_id, identity_mode="reuse", make_default=False)
            retry.identity_registered(retry.actor_id, identity_mode="new", make_default=True)

    def test_effective_identity_metadata_rejects_unknown_modes_and_non_boolean_default(self):
        with self.operation() as first:
            first.project_created("example")
            for options in ({"identity_mode": "unknown"}, {"make_default": "false"}):
                with self.subTest(options=options), self.assertRaises(progress.SetupProgressError):
                    first.identity_registered("example.director.codex.gibbs", **options)

    def test_inspect_pending_returns_exact_request_copy_and_completed_is_absent(self):
        inspect_args = {key: value for key, value in self.args.items() if key != "request"}
        self.assertIsNone(progress.inspect_pending(**inspect_args))
        with self.operation() as first:
            first.project_created("example")
        pending = progress.inspect_pending(**inspect_args)
        self.assertEqual(pending["request"], self.args["request"])
        pending["request"]["role"] = "worker"
        self.assertEqual(progress.inspect_pending(**inspect_args)["request"]["role"], "director")
        self.assertIsNone(progress.inspect_pending(**dict(inspect_args, client_instance="different")))
        with self.operation() as resumed:
            resumed.complete()
        self.assertIsNone(progress.inspect_pending(**inspect_args))

    def test_old_digest_only_schema_remains_readable_without_guessed_choices(self):
        with self.operation() as first:
            first.project_created("example")
            path = first.path
            record = first.record
        del record["request"]
        path.write_text(json.dumps(record))
        inspect_args = {key: value for key, value in self.args.items() if key != "request"}
        pending = progress.inspect_pending(**inspect_args)
        self.assertNotIn("request", pending)
        self.assertEqual(pending["project_id"], "example")
        with self.operation() as resumed:
            self.assertTrue(resumed.resumed)

    def test_saved_request_tampering_is_rejected(self):
        with self.operation() as first:
            path = first.path
            record = first.record
        record["request"]["role"] = "worker"
        path.write_text(json.dumps(record))
        inspect_args = {key: value for key, value in self.args.items() if key != "request"}
        with self.assertRaisesRegex(progress.SetupProgressError, "fingerprint mismatch"):
            progress.inspect_pending(**inspect_args)

    def test_request_values_are_typed_and_bounded_before_writing(self):
        invalid = ({"create_project": "\nsecret"}, {"role": "unexpected"},
                   {"make_default": "yes"}, {"skip_tools": "codex"},
                   {"actor_id": {"token": "secret"}}, {"create_project": "x" * 513})
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(progress.SetupProgressError):
                with self.operation(request=request):
                    self.fail("invalid request persisted")

    def test_actor_types_match_the_cli_contract(self):
        for actor_type in ("human", "agent", "system"):
            with self.subTest(actor_type=actor_type), self.operation(request={"actor_type": actor_type}) as current:
                self.assertEqual(current.record["request"]["actor_type"], actor_type)
        with self.assertRaisesRegex(progress.SetupProgressError, "actor_type"):
            with self.operation(request={"actor_type": "service"}):
                self.fail("CLI-incompatible actor type accepted")

    def test_expected_resume_rejects_completed_operation_without_starting_another(self):
        with self.operation() as original:
            original.project_created("example")
            expected = original.record["operation_id"]
            original.complete()
            path = original.path
        before = path.read_bytes()
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_resume_changed"):
            with self.operation(expected_operation_id=expected):
                self.fail("confirmation started another operation")
        self.assertEqual(path.read_bytes(), before)

    def test_expected_resume_rejects_missing_or_replaced_record(self):
        expected = "a" * 32
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_resume_changed"):
            with self.operation(expected_operation_id=expected):
                self.fail("missing original operation was created")
        self.assertEqual(list(self.storage.glob("*.json")), [])
        with self.operation() as replacement:
            replacement.project_created("example")
            path = replacement.path
        before = path.read_bytes()
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_resume_changed"):
            with self.operation(expected_operation_id=expected):
                self.fail("replacement operation was adopted")
        self.assertEqual(path.read_bytes(), before)

    def test_expected_resume_preserves_exact_unfinished_operation(self):
        with self.operation() as original:
            original.project_created("example")
            original.identity_registered("example.director.codex.gibbs")
            expected = original.record["operation_id"]
        with self.operation(expected_operation_id=expected) as resumed:
            self.assertTrue(resumed.resumed)
            self.assertEqual(resumed.actor_id, "example.director.codex.gibbs")
            self.assertEqual(resumed.record["operation_id"], expected)

    def test_expected_resume_cannot_change_even_unallocated_confirmed_request(self):
        with self.operation() as original:
            expected = original.record["operation_id"]
        with self.assertRaisesRegex(progress.SetupProgressError, "setup_request_conflict"):
            with self.operation(expected_operation_id=expected, request={"create_project": "Other"}):
                self.fail("confirmation silently changed original choices")


if __name__ == "__main__":
    unittest.main()
