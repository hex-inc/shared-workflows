"""Tests for the policy pull. Run: python -m unittest discover -s socket"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pull_socket_policies as pull
import sync_socket_policies as sync
from test_sync_socket_policies import REPO_LICENSE, REPO_SECURITY, FakeSession, shuffled


class PullTests(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ["SOCKET_API_KEY"] = "token"

        # Work on copies: a bug here must never rewrite the checked-in policies.
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        self.security = tmp / sync.SECURITY_FILE.name
        self.license = tmp / sync.LICENSE_FILE.name
        shutil.copy(sync.SECURITY_FILE, self.security)
        shutil.copy(sync.LICENSE_FILE, self.license)
        for attr, path in (("SECURITY_FILE", self.security), ("LICENSE_FILE", self.license)):
            patch = mock.patch.object(pull, attr, path)
            patch.start()
            self.addCleanup(patch.stop)

    @staticmethod
    def run_main(session) -> str:
        out = io.StringIO()
        with mock.patch.object(sync.requests, "Session", return_value=session):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                pull.main()
        return out.getvalue()

    def assert_pull_fails(self, session, message: str) -> None:
        """A failed pull raises; `message` is matched literally against the exception."""
        with mock.patch.object(sync.requests, "Session", return_value=session):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, re.escape(message)):
                    pull.main()

    def live(self, security=None, license=None, **kwargs) -> FakeSession:
        return FakeSession(
            {
                "security-policy": security if security is not None else REPO_SECURITY,
                "license-policy/view": license if license is not None else REPO_LICENSE,
            },
            **kwargs,
        )

    def test_checked_in_files_are_rendered_exactly_as_this_script_writes_them(self):
        """Otherwise the next real change would carry reformatting noise with it."""
        session = self.live()
        for path, policy in (
            (sync.SECURITY_FILE, pull.fetch_security(session)),
            (sync.LICENSE_FILE, pull.fetch_license(session)),
        ):
            with self.subTest(path.name):
                self.assertEqual(path.read_text(encoding="utf-8"), pull.render(policy))

    def test_a_pull_with_no_ui_changes_leaves_git_clean(self):
        before = (self.security.read_bytes(), self.license.read_bytes())

        output = self.run_main(self.live())

        self.assertEqual((self.security.read_bytes(), self.license.read_bytes()), before)
        self.assertIn("socket-security-policy.json: no changes", output)
        self.assertIn("socket-license-policy.json: no changes", output)
        self.assertIn("nothing to commit", output)

    def test_socket_returning_a_different_order_is_not_a_change(self):
        before = self.license.read_bytes()
        live = {**REPO_LICENSE, "allow": shuffled(REPO_LICENSE["allow"])}

        output = self.run_main(self.live(license=live))

        self.assertIn("socket-license-policy.json: no changes", output)
        self.assertEqual(self.license.read_bytes(), before)

    def test_a_reordered_file_is_left_alone_rather_than_called_drift(self):
        messy = json.dumps({**REPO_LICENSE, "allow": shuffled(REPO_LICENSE["allow"])}, indent=2)
        self.license.write_text(messy + "\n", encoding="utf-8")

        output = self.run_main(self.live())

        self.assertIn("socket-license-policy.json: no changes", output)
        self.assertEqual(self.license.read_text(encoding="utf-8"), messy + "\n")

    def test_deny_is_dropped_and_lists_are_sorted(self):
        live = {
            "allow": shuffled(REPO_LICENSE["allow"]),
            "warn": ["MPL-2.0"],
            "monitor": [],
            "options": [],
            "deny": ["GPL-3.0", "AGPL-3.0"],
        }

        self.run_main(self.live(license=live))
        written = json.loads(self.license.read_text())

        self.assertNotIn("deny", written)
        self.assertEqual(list(written), ["allow", "warn", "monitor", "options"])
        self.assertEqual(written["allow"], sorted(REPO_LICENSE["allow"]))
        self.assertEqual(written["warn"], ["MPL-2.0"])

    def test_reports_what_the_ui_change_was(self):
        live = json.loads(json.dumps(REPO_SECURITY))
        live["securityPolicyRules"]["gptMalware"] = {"action": "error"}
        live["securityPolicyDefault"] = "high"

        output = self.run_main(self.live(security=live))

        self.assertIn("socket-security-policy.json: 2 change(s)", output)
        self.assertIn("gptMalware: repo=warn live=error", output)
        self.assertIn("(default): repo=medium live=high", output)
        self.assertEqual(json.loads(self.security.read_text()), live)
        # The untouched policy is still reported, and one change is enough to commit.
        self.assertIn("socket-license-policy.json: no changes", output)
        self.assertIn("open a PR", output)

    def test_an_unknown_key_from_socket_stops_the_pull(self):
        before = (self.security.read_bytes(), self.license.read_bytes())
        live = {**REPO_SECURITY, "unexpectedMetadata": {"updatedBy": "someone"}}

        self.assert_pull_fails(self.live(security=live), "unrecognised key(s) unexpectedMetadata")

        self.assertEqual((self.security.read_bytes(), self.license.read_bytes()), before)

    def test_restores_a_file_that_has_been_emptied(self):
        self.license.write_text('{"allow": [], "warn": [], "monitor": [], "options": []}\n')

        output = self.run_main(self.live())

        self.assertEqual(json.loads(self.license.read_text()), REPO_LICENSE)
        self.assertIn("MIT: repo=(absent) live=allow", output)

    def test_restores_a_file_that_has_been_deleted(self):
        self.license.unlink()

        output = self.run_main(self.live())

        self.assertEqual(json.loads(self.license.read_text()), REPO_LICENSE)
        self.assertIn(f"{len(REPO_LICENSE['allow'])} change(s)", output)

    def test_an_emptied_policy_is_written_but_every_loss_is_reported(self):
        """Socket is trusted here; the safety net is reviewing the diff before committing."""
        empty = {"allow": [], "warn": [], "monitor": [], "options": []}

        output = self.run_main(self.live(license=empty))

        self.assertEqual(json.loads(self.license.read_text()), empty)
        self.assertIn(f"{len(REPO_LICENSE['allow'])} change(s)", output)
        self.assertIn("MIT: repo=allow live=(absent)", output)

    def test_leaves_both_files_alone_when_a_fetch_fails(self):
        before = (self.security.read_bytes(), self.license.read_bytes())

        self.assert_pull_fails(self.live(license=403), "HTTP 403")

        self.assertEqual((self.security.read_bytes(), self.license.read_bytes()), before)

    def test_rejects_a_license_bucket_that_is_not_a_list_of_strings(self):
        session = self.live(license={"allow": [{"id": "MIT"}]})
        self.assert_pull_fails(session, "expected allow to be a list of strings")

    def test_requires_an_api_key(self):
        os.environ["SOCKET_API_KEY"] = ""
        self.assert_pull_fails(self.live(), "SOCKET_API_KEY is required")


if __name__ == "__main__":
    unittest.main()
