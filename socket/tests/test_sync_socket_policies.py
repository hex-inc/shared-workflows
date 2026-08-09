"""Tests for the Socket policy sync. Run: python -m unittest discover -s socket"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import unittest
from unittest import mock

import sync_socket_policies as sync

REPO_SECURITY = json.loads((sync.HERE / "socket-security-policy.json").read_text())
REPO_LICENSE = json.loads((sync.HERE / "socket-license-policy.json").read_text())


class FakeResponse:
    def __init__(self, status: int, payload: dict) -> None:
        self.status_code = status
        self.ok = status < 400
        self.text = json.dumps(payload)
        self.content = self.text.encode()
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class FakeSession:
    """Answers GETs from `live`, matched on URL substring.

    A `live` value is either the payload to return or an HTTP status to fail with.
    Every call is recorded; an unmatched GET means the test itself is wrong.
    """

    def __init__(self, live: dict[str, dict | int], post_status: int = 200) -> None:
        self.live = live
        self.post_status = post_status
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, str, dict | None]] = []

    def request(self, method, url, json=None, timeout=None):  # noqa: A002 - requests' kwarg name
        self.calls.append((method, url, json))
        if method != "GET":
            return FakeResponse(self.post_status, {"ok": True})
        for fragment, payload in self.live.items():
            if fragment in url:
                if isinstance(payload, int):
                    return FakeResponse(payload, {"error": "denied"})
                return FakeResponse(200, payload)
        raise AssertionError(f"unexpected GET {url}")

    @property
    def posts(self) -> list[tuple[str, dict | None]]:
        return [(url, body) for method, url, body in self.calls if method == "POST"]


def shuffled(values: list[str]) -> list[str]:
    values = list(values)
    random.shuffle(values)
    return values


class FlattenTests(unittest.TestCase):
    def test_security_folds_default_in_with_the_rules(self):
        flat = sync.flatten_security(
            {
                "securityPolicyRules": {"gptMalware": {"action": "warn"}},
                "securityPolicyDefault": "medium",
            }
        )
        self.assertEqual(flat, {"gptMalware": "warn", "(default)": "medium"})

    def test_security_ignores_fields_other_than_action(self):
        flat = sync.flatten_security(
            {
                "securityPolicyRules": {"gptMalware": {"action": "warn", "addedAt": "2026-01-01"}},
                "securityPolicyDefault": "medium",
            }
        )
        self.assertEqual(flat["gptMalware"], "warn")

    def test_license_maps_each_name_to_its_bucket_and_ignores_deny(self):
        flat = sync.flatten_license(
            {
                "allow": ["MIT"],
                "warn": ["MPL-2.0"],
                "monitor": ["EPL-2.0"],
                "options": ["includeUnknown"],
                "deny": ["GPL-3.0"],
            }
        )
        self.assertEqual(
            flat,
            {
                "MIT": "allow",
                "MPL-2.0": "warn",
                "EPL-2.0": "monitor",
                "option:includeUnknown": "on",
            },
        )

    def test_license_keeps_both_buckets_when_a_license_is_listed_twice(self):
        flat = sync.flatten_license({"allow": ["MIT"], "warn": ["MIT"]})
        self.assertEqual(flat["MIT"], "allow+warn")

    def test_license_tolerates_missing_and_null_buckets(self):
        self.assertEqual(sync.flatten_license({"allow": None}), {})


class DiffTests(unittest.TestCase):
    def test_identical_policies_are_in_sync(self):
        self.assertEqual(sync.diff({"gptMalware": "warn"}, {"gptMalware": "warn"}), [])

    def test_reports_changed_added_and_removed_entries(self):
        self.assertEqual(
            sync.diff(
                {"changed": "ignore", "removed": "ignore"},
                {"changed": "error", "added": "warn"},
            ),
            [
                "added: repo=(absent) live=warn",
                "changed: repo=ignore live=error",
                "removed: repo=ignore live=(absent)",
            ],
        )


class LiveShapeTests(unittest.TestCase):
    """Socket growing a field must stop the run rather than be quietly ignored."""

    def test_accepts_the_shapes_socket_returns_today(self):
        session = FakeSession({"security-policy": REPO_SECURITY})
        self.assertEqual(sync.get_live_security(session), REPO_SECURITY)

    def test_the_derived_deny_list_is_accepted_and_ignored(self):
        live = {**REPO_LICENSE, "deny": ["AGPL-3.0", "SSPL-1.0"]}
        session = FakeSession({"license-policy/view": live})

        self.assertEqual(sync.get_live_license(session), live)
        flat = sync.flatten_license(live)
        self.assertNotIn("AGPL-3.0", flat)
        self.assertNotIn("deny", flat.values())

    def test_rejects_an_unknown_top_level_key(self):
        session = FakeSession({"license-policy/view": {**REPO_LICENSE, "blockList": []}})
        with self.assertRaisesRegex(RuntimeError, r"license policy: .*key\(s\) blockList"):
            sync.get_live_license(session)

    def test_names_every_unknown_key(self):
        session = FakeSession({"security-policy": {**REPO_SECURITY, "updatedBy": "x", "acl": 1}})
        with self.assertRaisesRegex(RuntimeError, r"key\(s\) acl, updatedBy"):
            sync.get_live_security(session)

    def test_rejects_an_unknown_field_on_a_single_rule(self):
        live = json.loads(json.dumps(REPO_SECURITY))
        live["securityPolicyRules"]["gptMalware"]["exemptions"] = []
        session = FakeSession({"security-policy": live})

        with self.assertRaisesRegex(RuntimeError, r"rule 'gptMalware'.*key\(s\) exemptions"):
            sync.get_live_security(session)


class RepoFileTests(unittest.TestCase):
    """The checked-in files must survive their own round trip."""

    def test_license_file_omits_deny(self):
        self.assertNotIn("deny", REPO_LICENSE)

    def test_license_ordering_and_a_derived_deny_list_are_not_drift(self):
        live = {
            "allow": shuffled(REPO_LICENSE["allow"]),
            "warn": REPO_LICENSE["warn"],
            "monitor": REPO_LICENSE["monitor"],
            "options": REPO_LICENSE["options"],
            "deny": ["GPL-3.0", "AGPL-3.0"],
        }
        self.assertEqual(
            sync.diff(sync.flatten_license(REPO_LICENSE), sync.flatten_license(live)), []
        )


class SyncTests(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)

    @staticmethod
    def run_sync(func, session, *, dry_run=False) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            func(session, "Policy", dry_run=dry_run)
        return out.getvalue()

    def test_in_sync_does_not_write(self):
        session = FakeSession({"security-policy": REPO_SECURITY})
        output = self.run_sync(sync.sync_security, session)
        self.assertIn("Policy: in sync", output)
        self.assertEqual(session.posts, [])

    def test_security_drift_posts_the_mapped_body(self):
        live = json.loads(json.dumps(REPO_SECURITY))
        live["securityPolicyRules"]["gptMalware"] = {"action": "ignore"}
        session = FakeSession({"security-policy": live})

        output = self.run_sync(sync.sync_security, session)

        self.assertIn("gptMalware: repo=warn live=ignore", output)
        self.assertIn("Policy: overwrite succeeded", output)
        [(url, body)] = session.posts
        self.assertIn("custom_rules_only=false", url)
        self.assertEqual(
            body,
            {
                "policyRules": REPO_SECURITY["securityPolicyRules"],
                "policyDefault": REPO_SECURITY["securityPolicyDefault"],
            },
        )

    def test_license_drift_posts_the_repo_file_as_is(self):
        live = {**REPO_LICENSE, "allow": REPO_LICENSE["allow"][:-1]}
        session = FakeSession({"license-policy/view": live})

        output = self.run_sync(sync.sync_license, session)

        self.assertIn("1 difference(s)", output)
        [(url, body)] = session.posts
        self.assertIn("merge_update=false", url)
        self.assertEqual(body, REPO_LICENSE)

    def test_dry_run_reports_drift_without_writing(self):
        live = json.loads(json.dumps(REPO_SECURITY))
        live["securityPolicyDefault"] = "high"
        session = FakeSession({"security-policy": live})

        output = self.run_sync(sync.sync_security, session, dry_run=True)

        self.assertIn("(default): repo=medium live=high", output)
        self.assertIn("dry run, not overwriting", output)
        self.assertEqual(session.posts, [])

    def test_failed_write_raises_with_the_status_and_body(self):
        live = json.loads(json.dumps(REPO_SECURITY))
        live["securityPolicyDefault"] = "high"
        session = FakeSession({"security-policy": live}, post_status=403)

        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            self.run_sync(sync.sync_security, session)

    def test_main_reports_both_policies_and_exits_zero_when_in_sync(self):
        session = FakeSession(
            {"security-policy": REPO_SECURITY, "license-policy/view": REPO_LICENSE}
        )
        os.environ.update({"SOCKET_API_KEY": "token", "SOCKET_SYNC_DRY_RUN": ""})
        out = io.StringIO()
        with mock.patch.object(sync.requests, "Session", return_value=session):
            with contextlib.redirect_stdout(out):
                code = sync.main()

        self.assertEqual(code, 0)
        self.assertIn("Security policy: in sync", out.getvalue())
        self.assertIn("License policy: in sync", out.getvalue())
        self.assertEqual(session.headers["authorization"], "Bearer token")
        self.assertEqual(session.posts, [])

    def test_main_exits_one_and_keeps_going_when_a_policy_fails(self):
        session = FakeSession({"security-policy": 403, "license-policy/view": REPO_LICENSE})
        os.environ["SOCKET_API_KEY"] = "token"
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sync.requests, "Session", return_value=session):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = sync.main()

        self.assertEqual(code, 1)
        self.assertIn("Security policy failed:", err.getvalue())
        self.assertIn("HTTP 403", err.getvalue())
        self.assertIn("License policy: in sync", out.getvalue())

    def test_main_requires_an_api_key(self):
        os.environ["SOCKET_API_KEY"] = ""
        with self.assertRaisesRegex(RuntimeError, "SOCKET_API_KEY is required"):
            sync.main()


if __name__ == "__main__":
    unittest.main()
