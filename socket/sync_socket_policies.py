#!/usr/bin/env python3
"""Make Socket's org policies match the JSON in this directory.

Compares the checked-in policies against the live Socket org and overwrites
Socket on any difference. 

Notes:
- Reading license policy from Socket API includes an informational `deny` field. 
  This is ignored. `deny` just reports what's not in `allow` etc.
- If Socket API returns unexpected keys, then the run errors.

"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
ORG = os.environ.get("SOCKET_ORG_SLUG") or "hex-inc"
BASE = f"https://api.socket.dev/v0/orgs/{ORG}/settings"
SECURITY_FILE = HERE / "socket-security-policy.json"
LICENSE_FILE = HERE / "socket-license-policy.json"
SECURITY_PATH = "security-policy?custom_rules_only=false"  # same path to read and to write
LICENSE_READ = "license-policy/view"
LICENSE_WRITE = "license-policy?merge_update=false"
LICENSE_BUCKETS = ("allow", "warn", "monitor")
# What Socket is expected to return. Anything else stops the run: a field we do
# not know about may change what a policy means, so a human should look first.
SECURITY_KEYS = frozenset({"securityPolicyRules", "securityPolicyDefault"})
RULE_KEYS = frozenset({"action"})
LICENSE_KEYS = frozenset({*LICENSE_BUCKETS, "options", "deny"})  # `deny` is read, then ignored


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def flatten_security(policy: dict) -> dict[str, str]:
    """Rule name -> action, with the default folded in as one more entry."""
    flat = {name: rule["action"] for name, rule in policy["securityPolicyRules"].items()}
    flat["(default)"] = policy["securityPolicyDefault"]
    return flat


def flatten_license(policy: dict) -> dict[str, str]:
    """License -> disposition, plus options. Any `deny` list is ignored."""
    flat = {f"option:{name}": "on" for name in policy.get("options") or []}
    for bucket in LICENSE_BUCKETS:
        for name in policy.get(bucket) or []:
            flat[name] = f"{flat[name]}+{bucket}" if name in flat else bucket
    return flat


def diff(repo: dict[str, str], live: dict[str, str]) -> list[str]:
    """How live differs from repo, one line per entry. Empty means in sync."""
    return [
        f"{key}: repo={repo.get(key, '(absent)')} live={live.get(key, '(absent)')}"
        for key in sorted(repo.keys() | live.keys())
        if repo.get(key) != live.get(key)
    ]


def call(session: requests.Session, method: str, path: str, body: dict | None = None):
    response = session.request(method, f"{BASE}/{path}", json=body, timeout=60)
    if not response.ok:
        raise RuntimeError(f"{method} {path} -> HTTP {response.status_code}: {response.text}")
    return response.json() if response.content else None


def require_known_keys(payload: dict, expected: frozenset[str], label: str) -> None:
    unexpected = sorted(set(payload) - expected)
    if unexpected:
        raise RuntimeError(
            f"{label}: Socket returned unrecognised key(s) {', '.join(unexpected)}; "
            "inspect them, then update the expected keys in sync_socket_policies.py"
        )


def get_live_security(session: requests.Session) -> dict:
    live = call(session, "GET", SECURITY_PATH)
    require_known_keys(live, SECURITY_KEYS, "security policy")
    for name, rule in live["securityPolicyRules"].items():
        require_known_keys(rule, RULE_KEYS, f"security policy rule {name!r}")
    return live


def get_live_license(session: requests.Session) -> dict:
    live = call(session, "GET", LICENSE_READ)
    require_known_keys(live, LICENSE_KEYS, "license policy")
    return live


def open_session() -> requests.Session:
    """Session carrying the API key. Raises if SOCKET_API_KEY is unset."""
    api_key = os.environ.get("SOCKET_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("SOCKET_API_KEY is required")
    session = requests.Session()
    session.headers.update({"accept": "application/json", "authorization": f"Bearer {api_key}"})
    return session


def report(name: str, lines: list[str], *, dry_run: bool) -> bool:
    """Print the comparison. Returns True if Socket should be overwritten."""
    if not lines:
        print(f"{name}: in sync")
        return False
    verdict = "dry run, not overwriting" if dry_run else "overwriting Socket with the repo policy"
    print(f"{name}: {len(lines)} difference(s), {verdict}")
    print("\n".join(f"  {line}" for line in lines))
    return not dry_run


def sync_security(session: requests.Session, name: str, *, dry_run: bool) -> None:
    repo = load(SECURITY_FILE)
    live = get_live_security(session)
    if report(name, diff(flatten_security(repo), flatten_security(live)), dry_run=dry_run):
        body = {
            "policyRules": repo["securityPolicyRules"],
            "policyDefault": repo["securityPolicyDefault"],
        }
        call(session, "POST", SECURITY_PATH, body)
        print(f"{name}: overwrite succeeded")


def sync_license(session: requests.Session, name: str, *, dry_run: bool) -> None:
    repo = load(LICENSE_FILE)
    if "deny" in repo:
        raise RuntimeError("license policy must not list `deny`; unlisted licenses are denied")
    live = get_live_license(session)
    if report(name, diff(flatten_license(repo), flatten_license(live)), dry_run=dry_run):
        call(session, "POST", LICENSE_WRITE, repo)
        print(f"{name}: overwrite succeeded")


POLICIES = (("Security policy", sync_security), ("License policy", sync_license))


def main() -> int:
    session = open_session()
    dry_run = os.environ.get("SOCKET_SYNC_DRY_RUN", "").lower() in ("1", "true", "yes")
    print(f"Syncing Socket org {ORG} from this repo (dry run: {dry_run})")

    failed = False
    for name, sync in POLICIES:
        try:
            sync(session, name, dry_run=dry_run)
        except Exception as exc:
            print(f"{name} failed: {exc!r}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
