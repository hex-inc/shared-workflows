#!/usr/bin/env python3
"""Overwrite this repo's policies with the live ones on Socket.

Run this after editing a policy in the Socket UI, then open a PR.

UI-only edits will be overwritten by the next sync.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import requests

from sync_socket_policies import (
    LICENSE_BUCKETS,
    LICENSE_FILE,
    ORG,
    SECURITY_FILE,
    diff,
    flatten_license,
    flatten_security,
    get_live_license,
    get_live_security,
    open_session,
)

Flatten = Callable[[dict], dict[str, str]]


def require_string_list(value: Any, *, label: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"expected {label} to be a list of strings, got {value!r:.60}")


def fetch_security(session: requests.Session) -> dict:
    live = get_live_security(session)
    # use socket's sort order
    policy = {
        "securityPolicyRules": live["securityPolicyRules"],
        "securityPolicyDefault": live["securityPolicyDefault"],
    }
    return policy


def fetch_license(session: requests.Session) -> dict:
    """The live license policy, every bucket sorted so a pull only shows real changes."""
    live = get_live_license(session)
    # use alphabetic sort order
    policy = {}
    for key in (*LICENSE_BUCKETS, "options"):  # `deny` is deliberately not among them
        bucket = live.get(key) or []
        require_string_list(bucket, label=key)
        policy[key] = sorted(bucket)
    return policy


def render(policy: dict) -> str:
    """The canonical on-disk form, which the checked-in files are expected to match."""
    return json.dumps(policy, indent=2) + "\n"


def flat_repo_policy(path: Path, flatten: Flatten) -> dict[str, str]:
    """The checked-in policy, flattened. A missing or empty file counts as empty."""
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    return flatten(json.loads(text)) if text.strip() else {}


def update(path: Path, policy: dict, flatten: Flatten) -> bool:
    """Overwrite `path` when Socket disagrees with it. True if it was written.

    Both sides are compared flattened, which is insensitive to the order of
    rules and license lists, so a pure reordering is never reported as a change.
    """
    changes = diff(flat_repo_policy(path, flatten), flatten(policy))
    if not changes:
        print(f"{path.name}: no changes")
        return False

    print(f"{path.name}: {len(changes)} change(s)")
    print("\n".join(f"  {line}" for line in changes))
    path.write_text(render(policy), encoding="utf-8")
    return True


def main() -> None:
    session = open_session()
    print(f"Reading policies from Socket org `{ORG}`")
    live_security = fetch_security(session)
    live_license = fetch_license(session)
    written = [
        update(SECURITY_FILE, live_security, flatten_security),
        update(LICENSE_FILE, live_license, flatten_license),
    ]

    if not any(written):
        print("The repo already matches Socket; nothing to commit.")
    else:
        print("Review the diff, then branch, commit, and open a PR.")


if __name__ == "__main__":
    main()
