# Shared GH Action workflows
Github Actions workflows that are shared across Hex repositories.

1. Dependency Review
    - This is used to detect & prevent the introduction of dependencies with unapproved licenses or known vulnerabilities.

2. Socket Policy Sync
    - Treats [`socket/`](socket/) as the source of truth for Hex’s Socket org (`hex-inc`) security and license policies.
    - Runs nightly at 1am US Central (2am during daylight saving), on pushes to `main` that change `socket/**`, and via `workflow_dispatch`.
    - Fetches live policies from the Socket API, compares for effective equivalency, and overwrites Socket when they drift (repo wins). UI edits in Socket are reverted by the next morning (or immediately on the next push/dispatch).
    - To change a policy: edit it in the Socket UI, run `socket/pull_socket_policies.py` to copy it back into this repo, then PR the diff. See [`socket/README.md`](socket/README.md) for the full loop and for license deny-by-default semantics.
    - Requires repository secret `SOCKET_API_KEY` with scopes: `security-policy:read`, `security-policy:update`, `license-policy:read`, `license-policy:update`.
