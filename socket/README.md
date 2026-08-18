# Socket policies

Security and license policies for Socket.dev. **This directory is the source of
truth**: a GitHub Action pushes it to Socket nightly, so any change made only in
the Socket UI is reverted by the next morning unless it also lands here.

## How to update a policy

1. Make the change in the Socket UI, where you get validation and can see what
   each rule affects.
2. Copy it back into this repo:

   ```sh
   SOCKET_API_KEY=... python socket/pull_socket_policies.py
   ```

   It reads the live policies, drops the license `deny` list, and rewrites the
   two JSON files, printing what changed.
3. Review `git diff`, then commit and open a PR.

Until that PR merges, the nightly sync keeps overwriting your UI change, so land
it the same day. To see what the sync would do without writing to Socket:

```sh
SOCKET_API_KEY=... SOCKET_SYNC_DRY_RUN=1 python socket/sync_socket_policies.py
```

Editing the JSON by hand and skipping step 1 works too — the sync pushes
whatever is on `main`. The UI is just an easier place to get it right.

## Files

- `socket-security-policy.json` — what to alert or block on
- `socket-license-policy.json` — allow-listed licenses
- `pull_socket_policies.py` — Socket → repo, for step 2 above
- `sync_socket_policies.py` — repo → Socket, run nightly by the workflow
- `tests/` — `python -m unittest discover -s socket` (no dependencies beyond `requests`)

License lists are kept sorted and the files are written exactly as
`pull_socket_policies.py` renders them, so pulls only ever show real changes.

## When Socket adds a field

Both scripts stop with `Socket returned unrecognised key(s) ...` if the API
returns anything they do not already know about, rather than ignoring it. A new
field may well change what a policy means, so work out what it does, then add it
to `SECURITY_KEYS`, `RULE_KEYS`, or `LICENSE_KEYS` in `sync_socket_policies.py`
and teach the comparison about it if it matters. The license read includes a
derived `deny` list, which is expected and deliberately ignored.

## License policy: deny by default

Any license that is not explicitly listed under `allow`, `warn`, or `monitor` is
**denied**. The Socket API returns a derived `deny` list when reading the live
policy; we do not store it in git because it is implied by omission, and it
would otherwise look like drift every time Socket's license catalog grows.
