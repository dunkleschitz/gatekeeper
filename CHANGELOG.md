# gatekeeper CHANGELOG

## v1 — 2026-10-21

Initial build.

- Single-file stdlib CLI (`gatekeeper.py`): `ask`, `wait`, `list`,
  `show`, `approve`, `deny`, `sweep`.
- File-based store (`<dir>/requests.jsonl` + `audit.jsonl`), append-only
  for asks, atomic rewrite for decisions.
- Rules enforced in code: first-decision-wins, no-self-approval,
  TTL expiry (lazy + `sweep`).
- Risks `low/medium/high/critical`; statuses
  `pending/approved/denied/expired`; requester names validated
  (`[A-Za-z0-9_-]`, 1–64 chars); store dir `0700`; corrupt JSONL lines
  reported and skipped.
- Exit codes 0 approved/ok / 1 denied-or-failed / 2 usage.
- 21 tests passing (`test_gatekeeper.py`).
