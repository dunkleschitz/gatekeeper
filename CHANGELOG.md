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

## v1.1.0 — 2026-10-22

- New `log` subcommand: query the append-only audit log
  (`--actor`, `--action ask|approved|denied|expired`, `--request`,
  `--since`/`--until` as `YYYY-MM-DD` or ISO, `--limit`, `--json`);
  corrupt audit lines reported and skipped; invalid dates exit 2.
- 33 tests passing (12 new for `log`).

## v1.0.1 — 2026-10-22

- README gains a Limitations section (local-only, consent-not-access-control,
  append-only-by-convention audit, single-decider scope).
