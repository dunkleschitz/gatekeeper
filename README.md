# gatekeeper — a human-in-the-loop approval queue an agent runs from a shell

Scheduled and outer-loop agents keep needing the same pattern: "ask a
human, wait for the answer." Frameworks offer it as hosted interrupts
(LangGraph, HumanLayer) or automation blocks (n8n), and DIY blog posts
show a JSON folder with a 14-line CLI — but there is no standalone,
zero-dependency published tool an agent can operate from a shell. This is
that: one Python file, stdlib only, no daemon, no account, no network.
Requests live as JSONL lines in a local store directory; the human
resolves them from any shell.

```bash
# the agent asks; gets a request id back immediately
RID=$(gatekeeper ask --requester builder --tool "deploy prod" \
    --risk critical --ttl 600 --note "Friday deploy, staging verified")

# ...later, from the human's shell...
gatekeeper list --status pending
gatekeeper approve --id "$RID" --by alice --note "looks good"

# the agent blocks until there is a decision (or expiry / timeout)
gatekeeper wait --id "$RID" --timeout 600
```

Exit codes: `0` approved/ok, `1` operational failure (denied, expired,
timed out, unknown id, rule violation), `2` usage error.

## Commands

| Command | Effect |
|---|---|
| `ask --requester R --tool T [--arg X ... \| --args-json J] --risk RISK [--ttl S] [--note N]` | Create a pending request; prints its id. |
| `wait --id ID [--timeout S] [--poll S]` | Block until approved, denied, expired, or timeout. |
| `list [--status STATUS]` | Requests oldest first: id, status, risk, requester, tool, expiry. |
| `show --id ID` | Full request as JSON. |
| `approve --id ID --by HUMAN [--note N]` | Approve. Fails if not pending, already decided, or self-approval. |
| `deny --id ID --by HUMAN [--note N]` | Deny (same rules). |
| `sweep` | Expire overdue requests now (also applied lazily everywhere). |
| `log [--actor A] [--action ACTION] [--request ID] [--since T] [--until T] [--limit N] [--json]` | Query the audit log (ask/approve/deny/expire events, oldest first); `--json` for JSON lines. |

Risks: `low`, `medium`, `high`, `critical`. Statuses: `pending`,
`approved`, `denied`, `expired`. Default TTL 3600 s.

`--version` prints the version and exits.

## Rules (the whole point)

- **First decision wins.** Deciding an already-decided request fails with
  exit 1; the earlier decision stands.
- **No self-approval.** The approver may not be the requester (exit 1).
- **Expiry.** A pending request past its TTL becomes `expired` and can no
  longer be decided. Expiry is applied lazily on every command, plus
  explicitly by `sweep`.
- **Audit.** Every `ask`, decision, and expiry is appended to
  `<dir>/audit.jsonl` (ISO-8601 UTC, actor, action, request id).
  Query it with `log`:

```bash
gatekeeper log --actor alice --since 2026-10-01   # everything Alice decided
gatekeeper log --action denied --json             # every denial, machine-readable
```

## Store format

`<dir>/requests.jsonl` — one JSON object per line, append-only for `ask`,
atomic rewrite (temp file + rename) for decisions. One record:

```json
{"id": "g-5e128cc999f6", "created_at": "2026-10-22T02:27:24Z",
 "requester": "builder", "tool": "deploy prod", "args": [],
 "risk": "critical", "note": "Friday deploy", "status": "approved",
 "expires_at": "2026-10-22T02:37:24Z",
 "decided_by": "alice", "decided_at": "2026-10-22T02:28:01Z"}
```

Store location: `--dir`, else `$GATEKEEPER_DIR`, else `~/.gatekeeper`.
Names are restricted to `[A-Za-z0-9_-]` (1–64 chars); the store directory
is created `0700`. Corrupt JSONL lines are reported and skipped, never
fatal. Request ids are 12-hex random values (`g-` + `secrets.token_hex(6)`).

## Limitations

- **Local by design.** Requester and human must share the store directory.
  This is not a networked approval service and has no push notification —
  `wait` polls, and the human has to run `list` to see what's pending.
- **Consent channel, not access control.** Anyone with shell access to the
  store can decide requests; there is no approver authentication. The
  rules (first-decision-wins, no-self-approval) are enforced in code for
  the normal CLI path, not against an adversary editing the JSONL directly.
- **Audit is append-only by convention.** `audit.jsonl` is tamper-evident
  only insofar as the store itself is protected (mode `0700`); it is not
  signed or hash-chained.
- **One human per decision.** Escalation, quorum, and delegation rules are
  out of scope — encode them in the agent's prompt, not here.

## License

MIT — see [LICENSE](LICENSE).

## How this was built

Designed and built by an AI agent under human direction in October 2026; reviewed and published by the maintainer. The test suite covers first-decision-wins, no-self-approval, TTL expiry, and the audit log. Known limits are listed under Limitations above: local by design, and a consent channel rather than access control.
