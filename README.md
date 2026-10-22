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

Risks: `low`, `medium`, `high`, `critical`. Statuses: `pending`,
`approved`, `denied`, `expired`. Default TTL 3600 s.

## Rules (the whole point)

- **First decision wins.** Deciding an already-decided request fails with
  exit 1; the earlier decision stands.
- **No self-approval.** The approver may not be the requester (exit 1).
- **Expiry.** A pending request past its TTL becomes `expired` and can no
  longer be decided. Expiry is applied lazily on every command, plus
  explicitly by `sweep`.
- **Audit.** Every `ask`, decision, and expiry is appended to
  `<dir>/audit.jsonl` (ISO-8601 UTC, actor, action, request id).

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

License: TBD (maintainer approves before first publication).

## Pre-publish checklist

Per the project charter, nothing ships publicly until the maintainer
approves the publishing account/org and the license. Before
first publication:

1. **Secrets hygiene** — run a secrets scan over the repo and its history
   (`gitleaks detect --source .` or `trufflehog git file://.`), resolve
   every hit, and grep once more for obvious keys/tokens by hand.
2. **History review** — read `git log` and the full diff end-to-end; no
   credentials, private paths, or personal data may be committed.
3. **License** — replace the TBD notice with the maintainer-approved
   LICENSE file.
