#!/usr/bin/env python3
"""gatekeeper — a human-in-the-loop approval queue an agent runs from a shell.

An agent that wants to do something risky asks; a human (or another
authorised approver) decides from any shell. No daemon, no account, no
network — requests live in a local directory as JSONL.

Usage:
    gatekeeper ask --requester AGENT --tool "rm -rf /tmp/stage" \\
        --risk high --ttl 600 --note "clearing build staging"
    gatekeeper wait --id g-0123456789ab --timeout 600
    gatekeeper list [--status pending]
    gatekeeper show --id g-0123456789ab
    gatekeeper approve --id g-0123456789ab --by ALICE [--note "looks fine"]
    gatekeeper deny    --id g-0123456789ab --by ALICE [--note "too broad"]
    gatekeeper log [--actor AGENT] [--action approved] [--since 2026-10-01] [--json]

Rules:
  * first-decision-wins: an already-decided request cannot be re-decided.
  * no-self-approval: the approver may not be the requester.
  * expiry: a request past its TTL becomes expired and cannot be decided;
    expiry is applied lazily on every read/write, and by `sweep`.
  * every decision (and expiry, and ask) is appended to an audit log,
    queryable with `log` (--actor/--action/--request/--since/--until/--limit/--json).

Exit codes: 0 approved/ok, 1 operational failure (denied, expired, timed
out, unknown id, rule violation), 2 usage error.
"""

import argparse
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone

VERSION = "1.1.0"

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RISKS = ("low", "medium", "high", "critical")
STATUSES = ("pending", "approved", "denied", "expired")
LOG_ACTIONS = ("ask", "approved", "denied", "expired")
DEFAULT_TTL = 3600
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?Z?)?$")


def fail(msg, code=1):
    print(f"gatekeeper: {msg}", file=sys.stderr)
    sys.exit(code)


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def store_dir(args):
    d = args.dir or os.environ.get("GATEKEEPER_DIR") or os.path.expanduser("~/.gatekeeper")
    d = os.path.abspath(d)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def req_path(d):
    return os.path.join(d, "requests.jsonl")


def audit_path(d):
    return os.path.join(d, "audit.jsonl")


def check_name(name, role):
    if not NAME_RE.match(name or ""):
        fail(f"invalid {role} name {name!r}: use [A-Za-z0-9_-], 1-64 chars", 2)
    return name


def new_id():
    return "g-" + secrets.token_hex(6)


def load_requests(path):
    """Return (requests dict id->req, corrupt_count). Requests in file order."""
    reqs = {}
    corrupt = 0
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    reqs[r["id"]] = r
                except (json.JSONDecodeError, KeyError, TypeError):
                    corrupt += 1
    return reqs, corrupt


def save_requests(path, reqs):
    """Atomic rewrite preserving insertion order."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in reqs.values():
            f.write(json.dumps(r, sort_keys=True) + "\n")
    os.replace(tmp, path)


def audit(d, actor, action, rid, detail=""):
    with open(audit_path(d), "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": iso(utcnow()),
            "actor": actor,
            "action": action,
            "request": rid,
            "detail": detail,
        }, sort_keys=True) + "\n")


def load_audit(path):
    """Return (audit entries list in file order, corrupt_count). Lenient:
    any non-object JSON counts as corrupt."""
    entries = []
    corrupt = 0
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if not isinstance(e, dict):
                        raise ValueError("not an object")
                    entries.append(e)
                except (json.JSONDecodeError, ValueError):
                    corrupt += 1
    return entries, corrupt


def norm_ts(value, flag):
    """Normalize --since/--until to full ISO for lexicographic compare."""
    if not TS_RE.match(value or ""):
        fail(f"invalid --{flag} {value!r}: use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ", 2)
    if "T" not in value:
        return value + "T00:00:00Z"
    if value.endswith("Z"):
        return value
    return value + "Z"


def is_expired(r, now=None):
    now = now or utcnow()
    return r["status"] == "pending" and r["expires_at"] <= iso(now)


def apply_expiry(d, reqs, actor="system"):
    """Mark pending requests past TTL as expired; audit each. Returns count."""
    changed = 0
    for r in reqs.values():
        if is_expired(r):
            r["status"] = "expired"
            r["decided_at"] = iso(utcnow())
            audit(d, actor, "expire", r["id"], "ttl elapsed")
            changed += 1
    if changed:
        save_requests(req_path(d), reqs)
    return changed


def cmd_ask(args):
    d = store_dir(args)
    requester = check_name(args.requester, "requester")
    if not args.tool:
        fail("--tool is required", 2)
    if args.risk not in RISKS:
        fail(f"invalid risk {args.risk!r}: one of {', '.join(RISKS)}", 2)
    if args.ttl is not None and args.ttl <= 0:
        fail("--ttl must be positive seconds", 2)
    ttl = args.ttl or DEFAULT_TTL
    if args.args_json:
        try:
            a = json.loads(args.args_json)
        except json.JSONDecodeError as e:
            fail(f"invalid --args-json: {e}", 2)
        if not isinstance(a, list):
            fail("--args-json must be a JSON array", 2)
        arglist = [str(x) for x in a]
    else:
        arglist = args.arg or []
    now = utcnow()
    rid = new_id()
    reqs, _ = load_requests(req_path(d))
    reqs[rid] = {
        "id": rid,
        "created_at": iso(now),
        "requester": requester,
        "tool": args.tool,
        "args": arglist,
        "risk": args.risk,
        "note": args.note or "",
        "status": "pending",
        "expires_at": iso(now + timedelta(seconds=ttl)),
        "decided_by": "",
        "decided_at": "",
    }
    save_requests(req_path(d), reqs)
    audit(d, requester, "ask", rid, f"tool={args.tool!r} risk={args.risk} ttl={ttl}")
    print(rid)
    return 0


def decide(args, decision):
    d = store_dir(args)
    approver = check_name(args.by, "approver")
    reqs, corrupt = load_requests(req_path(d))
    apply_expiry(d, reqs)
    r = reqs.get(args.id)
    if r is None:
        fail(f"unknown request id {args.id!r}", 1)
    if r["status"] != "pending":
        fail(f"request {r['id']} already {r['status']}: first decision wins", 1)
    if approver == r["requester"]:
        fail(f"{approver!r} is the requester: no self-approval", 1)
    r["status"] = decision
    r["decided_by"] = approver
    r["decided_at"] = iso(utcnow())
    if args.note:
        r["note"] = (r["note"] + " | " if r["note"] else "") + f"decision: {args.note}"
    save_requests(req_path(d), reqs)
    audit(d, approver, decision, r["id"], args.note or "")
    print(f"{r['id']} {decision}")
    return 0


def cmd_wait(args):
    d = store_dir(args)
    timeout = args.timeout if args.timeout is not None else DEFAULT_TTL
    poll = args.poll or 1.0
    if timeout <= 0 or poll <= 0:
        fail("--timeout and --poll must be positive", 2)
    deadline = time.monotonic() + timeout
    while True:
        reqs, _ = load_requests(req_path(d))
        apply_expiry(d, reqs)
        r = reqs.get(args.id)
        if r is None:
            fail(f"unknown request id {args.id!r}", 1)
        if r["status"] == "approved":
            print(f"{r['id']} approved by {r['decided_by']}")
            return 0
        if r["status"] in ("denied", "expired"):
            print(f"{r['id']} {r['status']}", file=sys.stderr)
            return 1
        if time.monotonic() >= deadline:
            print(f"{r['id']} timed out waiting ({timeout}s)", file=sys.stderr)
            return 1
        time.sleep(min(poll, max(0.05, deadline - time.monotonic())))


def cmd_list(args):
    d = store_dir(args)
    reqs, corrupt = load_requests(req_path(d))
    apply_expiry(d, reqs)
    rows = list(reqs.values())
    if args.status:
        if args.status not in STATUSES:
            fail(f"invalid status {args.status!r}: one of {', '.join(STATUSES)}", 2)
        rows = [r for r in rows if r["status"] == args.status]
    rows.sort(key=lambda r: r["created_at"])
    print(f"{'ID':<16}{'STATUS':<10}{'RISK':<9}{'REQUESTER':<14}{'TOOL':<24}EXPIRES")
    for r in rows:
        tool = r["tool"]
        if len(tool) > 22:
            tool = tool[:21] + "…"
        print(f"{r['id']:<16}{r['status']:<10}{r['risk']:<9}{r['requester']:<14}{tool:<24}{r['expires_at']}")
    if corrupt:
        print(f"gatekeeper: warning: {corrupt} corrupt line(s) skipped", file=sys.stderr)
    return 0


def cmd_show(args):
    d = store_dir(args)
    reqs, _ = load_requests(req_path(d))
    apply_expiry(d, reqs)
    r = reqs.get(args.id)
    if r is None:
        fail(f"unknown request id {args.id!r}", 1)
    print(json.dumps(r, indent=2, sort_keys=True))
    return 0


def cmd_sweep(args):
    d = store_dir(args)
    reqs, _ = load_requests(req_path(d))
    n = apply_expiry(d, reqs, actor="sweep")
    print(f"expired {n} request(s)")
    return 0


def cmd_log(args):
    d = store_dir(args)
    if args.limit is not None and args.limit < 0:
        fail("--limit must be >= 0", 2)
    since = norm_ts(args.since, "since") if args.since else None
    until = norm_ts(args.until, "until") if args.until else None
    if since and until and since > until:
        fail("--since is after --until: no entry can match", 2)
    entries, corrupt = load_audit(audit_path(d))
    rows = []
    for e in entries:
        if args.actor and e.get("actor") != args.actor:
            continue
        if args.action and e.get("action") != args.action:
            continue
        if args.request and e.get("request") != args.request:
            continue
        ts = e.get("ts", "")
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        rows.append(e)
    if args.limit is not None:
        rows = rows[:args.limit]
    if args.json:
        for e in rows:
            print(json.dumps(e, sort_keys=True))
    else:
        print(f"{'TIME':<20}{'ACTOR':<14}{'ACTION':<9}{'REQUEST':<16}DETAIL")
        for e in rows:
            detail = str(e.get("detail", ""))
            if len(detail) > 60:
                detail = detail[:59] + "…"
            print(f"{str(e.get('ts', '')):<20}{str(e.get('actor', '')):<14}"
                  f"{str(e.get('action', '')):<9}{str(e.get('request', '')):<16}{detail}")
    if corrupt:
        print(f"gatekeeper: warning: {corrupt} corrupt audit line(s) skipped",
              file=sys.stderr)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="gatekeeper", description=__doc__.splitlines()[0])
    p.add_argument("--dir", help="store directory (default ~/.gatekeeper or $GATEKEEPER_DIR)")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("ask", help="create an approval request")
    a.add_argument("--requester", required=True)
    a.add_argument("--tool", required=True)
    a.add_argument("--arg", action="append", default=[], help="tool argument (repeatable)")
    a.add_argument("--args-json", help="tool arguments as a JSON array")
    a.add_argument("--risk", required=True, choices=RISKS)
    a.add_argument("--ttl", type=int, help="seconds until expiry (default 3600)")
    a.add_argument("--note", default="")
    a.set_defaults(func=cmd_ask)

    w = sub.add_parser("wait", help="block until decided, expired, or timeout")
    w.add_argument("--id", required=True)
    w.add_argument("--timeout", type=float, help="max seconds to wait (default 3600)")
    w.add_argument("--poll", type=float, default=1.0, help="poll interval seconds")
    w.set_defaults(func=cmd_wait)

    li = sub.add_parser("list", help="list requests")
    li.add_argument("--status", choices=STATUSES)
    li.set_defaults(func=cmd_list)

    s = sub.add_parser("show", help="show one request as JSON")
    s.add_argument("--id", required=True)
    s.set_defaults(func=cmd_show)

    ap = sub.add_parser("approve", help="approve a request")
    ap.add_argument("--id", required=True)
    ap.add_argument("--by", required=True)
    ap.add_argument("--note", default="")
    ap.set_defaults(func=lambda args: decide(args, "approved"))

    dn = sub.add_parser("deny", help="deny a request")
    dn.add_argument("--id", required=True)
    dn.add_argument("--by", required=True)
    dn.add_argument("--note", default="")
    dn.set_defaults(func=lambda args: decide(args, "denied"))

    sw = sub.add_parser("sweep", help="expire overdue requests now")
    sw.set_defaults(func=cmd_sweep)

    lg = sub.add_parser("log", help="query the audit log")
    lg.add_argument("--actor", help="only entries by this actor")
    lg.add_argument("--action", choices=LOG_ACTIONS, help="only this action")
    lg.add_argument("--request", help="only entries for this request id")
    lg.add_argument("--since", help="entries at/after this time (YYYY-MM-DD or ISO)")
    lg.add_argument("--until", help="entries at/before this time (YYYY-MM-DD or ISO)")
    lg.add_argument("--limit", type=int, help="max entries to show")
    lg.add_argument("--json", action="store_true", help="output JSON lines")
    lg.set_defaults(func=cmd_log)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
