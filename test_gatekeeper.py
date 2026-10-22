#!/usr/bin/env python3
"""Tests for gatekeeper.py — run with: python3 test_gatekeeper.py"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

GK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gatekeeper.py")


def run(d, *argv):
    env = dict(os.environ, GATEKEEPER_DIR=d)
    p = subprocess.run([sys.executable, GK, *argv], env=env,
                       capture_output=True, text=True, timeout=60)
    return p


class GatekeeperTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="gk-test-")
        os.chmod(self.d, 0o700)

    def ask(self, **kw):
        a = ["ask", "--requester", kw.get("requester", "agent1"),
             "--tool", kw.get("tool", "rm -rf /tmp/x"),
             "--risk", kw.get("risk", "high"),
             "--ttl", str(kw.get("ttl", 600))]
        if "args_json" in kw:
            a += ["--args-json", kw["args_json"]]
        for x in kw.get("args", []):
            a += ["--arg", x]
        if kw.get("note"):
            a += ["--note", kw["note"]]
        p = run(self.d, *a)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.strip()

    def decide(self, rid, who, approve=True, note=""):
        a = ["approve" if approve else "deny", "--id", rid, "--by", who]
        if note:
            a += ["--note", note]
        return run(self.d, *a)

    # --- ask ---
    def test_ask_returns_id_and_stores_pending(self):
        rid = self.ask()
        self.assertTrue(rid.startswith("g-"))
        p = run(self.d, "show", "--id", rid)
        r = json.loads(p.stdout)
        self.assertEqual(r["status"], "pending")
        self.assertEqual(r["risk"], "high")
        self.assertEqual(r["requester"], "agent1")

    def test_ask_args_json_and_note(self):
        rid = self.ask(args_json='["a", 1, true]', note="n")
        r = json.loads(run(self.d, "show", "--id", rid).stdout)
        self.assertEqual(r["args"], ["a", "1", "True"])

    def test_ask_bad_risk_is_usage_error(self):
        p = run(self.d, "ask", "--requester", "a", "--tool", "t", "--risk", "extreme")
        self.assertEqual(p.returncode, 2)

    def test_ask_bad_requester_name(self):
        p = run(self.d, "ask", "--requester", "../evil", "--tool", "t", "--risk", "low")
        self.assertEqual(p.returncode, 2)

    def test_ask_bad_ttl(self):
        p = run(self.d, "ask", "--requester", "a", "--tool", "t", "--risk", "low", "--ttl", "-5")
        self.assertEqual(p.returncode, 2)

    # --- decide ---
    def test_approve_happy_path(self):
        rid = self.ask()
        p = self.decide(rid, "alice")
        self.assertEqual(p.returncode, 0)
        r = json.loads(run(self.d, "show", "--id", rid).stdout)
        self.assertEqual(r["status"], "approved")
        self.assertEqual(r["decided_by"], "alice")
        self.assertTrue(r["decided_at"])

    def test_deny_happy_path(self):
        rid = self.ask()
        p = self.decide(rid, "alice", approve=False, note="too broad")
        self.assertEqual(p.returncode, 0)
        r = json.loads(run(self.d, "show", "--id", rid).stdout)
        self.assertEqual(r["status"], "denied")
        self.assertIn("too broad", r["note"])

    def test_first_decision_wins(self):
        rid = self.ask()
        self.assertEqual(self.decide(rid, "alice").returncode, 0)
        p = self.decide(rid, "bob", approve=False)
        self.assertEqual(p.returncode, 1)
        self.assertIn("already approved", p.stderr)
        r = json.loads(run(self.d, "show", "--id", rid).stdout)
        self.assertEqual(r["decided_by"], "alice")

    def test_no_self_approval(self):
        rid = self.ask(requester="agent1")
        p = self.decide(rid, "agent1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("no self-approval", p.stderr)
        r = json.loads(run(self.d, "show", "--id", rid).stdout)
        self.assertEqual(r["status"], "pending")

    def test_decide_unknown_id(self):
        p = self.decide("g-deadbeefcafe", "alice")
        self.assertEqual(p.returncode, 1)

    def test_cannot_decide_expired(self):
        rid = self.ask(ttl=1)
        time.sleep(1.3)
        p = self.decide(rid, "alice")
        self.assertEqual(p.returncode, 1)
        self.assertIn("expired", p.stderr)

    # --- expiry ---
    def test_lazy_expiry_via_list(self):
        rid = self.ask(ttl=1)
        time.sleep(1.3)
        p = run(self.d, "list", "--status", "pending")
        self.assertEqual(p.returncode, 0)
        self.assertNotIn(rid, p.stdout)
        p = run(self.d, "list", "--status", "expired")
        self.assertIn(rid, p.stdout)

    def test_sweep(self):
        rid = self.ask(ttl=1)
        time.sleep(1.3)
        p = run(self.d, "sweep")
        self.assertEqual(p.returncode, 0)
        self.assertIn("expired 1", p.stdout)

    # --- wait ---
    def test_wait_returns_approved(self):
        rid = self.ask(ttl=60)
        def approver():
            time.sleep(0.4)
            self.decide(rid, "alice")
        threading.Thread(target=approver).start()
        p = run(self.d, "wait", "--id", rid, "--timeout", "10", "--poll", "0.1")
        self.assertEqual(p.returncode, 0)
        self.assertIn("approved", p.stdout)

    def test_wait_denied_exit1(self):
        rid = self.ask(ttl=60)
        def denier():
            time.sleep(0.4)
            self.decide(rid, "alice", approve=False)
        threading.Thread(target=denier).start()
        p = run(self.d, "wait", "--id", rid, "--timeout", "10", "--poll", "0.1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("denied", p.stderr)

    def test_wait_timeout(self):
        rid = self.ask(ttl=60)
        p = run(self.d, "wait", "--id", rid, "--timeout", "0.5", "--poll", "0.1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("timed out", p.stderr)

    def test_wait_sees_expiry(self):
        rid = self.ask(ttl=1)
        p = run(self.d, "wait", "--id", rid, "--timeout", "10", "--poll", "0.1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("expired", p.stderr)

    # --- audit + robustness ---
    def test_audit_log_records_ask_and_decision(self):
        rid = self.ask(note="hello")
        self.decide(rid, "alice", note="fine")
        with open(os.path.join(self.d, "audit.jsonl")) as f:
            acts = [json.loads(l)["action"] for l in f if l.strip()]
        self.assertEqual(acts, ["ask", "approved"])

    def test_corrupt_lines_skipped(self):
        rid = self.ask()
        with open(os.path.join(self.d, "requests.jsonl"), "a") as f:
            f.write("this is not json\n")
        p = run(self.d, "list")
        self.assertEqual(p.returncode, 0)
        self.assertIn(rid, p.stdout)
        self.assertIn("corrupt", p.stderr)

    def test_unique_ids(self):
        ids = {self.ask() for _ in range(20)}
        self.assertEqual(len(ids), 20)

    def test_store_dir_perms(self):
        st = os.stat(self.d)
        self.assertEqual(oct(st.st_mode & 0o777), "0o700")


if __name__ == "__main__":
    unittest.main(verbosity=2)
