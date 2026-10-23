"""Synthetic, offline-only acceptance tests for the identity-graph replay experiment."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from identity_replay import ReplayError, correlate, load_records, receipt

ROOT = Path(__file__).resolve().parent


def event(kind, name, minute, tenant="tenant-a", app="app-a", actor="sp-a", **fields):
    defaults = {
        "ts": f"2026-10-15T10:{minute:02d}:00Z",
        "event_id": name, "tenant": tenant, "app": app, "actor": actor,
        "source": "synthetic-source", "kind": kind,
    }
    return {**defaults, **fields}


def sequence():
    return [
        event("app_signin", "login", 0, result="success"),
        event("graph_activity", "graph", 1, operation="directory_read"),
        event("credential_added", "credential", 2, target="sp-a"),
        event("role_grant", "role", 3, target="sp-a", role="Global Administrator"),
    ]


class IdentityReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def parse(self, rows):
        path = self.root / "input.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return load_records(path)

    def test_synthetic_chain_produces_distinct_review_findings(self):
        result = receipt(self.parse(sequence()))
        self.assertEqual(result["schema"], "rizzer.identity-replay.v0")
        self.assertEqual(result["events"], 4)
        self.assertEqual([x["signal"] for x in result["findings"]],
                         ["credential_added", "self_privileged_role_grant"])
        self.assertEqual([x["priority"] for x in result["findings"]], ["review", "high"])
        self.assertEqual(result["findings"][0]["event_ids"],
                         ["login", "graph", "credential"])
        self.assertEqual(result["limits"]["compromise"], "not_established")

    def test_failed_signin_does_not_establish_sequence(self):
        rows = sequence()
        rows[0]["result"] = "failure"
        self.assertEqual(correlate(self.parse(rows)), [])

    def test_no_cross_tenant_or_actor_conflation(self):
        rows = [
            event("app_signin", "login", 0, result="success"),
            event("credential_added", "cross-tenant", 1, tenant="tenant-b", target="sp-a"),
            event("role_grant", "cross-actor", 2, actor="sp-b", target="sp-b",
                  role="Global Administrator"),
            event("credential_added", "cross-app", 3, app="app-b", target="sp-a"),
        ]
        self.assertEqual(correlate(self.parse(rows)), [])

    def test_only_forward_time_and_bounded_window(self):
        rows = [
            event("credential_added", "before", 0, target="sp-a"),
            event("app_signin", "login", 1, result="success"),
            event("credential_added", "after", 4, target="sp-a"),
        ]
        self.assertEqual(correlate(self.parse(rows), window_seconds=120), [])
        self.assertEqual([x["signal"] for x in correlate(self.parse(rows), 180)],
                         ["credential_added"])

    def test_input_reordering_does_not_change_receipt(self):
        rows = sequence()
        one = receipt(self.parse(rows))
        two = receipt(self.parse(list(reversed(rows))))
        self.assertEqual(one, two)

    def test_malformed_and_duplicate_events_rejected(self):
        samples = [
            [{**sequence()[0], "password": "should-not-be-ingested"}],
            [{**sequence()[0], "kind": "shell_exec"}],
            [{**sequence()[0], "kind": ["app_signin"]}],
            [{**sequence()[0], "result": "maybe"}],
            [{**sequence()[0], "ts": "2026-10-15T10:00:00+00:00"}],
            [{**sequence()[1], "operation": ["directory_read"]}],
            [sequence()[0], copy.deepcopy(sequence()[0])],
        ]
        for rows in samples:
            with self.subTest(rows=rows), self.assertRaises(ReplayError):
                self.parse(rows)
        with self.assertRaises(ReplayError):
            self.parse([])
        with self.assertRaises(ReplayError):
            correlate(self.parse(sequence()), 3601)

    def test_bounded_line_count(self):
        path = self.root / "too-many.jsonl"
        path.write_text("{}\n" * 4097)
        with self.assertRaises(ReplayError):
            load_records(path)

    def test_multitenant_fixture_keeps_failed_signins_and_other_principals_separate(self):
        fixture = ROOT / "fixtures" / "identity-multitenant.jsonl"
        parsed = load_records(fixture)
        result = receipt(parsed)
        self.assertEqual(result["events"], 12)
        self.assertEqual([f["event_ids"][-1] for f in result["findings"]],
                         ["cred-a", "grant-a"])
        self.assertEqual([f["priority"] for f in result["findings"]],
                         ["review", "high"])
        self.assertTrue(all(f["tenant"] == "tenant-a" and f["app"] == "app-a"
                            and f["actor"] == "sp-a" for f in result["findings"]))

    def test_cli_writes_new_directory_and_never_overwrites(self):
        source = self.root / "source.jsonl"
        source.write_text("".join(json.dumps(row) + "\n" for row in sequence()))
        output = self.root / "receipt-dir"
        command = [sys.executable, str(ROOT / "identity_replay.py"), "--input",
                   str(source), "--out", str(output)]
        first = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        text = (output / "receipt.json").read_text()
        self.assertEqual(len(json.loads(text)["findings"]), 2)
        second = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual((output / "receipt.json").read_text(), text)


if __name__ == "__main__":
    unittest.main()
