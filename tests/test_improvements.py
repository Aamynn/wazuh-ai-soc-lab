import copy
import io
import json
import random
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
from http.client import IncompleteRead
from pathlib import Path

from soc_lab.__main__ import main
from soc_lab.analysis import analyze, baseline, validate_analysis
from soc_lab.core import correlate, load_events, parse_time, strict_json
from soc_lab.reporting import markdown_report

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "sample-data/ssh-sequence.jsonl"


class ImprovementTests(unittest.TestCase):
    def setUp(self):
        self.events, _ = load_events(SAMPLE)
        self.incident = correlate(self.events)[0]

    def run_cli(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = main(list(args))
        return code, output.getvalue(), error.getvalue()

    def test_configurable_threshold_changes_results(self):
        code, output, _ = self.run_cli("--input", str(SAMPLE), "--threshold", "6")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["investigation_count"], 0)
        self.assertEqual(json.loads(output)["configuration"]["threshold"], 6)

    def test_invalid_configuration_is_rejected(self):
        for threshold, window in ((0, 300), (100, 300), (True, 300), (5, 0), (5, 86401)):
            with self.subTest(threshold=threshold, window=window):
                with self.assertRaises(ValueError):
                    correlate([], threshold, window)

    def test_duplicate_json_keys_and_constants_are_rejected(self):
        for value in ('{"id":"a","id":"b"}', '{"x": NaN}', '{"x": Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(value)

    def test_parse_error_does_not_echo_sensitive_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text('{"secret":"DO-NOT-ECHO"')
            code, output, error = self.run_cli("--input", str(path))
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertNotIn("DO-NOT-ECHO", error)

    def test_extreme_timestamp_does_not_crash(self):
        with self.assertRaises(ValueError):
            parse_time("0001-01-01T00:00:00+01:00")
        event = dict(self.events[-1], timestamp="0001-01-01T00:00:00Z")
        self.assertEqual(correlate([event]), [])

    def test_sliding_window_matches_reference_across_random_sequences(self):
        rng = random.Random(27)
        origin = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for case in range(30):
            events = []
            for number in range(25):
                events.append(dict(self.events[0], id="r-{}".format(number),
                                   timestamp=(origin + timedelta(seconds=rng.randrange(50))).isoformat(),
                                   event_type=rng.choice(["ssh_failed", "ssh_failed", "ssh_success"]),
                                   user=rng.choice(["alice", "bob"])))
            expected = {}
            for success in events:
                if success["event_type"] != "ssh_success":
                    continue
                end = parse_time(success["timestamp"])
                failures = [event for event in events if event["event_type"] == "ssh_failed"
                            and event["user"] == success["user"]
                            and end - timedelta(seconds=10) <= parse_time(event["timestamp"]) < end]
                if len(failures) >= 2:
                    expected["ssh-" + success["id"]] = {event["id"] for event in failures} | {success["id"]}
            rng.shuffle(events)
            actual = {item["incident_id"]: {event["id"] for event in item["events"]}
                      for item in correlate(events, threshold=2, window_seconds=10)}
            self.assertEqual(actual, expected, "case {}".format(case))

    def test_markdown_report_contains_timeline_and_provider(self):
        code, output, error = self.run_cli("--input", str(SAMPLE), "--format", "markdown")
        self.assertEqual(code, 0, error)
        self.assertIn("### Evidence timeline", output)
        self.assertIn("**Analysis provider:** baseline", output)
        self.assertIn("failure", output)

    def test_markdown_escapes_model_html_and_links(self):
        item = dict(self.incident, **analyze(self.incident))
        item["analysis"]["summary"] = '<script>alert(1)</script> [click](https://example.invalid)'
        report = {"event_count": 6, "investigation_count": 1, "input_sha256": "abc", "investigations": [item]}
        rendered = markdown_report(report)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("[click](", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_new_file_output_and_existing_file_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            code, output, error = self.run_cli("--input", str(SAMPLE), "--output", str(path))
            self.assertEqual(code, 0, error)
            self.assertEqual(output, "")
            first = path.read_text()
            self.assertEqual(json.loads(first)["investigation_count"], 1)
            code, _, _ = self.run_cli("--input", str(SAMPLE), "--output", str(path))
            self.assertEqual(code, 2)
            self.assertEqual(path.read_text(), first)

    def test_markdown_stdout_matches_saved_file_and_example(self):
        code, output, error = self.run_cli("--input", str(SAMPLE), "--format", "markdown")
        self.assertEqual(code, 0, error)
        self.assertEqual(output, (ROOT / "docs/examples/ssh-investigation.md").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            code, _, error = self.run_cli("--input", str(SAMPLE), "--format", "markdown", "--output", str(path))
            self.assertEqual(code, 0, error)
            self.assertEqual(path.read_text(), output)

    def test_empty_markdown_report_does_not_claim_safety(self):
        code, output, _ = self.run_cli("--input", str(SAMPLE), "--threshold", "6", "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertIn("does not establish", output)

    def test_transport_disconnect_falls_back(self):
        def interrupted(payload):
            raise IncompleteRead(b"partial")
        result = analyze(self.incident, "ollama", "local-model", interrupted)
        self.assertTrue(result["provenance"]["fallback"])

    def test_whitespace_padding_cannot_bypass_output_limit(self):
        result = baseline(self.incident)
        result["summary"] = "valid" + " " * 2000
        with self.assertRaises(ValueError):
            validate_analysis(result, self.incident)

    def test_evidence_limit_fails_without_truncation(self):
        events = [dict(self.events[0], id="f-{}".format(n)) for n in range(100)] + [self.events[-1]]
        with self.assertRaisesRegex(ValueError, "evidence limit"):
            correlate(events)

    def test_incident_limit_fails_without_truncation(self):
        events = copy.deepcopy(self.events[:-1]) + [dict(self.events[-1], id="s-{}".format(n)) for n in range(21)]
        with self.assertRaisesRegex(ValueError, "too many investigations"):
            correlate(events)


if __name__ == "__main__":
    unittest.main()
