import contextlib
import csv
import io
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from unittest import mock

from logwatch import Event, detect_alerts, main, read_events


BASE = datetime(2026, 10, 1, tzinfo=timezone.utc)


def event(seconds, ip="203.0.113.10", status="failure", username="student"):
    return Event(BASE + timedelta(seconds=seconds), ip, username, status)


class DetectionTests(unittest.TestCase):
    def test_threshold_and_inclusive_boundary(self):
        alerts = detect_alerts([event(0), event(30), event(60)], 3, 60)
        self.assertEqual(alerts[0].failure_count, 3)
        self.assertEqual(detect_alerts([event(0), event(30), event(61)], 3, 60), [])

    def test_unsorted_events_and_peak_window(self):
        alerts = detect_alerts([event(i) for i in [100, 30, 0, 20, 10]], 3, 30)
        self.assertEqual(alerts[0].failure_count, 4)
        self.assertEqual(alerts[0].window_start, BASE.isoformat())

    def test_ips_are_separate(self):
        self.assertEqual(detect_alerts([event(0), event(1, "192.0.2.2")], 2, 60), [])

    def test_success_is_not_counted_and_does_not_reset_failures(self):
        alerts = detect_alerts([event(0), event(1, status="success"), event(2)], 2, 60)
        self.assertEqual(alerts[0].failure_count, 2)

    def test_same_timestamp_rows_remain_distinct(self):
        self.assertEqual(detect_alerts([event(0)] * 5)[0].failure_count, 5)

    def test_tie_picks_earliest_window(self):
        alerts = detect_alerts([event(i) for i in [0, 1, 500, 501]], 2, 10)
        self.assertEqual(alerts[0].window_start, BASE.isoformat())

    def test_invalid_rule_is_rejected(self):
        for threshold, window in [(0, 60), (5, 0), (-1, 1)]:
            with self.assertRaises(ValueError):
                detect_alerts([], threshold, window)


class InputAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "events.csv"

    def write_rows(self, rows):
        with self.source.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "ip", "username", "status"])
            writer.writerows(rows)

    def run_cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main([str(self.source), *map(str, args)])

    def test_normalizes_timezone_ipv6_and_status(self):
        self.write_rows([["2026-10-01T03:00:00+03:00", "2001:db8:0::1", "student", "SUCCESS"]])
        events, rejected = read_events(self.source)
        self.assertEqual(rejected, [])
        self.assertEqual(events[0].timestamp, BASE)
        self.assertEqual(events[0].ip, "2001:db8::1")
        self.assertEqual(events[0].status, "success")

    def test_bad_rows_are_counted_without_losing_good_rows(self):
        self.write_rows([
            [BASE.isoformat(), "192.0.2.1", "student", "success"],
            ["2026-10-01T00:00:00", "192.0.2.1", "student", "failure"],
            [BASE.isoformat(), "not-an-ip", "student", "failure"],
            [BASE.isoformat(), "192.0.2.1", "student", "unknown"],
            [BASE.isoformat(), "192.0.2.1", "", "failure"],
            [BASE.isoformat(), "192.0.2.1", "student"],
        ])
        events, rejected = read_events(self.source)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(rejected), 5)
        self.assertEqual([r["line"] for r in rejected], [3, 4, 5, 6, 7])

    def test_header_order_and_bom_are_accepted(self):
        self.source.write_text(
            "status,username,ip,timestamp\nfailure,student,192.0.2.1,2026-10-01T00:00:00Z\n",
            encoding="utf-8-sig",
        )
        events, rejected = read_events(self.source)
        self.assertEqual(rejected, [])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].timestamp, BASE)

    def test_missing_input_file_returns_error(self):
        self.assertEqual(self.run_cli(), 1)

    def test_bad_schema_and_malformed_csv_fail(self):
        self.source.write_text("timestamp,ip,username,username\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            read_events(self.source)
        self.source.write_text('timestamp,ip,username,status\n"unterminated', encoding="utf-8")
        with self.assertRaises(csv.Error):
            read_events(self.source)

    def test_empty_or_invalid_file_creates_no_report(self):
        self.write_rows([])
        output = self.root / "output"
        self.assertEqual(self.run_cli("--output", output), 1)
        self.assertFalse(output.exists())

    def test_end_to_end_sample_matches_database_and_json(self):
        sample = Path(__file__).resolve().parents[1] / "data" / "sample_logins.csv"
        self.source.write_bytes(sample.read_bytes())
        output = self.root / "output"
        self.assertEqual(self.run_cli("--output", output), 0)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["summary"], {
            "valid_events": 12, "rejected_rows": 0, "failed_logins": 8,
            "successful_logins": 4, "unique_ips": 4, "flagged_ips": 1,
        })
        self.assertEqual(report["alerts"][0]["ip"], "203.0.113.10")
        with sqlite3.connect(output / "analysis.db") as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 12)
            self.assertEqual(db.execute("SELECT failure_count FROM alerts").fetchone()[0], 5)
        self.assertIn("203.0.113.10", (output / "report.md").read_text())

    def test_sql_input_is_stored_as_data(self):
        username = "'; DROP TABLE events; --"
        self.write_rows([[BASE.isoformat(), "192.0.2.1", username, "failure"]])
        output = self.root / "output"
        self.assertEqual(self.run_cli("--output", output), 0)
        with sqlite3.connect(output / "analysis.db") as db:
            self.assertEqual(db.execute("SELECT username FROM events").fetchone()[0], username)

    def test_existing_output_is_never_overwritten(self):
        self.write_rows([[BASE.isoformat(), "192.0.2.1", "student", "success"]])
        output = self.root / "output"
        self.assertEqual(self.run_cli("--output", output), 0)
        original = (output / "report.json").read_bytes()
        self.assertEqual(self.run_cli("--output", output), 1)
        self.assertEqual((output / "report.json").read_bytes(), original)

    def test_existing_output_gives_clear_message(self):
        self.write_rows([[BASE.isoformat(), "192.0.2.1", "student", "success"]])
        output = self.root / "output"
        output.mkdir()
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(main([str(self.source), "--output", str(output)]), 1)
        self.assertIn("already exists", err.getvalue())

    def test_failed_run_leaves_no_partial_output(self):
        self.write_rows([[BASE.isoformat(), "192.0.2.1", "student", "success"]])
        output = self.root / "output"
        with mock.patch("logwatch.save_database", side_effect=OSError("disk full")):
            self.assertEqual(self.run_cli("--output", output), 1)
        self.assertFalse(output.exists())

    def test_late_report_failure_cleans_output_and_allows_retry(self):
        self.write_rows([[BASE.isoformat(), "192.0.2.1", "student", "success"]])
        output = self.root / "output"
        with mock.patch("logwatch.render_markdown", side_effect=OSError("disk full")):
            self.assertEqual(self.run_cli("--output", output), 1)
        self.assertFalse(output.exists())
        self.assertEqual(self.run_cli("--output", output), 0)
        self.assertTrue((output / "analysis.db").is_file())
        self.assertTrue((output / "report.json").is_file())
        self.assertTrue((output / "report.md").is_file())

    def test_interrupted_report_write_cleans_partial_output(self):
        self.write_rows([[BASE.isoformat(), "192.0.2.1", "student", "success"]])
        output = self.root / "output"
        with mock.patch("logwatch.render_markdown", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_cli("--output", output)
        self.assertFalse(output.exists())

    def test_existing_output_file_is_preserved(self):
        self.write_rows([[BASE.isoformat(), "192.0.2.1", "student", "success"]])
        output = self.root / "output"
        output.write_text("existing file", encoding="utf-8")
        self.assertEqual(self.run_cli("--output", output), 1)
        self.assertEqual(output.read_text(encoding="utf-8"), "existing file")

    def test_cli_rejects_nonpositive_parameters(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            main([str(self.source), "--threshold", "0"])
        self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
