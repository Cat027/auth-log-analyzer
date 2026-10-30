"""Analyze normalized login logs using only the Python standard library."""

import argparse
import csv
import ipaddress
import json
import sqlite3
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    ip: str
    username: str
    status: str


@dataclass(frozen=True)
class Alert:
    ip: str
    failure_count: int
    window_start: str
    window_end: str


def read_events(path):
    """Validate CSV rows; return valid events and explicit rejection reasons."""
    events, rejected = [], []
    required = {"timestamp", "ip", "username", "status"}
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        if (reader.fieldnames is None or len(reader.fieldnames) != 4
                or set(reader.fieldnames) != required):
            raise ValueError("CSV headers must be timestamp,ip,username,status (any order).")
        for row in reader:
            line = reader.line_num
            try:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError("Incorrect number of columns.")
                stamp = row["timestamp"].strip()
                timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("Timestamp needs a timezone, such as Z or +00:00.")
                timestamp = timestamp.astimezone(timezone.utc)
                ip = str(ipaddress.ip_address(row["ip"].strip()))
                username = row["username"].strip()
                if (not username or len(username) > 128
                        or any(not char.isprintable() for char in username)):
                    raise ValueError("Username must contain 1–128 printable characters.")
                status = row["status"].strip().lower()
                if status not in {"success", "failure"}:
                    raise ValueError("Status must be success or failure.")
                events.append(Event(timestamp, ip, username, status))
            except (ValueError, OverflowError) as exc:
                rejected.append({"line": line, "reason": str(exc)})
    return events, rejected


def detect_alerts(events, threshold=5, window_seconds=60):
    """Find each IP's largest inclusive rolling window of failed logins."""
    if threshold < 1 or window_seconds < 1:
        raise ValueError("Threshold and window must be positive integers.")
    failures = defaultdict(list)
    for event in events:
        if event.status == "failure":
            failures[event.ip].append(event.timestamp)
    alerts = []
    for ip, timestamps in failures.items():
        window = deque()
        peak_count, peak_start, peak_end = 0, None, None
        for timestamp in sorted(timestamps):
            window.append(timestamp)
            while (timestamp - window[0]).total_seconds() > window_seconds:
                window.popleft()
            if len(window) > peak_count:
                peak_count = len(window)
                peak_start, peak_end = window[0], timestamp
        if peak_count >= threshold:
            alerts.append(Alert(ip, peak_count, peak_start.isoformat(), peak_end.isoformat()))
    return sorted(alerts, key=lambda item: (-item.failure_count, item.ip))


def build_report(events, rejected, alerts, source, threshold, window_seconds):
    return {
        "source": Path(source).name,
        "rule": {"threshold": threshold, "window_seconds": window_seconds,
                 "inclusive_boundary": True},
        "summary": {
            "valid_events": len(events),
            "rejected_rows": len(rejected),
            "failed_logins": sum(event.status == "failure" for event in events),
            "successful_logins": sum(event.status == "success" for event in events),
            "unique_ips": len({event.ip for event in events}),
            "flagged_ips": len(alerts),
        },
        "alerts": [asdict(alert) for alert in alerts],
        "rejected_rows": rejected,
    }


def save_database(path, events, report):
    """Keep normalized events, detection results and rejected rows queryable."""
    connection = sqlite3.connect(path)
    try:
        with connection:
            connection.executescript("""
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('success', 'failure'))
                );
                CREATE INDEX events_ip_time ON events(ip, timestamp);
                CREATE TABLE alerts (
                    ip TEXT PRIMARY KEY,
                    failure_count INTEGER NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL
                );
                CREATE TABLE rejected_rows (line INTEGER NOT NULL, reason TEXT NOT NULL);
                CREATE TABLE analysis (source TEXT, threshold INTEGER, window_seconds INTEGER);
            """)
            connection.executemany(
                "INSERT INTO events(timestamp, ip, username, status) VALUES (?, ?, ?, ?)",
                [(e.timestamp.isoformat(), e.ip, e.username, e.status) for e in events],
            )
            connection.executemany(
                "INSERT INTO alerts VALUES (?, ?, ?, ?)",
                [(a["ip"], a["failure_count"], a["window_start"], a["window_end"])
                 for a in report["alerts"]],
            )
            connection.executemany(
                "INSERT INTO rejected_rows VALUES (?, ?)",
                [(r["line"], r["reason"]) for r in report["rejected_rows"]],
            )
            connection.execute(
                "INSERT INTO analysis VALUES (?, ?, ?)",
                (report["source"], report["rule"]["threshold"], report["rule"]["window_seconds"]),
            )
    finally:
        connection.close()


def write_results(output, events, report):
    """Use a new directory for every run so earlier reports are preserved."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    save_database(output / "analysis.db", events, report)
    (output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    summary = report["summary"]
    lines = [
        "# Authentication log analysis", "",
        f"Source: {report['source'].replace(chr(10), ' ').replace(chr(13), ' ')}", "",
        f"Rule: at least {report['rule']['threshold']} failures from the same IP "
        f"within {report['rule']['window_seconds']} seconds (inclusive).", "",
        f"Valid events: {summary['valid_events']} | Rejected rows: {summary['rejected_rows']}",
        f"Failed logins: {summary['failed_logins']} | Successful logins: {summary['successful_logins']}",
        f"Flagged IPs: {summary['flagged_ips']}", "",
        "| IP | Peak failures | Window start (UTC) | Window end (UTC) |",
        "| --- | ---: | --- | --- |",
    ]
    for alert in report["alerts"]:
        lines.append(
            f"| {alert['ip']} | {alert['failure_count']} | "
            f"{alert['window_start']} | {alert['window_end']} |"
        )
    if not report["alerts"]:
        lines.extend(["", "No IP met the configured rule."])
    lines.extend(["", "Alerts identify patterns for review, not confirmed attacks.", ""])
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")


def positive_integer(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("Must be a positive integer.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Normalized CSV log file.")
    parser.add_argument("--threshold", type=positive_integer, default=5)
    parser.add_argument("--window-seconds", type=positive_integer, default=60)
    parser.add_argument("--output", type=Path, help="New output directory; must not exist.")
    args = parser.parse_args(argv)
    try:
        events, rejected = read_events(args.input)
        if not events:
            raise ValueError(f"No valid events found ({len(rejected)} rejected rows).")
        alerts = detect_alerts(events, args.threshold, args.window_seconds)
        report = build_report(events, rejected, alerts, args.input, args.threshold, args.window_seconds)
        output = args.output or Path("reports") / datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S%fZ")
        write_results(output, events, report)
    except (OSError, ValueError, UnicodeError, csv.Error, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Valid events: {len(events)} | Rejected rows: {len(rejected)}")
    print(f"Flagged IPs: {len(alerts)}")
    for alert in alerts:
        print(f"  {alert.ip}: {alert.failure_count} failures in the peak window")
    print(f"Reports saved to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
