# Auth Log Analyzer 🔐

A small defensive cybersecurity project built with **Python and SQLite**. It analyzes login records and flags IP addresses with repeated authentication failures inside a configurable time window.

This learning project connects programming, database development, and security log analysis. It was developed with AI assistance; the code is intentionally small enough to study and explain.

## Quick start

Requires **Python 3.12+**. No external packages or installation needed.

```bash
git clone https://github.com/Cat027/auth-log-analyzer.git
cd auth-log-analyzer
python3 logwatch.py data/sample_logins.csv --output reports/demo
```

Expected output:

```text
Valid events: 12 | Rejected rows: 0
Flagged IPs: 1
  203.0.113.10: 5 failures in the peak window
Reports saved to: reports/demo
```

See the [sample report](docs/sample_report.md).

Use a new directory for each run, or omit `--output` to generate a unique directory automatically.

## What it does

- Validates timestamps, IPv4/IPv6 addresses, usernames, and login statuses.
- Flags at least **5 failed logins from one IP within 60 seconds** by default.
- Sorts timestamps before applying a sliding window; unsorted input is supported.
- Reports invalid rows with their line numbers and rejection reasons.
- Exports a readable Markdown report, a JSON report, and a queryable SQLite database.
- Preserves previous reports by refusing to overwrite existing output directories.

Customize the rule:

```bash
python3 logwatch.py data/sample_logins.csv --threshold 3 --window-seconds 300
```

## Input format

The input is a **normalized CSV**, not a raw SSH, Windows, or web-server log. Convert other log formats to these four columns first:

```csv
timestamp,ip,username,status
2026-10-01T10:00:00Z,203.0.113.10,admin,failure
2026-10-01T10:00:10Z,192.0.2.20,analyst,success
```

Timestamps must include a timezone. Supported statuses are `success` and `failure` (case-insensitive). Each CSV row represents one event; duplicate rows count separately. The included data is entirely fictional.

## Database

Each run creates `analysis.db` with `events`, `alerts`, `rejected_rows`, and `analysis` tables. Timestamps are normalized to UTC. The `analysis` table records the source filename and rule parameters.

Example query with Python:

```python
import sqlite3

with sqlite3.connect("reports/demo/analysis.db") as db:
    rows = db.execute("""
        SELECT ip, COUNT(*) AS failures
        FROM events
        WHERE status = ?
        GROUP BY ip
        ORDER BY failures DESC
    """, ("failure",)).fetchall()
    print(rows)
```

This query counts failures across the entire file. Alerts use the rolling time window instead. User input is stored with parameterized SQL statements.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests cover detection boundaries, separate IPs, unsorted events, IPv6, timezone normalization, rejected rows, SQL-like usernames, report preservation, and end-to-end output consistency.

## Limitations

- An alert is a pattern to investigate, **not proof of an attack**. Shared IPs and normal user mistakes can trigger it.
- Failures are grouped by IP across usernames; successful logins do not reset the window.
- One alert per IP summarizes its largest failure window, choosing the earliest on ties. This does not list every suspicious interval.
- It does not inspect the network, block IPs, monitor in real time, or detect distributed attempts below the per-IP threshold.
- Events are loaded into memory; this version is intended for small learning datasets.
- No duplicate removal, raw-log parser, or live incident-response integration is implemented.

## Next steps

- Add a parser for a specific authentication log format.
- Add account-based detection alongside IP-based detection.
- Compare sample false positives under different thresholds.

For a guided explanation in Portuguese, see [docs/GUIA_PT_BR.md](docs/GUIA_PT_BR.md).
