# Technical Reference

[Back to the project README](../README.md)

## Input format

The input is a **normalized CSV**, not a raw SSH, Windows, or web-server log. Convert other log formats to these four columns first:

```csv
timestamp,ip,username,status
2026-10-01T10:00:00Z,203.0.113.10,admin,failure
2026-10-01T10:00:10Z,192.0.2.20,analyst,success
```

Timestamps need a timezone, such as `Z` or `+00:00`. Status must be `success` or `failure` (case-insensitive). Each row counts as a separate event, including identical rows.


## Command-line options

| Option | Default | Meaning |
| --- | --- | --- |
| `input` | Required | Path to a normalized CSV log file |
| `--threshold` | `5` | Minimum failures from one IP needed to generate an alert |
| `--window-seconds` | `60` | Length of the rolling window in seconds |
| `--output` | Unique directory under `reports/` | New output directory; must not already exist |
| `-h`, `--help` | — | Display command-line help |


## Failed writes and retries

An existing output path is rejected without overwriting it. Once a new run directory has been created, a failure during database or report writing triggers cleanup of that new directory. After correcting the underlying issue, retry with the same `--output` path. Existing output directories are never part of this cleanup.

## Output files

| File | Contents |
| --- | --- |
| `report.md` | Readable summary and flagged IPs |
| `report.json` | Rule settings, counts, alerts, and rejected rows |
| `analysis.db` | SQLite tables: `events`, `alerts`, `rejected_rows`, and `analysis` |

Example database query after the demo run:

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

This query counts failures across the whole file; the detection rule uses the rolling window instead.


## Recreate the demo (optional)

On Linux with DejaVu Sans Mono fonts and FFmpeg installed, install Pillow in a separate environment and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install Pillow
python tools/record_demo.py
```

This regenerates the MP4, GIF, and transcript from fresh executions. Output pacing is adjusted for readability; the demo does not add features to the analyzer.
