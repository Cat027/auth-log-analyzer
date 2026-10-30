# Auth Log Analyzer 🔐

A defensive cybersecurity learning project that analyzes login logs and flags repeated authentication failures by IP address. Built with **Python and SQLite**, with configurable detection rules and exportable reports.

**No external runtime dependencies · Offline analysis · Fictional sample data**

[Run the project](#run-the-project) · [Demo](#demo) · [Features](#features) · [Português](docs/GUIA_PT_BR.md)

## Demo

![Terminal demonstration of three detection configurations and the automated tests](docs/media/demo.gif)

**[Watch or download the 26-second video (MP4)](docs/media/demo.mp4)** · [Execution transcript](docs/media/demo-transcript.json)

The demonstration replays output captured from real executions, with adjusted pacing for readability. It is a rendered terminal replay, not a desktop screen recording. It shows:

| Configuration | Result with the included sample |
| --- | --- |
| Default: 5 failures in 60 seconds | 1 flagged IP |
| Higher threshold: 6 failures in 60 seconds | 0 flagged IPs |
| Wider window: 3 failures in 300 seconds | 2 flagged IPs |
| Automated tests | 14 tests passing |

## Technologies used

| Technology | Purpose |
| --- | --- |
| Python 3.12+ | CLI application and detection logic |
| SQLite / `sqlite3` | Store events, alerts, rejected rows, and analysis parameters |
| `csv` and `json` | Read normalized logs and export structured reports |
| `datetime` and `ipaddress` | Validate timestamps and IPv4/IPv6 addresses; normalize timezones |
| `argparse` | Configure the command-line interface |
| `collections.deque` | Maintain the rolling detection window |
| `unittest` | Automated tests |
| Git and GitHub | Version control and project documentation |

The analyzer uses only the Python standard library. **Pillow and FFmpeg are optional demo-generation tools**, not requirements for analyzing logs.

## Features

- Detect repeated failed logins from the same IP inside a configurable time window.
- Support IPv4, IPv6, timezone-aware timestamps, and unsorted events.
- Reject invalid rows with a line number and explanation.
- Generate Markdown, JSON, and SQLite outputs.
- Preserve earlier results by using a new output directory for each analysis.
- Store user-supplied values with parameterized SQL statements.
- Provide fictional data and tests for reproducible experimentation.

## What users can do

1. Run the included sample to see how the detection rule behaves.
2. Analyze their own login records after converting them to the documented CSV format.
3. Adjust the threshold and time window to compare results and possible false positives.
4. Read a report or query the resulting SQLite database.
5. Modify the implementation and run the tests to check its behavior.

An alert is a pattern for investigation, **not proof of an attack**.

## Run the project

Requires **Python 3.12+**. No `pip install` is needed to run the analyzer.

```bash
git clone https://github.com/Cat027/auth-log-analyzer.git
cd auth-log-analyzer
python3 --version
python3 logwatch.py data/sample_logins.csv --output reports/demo
```

Expected output:

```text
Valid events: 12 | Rejected rows: 0
Flagged IPs: 1
  203.0.113.10: 5 failures in the peak window
Reports saved to: reports/demo
```

Open `reports/demo/report.md` to read the result, or see the committed [sample report](docs/sample_report.md).

For another run, omit `--output` to create a unique directory automatically:

```bash
python3 logwatch.py data/sample_logins.csv
```

Compare two other configurations:

```bash
python3 logwatch.py data/sample_logins.csv --threshold 6
python3 logwatch.py data/sample_logins.csv --threshold 3 --window-seconds 300
```

Show the available options:

```bash
python3 logwatch.py --help
```

### Command-line options

| Option | Default | Meaning |
| --- | --- | --- |
| `input` | Required | Path to a normalized CSV log file |
| `--threshold` | `5` | Minimum failures from one IP needed to generate an alert |
| `--window-seconds` | `60` | Length of the rolling window in seconds |
| `--output` | Unique directory under `reports/` | New output directory; must not already exist |
| `-h`, `--help` | — | Display command-line help |

### Keyboard shortcuts

This is a command-line tool with **no application-specific keyboard shortcuts**. These standard shortcuts are useful in an interactive Linux/Bash terminal:

| Shortcut | Action |
| --- | --- |
| `Enter` | Execute the command |
| `↑` / `↓` | Browse command history |
| `Tab` | Complete commands or file paths when the shell supports completion |
| `Ctrl + C` | Interrupt the running command |
| `Ctrl + L` | Clear the terminal display |

## Input format

The input is a **normalized CSV**, not a raw SSH, Windows, or web-server log. Convert other log formats to these four columns first:

```csv
timestamp,ip,username,status
2026-10-01T10:00:00Z,203.0.113.10,admin,failure
2026-10-01T10:00:10Z,192.0.2.20,analyst,success
```

Timestamps need a timezone, such as `Z` or `+00:00`. Status must be `success` or `failure` (case-insensitive). Each row counts as a separate event, including identical rows.

## How the process works

1. **Read:** open the CSV and validate its column names.
2. **Validate:** check each timestamp, IP, username, and status; record rejected rows separately.
3. **Normalize:** convert timestamps to UTC and standardize IP formatting.
4. **Detect:** group failures by IP, sort their timestamps, and find the largest rolling window for each IP.
5. **Report:** export summaries, alerts, and rejection details.
6. **Store:** keep the validated events and analysis results in SQLite for later queries.

The time-window boundary is inclusive: events at seconds 0 and 60 can belong to the same 60-second window. A successful login does not reset the failure count.

### Output files

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

## How it was built

This project was developed with **AI assistance as a guided learning project**. I am studying the implementation and will document my own changes as the project evolves.

The implementation started with a small, reproducible problem: detecting repeated login failures in a fictional dataset. The code separates input validation, detection, reporting, and database storage into functions in `logwatch.py`. Standard-library tools keep setup simple. Tests check the rule boundaries and complete output generation; the terminal demo captures real execution results.

| File | Responsibility |
| --- | --- |
| `logwatch.py` | CLI, CSV validation, detection, reports, and SQLite storage |
| `data/sample_logins.csv` | Fictional dataset used in examples |
| `tests/test_logwatch.py` | Detection, input, CLI, and output tests |
| `docs/GUIA_PT_BR.md` | Guided explanation and exercises in Portuguese |
| `docs/media/` | Demo video, animated preview, and execution transcript |
| `tools/record_demo.py` | Optional script for regenerating the demonstration |

## What I'm learning

These are the topics I am studying through the project, rather than claims of completed expertise:

- Reading and validating structured data with Python.
- Comparing timezone-aware timestamps and using a sliding window.
- Designing SQLite tables and using parameterized queries.
- Testing boundaries, malformed input, and complete application behavior.
- Understanding detection thresholds, false positives, and the limits of IP-based rules.
- Using Git and writing documentation that others can reproduce.

The [Portuguese study guide](docs/GUIA_PT_BR.md) includes exercises to work through before presenting the implementation in an interview.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The current suite contains **14 tests**, covering time-window boundaries, separate IPs, unsorted events, duplicate rows, IPv6, timezone normalization, rejected input, SQL-like usernames, existing report protection, and end-to-end output consistency.

## Limitations and improvements

### Current limitations

- One alert per IP summarizes its largest failure window; it does not list every interval.
- Shared IPs can produce false positives, while distributed attempts may stay below the threshold.
- All events are loaded into memory, so this version is intended for small learning datasets.
- There is no raw-log parser, deduplication, live monitoring, IP blocking, or incident-response integration.

### Possible improvements

- [ ] Add a parser for one real authentication log format.
- [ ] Add account-based detection alongside IP-based detection.
- [ ] Compare false positives across more realistic fictional scenarios.
- [ ] Add optional duplicate handling with a documented event identifier.
- [ ] Process large files incrementally.
- [ ] Add automated test execution through GitHub Actions.

## Recreate the demo (optional)

On Linux with DejaVu Sans Mono fonts and FFmpeg installed, install Pillow in a separate environment and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install Pillow
python tools/record_demo.py
```

This regenerates the MP4, GIF, and transcript from fresh executions. Output pacing is adjusted for readability; the demo does not add features to the analyzer.
