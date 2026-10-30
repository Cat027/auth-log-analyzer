# Authentication log analysis

Source: sample_logins.csv

Rule: at least 5 failures from the same IP within 60 seconds (inclusive).

Valid events: 12 | Rejected rows: 0
Failed logins: 8 | Successful logins: 4
Flagged IPs: 1

| IP | Peak failures | Window start (UTC) | Window end (UTC) |
| --- | ---: | --- | --- |
| 203.0.113.10 | 5 | 2026-10-01T10:00:00+00:00 | 2026-10-01T10:00:40+00:00 |

Alerts identify patterns for review, not confirmed attacks.
