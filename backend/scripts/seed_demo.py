"""Load the bundled sample logs into a SentinelSOC instance.

The sample files contain realistic security log lines. To make the dashboard
meaningful on a fresh install, each line is re-stamped relative to "now" so the
events fall inside the dashboard's look-back window.

Usage:
    .venv/bin/python -m scripts.seed_demo [--org 1] [--source-dir ../data/samples]

Requires a running backend/database (or it will use the configured DATABASE_URL).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal, init_db  # noqa: E402
from app.models import Organization  # noqa: E402
from app.pipeline.pipeline import process_ingest  # noqa: E402

ISO_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})")
SYSLOG_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
MONTH_NAMES = {i + 1: m for m, i in MONTHS.items()}

FILES = [
    "linux_auth.log",
    "windows_event.jsonl",
    "web_server.log",
    "firewall.log",
    "application.log",
    "csv_logs.csv",
    "json_logs.jsonl",
]


def freshen(line: str, t: datetime) -> str:
    """Replace the timestamp in a sample line with the given time ``t``."""
    iso = ISO_RE.search(line)
    if iso:
        ts = t.strftime("%Y-%m-%dT%H:%M:%S")
        return line[:iso.start()] + ts + line[iso.end():]
    return line


def freshen_syslog(line: str, t: datetime) -> str:
    m = SYSLOG_RE.match(line)
    if not m:
        return line
    month = MONTH_NAMES[t.month]
    repl = f"{month} {t.day:2d} {t.strftime('%H:%M:%S')}"
    return repl + line[m.end():]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", type=int, default=1)
    parser.add_argument("--source-dir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "data", "samples"))
    parser.add_argument("--window-minutes", type=int, default=50)
    parser.add_argument("--skip", action="store_true",
                        help="skip re-stamping (use original timestamps)")
    args = parser.parse_args()

    init_db()
    from app.bootstrap import bootstrap as run_bootstrap
    db = SessionLocal()
    try:
        run_bootstrap(db)
        org = db.get(Organization, args.org)
        if org is None:
            print(f"Organization {args.org} not found")
            sys.exit(1)

        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=args.window_minutes)
        span = args.window_minutes * 60

        total_entries = 0
        for fname in FILES:
            path = os.path.join(args.source_dir, fname)
            if not os.path.exists(path):
                print(f"  (skip missing {path})")
                continue
            with open(path) as fh:
                lines = [l.rstrip("\n") for l in fh if l.strip()]
            n = len(lines)
            entries = []
            for i, line in enumerate(lines):
                frac = i / max(n - 1, 1)
                t = start + timedelta(seconds=int(frac * span))
                raw = line if args.skip else freshen(line, t)
                if not args.skip and fname == "linux_auth.log":
                    raw = freshen_syslog(line, t)
                kind = {
                    "linux_auth.log": "linux_auth",
                    "windows_event.jsonl": "windows_event",
                    "web_server.log": "web_server",
                    "firewall.log": "firewall",
                    "application.log": "application",
                    "csv_logs.csv": "csv",
                    "json_logs.jsonl": "json",
                }[fname]
                entries.append({"source_log_type": kind, "raw": raw})
            result = process_ingest(db, organization_id=org.id, entries=entries)
            total_entries += len(entries)
            print(f"  {fname}: {result.accepted} accepted, "
                  f"{result.alerts} alerts, {result.rejected} rejected")
        db.commit()
        print(f"Done. Seeded {total_entries} events into organization '{org.name}'.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
