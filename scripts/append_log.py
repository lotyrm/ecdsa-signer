#!/usr/bin/env python3
"""
Append a conversation message to today's daily log file under logs/log-YYYY-MM-DD.md.

Usage examples:
  python scripts/append_log.py --role user --message "Hola" \
    --log-dir logs

Optional flags:
  --timestamp 2025-10-20T18:44:45Z   # defaults to current UTC time
  --date 2025-10-20                  # overrides file date (UTC)
  --log-dir path/to/logs             # defaults to 'logs'

The script creates the daily file and header if it doesn't exist, and writes atomically.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
import tempfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Append a message to the daily conversation log")
    parser.add_argument("--role", required=True, help="Message role, e.g., user, assistant, system")
    parser.add_argument("--message", required=True, help="Message content to append")
    parser.add_argument("--timestamp", help="ISO-8601 UTC timestamp like 2025-10-20T18:44:45Z")
    parser.add_argument("--date", help="Log date YYYY-MM-DD (UTC). Defaults to today's UTC date")
    parser.add_argument("--log-dir", default="logs", help="Directory where logs are stored")
    return parser.parse_args()


def ensure_header(file_path: Path, log_date: str) -> str:
    """Return base file content with header if file doesn't exist or is empty."""
    header = f"# Registro diario - {log_date}\n\n"
    header += "Pega aquí los mensajes/conversación completos del día, o los fragmentos que quieras conservar íntegros.\n\n---\n"
    if not file_path.exists():
        return header
    try:
        existing = file_path.read_text(encoding="utf-8")
    except Exception:
        return header
    return existing if existing.strip() else header


def atomic_write_text(path: Path, content: str) -> None:
    """Write content atomically to `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(path.parent)) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, path)


def main() -> int:
    args = parse_args()

    now_utc = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    iso_ts = args.timestamp or now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    log_date = args.date or now_utc.strftime("%Y-%m-%d")

    log_dir = Path(args.log_dir)
    log_file = log_dir / f"log-{log_date}.md"

    base = ensure_header(log_file, log_date)

    # Normalize line endings and avoid trailing spaces
    message = args.message.replace("\r\n", "\n").replace("\r", "\n")

    entry_lines = []
    entry_lines.append("")
    entry_lines.append(f"## {iso_ts} - {args.role}")
    entry_lines.append("")
    entry_lines.append(message)
    entry_lines.append("")

    new_content = base.rstrip() + "\n" + "\n".join(entry_lines) + "\n"

    try:
        atomic_write_text(log_file, new_content)
    except Exception as exc:
        print(f"Error writing log: {exc}", file=sys.stderr)
        return 1

    print(str(log_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
