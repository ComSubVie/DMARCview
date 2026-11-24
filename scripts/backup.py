#!/usr/bin/env python3
"""Write a consistent SQLite backup of DMARCView's database.

    python3 scripts/backup.py [--destination data/backups] [--keep 14]

Safe to run while the app is serving requests.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.backup import BackupError, backup_database  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", help="directory for snapshots (default: DATA_DIR/backups)")
    parser.add_argument("--keep", type=int, default=None, help="snapshots to retain")
    args = parser.parse_args()
    try:
        target = backup_database(
            dest_dir=Path(args.destination) if args.destination else None, keep=args.keep
        )
    except BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"backup written to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
