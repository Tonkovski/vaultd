"""NX digital keeper: refresh the metadata feed cache under db/<vault>/.

Feeds (cache, not custody):

    db/nx_digital/
      titledb/           shallow git clone of blawar/titledb, master only
                         (carries cnmts.json — fixnsp's CNMTDB)
      hashdb/            No-Intro dat snapshots — NEVER fetched by this tool.
                         Datomatic offers no clean automation lane, so the
                         dats are manual drops; dbsync only reports each
                         snapshot's age and reminds when they grow stale.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date, datetime
from pathlib import Path

from vaultd.gitfeed import sync_git_feed
from vaultd.locator import DB_ROOT
from vaultd.sokoban.nx_digital import VAULT_NAME

TITLEDB_URL = "https://github.com/blawar/titledb"
TITLEDB_BRANCH = "master"
HASHDB_STALE_DAYS = 60
DAT_STAMP_RE = re.compile(r"\((\d{8})-\d{6}\)")


def report_hashdb(hashdb: Path) -> bool:
    print(f"hashdb: {hashdb}")
    if not hashdb.is_dir():
        print("  WARN: hashdb directory missing — No-Intro dats are manual "
              "drops; create it and add the current snapshots", file=sys.stderr)
        return False
    dats = sorted(hashdb.glob("*.xml"))
    if not dats:
        print("  WARN: no dat snapshots present — download current No-Intro "
              "dats from Datomatic and drop them here", file=sys.stderr)
        return False
    stale = False
    for dat in dats:
        match = DAT_STAMP_RE.search(dat.name)
        if match is None:
            print(f"  {dat.name}: no datestamp in filename")
            continue
        stamp = datetime.strptime(match.group(1), "%Y%m%d").date()
        age = (date.today() - stamp).days
        marker = "  <- STALE, refresh manually" if age > HASHDB_STALE_DAYS else ""
        stale |= age > HASHDB_STALE_DAYS
        print(f"  {dat.name}: {age} day(s) old{marker}")
    if stale:
        print(f"  reminder: snapshots older than {HASHDB_STALE_DAYS} days — "
              "fetch fresh dats from Datomatic and replace the files above")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-digital-dbsync", description=__doc__)
    parser.parse_args(argv)

    db_dir = DB_ROOT / VAULT_NAME
    db_dir.mkdir(parents=True, exist_ok=True)
    print(f"db: {db_dir}")

    ok = sync_git_feed(db_dir / "titledb", TITLEDB_URL, TITLEDB_BRANCH)
    ok &= report_hashdb(db_dir / "hashdb")
    print("dbsync: " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
