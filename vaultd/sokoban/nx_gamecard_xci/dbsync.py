"""NX gamecard keeper: refresh the metadata feed cache under db/<vault>/.

Feeds (cache, not custody — re-downloadable, never protected by catalog or
checksum):

    db/nx_gamecard_xci/
      titledb/          shallow git clone of blawar/titledb, master only
      switchtdb.xml     GameTDB title database, plain download

git runs as a subprocess with its output streaming to the terminal; a missing
git binary is a clean failure, not a stack trace. Interruption-safe: git's
own transaction model covers the clone/fetch, and the switchtdb download
lands via tmp + atomic replace.
"""

from __future__ import annotations

import argparse
import io
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

from vaultd.gitfeed import sync_git_feed
from vaultd.locator import DB_ROOT
from vaultd.sokoban.nx_gamecard_xci import VAULT_NAME

TITLEDB_URL = "https://github.com/blawar/titledb"
TITLEDB_BRANCH = "master"
SWITCHTDB_URL = "https://www.gametdb.com/switchtdb.zip"


def sync_titledb(db_dir: Path, url: str) -> bool:
    return sync_git_feed(db_dir / "titledb", url, TITLEDB_BRANCH)


def sync_switchtdb(db_dir: Path) -> bool:
    dest = db_dir / "switchtdb.xml"
    print(f"switchtdb: downloading {SWITCHTDB_URL}")
    req = urllib.request.Request(SWITCHTDB_URL, headers={"User-Agent": "vaultd/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = resp.read()
    except Exception as exc:  # noqa: BLE001 - network zoo
        print(f"ERROR: switchtdb download failed: {exc}", file=sys.stderr)
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            member = next((n for n in archive.namelist() if n.endswith(".xml")), None)
            if member is None:
                print("ERROR: switchtdb zip carries no XML member", file=sys.stderr)
                return False
            data = archive.read(member)
    except zipfile.BadZipFile as exc:
        print(f"ERROR: switchtdb download is not a zip: {exc}", file=sys.stderr)
        return False
    if not data.lstrip().startswith(b"<?xml"):
        print("ERROR: switchtdb zip member is not XML; discarded", file=sys.stderr)
        return False
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(dest)
    print(f"switchtdb: {member} ({len(data)} bytes) -> {dest}")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-gamecard-dbsync", description=__doc__)
    parser.parse_args(argv)

    db_dir = DB_ROOT / VAULT_NAME
    db_dir.mkdir(parents=True, exist_ok=True)
    print(f"db: {db_dir}")

    ok = sync_titledb(db_dir, TITLEDB_URL)
    ok &= sync_switchtdb(db_dir)
    print("dbsync: " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
