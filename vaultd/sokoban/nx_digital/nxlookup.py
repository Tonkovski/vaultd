"""NX digital keeper: ownership coverage report. Takes no arguments.

For every application group the vault owns anything of, reports against
titledb knowledge — regardless of artifact labels and regardless of hashdb:

  BASE  owned or MISSING
  UPD   latest owned vs the newest version titledb knows (versions.json)
  DLC   owned count vs the group's known DLC catalog (cnmts.json), with the
        missing ids named

Group arithmetic pinned from nxdumptool (include/core/title.h): patch id =
app + 0x800; add-on-content base = (app & 0xFFFFFFFFFFFFF000) + 0x1000 with
valid DLC ids in [aoc_base + 1, aoc_base + 2000].
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from vaultd import catalog, locator
from vaultd.locator import DB_ROOT
from vaultd.sokoban.nx_digital import VAULT_NAME
from vaultd.titledb import TitleDB

DB_DIR = DB_ROOT / VAULT_NAME
AOC_MASK = 0xFFFFFFFFFFFFF000
AOC_OFFSET = 0x1000
AOC_MIN_INDEX = 1
AOC_MAX_INDEX = 2000
PATCH_OFFSET = 0x800


def classify(tid: str) -> tuple[str, str]:
    """(kind, application id) for a title id: APP, UPD or DLC."""
    value = int(tid, 16)
    low13 = value & 0x1FFF
    if low13 == 0:
        return "APP", tid
    if low13 == PATCH_OFFSET:
        return "UPD", f"{value - PATCH_OFFSET:016X}"
    index = value & 0xFFF
    aoc_base = value & AOC_MASK
    if AOC_MIN_INDEX <= index <= AOC_MAX_INDEX and (aoc_base & 0x1FFF) == AOC_OFFSET:
        return "DLC", f"{aoc_base - AOC_OFFSET:016X}"
    return "APP", tid


def dlc_ids_of(app_id: str, known_tids: set[str]) -> list[str]:
    aoc_base = (int(app_id, 16) & AOC_MASK) + AOC_OFFSET
    out = []
    for index in range(AOC_MIN_INDEX, AOC_MAX_INDEX + 1):
        candidate = f"{aoc_base + index:016X}"
        if candidate.lower() in known_tids:
            out.append(candidate)
    return out


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("nxlookup takes no arguments (default behaviour only)",
              file=sys.stderr)
        return 2
    try:
        vdir = locator.resolve([VAULT_NAME])[VAULT_NAME]
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    titledb_dir = DB_DIR / "titledb"
    cnmts_path = titledb_dir / "cnmts.json"
    versions_path = titledb_dir / "versions.json"
    for required in (vdir / "datmeta.xml", cnmts_path, versions_path):
        if not required.is_file():
            print(f"ERROR: missing {required}", file=sys.stderr)
            return 2

    cat = catalog.load(vdir / "datmeta.xml")
    known_tids = set(json.loads(cnmts_path.read_text(encoding="utf-8")).keys())
    versions = json.loads(versions_path.read_text(encoding="utf-8"))
    names = TitleDB(titledb_dir)

    # ownership sweep: any fileshared in any release counts, labels ignored.
    owned_base: dict[str, list[str]] = {}      # app id -> base versions
    owned_upd: dict[str, list[int]] = {}       # app id -> update version ints
    owned_dlc: dict[str, set[str]] = {}        # app id -> dlc tids owned
    groups: set[str] = set()
    for entity in cat.entities:
        kind, app_id = classify(entity.identifier)
        has_files = any(release.shared for release in entity.releases)
        if not has_files:
            continue
        groups.add(app_id)
        if kind == "DLC":
            owned_dlc.setdefault(app_id, set()).add(entity.identifier)
            continue
        for release in entity.releases:
            if not release.shared:
                continue
            number = int(release.version.lstrip("v")) \
                if release.version.lstrip("v").isdigit() else None
            if release.standalone:
                owned_base.setdefault(app_id, []).append(release.version)
            elif number is not None:
                owned_upd.setdefault(app_id, []).append(number)

    print(f"vault: {vdir}")
    print(f"groups owned: {len(groups)}\n")
    incomplete = 0
    for app_id in sorted(groups):
        # only problems print: healthy groups and healthy lines are hidden.
        lines: list[str] = []

        if not owned_base.get(app_id):
            lines.append("  BASE  MISSING")

        version_rows = versions.get(app_id.lower()) or {}
        latest_known = max((int(key) for key in version_rows), default=None)
        have = max(owned_upd.get(app_id, []), default=None)
        if latest_known is not None:
            if have is None:
                lines.append(f"  UPD   MISSING: latest v{latest_known} "
                             f"({version_rows[str(latest_known)]})")
            elif have < latest_known:
                lines.append(f"  UPD   outdated: v{have} owned, latest "
                             f"v{latest_known} ({version_rows[str(latest_known)]})")

        known_dlc = dlc_ids_of(app_id, known_tids)
        owned = owned_dlc.get(app_id, set())
        missing = [tid for tid in known_dlc if tid not in owned]
        if missing:
            lines.append(f"  DLC   {len(known_dlc) - len(missing)}"
                         f"/{len(known_dlc)} owned; missing:")
            for tid in missing:
                dlc_name = names.query(tid)[0] or "(name unknown)"
                lines.append(f"        [{tid}] {dlc_name}")

        if lines:
            incomplete += 1
            name = names.query(app_id)[0] or "(name unknown)"
            print(f"[{app_id}] {name}")
            for line in lines:
                print(line)
            print()

    print(f"done: {len(groups)} group(s), {incomplete} with gaps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
