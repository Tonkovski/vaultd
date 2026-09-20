"""NX digital keeper: ownership coverage report. Takes no arguments.

For every application group the vault owns anything of, reports gaps —
anchored by the base application, regardless of artifact labels:

  BASE  owned or MISSING
  UPD   latest owned vs the newest version titledb knows (versions.json)
  DLC   owned count vs the group's known DLC catalog, with the missing
        ids named

titledb is the sole gap source. The DLC catalog is the union of every
title id titledb knows anywhere — cnmts.json keys, versions.json keys and
the id fields of all region catalogs — because each source alone is
partial (region catalogs list store ids cnmts never saw, and vice versa).
Owned artifacts never appear, whatever their label. Healthy groups and
healthy lines are hidden.

hashdb is optional and is queried only to mint the [MIA] mark: a gap line
earns it when the No-Intro dats hold no row for that title id (+version
for updates) — missing in action from preservation itself, not merely
from this vault. Without any dats the report still runs, minus the marks.

Group arithmetic pinned from nxdumptool (include/core/title.h): patch id =
app + 0x800; add-on-content base = (app & 0xFFFFFFFFFFFFF000) + 0x1000 with
valid DLC ids in [aoc_base + 1, aoc_base + 2000].
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import xml.etree.ElementTree as ET

from vaultd import catalog, locator
from vaultd.locator import DB_ROOT
from vaultd.sokoban.nx_digital import VAULT_NAME
from vaultd.titledb import REGION_PRIORITY, TitleDB

# Personal display ladder for THIS tool only. Regions listed here are
# consulted before the shared NACP-order spine (REGION_PRIORITY in
# vaultd/titledb.py — US.en, GB.en, JP.ja, the .en sweep, then NACP tail);
# the spine stays underneath as fallback so nothing goes nameless. Edit to
# taste; empty keeps the project-wide order. Presentation only — ingest
# keeps writing datmeta descriptions in canonical NACP order.
# DISPLAY_REGION_PRIORITY: list[str] = [
#     "US.en", "GB.en", "JP.ja",
#     "AR.en", "AU.en", "BG.en", "BR.en", "CA.en", "CL.en", "CN.en", "CO.en",
#     "CY.en", "CZ.en", "DK.en", "EE.en", "FI.en", "GR.en", "HR.en", "HU.en",
#     "IE.en", "IL.en", "JP.en", "LT.en", "LV.en", "MT.en", "MX.en", "NO.en",
#     "NZ.en", "PE.en", "PL.en", "RO.en", "SE.en", "SI.en", "SK.en", "ZA.en",
#     "FR.fr", "DE.de", "MX.es", "ES.es", "IT.it", "NL.nl", "CA.fr", "PT.pt",
#     "RU.ru", "KR.ko", "HK.zh", "CN.zh", "BR.pt",
# ]

DISPLAY_REGION_PRIORITY: list[str] = [
    "HK.zh", "CN.zh", "US.en", "GB.en", "JP.ja",
    "AR.en", "AU.en", "BG.en", "BR.en", "CA.en", "CL.en", "CN.en", "CO.en",
    "CY.en", "CZ.en", "DK.en", "EE.en", "FI.en", "GR.en", "HR.en", "HU.en",
    "IE.en", "IL.en", "JP.en", "LT.en", "LV.en", "MT.en", "MX.en", "NO.en",
    "NZ.en", "PE.en", "PL.en", "RO.en", "SE.en", "SI.en", "SK.en", "ZA.en",
    "FR.fr", "DE.de", "MX.es", "ES.es", "IT.it", "NL.nl", "CA.fr", "PT.pt",
    "RU.ru", "KR.ko", "BR.pt",
]

DB_DIR = DB_ROOT / VAULT_NAME
AOC_MASK = 0xFFFFFFFFFFFFF000
AOC_OFFSET = 0x1000
AOC_MIN_INDEX = 1
AOC_MAX_INDEX = 2000
PATCH_OFFSET = 0x800

_ID_FIELD = re.compile(rb'"id":\s*"([0-9A-Fa-f]{16})"')


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


def display_titledb() -> TitleDB:
    """TitleDB with this tool's personal display ladder applied.

    nxlookup's own; genezaccess carries its independent ladder in its own
    module — the two are edited separately.
    """
    return TitleDB(DB_DIR / "titledb", priority=[
        *DISPLAY_REGION_PRIORITY,
        *[region for region in REGION_PRIORITY
          if region not in DISPLAY_REGION_PRIORITY]])


def load_title_universe(titledb_dir: Path) -> set[str]:
    """Every title id titledb knows, lowercase, from all sources unioned."""
    universe: set[str] = set()
    for name in ("cnmts.json", "versions.json"):
        path = titledb_dir / name
        if path.is_file():
            universe.update(
                key.lower()
                for key in json.loads(path.read_text(encoding="utf-8")))
    for path in sorted(titledb_dir.glob("*.json")):
        if path.name in ("cnmts.json", "versions.json", "ncas.json"):
            continue
        universe.update(
            match.decode("ascii").lower()
            for match in _ID_FIELD.findall(path.read_bytes()))
    return universe


def load_dat_index(dats: list[Path]) -> tuple[set[str], set[tuple[str, int]]]:
    """(title ids, (title id, version) pairs) known to the No-Intro dats."""
    tids: set[str] = set()
    versions: set[tuple[str, int]] = set()
    for dat in dats:
        for game in ET.parse(dat).getroot().iter("game"):
            gid = game.findtext("game_id")
            if not gid:
                continue
            gid = gid.strip().upper()
            tids.add(gid)
            raw = (game.findtext("version1") or "").strip().lstrip("vV")
            if raw.isdigit():
                versions.add((gid, int(raw)))
    return tids, versions


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
    versions_path = titledb_dir / "versions.json"
    for required in (vdir / "datmeta.xml", titledb_dir / "cnmts.json",
                     versions_path):
        if not required.is_file():
            print(f"ERROR: missing {required}", file=sys.stderr)
            return 2

    cat = catalog.load(vdir / "datmeta.xml")
    universe = load_title_universe(titledb_dir)
    versions = json.loads(versions_path.read_text(encoding="utf-8"))
    names = display_titledb()

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

    # dats load lazily, once the first gap needs its verdict; absent dats
    # degrade to a report without [MIA] marks, never to a failure.
    dat_index: list[tuple[set[str], set[tuple[str, int]]] | None] = []

    def mia(tid: str, version: int | None = None) -> str:
        if not dat_index:
            dats = sorted((DB_DIR / "hashdb").glob("*.xml"))
            if not dats:
                print("note: no hashdb dats found; [MIA] verdicts "
                      "unavailable", file=sys.stderr)
            dat_index.append(load_dat_index(dats) if dats else None)
        if dat_index[0] is None:
            return ""
        tids, pairs = dat_index[0]
        if version is not None:
            known = (tid.upper(), version) in pairs
        else:
            known = tid.upper() in tids
        return "" if known else " [MIA]"

    print(f"vault: {vdir}")
    print(f"groups owned: {len(groups)}\n")
    incomplete = 0
    for app_id in sorted(groups):
        # only problems print: healthy groups and healthy lines are hidden.
        lines: list[str] = []

        if not owned_base.get(app_id):
            lines.append(f"  BASE  MISSING{mia(app_id)}")

        version_rows = versions.get(app_id.lower()) or {}
        latest_known = max((int(key) for key in version_rows), default=None)
        have = max(owned_upd.get(app_id, []), default=None)
        if latest_known is not None:
            upd_tid = f"{int(app_id, 16) + PATCH_OFFSET:016X}"
            if have is None:
                lines.append(f"  UPD   MISSING: latest v{latest_known} "
                             f"({version_rows[str(latest_known)]})"
                             f"{mia(upd_tid, latest_known)}")
            elif have < latest_known:
                lines.append(f"  UPD   outdated: v{have} owned, latest "
                             f"v{latest_known} ({version_rows[str(latest_known)]})"
                             f"{mia(upd_tid, latest_known)}")

        known_dlc = dlc_ids_of(app_id, universe)
        owned = owned_dlc.get(app_id, set())
        missing = [tid for tid in known_dlc if tid not in owned]
        if missing:
            lines.append(f"  DLC   {len(known_dlc) - len(missing)}"
                         f"/{len(known_dlc)} owned; missing:")
            for tid in missing:
                dlc_name = names.query(tid)[0] or "(name unknown)"
                lines.append(f"        [{tid}] {dlc_name}{mia(tid)}")

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
