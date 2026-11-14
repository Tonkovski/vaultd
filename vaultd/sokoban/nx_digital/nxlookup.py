"""NX digital keeper: targeted ownership coverage report.

Accepts one case-insensitive hexadecimal title id through ``--tid``. The id
may name a base application, update or DLC; all resolve to the same application
family. Reports only that family's missing members, regardless of artifact
labels:

  BASE  owned or MISSING
  UPD   latest owned vs the newest version titledb knows (versions.json)
  DLC   owned count vs the group's known DLC catalog, with the missing
        ids named

titledb is the sole gap source. The DLC catalog is the union of every
title id titledb knows anywhere — cnmts.json keys, versions.json keys and
the id fields of all region catalogs — because each source alone is
partial (region catalogs list store ids cnmts never saw, and vice versa).
Owned artifacts never appear, whatever their label. Healthy lines are hidden.

hashdb is optional and is queried only to mint the [MIA] mark: a gap line
earns it when the DATVault hashdb holds no row for that title id (+version
for updates) — missing in action from preservation itself, not merely
from this vault. Without any dats the report still runs, minus the marks.

Group arithmetic pinned from nxdumptool (include/core/title.h): patch id =
app + 0x800; add-on-content base = (app & 0xFFFFFFFFFFFFF000) + 0x1000 with
valid DLC ids in [aoc_base + 1, aoc_base + 2000].
"""

from __future__ import annotations

import argparse
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


def load_dat_index(dats: list[Path], wanted: set[str]
                   ) -> tuple[set[str], set[tuple[str, int]]]:
    """Wanted title ids and versions known to the hashdb, streamed per game."""
    tids: set[str] = set()
    versions: set[tuple[str, int]] = set()
    for dat in dats:
        for _, game in ET.iterparse(dat, events=("end",)):
            if game.tag != "game":
                continue
            gid = game.findtext("game_id")
            if not gid:
                game.clear()
                continue
            gid = gid.strip().upper()
            if gid not in wanted:
                game.clear()
                continue
            tids.add(gid)
            raw = (game.findtext("version1") or "").strip().lstrip("vV")
            if raw.isdigit():
                versions.add((gid, int(raw)))
            game.clear()
    return tids, versions


def title_id(value: str) -> str:
    if not re.fullmatch(r"[0-9A-Fa-f]{16}", value):
        raise argparse.ArgumentTypeError(
            "TID must be exactly 16 hexadecimal characters")
    return value.upper()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nxlookup",
        description="Report only missing members of one NX title family.")
    parser.add_argument(
        "--tid", required=True, type=title_id,
        help="base, update or DLC title id (16 hexadecimal characters)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)
    query_tid = args.tid
    query_kind, app_id = classify(query_tid)
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

    # Target-family ownership: any fileshared in any release counts, labels ignored.
    owned_base = False
    owned_upd: set[int] = set()
    owned_dlc: set[str] = set()
    for entity in cat.entities:
        kind, entity_app_id = classify(entity.identifier)
        if entity_app_id != app_id:
            continue
        has_files = any(release.shared for release in entity.releases)
        if not has_files:
            continue
        if kind == "DLC":
            owned_dlc.add(entity.identifier)
            continue
        for release in entity.releases:
            if not release.shared:
                continue
            number = int(release.version.lstrip("v")) \
                if release.version.lstrip("v").isdigit() else None
            if release.standalone:
                owned_base = True
            elif number is not None:
                owned_upd.add(number)

    # Each tuple is (kind, tid, version-or-None, display suffix). Only missing
    # entries are ever rendered.
    missing: list[tuple[str, str, int | None, str]] = []
    if not owned_base:
        missing.append(("BASE", app_id, None, ""))

    version_rows = versions.get(app_id.lower()) or {}
    latest_known = max((int(key) for key in version_rows), default=None)
    if latest_known is not None and latest_known not in owned_upd:
        upd_tid = f"{int(app_id, 16) + PATCH_OFFSET:016X}"
        released = version_rows[str(latest_known)]
        missing.append(("UPD", upd_tid, latest_known, f" ({released})"))

    known_dlc = dlc_ids_of(app_id, universe)
    if query_kind == "DLC" and query_tid not in known_dlc:
        known_dlc.append(query_tid)
        known_dlc.sort()
    for tid in known_dlc:
        if tid not in owned_dlc:
            dlc_name = names.query(tid)[0] or "(name unknown)"
            missing.append(("DLC", tid, None, f" {dlc_name}"))

    wanted = {tid for _, tid, _, _ in missing}
    dats = sorted((DB_DIR / "hashdb").glob("*.xml")) if wanted else []
    if dats:
        dat_tids, dat_versions = load_dat_index(dats, wanted)
    else:
        dat_tids, dat_versions = set(), set()
        if wanted:
            print("note: no hashdb dats found; [MIA] verdicts unavailable",
                  file=sys.stderr)

    family_name = names.query(app_id)[0] or "(name unknown)"
    query_label = "BASE" if query_kind == "APP" else query_kind
    print(f"family: [{app_id}] {family_name}")
    print(f"query:  [{query_tid}] {query_label}")
    if not missing:
        print("missing: none")
        return 0

    print("missing:")
    for kind, tid, version, suffix in missing:
        if version is None:
            known = tid in dat_tids
            identity = f"[{tid}]"
        else:
            known = (tid, version) in dat_versions
            identity = f"[{tid}][v{version}]"
        mia = "" if known or not dats else " [MIA]"
        print(f"  {kind:<4} {identity}{suffix}{mia}")
    print(f"done: {len(missing)} missing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
