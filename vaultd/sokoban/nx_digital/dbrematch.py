"""NX digital keeper: retire provenance labels the updated hashdb now covers.

Targets fileshared entries carrying a CUSTOM [LABEL] (the [GAMECARD] variant
marker is permanent and never targeted). When the current No-Intro dats
confirm the labeled NSP's sha1 with a clean row, the label retires by FORM
CONVERSION: the bare NSP is compressed to the archival NSZ (round-trip
sha1-verified), enrolled as the vanilla artifact, and the labeled NSP is
removed — filename, xml and checksum all move together.

The digest prints every claiming dat row alongside the enrolled entity
description, so a one-to-many hash clash has minimal influence. A release
already holding a vanilla artifact blocks the rematch (resolve by hand);
a sha1 matching only rejection rows is reported and kept.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from vaultd import catwrite, checksum, hashing, locator
from vaultd.catwrite import t
from vaultd.locator import DROPZONE
from vaultd.sokoban.nx_digital import VAULT_NAME
from vaultd.sokoban.nx_digital.ingest import (
    DB_DIR, Skip, gate_path, load_hashdb, marker_priority, nsz_roundtrip,
    parse_name, self_audit, stored_marker, sweep_unrecorded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-digital-dbrematch",
                                     description=__doc__)
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")
    args = parser.parse_args(argv)

    try:
        vdir = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    xml_path = vdir / "datmeta.xml"
    hashdb_dir = DB_DIR / "hashdb"
    if not xml_path.is_file() or not any(hashdb_dir.glob("*.xml")):
        print(f"ERROR: missing {xml_path if not xml_path.is_file() else hashdb_dir}",
              file=sys.stderr)
        return 2
    gate = load_hashdb(hashdb_dir)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    entries, problems = checksum.parse_file(vdir / "entities.checksum")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 2

    work_root = DROPZONE / "dbrematch-work"
    digest: list[str] = []
    rematched = unmatched = blocked = rejected = errors = 0
    entities_el = root.find(t("entities"))
    for entity_el in ([] if entities_el is None else entities_el.findall(t("entity"))):
        entity_tid = entity_el.get("identifier", "")
        description = entity_el.get("description") or "(no description)"
        releases_el = entity_el.find(t("releases"))
        if releases_el is None:
            continue
        for release_el in releases_el.findall(t("release")):
            ver = release_el.get("version", "")
            fs_el = release_el.find(t("fs"))
            if fs_el is None:
                continue
            shared = fs_el.findall(t("fileshared"))
            has_vanilla = any(stored_marker(fe.get("path", "")) == ""
                              for fe in shared)
            for fe in list(shared):
                old_name = fe.get("path", "")
                marker = stored_marker(old_name)
                if marker is None or marker_priority(marker) != 2:
                    continue
                sha1 = (fe.get("sha1") or "").lower()
                where = f"[{entity_tid}][{ver}] {old_name}"
                rows = gate.get(sha1)
                if rows is None:
                    unmatched += 1
                    digest.append(f"KEPT     {where}: sha1 still unknown to hashdb")
                    continue
                clean = sorted(name for name, reject in rows.items() if not reject)
                dirty = sorted(name for name, reject in rows.items() if reject)
                if not clean:
                    rejected += 1
                    digest.append(f"REJECTED {where}: sha1 matches only "
                                  f"rejection row(s): {'; '.join(dirty)}; "
                                  "kept, resolve by hand")
                    continue
                if has_vanilla:
                    blocked += 1
                    digest.append(f"BLOCKED  {where}: db now matches, but a "
                                  "vanilla artifact already holds this release; "
                                  "resolve by hand")
                    digest.append(f"         dat({len(clean)}): {'; '.join(clean)}")
                    digest.append(f"         enrolled description: {description}")
                    continue

                parsed = parse_name(Path(old_name))
                if parsed is None:
                    errors += 1
                    digest.append(f"ERROR    {where}: stored name is not parseable")
                    continue
                tid, pver, type_name, _ = parsed
                new_name = f"[{tid}][{pver}][{type_name}].nsz"
                rel_dir = f"{entity_tid}/releases/{ver}/fs/shared"
                old_rel, new_rel = f"{rel_dir}/{old_name}", f"{rel_dir}/{new_name}"
                old_abs = vdir / "entities" / Path(*old_rel.split("/"))
                new_abs = vdir / "entities" / Path(*new_rel.split("/"))
                if old_rel not in entries or new_rel in entries or not old_abs.exists():
                    errors += 1
                    digest.append(f"ERROR    {where}: vault state does not "
                                  "permit the conversion")
                    continue

                work = work_root / old_name
                try:
                    gate_path(new_rel, entries)
                    sweep_unrecorded(vdir, f"{entity_tid}/releases/{ver}", entries)
                    artifact = nsz_roundtrip(old_abs, work, sha1)
                    new_abs.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(artifact, new_abs)
                    placed = hashing.digest(new_abs, crc=True, md5=True, sha1=True)
                    verify = hashing.digest(artifact, sha1=True)
                    if placed["sha1"] != verify["sha1"]:
                        new_abs.unlink()
                        raise Skip("failed", "placed bytes differ from verified NSZ")
                except Skip as skip:
                    errors += 1
                    digest.append(f"ERROR    {where}: {skip}")
                    continue
                finally:
                    shutil.rmtree(work, ignore_errors=True)

                new_fe = ET.SubElement(fs_el, t("fileshared"))
                new_fe.set("path", new_name)
                new_fe.set("size", str(placed["size"]))
                new_fe.set("crc", str(placed["crc"]))
                new_fe.set("md5", str(placed["md5"]))
                new_fe.set("sha1", str(placed["sha1"]))
                fs_el.remove(fe)
                entries.pop(old_rel)
                entries[new_rel] = checksum.Entry(
                    crc=str(placed["crc"]), md5=str(placed["md5"]),
                    sha1=str(placed["sha1"]), size=int(placed["size"]),
                    path=new_rel)  # type: ignore[arg-type]
                catwrite.bump_stamp(root)
                catwrite.sort_tree(root)
                checksum.write_file(vdir / "entities.checksum", entries)
                catwrite.write_xml(xml_path, root)
                audit = self_audit(xml_path)
                if audit:
                    for line in audit:
                        print(f"ERROR: self-audit failed: {line}", file=sys.stderr)
                    return 1
                old_abs.unlink()
                rematched += 1
                has_vanilla = True
                digest.append(f"REMATCH  {where} -> {new_name}")
                digest.append(f"         dat({len(clean)}): {'; '.join(clean)}")
                digest.append(f"         enrolled description: {description}")

    shutil.rmtree(work_root, ignore_errors=True)
    print(f"vault: {vdir}")
    if digest:
        print()
        for line in digest:
            print(line)
    print(f"\nDone -- rematched: {rematched}, still unmatched: {unmatched}, "
          f"blocked by vanilla: {blocked}, rejection-row: {rejected}, "
          f"errors: {errors}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
