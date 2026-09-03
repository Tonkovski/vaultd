"""NX gamecard keeper: retire provenance labels the updated db now covers.

Targets fileshared entries carrying a [LABEL] marker. When the current
switchtdb confirms the entry's sha1, the label is removed everywhere it
lives: the stored filename on disk, the datmeta.xml path, and the
entities.checksum path. The digest prints every claiming tdb entry alongside
the enrolled entity description, so a one-to-many hash clash has minimal
influence — the human sees all names next to what the vault says it is.

Rules:
  * a release already holding a vanilla fileshared blocks the rematch
    (renaming would collide with the higher-priority artifact); reported,
    resolved by hand.
  * batch discipline: rename first, checkpoint checksum-then-xml atomically,
    self-audit; an interrupted run resumes (renamed-but-unrecorded artifacts
    are recognized and their bookkeeping completed).
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from vaultd import catwrite, checksum, locator
from vaultd.catwrite import t
from vaultd.sokoban.nx_gamecard_xci import VAULT_NAME
from vaultd.sokoban.nx_gamecard_xci.ingest import (
    DB_DIR, load_switchtdb, self_audit, stored_label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-gamecard-dbrematch", description=__doc__)
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")
    args = parser.parse_args(argv)

    try:
        vdir = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    xml_path = vdir / "datmeta.xml"
    gate_file = DB_DIR / "switchtdb.xml"
    if not xml_path.is_file() or not gate_file.is_file():
        print(f"ERROR: missing {xml_path if not xml_path.is_file() else gate_file}",
              file=sys.stderr)
        return 2
    gate = load_switchtdb(gate_file)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    entries, problems = checksum.parse_file(vdir / "entities.checksum")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 2

    digest: list[str] = []
    rematched = unmatched = blocked = errors = 0
    entities_el = root.find(t("entities"))
    for entity_el in ([] if entities_el is None else entities_el.findall(t("entity"))):
        tid = entity_el.get("identifier", "")
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
            vanilla_names = {fe.get("path", "") for fe in shared
                             if not stored_label(fe.get("path", ""))}
            for fe in shared:
                old_name = fe.get("path", "")
                label = stored_label(old_name)
                if not label:
                    continue
                sha1 = (fe.get("sha1") or "").lower()
                names = gate.get(sha1)
                if names is None:
                    unmatched += 1
                    digest.append(f"KEPT     [{tid}][{ver}] {old_name}: "
                                  "sha1 still unknown to switchtdb")
                    continue
                if vanilla_names:
                    blocked += 1
                    digest.append(
                        f"BLOCKED  [{tid}][{ver}] {old_name}: db now matches, but a "
                        "vanilla artifact already holds this release; resolve by hand")
                    digest.append(f"         tdb({len(names)}): {'; '.join(names)}")
                    digest.append(f"         enrolled description: {description}")
                    continue
                new_name = old_name.replace(label, "", 1)
                rel_dir = f"{tid}/releases/{ver}/fs/shared"
                old_rel, new_rel = f"{rel_dir}/{old_name}", f"{rel_dir}/{new_name}"
                if old_rel not in entries or new_rel in entries:
                    errors += 1
                    digest.append(f"ERROR    [{tid}][{ver}] {old_name}: checksum state "
                                  "does not permit the rename")
                    continue
                old_abs = vdir / "entities" / Path(*old_rel.split("/"))
                new_abs = vdir / "entities" / Path(*new_rel.split("/"))
                if old_abs.exists():
                    old_abs.rename(new_abs)
                elif new_abs.exists():
                    digest.append(f"RESUME   [{tid}][{ver}] {old_name}: disk already "
                                  "renamed; completing bookkeeping")
                else:
                    errors += 1
                    digest.append(f"ERROR    [{tid}][{ver}] {old_name}: "
                                  "payload missing on disk")
                    continue

                fe.set("path", new_name)
                old_entry = entries.pop(old_rel)
                entries[new_rel] = checksum.Entry(
                    crc=old_entry.crc, md5=old_entry.md5, sha1=old_entry.sha1,
                    size=old_entry.size, path=new_rel)
                catwrite.bump_stamp(root)
                catwrite.sort_tree(root)
                checksum.write_file(vdir / "entities.checksum", entries)
                catwrite.write_xml(xml_path, root)
                audit = self_audit(xml_path)
                if audit:
                    for line in audit:
                        print(f"ERROR: self-audit failed: {line}", file=sys.stderr)
                    return 1
                rematched += 1
                vanilla_names.add(new_name)
                digest.append(f"REMATCH  [{tid}][{ver}] {old_name} -> {new_name}")
                digest.append(f"         tdb({len(names)}): {'; '.join(names)}")
                digest.append(f"         enrolled description: {description}")

    print(f"vault: {vdir}")
    if digest:
        print()
        for line in digest:
            print(line)
    print(f"\nDone -- rematched: {rematched}, still unmatched: {unmatched}, "
          f"blocked by vanilla: {blocked}, errors: {errors}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
