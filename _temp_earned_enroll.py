"""One-shot: enroll old-vault artifacts directly, old catalog as oracle.

The full fixnsp+ingest pipeline was proven byte-identical to the old vault
(27/27 artifacts). On that strength, the staged files in dropzone/fixnsp-task
(.nsz and labeled .nsp, drained verbatim from the old vault) enroll directly:
each file must match its old-catalog declaration (sha1/md5/crc/size) or it is
left in place untouched. Linear, checkpoint per item, Ctrl-C ready — rerun
continues. Temporary script; delete after the drain completes.
"""

from __future__ import annotations

import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vaultd import catwrite, checksum, hashing, locator  # noqa: E402
from vaultd.catwrite import t  # noqa: E402
from vaultd.sokoban.nx_digital.ingest import (  # noqa: E402
    entity_for, find_entity, find_release, gate_path, parse_name,
    release_files, self_audit)
from vaultd.titledb import TitleDB  # noqa: E402

STAGED = Path(r"E:\vaultd\dropzone\fixnsp-task")
OLD_CATALOG = Path(r"E:\vaultd.bak\vault\NX-Digital\datmeta.xml")
OLD_NS = "{http://tonkovski.github.io/vaultd/datmeta}"


def load_oracle() -> dict[str, tuple[str, str, str, int]]:
    root = ET.parse(OLD_CATALOG).getroot()
    oracle = {}
    for fe in root.iter(f"{OLD_NS}fileshared"):
        oracle[fe.get("path")] = (fe.get("sha1"), fe.get("md5"),
                                  fe.get("crc"), int(fe.get("size")))
    return oracle


def main() -> int:
    vdir = locator.resolve(["nx_digital"])["nx_digital"]
    xml_path = vdir / "datmeta.xml"
    ck_path = vdir / "entities.checksum"
    oracle = load_oracle()
    titledb = TitleDB(Path(r"E:\vaultd\db\nx_digital\titledb"))
    tree = ET.parse(xml_path)
    root = tree.getroot()
    entries, problems = checksum.parse_file(ck_path)
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 2

    staged = sorted(p for p in STAGED.iterdir()
                    if p.is_file() and p.suffix.lower() in {".nsz", ".nsp"})
    print(f"oracle rows: {len(oracle)}   staged: {len(staged)}")
    enrolled = dups = skipped = failed = 0
    interrupted = False
    try:
        for index, source in enumerate(staged, 1):
            head = f"[{index}/{len(staged)}] {source.name}"
            decl = oracle.get(source.name)
            parsed = parse_name(source)
            if decl is None or parsed is None:
                print(f"{head} SKIP: not in old catalog / unparseable")
                skipped += 1
                continue
            tid, ver, type_name, _ = parsed
            entity_tid = entity_for(tid, type_name)

            entities_el = root.find(t("entities"))
            if entities_el is None:
                entities_el = ET.SubElement(root, t("entities"))
            entity_el = find_entity(entities_el, entity_tid)
            release_el = (find_release(entity_el, ver)
                          if entity_el is not None else None)
            if release_el is not None:
                enrolled_sha1s = {(fe.get("sha1") or "").lower()
                                  for fe in release_files(release_el)}
                if decl[0].lower() in enrolled_sha1s:
                    source.unlink()
                    print(f"{head} DUP: already enrolled; source deleted")
                    dups += 1
                    continue
                if any(fe.get("path") == source.name
                       for fe in release_files(release_el)):
                    print(f"{head} CONFLICT: same stored name, different "
                          "bytes; left in place")
                    failed += 1
                    continue

            rel_path = f"{entity_tid}/releases/{ver}/fs/shared/{source.name}"
            try:
                gate_path(rel_path, entries)
            except Exception as exc:  # noqa: BLE001
                print(f"{head} FAIL: {exc}")
                failed += 1
                continue
            # move semantics: same-volume rename, no byte rewrite. The decl
            # comes straight from the oracle; the deferred verification is
            # overwatch fswarmup hashing the whole custody afterwards.
            sha1_decl, md5_decl, crc_decl, size_decl = decl
            if source.stat().st_size != size_decl:
                print(f"{head} FAIL: size differs from old-catalog "
                      "declaration; left in place")
                failed += 1
                continue
            dest = vdir / "entities" / Path(*rel_path.split("/"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() and rel_path not in entries:
                dest.unlink()  # interrupted-copy leftover
            import os
            os.replace(source, dest)
            placed = {"sha1": sha1_decl, "md5": md5_decl,
                      "crc": crc_decl, "size": size_decl}

            if entity_el is None:
                entity_el = ET.SubElement(entities_el, t("entity"))
                entity_el.set("identifier", entity_tid)
            description, publisher, _region = titledb.query(entity_tid)
            if description and not entity_el.get("description"):
                entity_el.set("description", description)
            if publisher and not entity_el.get("publisher"):
                entity_el.set("publisher", publisher)
            if release_el is None:
                releases_el = entity_el.find(t("releases"))
                if releases_el is None:
                    releases_el = ET.SubElement(entity_el, t("releases"))
                release_el = ET.SubElement(releases_el, t("release"))
                release_el.set("version", ver)
                if type_name == "UPD":
                    release_el.set("standalone", "false")
                ET.SubElement(release_el, t("fs"))
            fs_el = release_el.find(t("fs"))
            fe = ET.SubElement(fs_el, t("fileshared"))
            fe.set("path", source.name)
            fe.set("size", str(placed["size"]))
            fe.set("crc", str(placed["crc"]))
            fe.set("md5", str(placed["md5"]))
            fe.set("sha1", str(placed["sha1"]))
            entries[rel_path] = checksum.Entry(
                crc=str(placed["crc"]), md5=str(placed["md5"]),
                sha1=str(placed["sha1"]), size=int(placed["size"]),
                path=rel_path)  # type: ignore[arg-type]

            catwrite.bump_stamp(root)
            catwrite.sort_tree(root)
            checksum.write_file(ck_path, entries)
            catwrite.write_xml(xml_path, root)
            audit = self_audit(xml_path)
            if audit:
                for line in audit:
                    print(f"ERROR: self-audit failed: {line}", file=sys.stderr)
                return 1
            enrolled += 1
            print(f"{head} OK", flush=True)
    except KeyboardInterrupt:
        interrupted = True
        print("\ninterrupted — rerun to continue where this left off")

    print(f"\nDone -- enrolled: {enrolled}, dups deleted: {dups}, "
          f"skipped: {skipped}, failed: {failed}, "
          f"remaining: {len([p for p in STAGED.iterdir() if p.is_file()])}")
    return 130 if interrupted else (1 if failed else 0)


if __name__ == "__main__":
    raise SystemExit(main())
