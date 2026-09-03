"""Verify datmeta.xml declarations against vault storage, one to one.

The uncompressed lane matches declarations against entities.checksum (pure
text vs text; fswarmup has already proven checksum == disk). The compressed
lane reads each release container's member table — paths, sizes, CRC32s —
straight from the archive header, no extraction (tier-2 directory audit).
Patches are plain in both modes and always go through the checksum lane.

Semantic rules V1-V4 from convention/datmeta.md live here.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from vaultd import catalog, checksum, winlint
from vaultd.overwatch import _common


def _lint_paths(cat: catalog.Catalog, report: _common.Report) -> None:
    """V2 (SHOULD): declared names are Windows-safe."""
    def lint(kind: str, value: str) -> None:
        for issue in winlint.path_issues(value):
            report.warn(f"V2 {kind} {value}: {issue}")

    for ent in cat.entities:
        lint("entity", ent.identifier)
        for rel in ent.releases:
            lint("release version", rel.version)
            for d in rel.dirs:
                lint("dir", d)
            for f in rel.shared:
                lint("fileshared", f.path)
            for f in rel.instances:
                lint("fileinstance", f.path)
            for item in rel.pix_items:
                lint("pix item", item)
        for pat in ent.patches:
            lint("patch", pat.name)
            for f in pat.files:
                lint("patch file", f.path)


def _match_hashed(decl: catalog.HashedFile, entry: checksum.Entry,
                  where: str, report: _common.Report) -> None:
    for field in ("crc", "md5", "sha1"):
        if getattr(decl, field) != getattr(entry, field):
            report.error(f"{field} mismatch: {where}: "
                         f"declared {getattr(decl, field)}, recorded {getattr(entry, field)}")
    if decl.size != entry.size:
        report.error(f"size mismatch: {where}: "
                     f"declared {decl.size}, recorded {entry.size}")


def _split_members(paths: dict[str, tuple[int, int | None]], prefix: str
                   ) -> dict[str, tuple[int, int | None]]:
    plen = len(prefix)
    return {p[plen:]: v for p, v in paths.items() if p.startswith(prefix)}


class _Consumer:
    """Tracks which checksum entries a declaration has claimed."""

    def __init__(self, entries: dict[str, checksum.Entry]) -> None:
        self.entries = entries
        self.consumed: set[str] = set()

    def take(self, path: str) -> checksum.Entry | None:
        entry = self.entries.get(path)
        if entry is not None:
            self.consumed.add(path)
        return entry

    def take_prefix(self, prefix: str) -> dict[str, checksum.Entry]:
        found = {p: e for p, e in self.entries.items()
                 if p.startswith(prefix) and p not in self.consumed}
        self.consumed.update(found)
        return found

    def leftovers(self) -> list[str]:
        return sorted(self.entries.keys() - self.consumed)


def _verify_instances(rel: catalog.Release, found: dict[str, int],
                      where: str, report: _common.Report) -> None:
    """V4: found maps '<set>/<path>' (or bad shapes) -> size."""
    declared = {i.path: i for i in rel.instances}
    seen: dict[str, int] = {p: 0 for p in declared}
    for rest, size in sorted(found.items()):
        set_name, sep, ipath = rest.partition("/")
        if not sep:
            report.error(f"V4 file directly under instance/, no set dir: {where}/{rest}")
            continue
        decl = declared.get(ipath)
        if decl is None:
            report.error(f"V4 undeclared instance file: {where}/{rest}")
            continue
        seen[ipath] += 1
        if decl.size is not None and size != decl.size:
            report.error(f"V4 size mismatch: {where}/{rest}: "
                         f"declared {decl.size}, found {size}")
    for ipath, decl in declared.items():
        if decl.required and seen[ipath] == 0:
            report.error(f"V4 required instance absent from every set: {where}/{ipath}")


def _verify_pix(rel: catalog.Release, found_files: set[str], has_item_dir,
                where: str, report: _common.Report) -> None:
    declared = set(rel.pix_items)
    for rest in sorted(found_files):
        item = rest.partition("/")[0]
        if item not in declared:
            report.error(f"undeclared pix item content: {where}/{rest}")
    for item in sorted(declared):
        if not has_item_dir(item):
            report.error(f"declared pix item has no directory: {where}/{item}")


def _verify_plain_release(ent: catalog.Entity, rel: catalog.Release,
                          consumer: _Consumer, entities_dir: Path,
                          report: _common.Report) -> None:
    rbase = f"{ent.identifier}/releases/{rel.version}"
    for dpath in rel.dirs:
        if not (entities_dir / rbase / "fs" / "shared" / dpath).is_dir():
            report.error(f"declared dir missing on disk: {rbase}/fs/shared/{dpath}")
    for decl in rel.shared:
        where = f"{rbase}/fs/shared/{decl.path}"
        entry = consumer.take(where)
        if entry is None:
            report.error(f"declared fileshared missing from checksum: {where}")
        else:
            _match_hashed(decl, entry, where, report)

    inst_prefix = f"{rbase}/fs/instance/"
    found = {path[len(inst_prefix):]: entry.size
             for path, entry in consumer.take_prefix(inst_prefix).items()}
    _verify_instances(rel, found, rbase + "/fs/instance", report)

    pix_prefix = f"{rbase}/pix/"
    pix_found = set(consumer.take_prefix(pix_prefix))
    _verify_pix(rel, {p[len(pix_prefix):] for p in pix_found},
                lambda item: (entities_dir / rbase / "pix" / item).is_dir(),
                rbase + "/pix", report)


def _verify_container(ent: catalog.Entity, rel: catalog.Release,
                      consumer: _Consumer, entities_dir: Path,
                      report: _common.Report) -> None:
    import py7zr

    cpath = f"{ent.identifier}/releases/{rel.version}.7z"
    if consumer.take(cpath) is None:
        report.error(f"release container missing from checksum: {cpath}")
    arch = entities_dir / cpath
    if not arch.is_file():
        report.error(f"release container missing on disk: {cpath}")
        return
    try:
        with py7zr.SevenZipFile(arch, mode="r") as z:
            infos = z.list()
    except Exception as exc:  # noqa: BLE001 - py7zr raises a small zoo
        report.error(f"cannot read container: {cpath}: {exc}")
        return

    files: dict[str, tuple[int, int | None]] = {}
    dirs: set[str] = set()
    for info in infos:
        member = info.filename.replace("\\", "/")
        if info.is_directory:
            dirs.add(member)
        else:
            files[member] = (info.uncompressed, info.crc32)

    claimed: set[str] = set()

    for dpath in rel.dirs:
        member = f"fs/shared/{dpath}"
        if member not in dirs and not any(p.startswith(member + "/") for p in files):
            report.error(f"declared dir missing in container: {cpath}!{member}")

    for decl in rel.shared:
        member = f"fs/shared/{decl.path}"
        where = f"{cpath}!{member}"
        if member not in files:
            report.error(f"declared fileshared missing in container: {where}")
            continue
        claimed.add(member)
        size, crc = files[member]
        if size != decl.size:
            report.error(f"size mismatch: {where}: declared {decl.size}, member {size}")
        if crc is None:
            report.error(f"V3 member has no CRC32 in container table: {where}")
        elif f"{crc & 0xFFFFFFFF:08X}" != decl.crc:
            report.error(f"crc mismatch: {where}: "
                         f"declared {decl.crc}, member {crc & 0xFFFFFFFF:08X}")

    inst = _split_members(files, "fs/instance/")
    claimed.update(f"fs/instance/{rest}" for rest in inst)
    _verify_instances(rel, {rest: size for rest, (size, _) in inst.items()},
                      f"{cpath}!fs/instance", report)

    pix = _split_members(files, "pix/")
    claimed.update(f"pix/{rest}" for rest in pix)
    _verify_pix(rel, set(pix),
                lambda item: f"pix/{item}" in dirs
                or any(p.startswith(f"pix/{item}/") for p in files),
                f"{cpath}!pix", report)

    for member in sorted(files.keys() - claimed):
        report.error(f"extra member in container: {cpath}!{member}")


def _verify_vault(name: str, vdir: Path) -> bool:
    report = _common.Report(name)
    try:
        cat = catalog.load(vdir / "datmeta.xml")
    except catalog.CatalogError as exc:
        report.error(str(exc))
        return report.emit()

    if cat.name != vdir.name:
        report.error(f"V1 catalog name '{cat.name}' != vault directory '{vdir.name}'")
    _lint_paths(cat, report)

    n_rel = sum(len(e.releases) for e in cat.entities)
    shared = [f for e in cat.entities for r in e.releases for f in r.shared]
    n_inst = sum(len(r.instances) for e in cat.entities for r in e.releases)
    n_pix = sum(len(r.pix_items) for e in cat.entities for r in e.releases)
    pfiles = [f for e in cat.entities for p in e.patches for f in p.files]
    print(f"== {name} ==")
    print(f"  entities: {len(cat.entities)}   releases: {n_rel}   "
          f"fileshared: {len(shared)} ({_common.fmt_size(sum(f.size for f in shared))})")
    print(f"  fileinstance decls: {n_inst}   pix items: {n_pix}   "
          f"patch files: {len(pfiles)} ({_common.fmt_size(sum(f.size for f in pfiles))})"
          f"   compression: {cat.compression}")

    entries, problems = checksum.parse_file(vdir / "entities.checksum")
    for problem in problems:
        report.error(problem)

    consumer = _Consumer(entries)
    entities_dir = vdir / "entities"
    compressed = cat.compression == "7z"

    for ent in cat.entities:
        for rel in ent.releases:
            if compressed:
                _verify_container(ent, rel, consumer, entities_dir, report)
            else:
                _verify_plain_release(ent, rel, consumer, entities_dir, report)
        for pat in ent.patches:
            for decl in pat.files:
                where = f"{ent.identifier}/patches/{pat.name}/{decl.path}"
                entry = consumer.take(where)
                if entry is None:
                    report.error(f"declared patch file missing from checksum: {where}")
                else:
                    _match_hashed(decl, entry, where, report)

    for path in consumer.leftovers():
        report.error(f"recorded but not declared: {path}")
    print(f"  checksum: {len(consumer.consumed)}/{len(entries)} line(s) consumed")

    n_ent = len(cat.entities)
    return report.emit(f"{n_ent} entit{'y' if n_ent == 1 else 'ies'}, "
                       f"compression {cat.compression}")


def main(argv: list[str] | None = None) -> int:
    _common.setup_io()
    parser = argparse.ArgumentParser(prog="datverify", description=__doc__)
    _common.add_vault_args(parser)
    ns = parser.parse_args(argv)

    vaults = _common.resolve_vaults(ns)
    if vaults is None:
        return 2

    all_ok = True
    for name, vdir in vaults.items():
        all_ok &= _verify_vault(name, vdir)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
