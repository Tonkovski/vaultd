"""Match physical entities/ storage against entities.checksum, one to one.

Compression-blind: this module deals with the storage filesystem as it is.
Speed levels select what is recomputed per file (size is a free stat and is
checked at every level):

    0  full trio: crc32 + md5 + sha1 (slow)
    1  sha1
    2  md5
    3  crc32 (default; sufficient for bitrot)
    4  filesize only
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from vaultd import checksum, hashing
from vaultd.overwatch import _common

_SPEED_FIELDS = {
    0: ("crc", "md5", "sha1"),
    1: ("sha1",),
    2: ("md5",),
    3: ("crc",),
    4: (),
}


def _walk_files(entities_dir: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(entities_dir):
        dirnames.sort()
        for fname in sorted(filenames):
            abs_path = Path(dirpath) / fname
            rel = abs_path.relative_to(entities_dir).as_posix()
            files[rel] = abs_path
    return files


def _verify_vault(name: str, vdir: Path, speed: int) -> tuple[bool, int]:
    report = _common.Report(name)
    entries: dict[str, checksum.Entry] = {}

    ck_path = vdir / "entities.checksum"
    if not ck_path.is_file():
        report.error(f"missing {ck_path}")
    else:
        entries, problems = checksum.parse_file(ck_path)
        for problem in problems:
            report.error(problem)

    entities_dir = vdir / "entities"
    files: dict[str, Path] = {}
    if not entities_dir.is_dir():
        if entries:
            report.error(f"missing {entities_dir}")
    else:
        files = _walk_files(entities_dir)

    total_bytes = sum(entry.size for entry in entries.values())
    print(f"== {name} ==")
    print(f"  checksum: {len(entries)} line(s), {_common.fmt_size(total_bytes)}"
          f"   disk: {len(files)} file(s)   speed: {speed}")

    for rel in sorted(entries.keys() - files.keys()):
        report.error(f"missing on disk: {rel}")
    for rel in sorted(files.keys() - entries.keys()):
        report.error(f"extra on disk: {rel}")

    fields = _SPEED_FIELDS[speed]
    common = sorted(entries.keys() & files.keys())
    hashed_bytes = 0
    started = time.monotonic()
    for index, rel in enumerate(common, 1):
        entry = entries[rel]
        try:
            actual_size = files[rel].stat().st_size
        except OSError as exc:
            report.error(f"cannot stat: {rel}: {exc}")
            continue
        if actual_size != entry.size:
            report.error(f"size mismatch: {rel}: "
                         f"recorded {entry.size}, actual {actual_size}")
            continue
        if not fields:
            continue
        print(f"  [{index}/{len(common)}] {rel} ({_common.fmt_size(entry.size)})")
        try:
            actual = hashing.digest(files[rel], crc="crc" in fields,
                                    md5="md5" in fields, sha1="sha1" in fields)
        except OSError as exc:
            report.error(f"cannot read: {rel}: {exc}")
            continue
        hashed_bytes += actual_size
        for field in fields:
            if actual[field] != getattr(entry, field):
                report.error(f"{field} mismatch: {rel}: "
                             f"recorded {getattr(entry, field)}, actual {actual[field]}")
    if fields and hashed_bytes:
        elapsed = time.monotonic() - started
        rate = hashed_bytes / elapsed if elapsed > 0 else 0
        print(f"  hashed {_common.fmt_size(hashed_bytes)} in {elapsed:.1f}s "
              f"({_common.fmt_size(int(rate))}/s)")

    return report.emit(f"{len(files)} file(s), speed {speed}"), len(files)


def main(argv: list[str] | None = None) -> int:
    _common.setup_io()
    parser = argparse.ArgumentParser(prog="fswarmup", description=__doc__)
    _common.add_vault_args(parser)
    parser.add_argument("--speed", type=int, choices=range(5), default=3,
                        help="0 full trio, 1 sha1, 2 md5, 3 crc32 (default), 4 size only")
    ns = parser.parse_args(argv)

    vaults = _common.resolve_vaults(ns)
    if vaults is None:
        return 2

    all_ok = True
    for name, vdir in vaults.items():
        ok, _ = _verify_vault(name, vdir, ns.speed)
        all_ok &= ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
