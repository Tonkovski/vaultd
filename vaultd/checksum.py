"""entities.checksum I/O.

Line format (convention/datmeta.md):
    <CRC32> <md5> <sha1> <size> <path relative to entities/>
Four fixed fields, then the remainder of the line is the path (may contain
spaces). CRC32 uppercase hex, md5/sha1 lowercase hex, size decimal bytes,
forward slashes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

LINE_RE = re.compile(
    r"^(?P<crc>[0-9A-F]{8}) (?P<md5>[0-9a-f]{32}) (?P<sha1>[0-9a-f]{40}) "
    r"(?P<size>0|[1-9][0-9]*) (?P<path>\S.*)$")


@dataclass(frozen=True)
class Entry:
    crc: str
    md5: str
    sha1: str
    size: int
    path: str


def format_line(entry: Entry) -> str:
    return f"{entry.crc} {entry.md5} {entry.sha1} {entry.size} {entry.path}"


def parse_file(path: Path) -> tuple[dict[str, Entry], list[str]]:
    """Parse entities.checksum -> ({path: Entry}, [problems])."""
    entries: dict[str, Entry] = {}
    problems: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {}, [f"cannot read {path}: {exc}"]
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line:
            problems.append(f"{path.name}:{lineno}: blank line")
            continue
        m = LINE_RE.match(line)
        if not m:
            problems.append(f"{path.name}:{lineno}: malformed line")
            continue
        entry = Entry(m["crc"], m["md5"], m["sha1"], int(m["size"]), m["path"])
        if entry.path in entries:
            problems.append(f"{path.name}:{lineno}: duplicate path {entry.path}")
            continue
        entries[entry.path] = entry
    return entries, problems
