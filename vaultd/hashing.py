"""Streaming digests for warmup and audits."""

from __future__ import annotations

import hashlib
import zlib
from pathlib import Path

_CHUNK = 1 << 20


def digest(path: Path, *, crc: bool = False, md5: bool = False,
           sha1: bool = False) -> dict[str, object]:
    """Stream a file once; return {'size': int} plus requested digests.

    'crc' is uppercase CRC32 hex, 'md5'/'sha1' lowercase hex.
    """
    crc_val = 0
    md5_h = hashlib.md5() if md5 else None
    sha1_h = hashlib.sha1() if sha1 else None
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            size += len(chunk)
            if crc:
                crc_val = zlib.crc32(chunk, crc_val)
            if md5_h is not None:
                md5_h.update(chunk)
            if sha1_h is not None:
                sha1_h.update(chunk)
    out: dict[str, object] = {"size": size}
    if crc:
        out["crc"] = f"{crc_val & 0xFFFFFFFF:08X}"
    if md5_h is not None:
        out["md5"] = md5_h.hexdigest()
    if sha1_h is not None:
        out["sha1"] = sha1_h.hexdigest()
    return out
