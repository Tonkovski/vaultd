"""Streaming digests for warmup and audits."""

from __future__ import annotations

import hashlib
import zlib
from pathlib import Path
from typing import BinaryIO, Callable

_CHUNK = 1 << 20


def digest(path: Path, *, crc: bool = False, md5: bool = False,
           sha1: bool = False, progress: Callable[[int], None] | None = None) -> dict[str, object]:
    """Stream a file once; return {'size': int} plus requested digests.

    'crc' is uppercase CRC32 hex, 'md5'/'sha1' lowercase hex.
    Optional progress receives cumulative bytes after each processed chunk.
    """
    with path.open("rb") as fh:
        return digest_stream(fh, crc=crc, md5=md5, sha1=sha1, progress=progress)


def digest_stream(fh: BinaryIO, *, crc: bool = False, md5: bool = False,
                  sha1: bool = False, output: BinaryIO | None = None,
                  progress: Callable[[int], None] | None = None) -> dict[str, object]:
    """Hash/copy once; progress receives cumulative bytes after each chunk."""
    crc_val = 0
    md5_h = hashlib.md5() if md5 else None
    sha1_h = hashlib.sha1() if sha1 else None
    size = 0
    while chunk := fh.read(_CHUNK):
        if output is not None and output.write(chunk) != len(chunk):
            raise OSError('short write while copying payload')
        size += len(chunk)
        if crc:
            crc_val = zlib.crc32(chunk, crc_val)
        if md5_h is not None:
            md5_h.update(chunk)
        if sha1_h is not None:
            sha1_h.update(chunk)
        if progress is not None:
            progress(size)
    out: dict[str, object] = {"size": size}
    if crc:
        out["crc"] = f"{crc_val & 0xFFFFFFFF:08X}"
    if md5_h is not None:
        out["md5"] = md5_h.hexdigest()
    if sha1_h is not None:
        out["sha1"] = sha1_h.hexdigest()
    return out
