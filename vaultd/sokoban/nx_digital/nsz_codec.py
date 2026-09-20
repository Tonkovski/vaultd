"""Run NSZ with correct decompressed NCZ member sizes.

NSZ 5.0 adds the entire first section to its preserved 0x4000-byte prefix,
even when that section starts inside the prefix. Its PFS0 size/offset table
then disagrees with the bytes the codec actually writes. A first-section gap
also exposes its fixed section-count accounting. Compute the final section
end instead; leave decompression and re-encryption to NSZ.

This process-local hook does not edit the installed package. fixnsp still
validates container bounds, NCA signatures and CNMT content before publishing.
"""
from __future__ import annotations

import struct

PREFIX_SIZE = 0x4000


def decompressed_ncz_size(stream) -> int:
    """Size of the prefix followed by the NCZ sections' remaining bytes."""
    stream.seek(PREFIX_SIZE)
    header = stream.read(16)
    if len(header) != 16 or header[:8] != b'NCZSECTN':
        raise ValueError('missing or truncated NCZSECTN header')
    count, = struct.unpack_from('<Q', header, 8)
    if not 1 <= count <= 0x10000:
        raise ValueError('invalid NCZ section count')
    end = PREFIX_SIZE
    for index in range(count):
        section = stream.read(64)
        if len(section) != 64:
            raise ValueError('truncated NCZ section table')
        offset, size = struct.unpack_from('<QQ', section)
        stop = offset + size
        if not size or stop > 0xFFFFFFFFFFFFFFFF or stop < PREFIX_SIZE:
            raise ValueError('invalid NCZ section extent')
        # NSZ supports a gap before the first section. Remaining sections
        # must be contiguous: its decoder appends their bytes sequentially.
        if index and offset != end:
            raise ValueError('noncontiguous or overlapping NCZ sections')
        end = stop
    return end


def main() -> None:
    from nsz import Decompressor, main as nsz_main

    if not callable(getattr(Decompressor, '__getDecompressedNczSize', None)):
        raise RuntimeError('unsupported NSZ decompressor: size hook unavailable')
    Decompressor.__getDecompressedNczSize = decompressed_ncz_size
    nsz_main()
