"""Signature-gated digital-content repair engine (the fixnsp rewrite).

The linear specification lives in fixnsp.md beside this file; this module is
its implementation. Strict-only: no permissive mode, no BestEffort output.
External dependency: `nsz` as a decompression codec for NSZ/XCZ inputs —
nothing else. All parsing, hashing, crypto, ticket generation, NCA/CNMT
mutation, PFS0/HFS0 IO and every verdict are in-process; Nintendo's
signatures are the only authorities that approve bytes.

Intake default is the workspace dropzone's keeper sub-area dropzone/fixnsp;
outputs publish to the dropzone ROOT — the digital ingest's scan surface, so
repaired NSPs flow straight into enrollment. Fully successful sources are
archived to dropzone/fixnsp-success. CNMTDB (db/nx_digital/titledb/cnmts.json) proposes
Meta scalar candidates; firmware values observed elsewhere in CNMTDB and the
optional db/nx_digital/firmware_versions.json (a JSON list of released-firmware
requiredSystemVersion integers) bound the fallback axis. Neither database can
authorize output.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Callable

from Cryptodome.Cipher import AES

from vaultd.locator import DB_ROOT, DROPZONE, REPO_ROOT
from vaultd.sokoban.nx_digital import VAULT_NAME

PFS0_MAGIC = b"PFS0"
PFS0_HEADER_ALIGNMENT = 0x20
HFS0_MAGIC = b"HFS0"
XCI_HEAD_MAGIC = b"HEAD"
IVFC_MAGIC = b"IVFC"
NCA_HEADER_SIZE = 0xC00
MEDIA_SIZE = 0x200
ISSUER = b"Root-CA00000003-XS00000020"
DEFAULT_CERT = Path(__file__).with_name("default.cert")
DB_DIR = DB_ROOT / VAULT_NAME
TICKET_SIGNATURE_TYPE_RSA2048_SHA256 = bytes.fromhex("04000100")
TICKET_RSA2048_SHA256_MODULI = {
    ISSUER: int(
        (
            "D21D3CE67C1069DA049D5E5310E76B907E18EEC80B337C4723E339573F4C6649"
            "07DB2F0832D03DF5EA5F160A4AF24100D71AFAC2E3AE75AFA1228012A9A21616"
            "597DF71EAFCB65941470D1B40F5EF83A597E179FCB5B57C2EE17DA3BC3769864"
            "CB47856767229D67328141FC9AB1DF149E0C5C15AEB80BC58FC71BE18966642D"
            "68308B506934B8EF779F78E4DDF30A0DCF93FCAFBFA131A8839FD641949F47EE"
            "25CEECF814D55B0BE6E5677C1EFFEC6F29871EF29AA3ED9197B0D83852E05090"
            "8031EF1ABBB5AFC8B3DD937A076FF6761AB362405C3F7D86A3B17A6170A659C1"
            "6008950F7F5E06A5DE3E5998895EFA7DEEA060BE9575668F78AB1907B3BA1B7D"
        ),
        16,
    )
}
NCA_HEADER_FIXED_KEY_MODULI = tuple(
    bytes.fromhex(value)
    for value in (
        (
            "BFBE406CF4A780E9F07D0C99611D772F96BC4B9E58381B03ABB175499F2B4D58"
            "34B005A37522BE1A3F0373AC7068D116B904465EB707912F078B26DEF60007B2"
            "B451F80D0A5E58ADEBBC9AD649B964EFA782B5CF6D7013B00F85F6A908AA4D67"
            "6687FA89FF7590181E6B3DE98A68C92604D980CE3F5E92CE01FF063BF2C1A90C"
            "CE026F16BC92420A4164CD52B6344DAEC02EDEA4DF27683CC1A060AD43F3FC86"
            "C13E6C46F77C299FFAFDF0E3CE64E735F2F656566F6DF1E242B08340A5C3202B"
            "CC9AAECAED4D7030A8701C70FD1363290279EAD2A7AF3528321C7BE62F1AAA40"
            "7E328C2742FE8278EC0DEBE6834B6D8104401A9E9A67F67229FA04F09DE4F403"
        ),
        (
            "ADE3E1FA0435E5B6DD49EA8929B1FFB643DFCA96A04A13DF43D9949796436548"
            "705833A27D357B96745E0B5C32181424C258B36C227AA1B7CB90A7A3F97D4516"
            "A5C8ED8FAD395E9E4B51687DF80C35C63F91AE44A592300D46F840FFD0FF06D2"
            "1C7F9618DCB71D663ED173BC158A2F94F300C183F1CDD78188ABDF8CEF97DD1B"
            "175F58F69AE9E8C22F3815F52107F837905D2E024024150D25B7265D09CC4CF4"
            "F21B94705A9EEEED7777D45199F5DC761EE36C8CD112D457D1B683E4E4FEDAE9"
            "B43B33E5378ADFB57F89F19B9EB015B23AFEEA61845B7D4B23120B8312F2226B"
            "B922964B260B635E965752A3676422CAD0563E74B5981F0DF8B334E698685AAD"
        ),
    )
)

TITLE_TYPE_NAMES = {0x80: "BASE", 0x81: "UPD", 0x82: "DLC", 0x84: "UPD"}
CNMT_FILE_TYPE_NAMES = {
    0x80: "Application",
    0x81: "Patch",
    0x82: "AddOnContent",
    0x84: "DataPatch",
}
NCA_CONTENT_NAMES = {0: "PROGRAM", 1: "META", 2: "CONTROL", 3: "MANUAL",
                     4: "DATA", 5: "PUBLICDATA"}
TITLE_BEARING_NCA_TYPES = {0, 4, 5}
RECOVERABLE_TITLE_RIGHTS_NCA_TYPES = TITLE_BEARING_NCA_TYPES | {3}
NCA_KEY_GENERATION_SINCE_301 = 3
KEY_LINE_RE = re.compile(r"^\s*([a-z0-9_]+)\s*=\s*([0-9a-f]+)\s*$", re.I)


class FixError(RuntimeError):
    pass


def configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


class Outcome(str, Enum):
    PRESERVE = "PRESERVE"
    RESTORED = "RESTORED"
    IMPOSSIBLE = "IMPOSSIBLE"


# --------------------------------------------------------------------------
# crypto primitives (Cryptodome-backed)

def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_xts_crypt(data: bytes, key: bytes, *, decrypt: bool,
                  sector_size: int = 0x200, first_sector: int = 0) -> bytes:
    """Nintendo AES-XTS: the tweak is the sector index as 16 big-endian bytes
    (standard XTS uses little-endian); GF doubling is standard."""
    if len(key) != 32 or len(data) % sector_size:
        raise FixError("invalid XTS input")
    crypt = AES.new(key[:16], AES.MODE_ECB)
    tweaker = AES.new(key[16:], AES.MODE_ECB)
    operation = crypt.decrypt if decrypt else crypt.encrypt
    out = bytearray()
    mask = (1 << 128) - 1
    for index in range(len(data) // sector_size):
        sector = data[index * sector_size:(index + 1) * sector_size]
        tweak = tweaker.encrypt((first_sector + index).to_bytes(16, "big"))
        value = int.from_bytes(tweak, "little")
        stream = bytearray()
        for _ in range(sector_size // 16):
            stream += value.to_bytes(16, "little")
            carry = value >> 127
            value = ((value << 1) & mask) ^ (0x87 if carry else 0)
        pad = bytes(stream)
        mixed = bytes(a ^ b for a, b in zip(sector, pad))
        flat = operation(mixed)
        out += bytes(a ^ b for a, b in zip(flat, pad))
    return bytes(out)


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes, absolute_offset: int) -> bytes:
    if absolute_offset % 16:
        raise FixError("CTR offset must be block aligned")
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce[:8],
                     initial_value=absolute_offset // 16)
    return cipher.encrypt(data)


@dataclass(frozen=True)
class KeySet:
    values: dict[str, bytes]

    @classmethod
    def load(cls, path: Path) -> "KeySet":
        values: dict[str, bytes] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            match = KEY_LINE_RE.match(line)
            if match:
                values[match.group(1).lower()] = bytes.fromhex(match.group(2))
        return cls(values)

    def require(self, name: str) -> bytes:
        try:
            return self.values[name.lower()]
        except KeyError as exc:
            raise FixError(f"required key missing from prod.keys: {name}") from exc

    @property
    def header_key(self) -> bytes:
        value = self.require("header_key")
        if len(value) != 32:
            raise FixError("header_key must be 32 bytes")
        return value

    def master_key(self, index: int) -> bytes:
        return self.require(f"master_key_{index:02x}")

    def titlekek(self, master_key_index: int) -> bytes:
        return ecb_decrypt(self.master_key(master_key_index),
                           self.require("titlekek_source"))

    def key_area_key(self, master_key_index: int, key_index: int) -> bytes:
        source_names = {0: "key_area_key_application_source",
                        1: "key_area_key_ocean_source",
                        2: "key_area_key_system_source"}
        if key_index not in source_names:
            raise FixError(f"unsupported NCA key-area index: {key_index}")
        first = ecb_decrypt(self.master_key(master_key_index),
                            self.require("aes_kek_generation_source"))
        second = ecb_decrypt(first, self.require(source_names[key_index]))
        return ecb_decrypt(second, self.require("aes_key_generation_source"))


@dataclass(frozen=True)
class TitleKeys:
    """Optional title.keys material, indexed by RightsId.

    Values use the conventional title.keys representation: the titlekek-
    encrypted 16-byte title key, not plaintext key material.
    """
    values: dict[str, bytes]

    @classmethod
    def load(cls, path: Path | None) -> "TitleKeys":
        values: dict[str, bytes] = {}
        if path is None or not path.is_file():
            return cls(values)
        for line in path.read_text(encoding="utf-8").splitlines():
            match = KEY_LINE_RE.match(line)
            if match and len(match.group(1)) == 32 and len(match.group(2)) == 32:
                values[match.group(1).lower()] = bytes.fromhex(match.group(2))
        return cls(values)


# --------------------------------------------------------------------------
# PFS0 / HFS0 / XCI containers

@dataclass(frozen=True)
class Pfs0Entry:
    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class Hfs0Entry:
    name: str
    offset: int
    size: int
    hashed_size: int
    digest: bytes


def copy_exact(source, destination, size: int, chunk_size: int = 8 * 1024 * 1024) -> None:
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, chunk_size))
        if not chunk:
            raise FixError(f"unexpected EOF with {remaining} bytes remaining")
        destination.write(chunk)
        remaining -= len(chunk)


def safe_member_name(raw: bytes, index: int, kind: str) -> str:
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixError(f"{kind} name {index} is not valid UTF-8") from exc
    if not name or name in {".", ".."} or any(char in name for char in "/\\:"):
        raise FixError(f"unsafe {kind} file name: {name!r}")
    return name


def read_pfs0_table(path: Path) -> list[Pfs0Entry]:
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(0x10)
        if len(header) != 0x10 or header[:4] != PFS0_MAGIC:
            raise FixError(f"not a PFS0 NSP: {path.name}")
        count, string_size, reserved = struct.unpack_from("<III", header, 4)
        if reserved != 0 or count > 0x10000 or string_size > 0x1000000:
            raise FixError("implausible PFS0 header")
        table = handle.read(count * 0x18)
        strings = handle.read(string_size)
        if len(table) != count * 0x18 or len(strings) != string_size:
            raise FixError("truncated PFS0 header")
        data_offset = 0x10 + len(table) + len(strings)

    entries: list[Pfs0Entry] = []
    ranges: list[tuple[int, int, str]] = []
    for index in range(count):
        relative, size, name_offset, entry_reserved = struct.unpack_from(
            "<QQII", table, index * 0x18)
        if entry_reserved != 0 or name_offset >= len(strings):
            raise FixError(f"invalid PFS0 entry {index}")
        end = strings.find(b"\0", name_offset)
        if end < 0:
            raise FixError(f"PFS0 name {index} is not null terminated")
        name = safe_member_name(strings[name_offset:end], index, "PFS0")
        absolute = data_offset + relative
        stop = absolute + size
        if absolute < data_offset or stop > file_size:
            raise FixError(f"PFS0 file extends past EOF: {name}")
        entries.append(Pfs0Entry(name, absolute, size))
        ranges.append((absolute, stop, name))
    for left, right in zip(sorted(ranges), sorted(ranges)[1:]):
        if left[1] > right[0]:
            raise FixError(f"overlapping PFS0 entries: {left[2]} and {right[2]}")
    if len({entry.name.casefold() for entry in entries}) != len(entries):
        raise FixError("duplicate PFS0 file names")
    return entries


def extract_pfs0(path: Path, out_dir: Path) -> list[Path]:
    entries = read_pfs0_table(path)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    extracted: list[Path] = []
    with path.open("rb") as source:
        for entry in entries:
            destination = out_dir / entry.name
            source.seek(entry.offset)
            with destination.open("wb") as output:
                copy_exact(source, output, entry.size)
            extracted.append(destination)
    return extracted


def read_hfs0_table(path: Path, base_offset: int, container_size: int, *,
                    allow_partition_tail_trim: bool = False) -> list[Hfs0Entry]:
    """Read strict member bounds. The XCI root alone can defer tail checks
    until read_xci_partitions verifies every nested member against real EOF."""
    file_size = path.stat().st_size
    container_end = base_offset + container_size
    if base_offset < 0 or container_size < 0x10 or container_end > file_size:
        raise FixError("invalid HFS0 container bounds")
    with path.open("rb") as handle:
        handle.seek(base_offset)
        header = handle.read(0x10)
        if len(header) != 0x10 or header[:4] != HFS0_MAGIC:
            raise FixError(f"not an HFS0 partition at 0x{base_offset:X}")
        count, string_size, reserved = struct.unpack_from("<III", header, 4)
        if reserved != 0 or count > 0x10000 or string_size > 0x1000000:
            raise FixError("implausible HFS0 header")
        table = handle.read(count * 0x40)
        strings = handle.read(string_size)
        if len(table) != count * 0x40 or len(strings) != string_size:
            raise FixError("truncated HFS0 header")
        data_offset = base_offset + 0x10 + len(table) + len(strings)
        if data_offset > container_end:
            raise FixError("HFS0 header extends past its container")

    entries: list[Hfs0Entry] = []
    ranges: list[tuple[int, int, str]] = []
    for index in range(count):
        relative, size, name_offset, hashed_size, entry_reserved = struct.unpack_from(
            "<QQIIQ", table, index * 0x40)
        digest = table[index * 0x40 + 0x20:index * 0x40 + 0x40]
        if entry_reserved != 0 or name_offset >= len(strings) or hashed_size > size:
            raise FixError(f"invalid HFS0 entry {index}")
        end = strings.find(b"\0", name_offset)
        if end < 0:
            raise FixError(f"HFS0 name {index} is not null terminated")
        name = safe_member_name(strings[name_offset:end], index, "HFS0")
        absolute = data_offset + relative
        stop = absolute + size
        tail_can_be_checked = (allow_partition_tail_trim
                               and absolute < container_end
                               and absolute + hashed_size <= container_end)
        if (absolute < data_offset or stop < absolute
                or (stop > container_end and not tail_can_be_checked)):
            raise FixError(f"HFS0 file extends past its container: {name} "
                           f"(end 0x{stop:X}, container end 0x{container_end:X})")
        entries.append(Hfs0Entry(name, absolute, size, hashed_size, digest))
        ranges.append((absolute, stop, name))
    for left, right in zip(sorted(ranges), sorted(ranges)[1:]):
        if left[1] > right[0]:
            raise FixError(f"overlapping HFS0 entries: {left[2]} and {right[2]}")
    if len({entry.name.casefold() for entry in entries}) != len(entries):
        raise FixError("duplicate HFS0 file names")
    return entries


def verify_hfs0_entry_hashes(path: Path, entries: list[Hfs0Entry]) -> None:
    with path.open("rb") as handle:
        for entry in entries:
            if not entry.hashed_size:
                continue
            handle.seek(entry.offset)
            digest = hashlib.sha256()
            remaining = entry.hashed_size
            while remaining:
                chunk = handle.read(min(remaining, 8 * 1024 * 1024))
                if not chunk:
                    raise FixError(f"unexpected EOF hashing HFS0 entry: {entry.name}")
                digest.update(chunk)
                remaining -= len(chunk)
            if not hmac.compare_digest(digest.digest(), entry.digest):
                raise FixError(f"HFS0 entry hash mismatch: {entry.name}")


def read_xci_partitions(path: Path) -> tuple[dict[str, list[Hfs0Entry]], tuple[str, ...]]:
    """Validate the root and selected content tables before any extraction.

    A root partition can declare a tail beyond EOF only when its complete
    nested HFS0 and every member/hash region fit in the bytes actually present.
    No leaf file is ever clipped or padded to manufacture missing content.
    """
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(0x200)
    if len(header) != 0x200 or header[0x100:0x104] != XCI_HEAD_MAGIC:
        raise FixError("no valid XCI HEAD header")
    root_offset = struct.unpack_from("<Q", header, 0x130)[0]
    if root_offset < 0x200 or root_offset >= file_size:
        raise FixError("invalid XCI root HFS0 offset")
    root_entries = read_hfs0_table(path, root_offset, file_size - root_offset,
                                   allow_partition_tail_trim=True)
    if not root_entries:
        raise FixError("XCI root HFS0 is empty")
    if not {entry.name.casefold() for entry in root_entries}.issubset(
            {"update", "logo", "normal", "secure"}):
        raise FixError("XCI root HFS0 has unknown partitions")
    verify_hfs0_entry_hashes(path, root_entries)

    partitions: dict[str, list[Hfs0Entry]] = {}
    warnings: list[str] = []
    for root_entry in root_entries:
        name = root_entry.name.casefold()
        trimmed = max(0, root_entry.offset + root_entry.size - file_size)
        if name not in {"secure", "normal"} and not trimmed:
            continue
        available = min(root_entry.size, file_size - root_entry.offset)
        # Strict nested bounds are mandatory, including any trimmed partition
        # that would otherwise be ignored for game-content extraction.
        entries = read_hfs0_table(path, root_entry.offset, available)
        verify_hfs0_entry_hashes(path, entries)
        if trimmed:
            warnings.append(f"XCI {name}: {trimmed} bytes of unreferenced partition "
                            "tail omitted; all members and hashed regions are present")
        if name in {"secure", "normal"}:
            partitions[name] = entries
    return partitions, tuple(warnings)


def extract_xci(path: Path, out_dir: Path) -> tuple[str, ...]:
    """Extract complete game-content members; accept proven partition-tail trims."""
    partitions, warnings = read_xci_partitions(path)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with path.open("rb") as source:
        for partition_name in ("secure", "normal"):
            entries = partitions.get(partition_name, [])
            if not entries:
                continue
            partition_dir = out_dir / partition_name
            partition_dir.mkdir()
            for entry in entries:
                source.seek(entry.offset)
                with (partition_dir / entry.name).open("wb") as output:
                    copy_exact(source, output, entry.size)
    return warnings


def pfs0_string_table_size(raw_size: int, file_count: int) -> int:
    """The nxdumptool rule: align the full header to 0x20; when already
    aligned, add a full 0x20 block."""
    unpadded_header_size = 0x10 + file_count * 0x18 + raw_size
    padding_size = PFS0_HEADER_ALIGNMENT - (unpadded_header_size % PFS0_HEADER_ALIGNMENT)
    return raw_size + padding_size


def write_pfs0(path: Path, files: list[Path], names: list[str] | None = None,
               expected_hashes: list[str] | None = None) -> None:
    if names is not None and len(names) != len(files):
        raise FixError("PFS0 output name/file count mismatch")
    if expected_hashes is not None and len(expected_hashes) != len(files):
        raise FixError("PFS0 expected hash/file count mismatch")
    sizes = [item.stat().st_size for item in files]
    names = [name.encode("utf-8") for name in
             (names if names is not None else [item.name for item in files])]
    if len({name.lower() for name in names}) != len(names):
        raise FixError("duplicate output PFS0 names")
    name_offsets: list[int] = []
    strings = bytearray()
    for name in names:
        safe_member_name(name, len(name_offsets), "PFS0")
        name_offsets.append(len(strings))
        strings += name + b"\0"
    string_size = pfs0_string_table_size(len(strings), len(files))
    strings += b"\0" * (string_size - len(strings))

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        output.write(struct.pack("<4sIII", PFS0_MAGIC, len(files), len(strings), 0))
        relative = 0
        for size, name_offset in zip(sizes, name_offsets):
            output.write(struct.pack("<QQII", relative, size, name_offset, 0))
            relative += size
        output.write(strings)
        for index, (item, size) in enumerate(zip(files, sizes)):
            digest = hashlib.sha256() if expected_hashes is not None else None
            with item.open("rb") as source:
                remaining = size
                while remaining:
                    chunk = source.read(min(remaining, 8 * 1024 * 1024))
                    if not chunk:
                        raise FixError(f"PFS0 member truncated while packing: {item.name}")
                    output.write(chunk)
                    if digest is not None:
                        digest.update(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise FixError(f"PFS0 member grew while packing: {item.name}")
            if digest is not None and digest.hexdigest() != expected_hashes[index].lower():
                raise FixError(f"PFS0 member hash changed while packing: {item.name}")


# --------------------------------------------------------------------------
# signature verification (in-house, sole verifier)

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mgf1_sha256(seed: bytes, size: int) -> bytes:
    output = bytearray()
    for counter in range((size + 31) // 32):
        output += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
    return bytes(output[:size])


def rsa_pkcs1_v15_sha256_signature_valid(signature: bytes, signed_data: bytes,
                                         modulus: int) -> bool:
    encoded_size = (modulus.bit_length() + 7) // 8
    if len(signature) != encoded_size:
        return False
    signature_value = int.from_bytes(signature, "big")
    if signature_value >= modulus:
        return False
    encoded = pow(signature_value, 65537, modulus).to_bytes(encoded_size, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    digest = hashlib.sha256(signed_data).digest()
    padding_size = encoded_size - len(digest_info) - len(digest) - 3
    if padding_size < 8:
        return False
    expected = b"\x00\x01" + b"\xFF" * padding_size + b"\x00" + digest_info + digest
    return hmac.compare_digest(encoded, expected)


def ticket_signature_valid(data: bytes) -> bool:
    if len(data) < 0x2C0 or data[:4] != TICKET_SIGNATURE_TYPE_RSA2048_SHA256:
        return False
    issuer = data[0x140:0x180].split(b"\0", 1)[0]
    modulus = TICKET_RSA2048_SHA256_MODULI.get(issuer)
    if modulus is None:
        return False
    return rsa_pkcs1_v15_sha256_signature_valid(data[4:0x104], data[0x140:], modulus)


def nca_main_signature_valid(raw: bytes | bytearray) -> bool:
    raw = bytes(raw)
    if len(raw) < 0x400:
        return False
    key_generation = raw[0x221]
    if key_generation >= len(NCA_HEADER_FIXED_KEY_MODULI):
        return False
    modulus = int.from_bytes(NCA_HEADER_FIXED_KEY_MODULI[key_generation], "big")
    encoded_size = (modulus.bit_length() + 7) // 8
    signature_value = int.from_bytes(raw[:0x100], "big")
    if signature_value >= modulus:
        return False
    encoded = pow(signature_value, 65537, modulus).to_bytes(encoded_size, "big")
    hash_size = 32
    if encoded[-1:] != b"\xBC" or encoded_size < hash_size * 2 + 2:
        return False
    masked_db = encoded[:encoded_size - hash_size - 1]
    message_hash = encoded[encoded_size - hash_size - 1:-1]
    unused_bits = encoded_size * 8 - (modulus.bit_length() - 1)
    if masked_db[0] >> (8 - unused_bits):
        return False
    db_mask = mgf1_sha256(message_hash, len(masked_db))
    database = bytearray(a ^ b for a, b in zip(masked_db, db_mask))
    database[0] &= 0xFF >> unused_bits
    padding_size = encoded_size - hash_size * 2 - 2
    if database[:padding_size] != bytes(padding_size) or database[padding_size] != 1:
        return False
    salt = bytes(database[-hash_size:])
    signed_hash = hashlib.sha256(raw[0x200:0x400]).digest()
    expected = hashlib.sha256(b"\0" * 8 + signed_hash + salt).digest()
    return message_hash == expected


# --------------------------------------------------------------------------
# NCA headers and sections

@dataclass(frozen=True)
class NcaSection:
    index: int
    offset: int
    size: int
    fs_type: int
    crypto_type: int
    counter: bytes


@dataclass
class NcaHeader:
    path: Path
    raw: bytearray
    title_id: str
    content_type: int
    distribution_type: int
    crypto_type: int
    crypto_type2: int
    key_index: int
    key_generation: int
    master_key_index: int
    rights_id: str | None
    sections: list[NcaSection]
    decrypted_key_area: tuple[bytes, bytes, bytes, bytes] | None

    @property
    def content_name(self) -> str:
        return NCA_CONTENT_NAMES.get(self.content_type, f"UNKNOWN-{self.content_type}")

    @property
    def is_gamecard(self) -> bool:
        return bool(self.raw[0x204])

    @property
    def has_title_rights(self) -> bool:
        return self.rights_id is not None

    @property
    def effective_key(self) -> bytes | None:
        if self.decrypted_key_area is None:
            return None
        return self.decrypted_key_area[2]


def validate_signed_nca_header(header: NcaHeader) -> None:
    """Reject signed but nonconforming header enums before grouping."""
    if header.distribution_type not in {0, 1}:
        raise FixError(f"invalid NCA distribution type: {header.distribution_type}")
    if header.content_type not in NCA_CONTENT_NAMES:
        raise FixError(f"invalid NCA content type: {header.content_type}")
    if header.key_index not in {0, 1, 2}:
        raise FixError(f"invalid NCA key index: {header.key_index}")


def expected_rights_id_generation(key_generation: int) -> int:
    if key_generation < 0:
        raise FixError(f"invalid NCA key generation: {key_generation}")
    return 0 if key_generation < NCA_KEY_GENERATION_SINCE_301 else key_generation


def candidate_rights_ids(nca_title_id: str, key_generation: int) -> tuple[str, ...]:
    title_value = int(nca_title_id, 16)
    title_values = [title_value]
    if title_value & 0xFFF == 0:
        title_values.append(title_value | 0x800)
    suffix = expected_rights_id_generation(key_generation)
    return tuple(f"{value:016x}{suffix:016x}" for value in title_values)


def canonical_crypto_types(key_generation: int) -> tuple[int, int]:
    if key_generation < 0:
        raise FixError(f"invalid NCA key generation: {key_generation}")
    if key_generation <= 2:
        return key_generation, 0
    return 2, key_generation


def available_nca_generations(keys: KeySet) -> tuple[int, ...]:
    generations = {0}
    for name in keys.values:
        match = re.fullmatch(r"master_key_([0-9a-f]{2})", name)
        if match:
            generations.add(int(match.group(1), 16) + 1)
    return tuple(sorted(generations))


def recoverable_key_area_titlekey(
        slots: tuple[bytes, bytes, bytes, bytes] | None) -> bytes | None:
    if slots is None:
        return None
    titlekey = slots[2]
    if titlekey == b"\0" * 16:
        return None
    if any(slot not in {b"\0" * 16, titlekey} for slot in slots):
        return None
    return titlekey


def rights_id_generation(rights_id: str) -> int:
    raw = bytes.fromhex(rights_id)
    if len(raw) != 16:
        raise FixError(f"invalid RightsId: {rights_id}")
    return int.from_bytes(raw[8:16], "big")


def validate_rights_id_generation(header: NcaHeader) -> None:
    if header.rights_id is None:
        return
    actual = rights_id_generation(header.rights_id)
    expected = expected_rights_id_generation(header.key_generation)
    if actual != expected:
        raise FixError(
            f"invalid signed NCA RightsId generation: {header.path.name} "
            f"has {actual}, expected {expected} for NCA generation "
            f"{header.key_generation}")


def read_nca_header(path: Path, keys: KeySet) -> NcaHeader:
    with path.open("rb") as handle:
        encrypted = handle.read(NCA_HEADER_SIZE)
    if len(encrypted) != NCA_HEADER_SIZE:
        raise FixError(f"NCA is smaller than its header: {path.name}")
    raw = bytearray(aes_xts_crypt(encrypted, keys.header_key, decrypt=True))
    magic = bytes(raw[0x200:0x204])
    if magic == b"NCA2":
        raise FixError(
            f"legacy NCA2 is outside the StandardNSP lane and cannot be "
            f"authentically converted: {path.name}")
    if magic != b"NCA3":
        raise FixError(f"failed to decrypt NCA header: {path.name}")

    content_type = raw[0x205]
    distribution_type = raw[0x204]
    crypto_type = raw[0x206]
    key_index = raw[0x207]
    crypto_type2 = raw[0x220]
    key_generation = max(crypto_type, crypto_type2)
    master_key_index = max(key_generation - 1, 0)
    title_id = f"{int.from_bytes(raw[0x210:0x218], 'little'):016X}"
    rights_bytes = bytes(raw[0x230:0x240])
    rights_id = rights_bytes.hex() if any(rights_bytes) else None

    decrypted_key_area = None
    if rights_id is None:
        kaek = keys.key_area_key(master_key_index, key_index)
        plain = ecb_decrypt(kaek, bytes(raw[0x300:0x340]))
        decrypted_key_area = tuple(plain[i:i + 16] for i in range(0, 0x40, 16))

    sections: list[NcaSection] = []
    for index in range(4):
        entry_offset = 0x240 + index * 0x10
        media_start, media_end = struct.unpack_from("<II", raw, entry_offset)
        if not media_start and not media_end:
            continue
        if media_end <= media_start:
            raise FixError(f"invalid NCA section table: {path.name} section {index}")
        fs_offset = 0x400 + index * 0x200
        counter = bytes((b"\0" * 8 + raw[fs_offset + 0x140:fs_offset + 0x148])[::-1])
        sections.append(NcaSection(
            index=index,
            offset=media_start * MEDIA_SIZE,
            size=(media_end - media_start) * MEDIA_SIZE,
            fs_type=raw[fs_offset + 3],
            crypto_type=raw[fs_offset + 4],
            counter=counter,
        ))

    expected_size = struct.unpack_from("<Q", raw, 0x208)[0]
    if expected_size != path.stat().st_size:
        raise FixError(f"NCA header size differs from file size: {path.name}")
    return NcaHeader(path=path, raw=raw, title_id=title_id,
                     content_type=content_type, distribution_type=distribution_type,
                     crypto_type=crypto_type, crypto_type2=crypto_type2,
                     key_index=key_index, key_generation=key_generation,
                     master_key_index=master_key_index, rights_id=rights_id,
                     sections=sections, decrypted_key_area=decrypted_key_area)


def write_nca_header(path: Path, raw: bytearray, keys: KeySet) -> None:
    if len(raw) != NCA_HEADER_SIZE or bytes(raw[0x200:0x204]) != b"NCA3":
        raise FixError("refusing to write an invalid decrypted NCA header")
    encrypted = aes_xts_crypt(bytes(raw), keys.header_key, decrypt=False)
    with path.open("r+b") as handle:
        handle.seek(0)
        handle.write(encrypted)


# --------------------------------------------------------------------------
# tickets

@dataclass(frozen=True)
class TicketInfo:
    path: Path
    rights_id: str
    encrypted_titlekey: bytes | None
    key_generation: int
    signature_class: str
    signature_valid: bool
    titlekey_type: int = 0


def parse_ticket(path: Path) -> TicketInfo:
    data = path.read_bytes()
    if len(data) < 0x2C0:
        raise FixError(f"ticket too small: {path.name}")
    if data[:4] != TICKET_SIGNATURE_TYPE_RSA2048_SHA256:
        raise FixError(f"unsupported ticket signature format: {path.name}")
    titlekey_type = data[0x281]
    signature = data[4:0x104]
    signature_class = "FF" if signature == b"\xFF" * 0x100 else "NONFF"
    return TicketInfo(path=path, rights_id=data[0x2A0:0x2B0].hex(),
                      encrypted_titlekey=(data[0x180:0x190] if titlekey_type == 0 else None),
                      key_generation=data[0x285],
                      signature_class=signature_class,
                      signature_valid=ticket_signature_valid(data),
                      titlekey_type=titlekey_type)


def ticket_titlekey_failure(ticket: TicketInfo) -> str | None:
    if ticket.titlekey_type == 1:
        return ("personalized ticket requires console-specific RSA-OAEP unwrapping; "
                "conversion is not supported by fixnsp (not evidence of a corrupt titlekey)")
    if ticket.titlekey_type != 0:
        return f"unsupported ticket titlekey type: 0x{ticket.titlekey_type:02X}"
    if ticket.encrypted_titlekey is None or len(ticket.encrypted_titlekey) != 16:
        return "common ticket has no usable encrypted titlekey"
    return None


def update_ticket_failure(ticket: TicketInfo | None) -> str | None:
    if ticket is None:
        return "UPD title-rights content has no matching original ticket"
    if failure := ticket_titlekey_failure(ticket):
        return failure
    if ticket.signature_class == "FF":
        return "UPD original ticket is FF/fake-signed"
    if not ticket.signature_valid:
        return "UPD original ticket failed Nintendo RSA signature verification"
    return None


def make_public_ticket(rights_id: str, encrypted_titlekey: bytes,
                       key_generation: int) -> bytes:
    rights = bytes.fromhex(rights_id)
    if len(rights) != 16 or len(encrypted_titlekey) != 16:
        raise FixError("invalid public-ticket material")
    if not 0 <= key_generation <= 0xFF:
        raise FixError(f"invalid ticket key generation: {key_generation}")
    ticket = bytearray(0x2C0)
    ticket[0x000:0x004] = TICKET_SIGNATURE_TYPE_RSA2048_SHA256
    ticket[0x004:0x104] = b"\xFF" * 0x100
    ticket[0x140:0x140 + len(ISSUER)] = ISSUER
    ticket[0x180:0x190] = encrypted_titlekey
    ticket[0x280:0x288] = bytes([0x02, 0, 0, 0, 0, key_generation, 0, 0])
    ticket[0x2A0:0x2B0] = rights
    ticket[0x2B8:0x2BC] = bytes.fromhex("C0020000")
    return bytes(ticket)


def titlekey_from_ticket(ticket: TicketInfo, header: NcaHeader, keys: KeySet) -> bytes:
    if failure := ticket_titlekey_failure(ticket):
        raise FixError(failure)
    if ticket.rights_id.lower() != (header.rights_id or "").lower():
        raise FixError(f"ticket RightsId does not match NCA: {header.path.name}")
    if ticket.key_generation != header.key_generation:
        raise FixError(
            f"ticket/NCA generation mismatch for {header.path.name}: "
            f"ticket={ticket.key_generation}, NCA={header.key_generation}")
    return ecb_decrypt(keys.titlekek(max(ticket.key_generation - 1, 0)),
                       ticket.encrypted_titlekey)


class TitleKeyProofStatus(str, Enum):
    PROVEN = "PROVEN"
    REJECTED = "REJECTED"
    UNPROVABLE = "UNPROVABLE"


@dataclass(frozen=True)
class TitleKeyProof:
    status: TitleKeyProofStatus
    witness: str | None = None
    attempted: int = 0
    limitations: tuple[str, ...] = ()


TITLEKEY_PROOF_LIMIT = 1 << 22
SPARSE_NODE_SIZE = 0x4000
SPARSE_NODE_OFFSET_COUNT = (SPARSE_NODE_SIZE - 0x10) // 8
SPARSE_NODE_ENTRY_COUNT = (SPARSE_NODE_SIZE - 0x10) // 0x14


def decrypt_ctr_region(path: Path, key: bytes, counter: bytes,
                       offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        raise FixError("negative AES-CTR proof region")
    boundary = offset & ~0xF
    shift = offset - boundary
    with path.open("rb") as handle:
        handle.seek(boundary)
        encrypted = handle.read(shift + size)
    if len(encrypted) != shift + size:
        raise FixError(f"titlekey proof extends past EOF: {path.name}")
    plain = aes_ctr_crypt(encrypted, key, counter, boundary)
    return plain[shift:shift + size]


def hash_ctr_region(path: Path, key: bytes, counter: bytes,
                    offset: int, size: int, padded_size: int) -> bytes:
    """Hash a bounded AES-CTR region without loading it as one object."""
    if offset < 0 or size < 0 or padded_size < size:
        raise FixError("invalid AES-CTR hash proof region")
    boundary = offset & ~0xF
    shift = offset - boundary
    remaining = shift + size
    digest = hashlib.sha256()
    cipher = AES.new(key, AES.MODE_CTR, nonce=counter[:8],
                     initial_value=boundary // 16)
    with path.open("rb") as handle:
        handle.seek(boundary)
        skip = shift
        while remaining:
            wanted = min(remaining, 1024 * 1024)
            encrypted = handle.read(wanted)
            if len(encrypted) != wanted:
                raise FixError(f"titlekey proof extends past EOF: {path.name}")
            plain = cipher.decrypt(encrypted)
            if skip:
                plain = plain[skip:]
                skip = 0
            digest.update(plain)
            remaining -= wanted
    padding = padded_size - size
    zeroes = bytes(min(padding, 1024 * 1024))
    while padding:
        amount = min(padding, len(zeroes))
        digest.update(zeroes[:amount])
        padding -= amount
    return digest.digest()


def sparse_node_opens(node: bytes, entry_count: int) -> bool:
    if len(node) != SPARSE_NODE_SIZE or entry_count <= 0:
        return False
    index, count = struct.unpack_from("<ii", node, 0)
    end_offset = struct.unpack_from("<q", node, 8)[0]
    if not 1 <= count <= SPARSE_NODE_OFFSET_COUNT:
        return False
    first_offset = struct.unpack_from("<q", node, 0x10)[0]
    entry_sets = ((entry_count + SPARSE_NODE_ENTRY_COUNT - 1)
                  // SPARSE_NODE_ENTRY_COUNT)
    if entry_sets > SPARSE_NODE_OFFSET_COUNT and count < SPARSE_NODE_OFFSET_COUNT:
        start_offset = struct.unpack_from("<q", node, 0x10 + count * 8)[0]
    else:
        start_offset = first_offset
    return (index == 0 and 0 <= start_offset <= first_offset
            and start_offset < end_offset)


def prove_titlekey(headers: list[NcaHeader], plain_titlekey: bytes) -> TitleKeyProof:
    """Try every independently readable proof for one RightsId.

    StandardNSP's rule is existential: one hash-level or sparse-table proof is
    enough. A candidate is rejected only when at least one proof was actually
    decrypted and none opened; otherwise it is explicitly unprovable.
    """
    attempted = 0
    limitations: list[str] = []
    for header in headers:
        for section in header.sections:
            label = f"{header.path.name} section {section.index}"
            if section.crypto_type == 1:
                continue
            if section.crypto_type == 4:
                limitations.append(f"{label}: AES-CTR-EX depends on base content")
                continue
            if section.crypto_type != 3:
                limitations.append(
                    f"{label}: unsupported encryption type {section.crypto_type}")
                continue
            fs_offset = 0x400 + section.index * 0x200
            sparse_generation = struct.unpack_from(
                "<H", header.raw, fs_offset + 0x170)[0]
            try:
                if sparse_generation:
                    entry_count = struct.unpack_from(
                        "<i", header.raw, fs_offset + 0x160)[0]
                    bucket_offset = struct.unpack_from(
                        "<Q", header.raw, fs_offset + 0x148)[0]
                    bucket_size = struct.unpack_from(
                        "<Q", header.raw, fs_offset + 0x150)[0]
                    physical_offset = struct.unpack_from(
                        "<Q", header.raw, fs_offset + 0x168)[0]
                    node_offset = physical_offset + bucket_offset
                    if entry_count == 0:
                        continue
                    if (entry_count < 0 or bucket_size < SPARSE_NODE_SIZE
                            or node_offset + SPARSE_NODE_SIZE > header.path.stat().st_size):
                        limitations.append(f"{label}: invalid sparse-table bounds")
                        continue
                    upper = bytearray(
                        header.raw[fs_offset + 0x140:fs_offset + 0x148])
                    upper[:4] = (sparse_generation << 16).to_bytes(4, "little")
                    counter = bytes((bytes(8) + bytes(upper))[::-1])
                    node = decrypt_ctr_region(
                        header.path, plain_titlekey, counter,
                        node_offset, SPARSE_NODE_SIZE)
                    attempted += 1
                    if sparse_node_opens(node, entry_count):
                        return TitleKeyProof(
                            TitleKeyProofStatus.PROVEN, f"{label} sparse table",
                            attempted, tuple(limitations))
                    continue

                if section.fs_type == 2:
                    master = bytes(
                        header.raw[fs_offset + 0x08:fs_offset + 0x28])
                    region_offset, region_size = struct.unpack_from(
                        "<QQ", header.raw, fs_offset + 0x30)
                    padded_size = region_size
                elif section.fs_type == 3:
                    if bytes(header.raw[fs_offset + 0x08:
                                        fs_offset + 0x0C]) != IVFC_MAGIC:
                        limitations.append(f"{label}: invalid IVFC magic")
                        continue
                    master = bytes(
                        header.raw[fs_offset + 0xC8:fs_offset + 0xE8])
                    level_offset, level_size, block_order = struct.unpack_from(
                        "<QQI", header.raw, fs_offset + 0x18)
                    if block_order >= 64:
                        limitations.append(f"{label}: invalid IVFC block order")
                        continue
                    padded_size = 1 << block_order
                    region_offset = level_offset
                    region_size = min(level_size, padded_size)
                else:
                    limitations.append(
                        f"{label}: unsupported hash type {section.fs_type}")
                    continue
                if (not region_size or padded_size > TITLEKEY_PROOF_LIMIT
                        or region_offset + region_size > section.size):
                    limitations.append(f"{label}: first hash level is not readable")
                    continue
                actual = hash_ctr_region(
                    header.path, plain_titlekey, section.counter,
                    section.offset + region_offset, region_size, padded_size)
                attempted += 1
                if hmac.compare_digest(actual, master):
                    return TitleKeyProof(
                        TitleKeyProofStatus.PROVEN, f"{label} first hash level",
                        attempted, tuple(limitations))
            except (FixError, OSError, ValueError) as exc:
                limitations.append(f"{label}: {exc}")
    status = (TitleKeyProofStatus.REJECTED if attempted
              else TitleKeyProofStatus.UNPROVABLE)
    return TitleKeyProof(status, attempted=attempted,
                         limitations=tuple(dict.fromkeys(limitations)))


# --------------------------------------------------------------------------
# CNMT and Meta NCA

@dataclass(frozen=True)
class CnmtEntry:
    hash: str
    nca_id: str
    size: int
    content_type: int
    id_offset: int
    offset: int


@dataclass(frozen=True)
class CnmtInfo:
    title_id: str
    version: int
    title_type: int
    type_name: str
    content_entries: tuple[CnmtEntry, ...]
    required_system_version: int | None
    required_application_version: int | None
    field_offsets: dict[str, int]


def parse_cnmt_payload(payload: bytes) -> CnmtInfo:
    if len(payload) < 0x20:
        raise FixError("CNMT payload is too small")
    title_id = payload[0:8][::-1].hex()
    version = struct.unpack_from("<I", payload, 0x08)[0]
    title_type = payload[0x0C]
    ext_size = struct.unpack_from("<H", payload, 0x0E)[0]
    content_count = struct.unpack_from("<H", payload, 0x10)[0]
    meta_count = struct.unpack_from("<H", payload, 0x12)[0]
    type_name = TITLE_TYPE_NAMES.get(title_type, f"UNKNOWN-{title_type:02X}")
    if type_name.startswith("UNKNOWN"):
        raise FixError(f"unsupported CNMT title type: 0x{title_type:02X}")

    extended = payload[0x20:0x20 + ext_size]
    required_system_version = None
    required_application_version = None
    field_offsets = {"titleType": 0x0C}
    if title_type in (0x80, 0x81, 0x84) and len(extended) >= 0x0C:
        required_system_version = struct.unpack_from("<I", extended, 0x08)[0]
        field_offsets["requiredSystemVersion"] = 0x20 + 0x08
    elif title_type == 0x82 and len(extended) >= 0x10:
        required_application_version = struct.unpack_from("<I", extended, 0x08)[0]
        field_offsets["requiredApplicationVersion"] = 0x20 + 0x08

    entry_base = 0x20 + ext_size
    entry_end = entry_base + content_count * 0x38
    meta_end = entry_end + meta_count * 0x10
    if entry_end > len(payload) or meta_end > len(payload):
        raise FixError("CNMT entry table extends past EOF")
    entries: list[CnmtEntry] = []
    for index in range(content_count):
        offset = entry_base + index * 0x38
        entries.append(CnmtEntry(
            hash=payload[offset:offset + 0x20].hex(),
            nca_id=payload[offset + 0x20:offset + 0x30].hex(),
            size=int.from_bytes(payload[offset + 0x30:offset + 0x36], "little"),
            content_type=payload[offset + 0x36],
            id_offset=payload[offset + 0x37],
            offset=offset,
        ))
    return CnmtInfo(title_id=title_id, version=version, title_type=title_type,
                    type_name=type_name, content_entries=tuple(entries),
                    required_system_version=required_system_version,
                    required_application_version=required_application_version,
                    field_offsets=field_offsets)


def patch_cnmt_scalar_fields(payload: bytes, info: CnmtInfo,
                             candidates: dict[str, int]) -> tuple[bytes, tuple[str, ...]]:
    patched = bytearray(payload)
    changes: list[str] = []
    current_values = {"requiredSystemVersion": info.required_system_version,
                      "requiredApplicationVersion": info.required_application_version}
    for name, candidate in candidates.items():
        offset = info.field_offsets.get(name)
        if offset is None or not 0 <= candidate <= 0xFFFFFFFF:
            raise FixError(f"invalid CNMT scalar candidate: {name}={candidate}")
        struct.pack_into("<I", patched, offset, candidate)
        changes.append(f"{name} {current_values.get(name)} -> {candidate}")
    return bytes(patched), tuple(changes)


@dataclass
class CnmtKnowledgeBase:
    path: Path
    _records: dict[str, object] | None = field(default=None, init=False, repr=False)
    _system_versions: tuple[int, ...] | None = field(default=None, init=False, repr=False)
    _load_error: str | None = field(default=None, init=False, repr=False)

    def _load(self) -> dict[str, object]:
        if self._records is None:
            if not self.path.exists():
                self._records = {}
            else:
                try:
                    loaded = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    self._load_error = f"{self.path}: {exc}"
                    loaded = {}
                if not isinstance(loaded, dict):
                    self._load_error = f"{self.path}: JSON root is not an object"
                    loaded = {}
                self._records = loaded
        return self._records

    @property
    def load_error(self) -> str | None:
        self._load()
        return self._load_error

    def record_exists(self, info: CnmtInfo) -> bool:
        title_records = self._load().get(info.title_id.lower())
        return isinstance(title_records, dict) and isinstance(
            title_records.get(str(info.version)), dict)

    def verified_record(self, info: CnmtInfo) -> dict[str, object] | None:
        title_records = self._load().get(info.title_id.lower())
        if not isinstance(title_records, dict):
            return None
        record = title_records.get(str(info.version))
        if not isinstance(record, dict):
            return None
        if str(record.get("titleId", "")).lower() != info.title_id.lower():
            return None
        if record.get("titleType") != info.title_type:
            return None
        db_entries = record.get("contentEntries")
        if not isinstance(db_entries, list):
            return None
        expected = [(entry.nca_id.lower(), entry.content_type)
                    for entry in info.content_entries]
        got: list[tuple[str, int]] = []
        for entry in db_entries:
            if not isinstance(entry, dict):
                return None
            nca_id = str(entry.get("ncaId", "")).lower()
            content_type = entry.get("type")
            if not re.fullmatch(r"[0-9a-f]{32}", nca_id) or not isinstance(content_type, int):
                return None
            got.append((nca_id, content_type))
        return record if got == expected else None

    def scalar_candidates(self, info: CnmtInfo) -> dict[str, int]:
        record = self.verified_record(info)
        if record is None:
            return {}
        candidates: dict[str, int] = {}
        for name, current in (("requiredSystemVersion", info.required_system_version),
                              ("requiredApplicationVersion", info.required_application_version)):
            candidate = record.get(name)
            if (name in info.field_offsets and isinstance(candidate, int)
                    and not isinstance(candidate, bool)
                    and 0 <= candidate <= 0xFFFFFFFF and candidate != current):
                candidates[name] = candidate
        return candidates

    def system_version_candidates(self) -> tuple[int, ...]:
        """Observed firmware values are proposals, never signature authority."""
        if self._system_versions is None:
            values = {
                value
                for versions in self._load().values() if isinstance(versions, dict)
                for record in versions.values() if isinstance(record, dict)
                if isinstance(value := record.get("requiredSystemVersion"), int)
                and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF
            }
            self._system_versions = tuple(sorted(values)[:1000])
        return self._system_versions


def load_firmware_catalog(path: Path) -> tuple[int, ...]:
    """Released-firmware requiredSystemVersion values; the CNMTDB-silent
    fallback axis. Optional data — absent file means the axis stays closed."""
    if not path.exists():
        return ()
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    values = sorted({value for value in loaded
                     if isinstance(value, int) and not isinstance(value, bool)
                     and 0 <= value <= 0xFFFFFFFF}) if isinstance(loaded, list) else []
    return tuple(values[:1000])


def nca_section_key(header: NcaHeader, keys: KeySet,
                    ticket: TicketInfo | None = None) -> bytes:
    if header.has_title_rights:
        if ticket is None:
            raise FixError(
                f"title-rights NCA needs a ticket to read sections: {header.path.name}")
        return titlekey_from_ticket(ticket, header, keys)
    key = header.effective_key
    if key is None or key == b"\0" * 16:
        raise FixError(f"NCA key area has no effective section key: {header.path.name}")
    return key


def read_nca_section(header: NcaHeader, section: NcaSection, keys: KeySet,
                     ticket: TicketInfo | None = None) -> bytes:
    with header.path.open("rb") as handle:
        handle.seek(section.offset)
        encrypted = handle.read(section.size)
    if len(encrypted) != section.size:
        raise FixError(f"truncated NCA section: {header.path.name}")
    if section.crypto_type == 1:
        return encrypted
    if section.crypto_type != 3:
        raise FixError(
            f"unsupported section crypto type {section.crypto_type}: {header.path.name}")
    return aes_ctr_crypt(encrypted, nca_section_key(header, keys, ticket),
                         section.counter, section.offset)


def write_nca_section(path: Path, section: NcaSection, plain: bytes, key: bytes) -> None:
    if len(plain) != section.size:
        raise FixError("refusing to resize an NCA section")
    if section.crypto_type == 1:
        encrypted = plain
    elif section.crypto_type == 3:
        encrypted = aes_ctr_crypt(plain, key, section.counter, section.offset)
    else:
        raise FixError(f"unsupported writable section crypto type: {section.crypto_type}")
    with path.open("r+b") as handle:
        handle.seek(section.offset)
        handle.write(encrypted)


def memory_pfs0_cnmt(data: bytes) -> tuple[int, int, str]:
    if len(data) < 0x10 or data[:4] != PFS0_MAGIC:
        raise FixError("inner Meta NCA data layer is not PFS0")
    count, string_size, reserved = struct.unpack_from("<III", data, 4)
    if reserved != 0:
        raise FixError("inner PFS0 reserved field is not zero")
    table_end = 0x10 + count * 0x18
    strings_end = table_end + string_size
    if table_end > len(data) or strings_end > len(data):
        raise FixError("truncated inner PFS0")
    strings = data[table_end:strings_end]
    members: list[tuple[int, int, str]] = []
    ranges: list[tuple[int, int]] = []
    for index in range(count):
        offset, size, name_offset, entry_reserved = struct.unpack_from(
            "<QQII", data, 0x10 + index * 0x18)
        if entry_reserved or name_offset >= string_size:
            raise FixError(f"invalid inner PFS0 entry {index}")
        name_end = strings.find(b"\0", name_offset)
        if name_end < 0:
            raise FixError(f"inner PFS0 name {index} is not terminated")
        name = safe_member_name(strings[name_offset:name_end], index, "PFS0")
        start = strings_end + offset
        end = start + size
        if start < strings_end or end < start or end > len(data):
            raise FixError(f"inner PFS0 member extends past data layer: {name}")
        if size:
            ranges.append((start, end))
        members.append((start, end, name))
    ordered = sorted(ranges)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise FixError("inner PFS0 members overlap")
    cnmts = [member for member in members if member[2].lower().endswith(".cnmt")]
    if len(cnmts) != 1:
        raise FixError(
            f"expected exactly one .cnmt member inside Meta NCA, found {len(cnmts)}")
    return cnmts[0]


def validate_cnmt_member_name(name: str, info: CnmtInfo) -> None:
    match = re.fullmatch(
        r"(Application|Patch|AddOnContent|DataPatch)_([0-9a-fA-F]{16})\.cnmt",
        name, re.IGNORECASE)
    if match is None:
        raise FixError(f"noncanonical CNMT member name: {name}")
    expected_type = CNMT_FILE_TYPE_NAMES[info.title_type]
    if match.group(1).lower() != expected_type.lower():
        raise FixError(
            f"CNMT member type/name mismatch: {name} contains {match.group(1)}, "
            f"payload is {expected_type}")
    if match.group(2).lower() != info.title_id.lower():
        raise FixError(
            f"CNMT member title ID/name mismatch: {name} contains "
            f"{match.group(2).upper()}, payload is {info.title_id.upper()}")


@dataclass(frozen=True)
class MetaHashLayout:
    block_size: int
    hash_offset: int
    hash_size: int
    data_offset: int
    data_size: int


@dataclass(frozen=True)
class MetaPayload:
    header: NcaHeader
    section: NcaSection
    section_plain: bytes
    hash_layout: MetaHashLayout
    data_offset: int
    cnmt_start: int
    cnmt_end: int
    cnmt_name: str
    payload: bytes
    info: CnmtInfo


def read_meta_hash_layout(header: NcaHeader, section: NcaSection) -> MetaHashLayout:
    if section.fs_type != 2:
        raise FixError(f"Meta NCA does not use HierarchicalSha256: {header.path.name}")
    fs_offset = 0x400 + section.index * 0x200
    block_size, layer_count = struct.unpack_from("<II", header.raw, fs_offset + 0x28)
    hash_offset, hash_size = struct.unpack_from("<QQ", header.raw, fs_offset + 0x30)
    data_offset, data_size = struct.unpack_from("<QQ", header.raw, fs_offset + 0x40)
    if (block_size < 0x20 or block_size & (block_size - 1) or layer_count != 2
            or not hash_size or not data_size
            or hash_offset + hash_size > section.size
            or data_offset + data_size > section.size
            or hash_offset + hash_size > data_offset):
        raise FixError(f"invalid Meta NCA HierarchicalSha256 layout: {header.path.name}")
    expected_hash_size = ((data_size + block_size - 1) // block_size) * 0x20
    if hash_size != expected_hash_size:
        raise FixError(f"unsupported Meta NCA hash-layer size: {header.path.name}")
    return MetaHashLayout(block_size=block_size, hash_offset=hash_offset,
                          hash_size=hash_size, data_offset=data_offset,
                          data_size=data_size)


def validate_meta_hash_layers(header: NcaHeader, section: NcaSection,
                              plain: bytes) -> None:
    layout = read_meta_hash_layout(header, section)
    if len(plain) != section.size:
        raise FixError(f"invalid Meta NCA hash-layer bounds: {header.path.name}")
    for index in range(layout.hash_size // 0x20):
        block_start = layout.data_offset + index * layout.block_size
        block_end = min(block_start + layout.block_size,
                        layout.data_offset + layout.data_size)
        stored = plain[layout.hash_offset + index * 0x20:
                       layout.hash_offset + (index + 1) * 0x20]
        if stored != hashlib.sha256(plain[block_start:block_end]).digest():
            raise FixError(
                f"Meta NCA data-layer hash mismatch at block {index}: {header.path.name}")
    fs_offset = 0x400 + section.index * 0x200
    stored_master = bytes(header.raw[fs_offset + 0x08:fs_offset + 0x28])
    hash_layer = plain[layout.hash_offset:layout.hash_offset + layout.hash_size]
    if stored_master != hashlib.sha256(hash_layer).digest():
        raise FixError(f"Meta NCA master hash mismatch: {header.path.name}")
    section_header = bytes(header.raw[fs_offset:fs_offset + 0x200])
    stored_section = bytes(header.raw[0x280 + section.index * 0x20:
                                      0x2A0 + section.index * 0x20])
    if stored_section != hashlib.sha256(section_header).digest():
        raise FixError(f"Meta NCA section-header hash mismatch: {header.path.name}")


def read_meta_payload(path: Path, keys: KeySet, *,
                      allow_extra_sections: bool = False) -> MetaPayload:
    header = read_nca_header(path, keys)
    section_zero = [section for section in header.sections if section.index == 0]
    if (header.content_type != 1 or len(section_zero) != 1
            or (not allow_extra_sections and len(header.sections) != 1)):
        raise FixError(f"expected an ordinary single-section Meta NCA: {path.name}")
    section = section_zero[0]
    hash_layout = read_meta_hash_layout(header, section)
    plain = read_nca_section(header, section, keys)
    validate_meta_hash_layers(header, section, plain)
    data_offset = hash_layout.data_offset
    data_end = data_offset + hash_layout.data_size
    if plain[data_offset:data_offset + 4] != PFS0_MAGIC:
        raise FixError(f"Meta NCA data layer is not PFS0: {path.name}")
    cnmt_start, cnmt_end, cnmt_name = memory_pfs0_cnmt(
        plain[data_offset:data_end])
    cnmt_start += data_offset
    cnmt_end += data_offset
    payload = plain[cnmt_start:cnmt_end]
    info = parse_cnmt_payload(payload)
    validate_cnmt_member_name(cnmt_name, info)
    return MetaPayload(header=header, section=section, section_plain=plain,
                       hash_layout=hash_layout, data_offset=data_offset,
                       cnmt_start=cnmt_start, cnmt_end=cnmt_end,
                       cnmt_name=cnmt_name, payload=payload,
                       info=info)


@dataclass(frozen=True)
class NcaRewrite:
    source: Path
    output: Path
    old_hash: str
    old_id: str
    new_hash: str
    new_id: str
    rights_id: str | None = None
    encrypted_titlekey: bytes | None = None


def patch_cnmt_payload(payload: bytes, rewrites: list[NcaRewrite]) -> tuple[bytes, int]:
    info = parse_cnmt_payload(payload)
    patched = bytearray(payload)
    changed = 0
    for rewrite in rewrites:
        matches = [entry for entry in info.content_entries
                   if entry.nca_id.lower() == rewrite.old_id.lower()]
        if len(matches) != 1:
            raise FixError(
                f"expected one CNMT entry for {rewrite.old_id}, found {len(matches)}")
        entry = matches[0]
        if entry.hash.lower() != rewrite.old_hash.lower():
            raise FixError(f"CNMT hash does not match source NCA: {rewrite.source.name}")
        patched[entry.offset:entry.offset + 0x20] = bytes.fromhex(rewrite.new_hash)
        patched[entry.offset + 0x20:entry.offset + 0x30] = bytes.fromhex(rewrite.new_id)
        changed += 1
    return bytes(patched), changed


def rebuild_meta_layers(meta: MetaPayload, patched_payload: bytes,
                        header_raw: bytearray | None = None) -> tuple[bytes, bytearray]:
    if len(patched_payload) != len(meta.payload):
        raise FixError("refusing to resize a CNMT payload")
    plain = bytearray(meta.section_plain)
    plain[meta.cnmt_start:meta.cnmt_end] = patched_payload
    layout = meta.hash_layout
    for index in range(layout.hash_size // 0x20):
        block_start = layout.data_offset + index * layout.block_size
        block_end = min(block_start + layout.block_size,
                        layout.data_offset + layout.data_size)
        digest = hashlib.sha256(plain[block_start:block_end]).digest()
        plain[layout.hash_offset + index * 0x20:
              layout.hash_offset + (index + 1) * 0x20] = digest
    hash_layer = bytes(plain[layout.hash_offset:layout.hash_offset + layout.hash_size])
    master_hash = hashlib.sha256(hash_layer).digest()
    raw = bytearray(meta.header.raw if header_raw is None else header_raw)
    fs_offset = 0x400 + meta.section.index * 0x200
    raw[fs_offset + 0x08:fs_offset + 0x28] = master_hash
    section_header = bytes(raw[fs_offset:fs_offset + 0x200])
    raw[0x280 + meta.section.index * 0x20:0x2A0 + meta.section.index * 0x20] = \
        hashlib.sha256(section_header).digest()
    return bytes(plain), raw


def canonicalize_unsigned_meta(meta: MetaPayload, plain: bytes,
                               raw: bytearray) -> tuple[bytes, bytearray, bool]:
    """Restore convention-defined bytes not covered by Meta's data layers.

    This is only a repair candidate. The Nintendo main signature still decides
    whether the zeroed header bytes are authentic.
    """
    changed = False
    if any(raw[0x100:0x200]):
        raw[0x100:0x200] = bytes(0x100)
        changed = True
    for index in range(1, 4):
        table = 0x240 + index * 0x10
        if any(raw[table:table + 0x10]):
            raw[table:table + 0x10] = bytes(0x10)
            changed = True
        start = 0x400 + index * 0x200
        if any(raw[start:start + 0x200]):
            raw[start:start + 0x200] = bytes(0x200)
            changed = True
    mutable = bytearray(plain)
    occupied = sorted((
        (meta.hash_layout.hash_offset,
         meta.hash_layout.hash_offset + meta.hash_layout.hash_size),
        (meta.hash_layout.data_offset,
         meta.hash_layout.data_offset + meta.hash_layout.data_size),
    ))
    cursor = 0
    for start, end in occupied:
        if any(mutable[cursor:start]):
            mutable[cursor:start] = bytes(start - cursor)
            changed = True
        cursor = end
    if any(mutable[cursor:]):
        mutable[cursor:] = bytes(len(mutable) - cursor)
        changed = True
    return bytes(mutable), raw, changed


def rebuild_meta_nca(source: Path, out_dir: Path, rewrites: list[NcaRewrite],
                     keys: KeySet, distribution_type: int | None = None) -> NcaRewrite:
    meta = read_meta_payload(source, keys)
    patched_payload, changed = patch_cnmt_payload(meta.payload, rewrites)
    if changed != len(rewrites):
        raise FixError("not every content rewrite reached the CNMT")
    header_raw = None
    if distribution_type is not None:
        header_raw = bytearray(meta.header.raw)
        header_raw[0x204] = distribution_type
    plain, raw = rebuild_meta_layers(meta, patched_payload, header_raw)

    out_dir.mkdir(parents=True, exist_ok=True)
    temporary = out_dir / source.name
    shutil.copy2(source, temporary)
    section_key = nca_section_key(meta.header, keys)
    write_nca_section(temporary, meta.section, plain, section_key)
    write_nca_header(temporary, raw, keys)
    old_hash = sha256_file(source)
    new_hash = sha256_file(temporary)
    destination = out_dir / f"{new_hash[:32]}.cnmt.nca"
    if destination != temporary:
        if destination.exists():
            destination.unlink()
        temporary.rename(destination)
    return NcaRewrite(source=source, output=destination, old_hash=old_hash,
                      old_id=old_hash[:32], new_hash=new_hash, new_id=new_hash[:32])


# --------------------------------------------------------------------------
# repair primitives

# --------------------------------------------------------------------------
# inspection dataclasses

@dataclass(frozen=True)
class NcaVerification:
    path: Path
    main_signature_valid: bool


@dataclass(frozen=True)
class NcaArtifact:
    path: Path
    header: NcaHeader
    verification: NcaVerification
    sha256: str
    nca_id: str
    recovery: NcaRewrite | None = None
    recovery_reason: str | None = None
    origins: tuple[Path, ...] = ()
    recovery_history: tuple[NcaRewrite, ...] = ()


def canonicalize_signed_meta_artifact(artifact: NcaArtifact, out_dir: Path,
                                      keys: KeySet) -> NcaArtifact:
    """Canonicalize only convention bytes outside Nintendo's signed regions.

    Section geometry lives in the signed header and is therefore rejected,
    never rewritten. Signature 2, absent fs-header slots and plaintext outside
    Meta's hash/data regions are not covered by the first signature or Meta
    hash tree and may be zeroed without inventing signed state.
    """
    if artifact.header.content_type != 1:
        return artifact
    meta = read_meta_payload(artifact.path, keys)
    if meta.section.offset != NCA_HEADER_SIZE:
        raise FixError(
            f"signed Meta section 0 does not start at 0x{NCA_HEADER_SIZE:X}: "
            f"{artifact.path.name}")
    if meta.section.offset + meta.section.size != artifact.path.stat().st_size:
        raise FixError(
            f"signed Meta section 0 does not end at NCA EOF: {artifact.path.name}")

    raw = bytearray(meta.header.raw)
    plain = bytearray(meta.section_plain)
    changes: list[str] = []
    if any(raw[0x100:0x200]):
        raw[0x100:0x200] = bytes(0x100)
        changes.append("second signature")
    if any(raw[0x600:0xC00]):
        raw[0x600:0xC00] = bytes(0x600)
        changes.append("absent fs-header slots")

    occupied = (
        (meta.hash_layout.hash_offset,
         meta.hash_layout.hash_offset + meta.hash_layout.hash_size),
        (meta.hash_layout.data_offset,
         meta.hash_layout.data_offset + meta.hash_layout.data_size),
    )
    cursor = 0
    padding_changed = False
    for start, end in occupied:
        if any(plain[cursor:start]):
            plain[cursor:start] = bytes(start - cursor)
            padding_changed = True
        cursor = end
    if any(plain[cursor:]):
        plain[cursor:] = bytes(len(plain) - cursor)
        padding_changed = True
    if padding_changed:
        changes.append("section padding")
    if not changes:
        return artifact

    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".meta-", suffix=".tmp",
                                     dir=out_dir, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        shutil.copy2(artifact.path, temporary)
        if padding_changed:
            write_nca_section(temporary, meta.section, bytes(plain),
                              nca_section_key(meta.header, keys))
        write_nca_header(temporary, raw, keys)
        new_hash = sha256_file(temporary)
        destination = out_dir / new_hash / f"{new_hash[:32]}.cnmt.nca"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if sha256_file(destination) != new_hash:
                raise FixError(
                    "existing canonical Meta output disagrees with its full hash")
        else:
            temporary.rename(destination)
    finally:
        temporary.unlink(missing_ok=True)

    header = read_nca_header(destination, keys)
    if not nca_main_signature_valid(header.raw):
        raise FixError("Meta canonicalization invalidated Nintendo's main signature")
    validate_signed_nca_header(header)
    verified = read_meta_payload(destination, keys)
    if (any(verified.header.raw[0x100:0x200])
            or any(verified.header.raw[0x600:0xC00])):
        raise FixError("Meta canonicalization did not produce zero header padding")
    check_plain = verified.section_plain
    covered = [False] * len(check_plain)
    for start, end in occupied:
        covered[start:end] = [True] * (end - start)
    if any(value for index, value in enumerate(check_plain) if not covered[index]):
        raise FixError("Meta canonicalization did not produce zero section padding")

    reason = "standardized Meta " + ", ".join(changes)
    rewrite = NcaRewrite(
        source=artifact.path, output=destination,
        old_hash=artifact.sha256, old_id=artifact.nca_id,
        new_hash=new_hash, new_id=new_hash[:32])
    prior_history = artifact.recovery_history or (
        (artifact.recovery,) if artifact.recovery is not None else ())
    prior_reason = artifact.recovery_reason
    combined_reason = "; ".join(
        item for item in (prior_reason, reason) if item)
    return NcaArtifact(
        destination, header, NcaVerification(destination, True),
        new_hash, new_hash[:32], rewrite, combined_reason,
        artifact.origins, (*prior_history, rewrite))


@dataclass(frozen=True)
class InspectionResult:
    artifacts: dict[str, NcaArtifact]  # Full SHA-256, not a filename or short ID.
    content_paths: tuple[Path, ...]
    warnings: tuple[str, ...]
    failed_meta_attempts: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class PackageGroup:
    source: Path
    container_type: str
    extract_dir: Path
    meta: MetaPayload
    meta_artifact: NcaArtifact
    content: tuple[NcaArtifact, ...]
    missing_entries: tuple[CnmtEntry, ...]
    tickets: tuple[TicketInfo, ...]
    certs: tuple[Path, ...]


@dataclass(frozen=True)
class GroupDiscovery:
    groups: tuple[PackageGroup, ...]
    failed_attempts: tuple[str, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass
class NcaDecision:
    source: NcaArtifact
    output: Path
    outcome: Outcome
    verification: NcaVerification
    rewrite: NcaRewrite | None = None
    reason: str = ""


@dataclass
class RepairPlan:
    group: PackageGroup
    outcome: Outcome
    output_name: str
    content: list[NcaDecision] = field(default_factory=list)
    meta: NcaDecision | None = None
    ticket_path: Path | None = None
    cert_path: Path | None = None
    warnings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    gamecard_variant: bool = False

    @property
    def publishable(self) -> bool:
        return (not self.failures and self.meta is not None
                and self.outcome != Outcome.IMPOSSIBLE)


def verify_nca_file(path: Path, keys: KeySet) -> NcaVerification:
    header = read_nca_header(path, keys)
    return NcaVerification(path, nca_main_signature_valid(header.raw))


def decision_hash(decision: NcaDecision) -> str:
    return decision.rewrite.new_hash if decision.rewrite is not None else decision.source.sha256


# --------------------------------------------------------------------------
# header repair: the bounded enumeration

def enumerate_header_candidates(header: NcaHeader, keys: KeySet
                                ) -> list[tuple[bytearray, str | None, bytes | None, str]]:
    """The composed transform space: (raw header, rights id, encrypted
    titlekey, reason) per candidate, each axis a deterministic inverse.
    Empty for rights-bearing NCAs and unavailable key areas."""
    if header.has_title_rights or header.decrypted_key_area is None:
        return []
    titlekey = recoverable_key_area_titlekey(header.decrypted_key_area)
    candidates: list[tuple[bytearray, str | None, bytes | None, str]] = []
    seen: set[bytes] = set()

    def add(raw: bytearray, rights_id: str | None,
            encrypted_titlekey: bytes | None, reason: str) -> None:
        identity = bytes(raw)
        if identity not in seen:
            seen.add(identity)
            candidates.append((raw, rights_id, encrypted_titlekey, reason))

    def add_rightless_distributions(raw: bytearray, reason: str) -> None:
        for distribution in (0, 1):
            candidate = bytearray(raw)
            candidate[0x204] = distribution
            changes = [reason] if reason else []
            if distribution != header.distribution_type:
                changes.append(f"distribution {header.distribution_type} -> {distribution}")
            add(candidate, None, None, "; ".join(changes) or "original header")

    # Keep the unmodified key area available for distribution-only and Meta
    # payload repair, then compose distribution with every generation inverse.
    add_rightless_distributions(bytearray(header.raw), "")
    for generation in available_nca_generations(keys):
        crypto_type, crypto_type2 = canonical_crypto_types(generation)
        master_key_index = max(generation - 1, 0)
        try:
            key_area_key = keys.key_area_key(master_key_index, header.key_index)
        except FixError:
            continue
        rightless = bytearray(header.raw)
        rightless[0x206] = crypto_type
        rightless[0x220] = crypto_type2
        rightless[0x230:0x240] = b"\0" * 0x10
        rightless[0x300:0x340] = ecb_encrypt(
            key_area_key, b"".join(header.decrypted_key_area))
        add_rightless_distributions(
            rightless, f"crypto generation {header.key_generation} -> {generation}")
        if (titlekey is None
                or header.content_type not in RECOVERABLE_TITLE_RIGHTS_NCA_TYPES
                or header.is_gamecard or header.distribution_type != 0):
            continue
        encrypted_titlekey = ecb_encrypt(keys.titlekek(master_key_index), titlekey)
        for rights_id in candidate_rights_ids(header.title_id, generation):
            rights_bearing = bytearray(header.raw)
            rights_bearing[0x206] = crypto_type
            rights_bearing[0x220] = crypto_type2
            rights_bearing[0x230:0x240] = bytes.fromhex(rights_id)
            rights_bearing[0x300:0x340] = b"\0" * 0x40
            add(rights_bearing, rights_id, encrypted_titlekey,
                "title-rights and crypto-generation restoration "
                f"{header.key_generation} -> {generation} "
                f"(RightsId title {rights_id[:16].upper()})")
    return candidates


def meta_payload_candidates(meta: MetaPayload,
                            knowledge: CnmtKnowledgeBase | None,
                            firmware_catalog: tuple[int, ...],
                            recovered_content: dict[str, NcaArtifact] | None = None):
    """Compose supported CNMT inverses, preserving all unrelated payload bytes.

    Match rewritten entries to recovered content by the exact old full hash
    and size, then propose the recovered full hash/ID pair. Duplicate copies
    retain all recovery histories. Only the Meta signature can approve a
    proposal; filenames and database records cannot authorize membership.
    """
    payloads = [(meta.payload, "")]
    corrected = bytearray(meta.payload)
    changed = 0
    for entry in meta.info.content_entries:
        matches: dict[str, NcaArtifact] = {}
        for artifact in (recovered_content or {}).values():
            history = artifact.recovery_history or ((artifact.recovery,) if artifact.recovery else ())
            if (artifact.verification.main_signature_valid
                    and artifact.header.content_type != 1
                    and artifact.nca_id.lower() == artifact.sha256[:32].lower()
                    and artifact.path.stat().st_size == entry.size
                    and (artifact.sha256.lower() == entry.hash.lower()
                         or any(r.old_hash.lower() == entry.hash.lower()
                                and r.new_hash.lower() == artifact.sha256.lower()
                                for r in history))):
                matches[artifact.sha256] = artifact
        if len(matches) != 1:
            continue
        artifact = next(iter(matches.values()))
        if entry.hash.lower() == artifact.sha256.lower() and entry.nca_id.lower() == artifact.nca_id:
            continue
        corrected[entry.offset:entry.offset + 0x20] = bytes.fromhex(artifact.sha256)
        corrected[entry.offset + 0x20:entry.offset + 0x30] = bytes.fromhex(artifact.nca_id)
        changed += 1
    if changed:
        payloads.append((bytes(corrected), f"restored {changed} CNMT content hash/ID pair(s)"))

    scalar_sets: list[tuple[dict[str, int], str]] = [({}, "")]
    db_candidates = knowledge.scalar_candidates(meta.info) if knowledge is not None else {}
    if db_candidates:
        scalar_sets.append((db_candidates, "CNMTDB candidate"))
    if "requiredSystemVersion" in meta.info.field_offsets:
        observed = knowledge.system_version_candidates() if knowledge is not None else ()
        for value in sorted(set(firmware_catalog) | set(observed)):
            proposal = {"requiredSystemVersion": value}
            if value != meta.info.required_system_version and proposal != db_candidates:
                origin = ("firmware-catalog candidate" if value in firmware_catalog
                          else "CNMTDB observed-system-version candidate")
                scalar_sets.append((proposal, origin))

    for payload, content_reason in payloads:
        for scalars, origin in scalar_sets:
            if not content_reason and not scalars:
                continue  # Unchanged payload was already tried by the header lane.
            patched, changes = patch_cnmt_scalar_fields(payload, meta.info, scalars)
            scalar_reason = f"{origin} " + ", ".join(changes) if scalars else ""
            reason = "; ".join(part for part in (content_reason, scalar_reason) if part)
            yield patched, reason


def restore_signed_header_nca(source: Path, out_dir: Path, keys: KeySet,
                              source_hash: str | None = None,
                              knowledge: CnmtKnowledgeBase | None = None,
                              firmware_catalog: tuple[int, ...] = (),
                              recovered_content: dict[str, NcaArtifact] | None = None
                              ) -> tuple[NcaRewrite, str] | None:
    """Signature-driven recovery, independent of input filenames:
    enumerate the composed transform space and accept the candidate whose
    Nintendo main signature verifies. The signature pins the signed header,
    not the entire body; publication still requires signed CNMT hash/size proof.
    Compute the recovered ID from its full hash after signature approval. For a
    Meta NCA, exact recovered content hashes and CNMT scalar proposals compose
    with the header axes: the section hash inside the signed header pins the
    payload transitively. Title-specific proposals precede firmware values
    observed elsewhere in CNMTDB or in the optional firmware catalog."""
    header = read_nca_header(source, keys)
    candidates = enumerate_header_candidates(header, keys)
    # (raw header, restored plaintext section or None, rights id,
    #  encrypted titlekey, reason)
    winners: list[tuple[bytearray, bytes | None, str | None, bytes | None, str]] = []
    for raw, rights_id, encrypted_titlekey, reason in candidates:
        if nca_main_signature_valid(raw):
            winners.append((raw, None, rights_id, encrypted_titlekey, reason))

    meta = None
    if not winners and header.content_type == 1:
        meta = read_meta_payload(source, keys, allow_extra_sections=True)
        payload_candidates = [(meta.payload, "")]
        payload_candidates.extend(meta_payload_candidates(
            meta, knowledge, firmware_catalog, recovered_content))
        for patched_payload, payload_reason in payload_candidates:
            for raw, rights_id, encrypted_titlekey, reason in candidates:
                meta_plain, meta_raw = rebuild_meta_layers(
                    meta, patched_payload, raw)
                meta_plain, meta_raw, canonicalized = canonicalize_unsigned_meta(
                    meta, meta_plain, meta_raw)
                if not payload_reason and not canonicalized:
                    continue
                if nca_main_signature_valid(meta_raw):
                    repair_reason = "; ".join(part for part in (
                        reason, payload_reason,
                        "zeroed uncovered Meta bytes" if canonicalized else "")
                        if part)
                    winners.append((meta_raw, meta_plain, rights_id,
                                    encrypted_titlekey,
                                    repair_reason))
            if winners:
                break

    if not winners:
        return None
    if len({bytes(winner[0]) for winner in winners}) > 1:
        raise FixError("multiple distinct signed header candidates "
                       f"(cryptographically impossible): {source.name}")
    raw, restored_plain, rights_id, encrypted_titlekey, reason = winners[0]
    old_hash = source_hash or sha256_file(source)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Input names must not overwrite previously recovered inventory members.
    with tempfile.NamedTemporaryFile(prefix=".nca-", suffix=".tmp", dir=out_dir,
                                     delete=False) as handle:
        temporary = Path(handle.name)
    try:
        shutil.copy2(source, temporary)
        if restored_plain is not None:
            write_nca_section(temporary, meta.section, restored_plain,
                              nca_section_key(meta.header, keys))
        write_nca_header(temporary, raw, keys)
        new_hash = sha256_file(temporary)
        suffix = ".cnmt.nca" if header.content_type == 1 else ".nca"
        destination = out_dir / new_hash / f"{new_hash[:32]}{suffix}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if sha256_file(destination) != new_hash:
                raise FixError("existing recovery output disagrees with its full hash")
        else:
            temporary.rename(destination)
    finally:
        temporary.unlink(missing_ok=True)
    rewrite = NcaRewrite(source=source, output=destination, old_hash=old_hash,
                         old_id=old_hash[:32], new_hash=new_hash,
                         new_id=new_hash[:32], rights_id=rights_id,
                         encrypted_titlekey=encrypted_titlekey)
    return rewrite, reason


# --------------------------------------------------------------------------
# intake / inspection / discovery

# nsz via `python -c`, never its .exe shim (breaks multiprocessing spawn on
# Windows under redirected standard handles).
_NSZ_BOOTSTRAP = ("import sys; from vaultd.sokoban.nx_digital.nsz_codec import main; "
                  "sys.argv[0] = 'nsz'; main()")


def decompress_nsz(source: Path, out_dir: Path) -> Path:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    result = subprocess.run(
        [sys.executable, "-c", _NSZ_BOOTSTRAP, "-D", "--machine-readable",
         "-o", str(out_dir), str(source)],
        cwd=REPO_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace")
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if "ModuleNotFoundError" in stderr and "nsz" in stderr:
            raise FixError("nsz not installed in the venv; run: uv sync")
        raise FixError(f"nsz decompression failed: {stderr[-400:]}")
    wanted = ".nsp" if source.suffix.lower() == ".nsz" else ".xci"
    produced = sorted(out_dir.glob(f"*{wanted}"))
    if len(produced) != 1:
        raise FixError(f"nsz decompression produced {len(produced)} {wanted} files")
    return produced[0]


def rejoin_split_nsp(source_dir: Path, work: Path) -> Path:
    members = sorted(source_dir.iterdir())
    unexpected = [item.name for item in members
                  if not item.is_file() or re.fullmatch(r"\d{2}", item.name) is None]
    if unexpected:
        raise FixError("split NSP directory contains unexpected member(s): "
                       + ", ".join(unexpected))
    parts = members
    if not parts:
        raise FixError(f"split NSP directory has no numeric parts: {source_dir.name}")
    expected = [f"{index:02d}" for index in range(len(parts))]
    if [item.name for item in parts] != expected:
        raise FixError(f"split NSP parts are not contiguous: {source_dir.name}")
    sizes = [item.stat().st_size for item in parts]
    if len(sizes) > 2 and len({size for size in sizes[:-1]}) != 1:
        raise FixError(f"split NSP chunk sizes are inconsistent: {source_dir.name}")
    joined = work / f"{source_dir.stem}.nsp"
    work.mkdir(parents=True, exist_ok=True)
    with joined.open("wb") as output:
        for item in parts:
            with item.open("rb") as chunk:
                shutil.copyfileobj(chunk, output, 8 * 1024 * 1024)
    read_pfs0_table(joined)
    return joined


def prepare_input(source: Path, work_root: Path, keep_work: bool
                  ) -> tuple[str, Path, tuple[str, ...]]:
    suffix = source.suffix.lower()
    work = work_root / source.name
    resolved_source, resolved_work = source.resolve(), work.resolve()
    if (resolved_work == resolved_source
            or (source.is_dir() and resolved_source in resolved_work.parents)):
        raise FixError(f"work path overlaps input source: {work}")
    if work.exists() and not keep_work:
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    warnings: tuple[str, ...] = ()
    if source.is_dir() and suffix == ".nsp":
        nsp = rejoin_split_nsp(source, work / "rejoined")
        container_type = "NSP-SPLIT"
    elif suffix == ".nsp":
        nsp, container_type = source, "NSP"
    elif suffix == ".nsz":
        nsp, container_type = decompress_nsz(source, work / "decompressed"), "NSZ"
    elif suffix in {".xci", ".xcz"}:
        xci = source
        container_type = "XCI"
        if suffix == ".xcz":
            xci = decompress_nsz(source, work / "decompressed")
            container_type = "XCZ"
        extract_dir = work / "extract"
        warnings = extract_xci(xci, extract_dir)
        return container_type, extract_dir, warnings
    else:
        raise FixError(f"unsupported input type: {source.name}")
    extract_dir = work / "extract"
    extract_pfs0(nsp, extract_dir)
    return container_type, extract_dir, warnings


def content_scope_paths(extract_dir: Path, container_type: str) -> tuple[Path, ...]:
    if container_type not in {"XCI", "XCZ"}:
        return (extract_dir,)
    scopes = tuple(path for path in (extract_dir / "secure", extract_dir / "normal")
                   if path.is_dir())
    if not scopes:
        raise FixError("XCI contains no secure/normal content partition")
    return scopes


def inspect_ncas(scope_path: Path, keys: KeySet,
                 knowledge: CnmtKnowledgeBase | None,
                 firmware_catalog: tuple[int, ...], *,
                 content_paths: tuple[Path, ...] | None = None
                 ) -> tuple[dict[str, NcaArtifact], list[str], list[str], list[str]]:
    """One source inventory: recover all content before any Meta; names are labels."""
    artifacts: dict[str, NcaArtifact] = {}
    warnings: list[str] = []
    failed_meta_attempts: list[str] = []
    errors: list[str] = []
    recovery_dir = scope_path.parent / f"{scope_path.name}-header-recovery"

    def register(artifact: NcaArtifact) -> None:
        existing = artifacts.get(artifact.sha256)
        if existing is not None:
            history = tuple(dict.fromkeys((*existing.recovery_history,
                                           *artifact.recovery_history)))
            artifacts[artifact.sha256] = replace(
                existing, origins=tuple(sorted(set(existing.origins + artifact.origins))),
                recovery_history=history)
            warnings.append(f"duplicate NCA content shared: {artifact.origins[0]}")
        else:
            artifacts[artifact.sha256] = artifact

    readable = []
    for root in content_paths or (scope_path,):
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            if path.name.lower().endswith(".cnmt.xml"):
                warnings.append(
                    f"CNMT XML sidecar omitted; it restates the Meta NCA: {path}")
                continue
            if path.suffix.lower() not in {".nca", ".tik", ".cert"}:
                errors.append(
                    f"unsupported container member left unused: {path}")
                continue
            if path.suffix.lower() != ".nca":
                continue
            try:
                digest = sha256_file(path)
                header = read_nca_header(path, keys)
            except (FixError, OSError, ValueError) as exc:
                detail = f"unreadable NCA left unused: {path}: {exc}"
                # If the header cannot be read, the suffix is only a diagnostic
                # hint that a Meta attempt failed; it never authorizes content.
                (failed_meta_attempts if path.name.lower().endswith(".cnmt.nca")
                 else errors).append(detail)
                continue
            readable.append((path, digest, header))

    processed: dict[str, NcaArtifact | None] = {}
    for path, digest, header in sorted(
            readable, key=lambda item: (item[2].content_type == 1, item[0])):
        if digest in processed:
            prior = processed[digest]
            if prior is not None:
                register(replace(prior, origins=(path,)))
            else:
                warnings.append(f"duplicate unrecoverable NCA left unused: {path}")
            continue
        processed[digest] = None
        try:
            verification = NcaVerification(path, nca_main_signature_valid(header.raw))
            if verification.main_signature_valid:
                validate_signed_nca_header(header)
                artifact = NcaArtifact(path, header, verification, digest, digest[:32],
                                       origins=(path,))
            else:
                restored = restore_signed_header_nca(
                    path, recovery_dir, keys, digest, knowledge, firmware_catalog, artifacts)
                if restored is None:
                    raise FixError("Nintendo main signature invalid; no supported repair restored it")
                rewrite, reason = restored
                restored_header = read_nca_header(rewrite.output, keys)
                validate_rights_id_generation(restored_header)
                verification = verify_nca_file(rewrite.output, keys)
                if not verification.main_signature_valid:
                    raise FixError("recovery failed final signature verification")
                validate_signed_nca_header(restored_header)
                artifact = NcaArtifact(
                    rewrite.output, restored_header, verification, rewrite.new_hash,
                    rewrite.new_id, rewrite, reason, (path,), (rewrite,))
                warnings.append(f"restored signed NCA candidate: {path.name} -> "
                                f"{rewrite.output.name} ({reason})")
            if artifact.header.content_type == 1:
                previous_hash = artifact.sha256
                artifact = canonicalize_signed_meta_artifact(
                    artifact, recovery_dir, keys)
                if artifact.sha256 != previous_hash:
                    warnings.append(
                        f"standardized signed Meta NCA: {path.name} -> "
                        f"{artifact.path.name} ({artifact.recovery_reason})")
            processed[digest] = artifact
            register(artifact)
        except (FixError, OSError, ValueError) as exc:
            detail = f"NCA left unused: {path}; {exc}"
            (failed_meta_attempts if header.content_type == 1 else errors).append(detail)
    return artifacts, warnings, failed_meta_attempts, errors


def inspect_container(extract_dir: Path, container_type: str, keys: KeySet,
                      knowledge: CnmtKnowledgeBase | None,
                      firmware_catalog: tuple[int, ...]) -> InspectionResult:
    paths = content_scope_paths(extract_dir, container_type)
    artifacts, warnings, failures, errors = inspect_ncas(
        extract_dir, keys, knowledge, firmware_catalog, content_paths=paths)
    if container_type in {"XCI", "XCZ"} and (extract_dir / "update").is_dir():
        warnings.append("XCI update partition left untouched")
    if not artifacts:
        warnings.append("input has no usable NCAs after verification/recovery")
    return InspectionResult(
        artifacts, paths, tuple(warnings), tuple(failures), tuple(errors))


def discover_groups(source: Path, container_type: str,
                    inspection: InspectionResult, keys: KeySet) -> GroupDiscovery:
    """Signed CNMTs select exact members from this input's shared inventory."""
    groups: list[PackageGroup] = []
    failed_attempts = list(inspection.failed_meta_attempts)
    warnings: list[str] = []
    errors: list[str] = []
    tickets: dict[str, TicketInfo] = {}
    certs: list[Path] = []
    for root in inspection.content_paths:
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            if path.suffix.lower() == ".tik":
                try:
                    ticket = parse_ticket(path)
                    tickets.setdefault(sha256_file(path), ticket)
                except (FixError, OSError, ValueError) as exc:
                    errors.append(f"unreadable ticket left unused: {path}: {exc}")
            elif path.suffix.lower() == ".cert":
                certs.append(path)
    referenced: set[str] = set()
    meta_hashes: set[str] = set()
    for digest, artifact in sorted(inspection.artifacts.items()):
        if artifact.header.content_type != 1:
            continue
        meta_hashes.add(digest)
        try:
            if not artifact.verification.main_signature_valid:
                raise FixError("Meta signature invalid after recovery")
            meta = read_meta_payload(artifact.path, keys)
            if len({e.nca_id.lower() for e in meta.info.content_entries}) != len(meta.info.content_entries):
                raise FixError("duplicate content IDs in signed CNMT")
        except (FixError, OSError, ValueError) as exc:
            failed_attempts.append(f"{artifact.path.name}: {exc}")
            continue
        content: list[NcaArtifact] = []
        missing: list[CnmtEntry] = []
        for entry in meta.info.content_entries:
            candidate = inspection.artifacts.get(entry.hash.lower())
            if (candidate is None or not candidate.verification.main_signature_valid
                    or candidate.header.content_type == 1
                    or candidate.nca_id.lower() != entry.nca_id.lower()
                    or candidate.path.stat().st_size != entry.size):
                missing.append(entry)
            else:
                content.append(candidate)
                referenced.add(candidate.sha256)
        groups.append(PackageGroup(
            source=source, container_type=container_type,
            extract_dir=inspection.content_paths[0], meta=meta, meta_artifact=artifact,
            content=tuple(content), missing_entries=tuple(missing),
            tickets=tuple(tickets[key] for key in sorted(tickets)), certs=tuple(certs)))
    orphaned = set(inspection.artifacts) - referenced - meta_hashes
    if orphaned:
        shown = ", ".join(item[:32] for item in sorted(orphaned)[:5])
        errors.append(f"{len(orphaned)} unreferenced signed NCA candidate(s) "
                      f"left unused in this input: {shown}")
    used_rights = {artifact.header.rights_id for group in groups
                   for artifact in group.content if artifact.header.rights_id}
    if used_rights:
        unused_tickets = [ticket.path.name for ticket in tickets.values()
                          if ticket.rights_id not in used_rights]
        if unused_tickets:
            shown = ", ".join(sorted(unused_tickets)[:5])
            errors.append(f"{len(unused_tickets)} ticket(s) do not apply to any "
                          f"discovered title-rights group: {shown}")
    return GroupDiscovery(
        tuple(groups), tuple(failed_attempts), tuple(warnings), tuple(errors))


# --------------------------------------------------------------------------
# the plan

def matching_update_ticket(
        group: PackageGroup, rights_id: str,
        headers: list[NcaHeader], keys: KeySet
        ) -> tuple[TicketInfo | None, TitleKeyProof | None]:
    """Select a genuine update ticket by RightsId, signature and key proof."""
    relevant = [h for h in headers if h.rights_id == rights_id]
    generations = {h.key_generation for h in relevant}
    if len(generations) != 1:
        raise FixError("ticket selection requires one signed content generation")
    generation = next(iter(generations))
    matches = [ticket for ticket in group.tickets
               if ticket.rights_id.lower() == rights_id.lower()]
    if not matches:
        return None, None
    accepted: dict[bytes, tuple[TicketInfo, TitleKeyProof]] = {}
    rejected: set[str] = set()
    for ticket in matches:
        if failure := ticket_titlekey_failure(ticket):
            rejected.add(failure)
            continue
        if ticket.signature_class == "FF":
            rejected.add("FF/fake-signed ticket")
            continue
        if not ticket.signature_valid:
            rejected.add("Nintendo RSA signature invalid")
            continue
        if ticket.key_generation != generation:
            rejected.add(
                f"ticket generation {ticket.key_generation} does not match signed "
                f"NCA generation {generation}")
            continue
        try:
            plain = ecb_decrypt(keys.titlekek(max(generation - 1, 0)),
                                ticket.encrypted_titlekey)
            proof = prove_titlekey(relevant, plain)
        except (FixError, ValueError, OSError) as exc:
            rejected.add(str(exc))
            continue
        if proof.status == TitleKeyProofStatus.REJECTED:
            rejected.add("titlekey failed every readable signed-NCA proof")
            continue
        accepted.setdefault(ticket.path.read_bytes(), (ticket, proof))
    if not accepted:
        detail = ("; " + "; ".join(sorted(rejected))) if rejected else ""
        raise FixError(
            "no matching update ticket passes the signed content requirements"
            + detail)
    if len(accepted) != 1:
        raise FixError(
            f"multiple distinct valid update tickets for RightsId {rights_id}")
    return next(iter(accepted.values()))


def is_gamecard_oriented(header: NcaHeader) -> bool:
    return header.is_gamecard or header.distribution_type != 0


def classify_gamecard_group(info: CnmtInfo, artifacts: tuple[NcaArtifact, ...]
                            ) -> tuple[bool, str | None]:
    oriented = [artifact for artifact in artifacts
                if is_gamecard_oriented(artifact.header)]
    if not oriented:
        return False, None
    if len(oriented) != len(artifacts):
        return False, f"{info.type_name} mixes gamecard- and digital-distribution NCAs"
    if any(artifact.header.has_title_rights for artifact in artifacts):
        return False, f"GAMECARD {info.type_name} contains unexpected title-rights NCA(s)"
    unsigned = [artifact.path.name for artifact in artifacts
                if not artifact.verification.main_signature_valid]
    if unsigned:
        return False, (f"GAMECARD {info.type_name} has invalid Nintendo main "
                       f"signature(s): {', '.join(unsigned)}")
    return True, None


def is_standard_omitted_entry(info: CnmtInfo, entry: CnmtEntry) -> bool:
    return info.type_name == "UPD" and entry.content_type == 6


def partition_standard_content(group: PackageGroup
                               ) -> tuple[tuple[NcaArtifact, ...], tuple[NcaArtifact, ...]]:
    entries = {entry.nca_id.lower(): entry for entry in group.meta.info.content_entries}
    included: list[NcaArtifact] = []
    delta_fragments: list[NcaArtifact] = []
    for artifact in group.content:
        entry = entries.get(artifact.nca_id)
        if entry is None:
            raise FixError(f"internal CNMT mapping failure: {artifact.path.name}")
        (delta_fragments if is_standard_omitted_entry(group.meta.info, entry)
         else included).append(artifact)
    return tuple(included), tuple(delta_fragments)


def worst_outcome(values: list[Outcome]) -> Outcome:
    if Outcome.IMPOSSIBLE in values:
        return Outcome.IMPOSSIBLE
    if Outcome.RESTORED in values:
        return Outcome.RESTORED
    return Outcome.PRESERVE


def classify_missing_content(info: CnmtInfo, missing_entries: tuple[CnmtEntry, ...],
                             meta_signature_valid: bool) -> tuple[str | None, str | None]:
    if not missing_entries:
        return None, None
    missing_types = {entry.content_type for entry in missing_entries}
    if info.type_name == "UPD" and missing_types == {6}:
        authority = ("signed local CNMT records" if meta_signature_valid
                     else "unsigned local CNMT references")
        return None, (f"{authority} {len(missing_entries)} type-6 delta fragments "
                      "that are not included in this package")
    names = ", ".join(f"{entry.nca_id}.nca" for entry in missing_entries)
    return f"missing required content NCA referenced by local CNMT: {names}", None


def build_repair_plan(group: PackageGroup, group_work: Path, keys: KeySet,
                      default_cert: Path,
                      title_keys: TitleKeys | None = None) -> RepairPlan:
    info = group.meta.info
    plan = RepairPlan(
        group=group, outcome=Outcome.PRESERVE,
        output_name=f"[{info.title_id.upper()}][v{info.version}][{info.type_name}].nsp")
    standard_content, carried_delta_fragments = partition_standard_content(group)
    entry_by_id = {entry.nca_id.lower(): entry for entry in info.content_entries}
    if carried_delta_fragments:
        exact = [artifact for artifact in carried_delta_fragments
                 if artifact.sha256.lower() == entry_by_id[artifact.nca_id].hash.lower()
                 and artifact.path.stat().st_size == entry_by_id[artifact.nca_id].size]
        signed = [artifact for artifact in exact
                  if artifact.verification.main_signature_valid]
        plan.warnings.append(
            f"standard NSP omitted {len(carried_delta_fragments)} carried type-6 "
            f"delta fragment(s); {len(exact)} match local CNMT hash/size and "
            f"{len(signed)} have a valid Nintendo main signature")
    missing_failure, missing_warning = classify_missing_content(
        info, group.missing_entries,
        group.meta_artifact.verification.main_signature_valid)
    if missing_failure:
        plan.failures.append(missing_failure)
    if missing_warning:
        plan.warnings.append(missing_warning)

    outcomes: list[Outcome] = []
    for artifact in (*standard_content, group.meta_artifact):
        restored = bool(artifact.recovery or artifact.recovery_history)
        outcome = Outcome.RESTORED if restored else Outcome.PRESERVE
        reason = artifact.recovery_reason or "Nintendo main signature valid"
        if not artifact.verification.main_signature_valid:
            outcome = Outcome.IMPOSSIBLE
            reason = "unsigned NCA reached grouping"
            plan.failures.append(f"{reason}: {artifact.path.name}")
        decision = NcaDecision(artifact, artifact.path, outcome,
                               artifact.verification, artifact.recovery, reason)
        if artifact is group.meta_artifact:
            plan.meta = decision
        else:
            plan.content.append(decision)
        outcomes.append(outcome)

    decisions = plan.content + [plan.meta]
    final_artifacts: list[NcaArtifact] = []
    for decision in decisions:
        digest = decision_hash(decision)
        header = (read_nca_header(decision.output, keys)
                  if decision.rewrite is not None else decision.source.header)
        final_artifacts.append(NcaArtifact(
            decision.output, header, decision.verification, digest, digest[:32],
            decision.rewrite, decision.reason))
    gamecard_variant, gamecard_failure = classify_gamecard_group(
        info, tuple(final_artifacts))
    if gamecard_failure:
        plan.failures.append(gamecard_failure)
    if gamecard_variant:
        plan.gamecard_variant = True
        plan.output_name = (f"[{info.title_id.upper()}][v{info.version}]"
                            f"[{info.type_name}][GAMECARD].nsp")

    output_headers = [artifact.header for artifact in final_artifacts[:-1]]
    for header in output_headers:
        try:
            validate_rights_id_generation(header)
        except FixError as exc:
            plan.failures.append(str(exc))
    rights_ids = sorted({header.rights_id for header in output_headers if header.rights_id})
    if len(rights_ids) > 1:
        plan.failures.append(f"multiple RightsIds in one CNMT group: {rights_ids}")
    rights_id = rights_ids[0] if len(rights_ids) == 1 else None
    rights_generations = sorted({header.key_generation for header in output_headers
                                 if rights_id is not None
                                 and header.rights_id == rights_id})
    if len(rights_generations) > 1:
        plan.failures.append("matching rights-bearing NCAs disagree on key generation: "
                             f"{rights_generations}")
    ticket_generation = rights_generations[0] if len(rights_generations) == 1 else None
    ticket_dir = group_work / "ticket"

    if rights_id and ticket_generation is None:
        plan.failures.append("title-rights content has no unambiguous NCA key generation")
    elif rights_id and info.type_name in {"BASE", "DLC"}:
        relevant = [header for header in output_headers
                    if header.rights_id == rights_id]
        matching_tickets = [ticket for ticket in group.tickets
                            if ticket.rights_id.lower() == rights_id.lower()]
        genuine = [ticket for ticket in matching_tickets
                   if ticket.signature_class == "NONFF" and ticket.signature_valid]
        accepted: dict[bytes, set[str]] = {}
        rejected_sources: set[str] = set()

        if genuine:
            plan.failures.append(
                f"{info.type_name} has a genuine non-FF ticket; StandardNSP only "
                "defines preservation of genuine tickets for Patch/DataPatch, so "
                "automatic conversion would discard signed evidence")
        else:
            recovered_materials = {
                rewrite.encrypted_titlekey
                for item in plan.content
                for rewrite in (item.source.recovery_history or
                                ((item.rewrite,) if item.rewrite else ()))
                if rewrite.encrypted_titlekey is not None
            }
            for material in recovered_materials:
                try:
                    plain = ecb_decrypt(
                        keys.titlekek(max(ticket_generation - 1, 0)), material)
                    proof = prove_titlekey(relevant, plain)
                except (FixError, ValueError, OSError) as exc:
                    rejected_sources.add(f"signed recovery material: {exc}")
                    continue
                if proof.status == TitleKeyProofStatus.REJECTED:
                    rejected_sources.add(
                        "signed recovery material failed every readable proof")
                    continue
                accepted.setdefault(material, set()).add("signed NCA recovery")
                if proof.status == TitleKeyProofStatus.UNPROVABLE:
                    plan.warnings.append(
                        "signed NCA recovery supplied the titlekey, but this "
                        "RightsId has no independently readable titlekey proof")

            for ticket in matching_tickets:
                if failure := ticket_titlekey_failure(ticket):
                    rejected_sources.add(f"input ticket: {failure}")
                    continue
                try:
                    plain = ecb_decrypt(
                        keys.titlekek(max(ticket_generation - 1, 0)),
                        ticket.encrypted_titlekey)
                    proof = prove_titlekey(relevant, plain)
                except (FixError, ValueError, OSError) as exc:
                    rejected_sources.add(f"input ticket: {exc}")
                    continue
                if proof.status == TitleKeyProofStatus.PROVEN:
                    accepted.setdefault(ticket.encrypted_titlekey, set()).add(
                        "input ticket")
                else:
                    rejected_sources.add(
                        "input ticket titlekey "
                        + ("failed every readable proof"
                           if proof.status == TitleKeyProofStatus.REJECTED
                           else "has no independently readable proof"))

            has_personalized_ticket = any(
                ticket.titlekey_type == 1 for ticket in matching_tickets)
            if (has_personalized_ticket and title_keys is not None
                    and rights_id.lower() in title_keys.values):
                external = title_keys.values[rights_id.lower()]
                try:
                    plain = ecb_decrypt(
                        keys.titlekek(max(ticket_generation - 1, 0)), external)
                    proof = prove_titlekey(relevant, plain)
                except (FixError, ValueError, OSError) as exc:
                    rejected_sources.add(f"title.keys: {exc}")
                else:
                    if proof.status == TitleKeyProofStatus.PROVEN:
                        accepted.setdefault(external, set()).add("title.keys")
                    else:
                        rejected_sources.add(
                            "title.keys entry "
                            + ("failed every readable proof"
                               if proof.status == TitleKeyProofStatus.REJECTED
                               else "has no independently readable proof"))

            if len(accepted) > 1:
                plan.failures.append(
                    f"multiple distinct proven titlekeys for RightsId {rights_id}")
            elif not accepted:
                detail = ("; " + "; ".join(sorted(rejected_sources))
                          if rejected_sources else "")
                plan.failures.append(
                    f"{info.type_name} title-rights content has no acceptable "
                    f"ticket/titlekey{detail}")
            else:
                encrypted_titlekey = next(iter(accepted))
                ticket_dir.mkdir(parents=True, exist_ok=True)
                plan.ticket_path = ticket_dir / f"{rights_id}.tik"
                generated = make_public_ticket(
                    rights_id, encrypted_titlekey, ticket_generation)
                plan.ticket_path.write_bytes(generated)
                existing_bytes = {
                    ticket.path.read_bytes() for ticket in matching_tickets}
                if generated not in existing_bytes:
                    outcomes.append(Outcome.RESTORED)
                repaired_generations = sorted({
                    ticket.key_generation for ticket in matching_tickets
                    if ticket.encrypted_titlekey == encrypted_titlekey
                    and ticket.key_generation != ticket_generation
                })
                if repaired_generations:
                    shown = ", ".join(map(str, repaired_generations))
                    plan.warnings.append(
                        f"ticket generation repaired from {shown} to signed NCA "
                        f"generation {ticket_generation}")
    elif rights_id and info.type_name == "UPD":
        selection_failed = False
        try:
            existing_ticket, proof = matching_update_ticket(
                group, rights_id, output_headers, keys)
        except FixError as exc:
            plan.failures.append(str(exc))
            existing_ticket, proof = None, None
            selection_failed = True
        if existing_ticket is None and not selection_failed:
            ticket_failure = update_ticket_failure(None)
            if ticket_failure is not None:
                plan.failures.append(ticket_failure)
        elif existing_ticket is not None:
            ticket_dir.mkdir(parents=True, exist_ok=True)
            plan.ticket_path = ticket_dir / f"{rights_id}.tik"
            shutil.copy2(existing_ticket.path, plan.ticket_path)
            if proof is not None and proof.status == TitleKeyProofStatus.UNPROVABLE:
                plan.warnings.append(
                    "original UPD ticket accepted by Nintendo RSA signature; this "
                    "RightsId has no independently readable titlekey proof")
    elif group.tickets:
        plan.warnings.append(
            "orphan ticket omitted because no output NCA uses title rights")

    if plan.ticket_path is not None:
        if not default_cert.exists():
            plan.failures.append(f"pinned cert missing: {default_cert}")
        else:
            plan.cert_path = ticket_dir / f"{plan.ticket_path.stem}.cert"
            shutil.copy2(default_cert, plan.cert_path)
        payload_meta = read_meta_payload(plan.meta.output, keys)
        payload_entries = {entry.nca_id.lower(): entry
                           for entry in payload_meta.info.content_entries}
        for decision, header in zip(plan.content, output_headers):
            if header.rights_id != rights_id:
                continue
            digest = decision_hash(decision)
            entry = payload_entries.get(digest[:32].lower())
            exact = (entry is not None and entry.hash.lower() == digest.lower()
                     and entry.size == decision.output.stat().st_size)
            if not exact:
                plan.failures.append(
                    "staged CNMT does not exactly describe rights-bearing NCA: "
                    f"{decision.output.name}")

    if plan.failures:
        outcomes.append(Outcome.IMPOSSIBLE)
    plan.outcome = worst_outcome(outcomes)
    return plan


# --------------------------------------------------------------------------
# verification, publication

def verify_plan_integrity(plan: RepairPlan, keys: KeySet) -> None:
    if plan.meta is None:
        raise FixError("repair plan has no Meta NCA")
    meta = read_meta_payload(plan.meta.output, keys)
    content_by_id = {decision_hash(decision)[:32]: (decision, decision_hash(decision))
                     for decision in plan.content}
    standard_omitted = {entry.nca_id.lower() for entry in meta.info.content_entries
                        if is_standard_omitted_entry(meta.info, entry)}
    for entry in meta.info.content_entries:
        actual = content_by_id.get(entry.nca_id.lower())
        if actual is None:
            if entry.nca_id.lower() in standard_omitted:
                continue
            raise FixError(f"post-build CNMT references absent NCA: {entry.nca_id}.nca")
        decision, digest = actual
        if digest.lower() != entry.hash.lower():
            raise FixError(f"post-build CNMT hash mismatch: {decision.output.name}")
        if decision.output.stat().st_size != entry.size:
            raise FixError(f"post-build CNMT size mismatch: {decision.output.name}")

    output_rights = {header.rights_id for header in
                     (read_nca_header(item.output, keys) for item in plan.content)
                     if header.rights_id}
    if plan.ticket_path is None:
        if output_rights:
            raise FixError("post-build title-rights content has no ticket")
    else:
        ticket = parse_ticket(plan.ticket_path)
        if failure := ticket_titlekey_failure(ticket):
            raise FixError(f"post-build ticket rejected: {failure}")
        if output_rights != {ticket.rights_id.lower()}:
            raise FixError("post-build ticket RightsId does not match content NCAs")
        if plan.cert_path is None or \
                plan.cert_path.stem.lower() != ticket.rights_id.lower():
            raise FixError("post-build cert is absent or misnamed")

    failed = [item.output.name for item in plan.content + [plan.meta]
              if not item.verification.main_signature_valid]
    if failed:
        raise FixError(f"post-build signature failure: {', '.join(failed)}")


def verify_packed_output(path: Path, names: list[str], sizes: list[int],
                         expected_hashes: list[str], keys: KeySet) -> None:
    """Bounded readback: every NCA header, and complete Meta/ticket/cert bytes.

    Large content bodies are hashed during the packing copy, not reread here.
    """
    table = read_pfs0_table(path)
    if ([entry.name for entry in table] != names
            or [entry.size for entry in table] != sizes):
        raise FixError("post-build PFS0 order/name/size verification failed")
    if table and table[-1].offset + table[-1].size != path.stat().st_size:
        raise FixError("post-build PFS0 contains unexpected trailing bytes")
    with path.open("rb") as packed:
        for entry, expected in zip(table, expected_hashes):
            packed.seek(entry.offset)
            if entry.name.lower().endswith(".nca"):
                encrypted = packed.read(min(NCA_HEADER_SIZE, entry.size))
                if len(encrypted) != NCA_HEADER_SIZE:
                    raise FixError(f"post-build NCA header truncated: {entry.name}")
                raw = aes_xts_crypt(encrypted, keys.header_key, decrypt=True)
                if (raw[0x200:0x204] != b"NCA3"
                        or not nca_main_signature_valid(raw)):
                    raise FixError(f"post-build NCA header/signature invalid: {entry.name}")
                if struct.unpack_from("<Q", raw, 0x208)[0] != entry.size:
                    raise FixError(f"post-build NCA header size mismatch: {entry.name}")
                if not entry.name.lower().endswith(".cnmt.nca"):
                    continue
            packed.seek(entry.offset)
            digest = hashlib.sha256()
            remaining = entry.size
            while remaining:
                chunk = packed.read(min(remaining, 8 * 1024 * 1024))
                if not chunk:
                    raise FixError(f"post-build member truncated: {entry.name}")
                digest.update(chunk)
                remaining -= len(chunk)
            if digest.hexdigest() != expected.lower():
                raise FixError(f"post-build member hash mismatch: {entry.name}")


def publish_atomic(candidate: Path, destination: Path, overwrite: bool,
                   verify: Callable[[Path], None] | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise FixError(f"output exists: {destination.name} (use --overwrite)")
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        shutil.copy2(candidate, temporary)
        if verify is not None:
            verify(temporary)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def archive_successful_source(source: Path, success_dir: Path) -> tuple[Path, bool]:
    source = source.resolve()
    success_dir = success_dir.resolve()
    if source.parent == success_dir:
        return source, False
    success_dir.mkdir(parents=True, exist_ok=True)
    destination = success_dir / source.name
    counter = 0
    while destination.exists():
        counter += 1
        destination = success_dir / f"{source.stem}.{counter}{source.suffix}"
    return Path(shutil.move(str(source), str(destination))), True


def execute_plan(plan: RepairPlan, group_work: Path, out_dir: Path,
                 keys: KeySet, overwrite: bool) -> Path:
    if not plan.publishable:
        raise FixError("repair plan is not publishable")
    verify_plan_integrity(plan, keys)
    files = [decision.output for decision in plan.content]
    files.append(plan.meta.output)
    if plan.ticket_path is not None:
        files.append(plan.ticket_path)
    if plan.cert_path is not None:
        files.append(plan.cert_path)
    candidate = group_work / "candidate.nsp"
    names = [decision_hash(item)[:32] + ".nca" for item in plan.content]
    names.append(decision_hash(plan.meta)[:32] + ".cnmt.nca")
    names.extend(path.name for path in files[len(names):])
    expected_hashes = [decision_hash(item) for item in plan.content + [plan.meta]]
    for extra in files[len(expected_hashes):]:
        with extra.open("rb") as handle:
            expected_hashes.append(hashlib.file_digest(handle, "sha256").hexdigest())
    sizes = [item.stat().st_size for item in files]
    write_pfs0(candidate, files, names, expected_hashes)
    def verify(path: Path) -> None:
        verify_packed_output(path, names, sizes, expected_hashes, keys)
    verify(candidate)
    destination = out_dir / plan.output_name
    publish_atomic(candidate, destination, overwrite, verify)
    return destination


def group_output_dir(out_dir: Path, group: PackageGroup,
                     groups: tuple[PackageGroup, ...]) -> Path:
    info = group.meta.info
    identity = (info.title_id, info.version, info.title_type)
    variants = {item.meta_artifact.sha256 for item in groups
                if (item.meta.info.title_id, item.meta.info.version,
                    item.meta.info.title_type) == identity}
    if len(variants) > 1:
        # No invented ingest labels and no replacement of a sibling variant,
        # even with --overwrite. These require an explicit operator choice.
        return out_dir / "fixnsp-variants" / group.meta_artifact.sha256
    return out_dir


def display_outcome(outcome: Outcome) -> str:
    return {
        Outcome.PRESERVE: "PRESERVED",
        Outcome.RESTORED: "RESTORED",
        Outcome.IMPOSSIBLE: "REJECTED",
    }[outcome]


def display_repair_reason(reason: str) -> str:
    match = re.fullmatch(
        r"title-rights and crypto-generation restoration (\d+) -> (\d+) "
        r"\(RightsId title ([0-9a-fA-F]{16})\)", reason)
    if match is None:
        return reason
    previous, current, title_id = match.groups()
    generation = (f"key generation unchanged at {current}"
                  if previous == current
                  else f"key generation {previous} -> {current}")
    return f"restored title rights for {title_id.upper()}; {generation}"


def is_inventory_repair_message(message: str) -> bool:
    return message.startswith("restored signed NCA candidate:")


def print_finding(message: str, *, indent: str = "  ") -> None:
    if is_inventory_repair_message(message):
        return
    lowered = message.lower()
    if ("cnmt xml sidecar" in lowered
            or "type-6 delta fragment" in lowered or "orphan ticket" in lowered
            or "no independently readable titlekey proof" in lowered):
        label = "notice"
    elif ("ticket generation repaired" in lowered
          or message.startswith("standardized signed Meta NCA:")):
        label = "repair"
    else:
        label = "warning"
    print(f"{indent}{label:<9} {message}")


def decision_rights_id(decision: NcaDecision) -> str | None:
    if decision.rewrite is not None and decision.rewrite.rights_id:
        return decision.rewrite.rights_id.lower()
    return decision.source.header.rights_id


def rejected_ticket_reason(ticket: TicketInfo) -> str:
    if failure := ticket_titlekey_failure(ticket):
        return failure
    if ticket.signature_class == "FF":
        return "FF/fake-signed ticket"
    if not ticket.signature_valid:
        return "Nintendo RSA signature invalid"
    return "titlekey failed the signed NCA decrypt probe"


def print_ticket_status(plan: RepairPlan) -> None:
    info = plan.group.meta.info
    if plan.ticket_path is not None:
        action = ("preserved original signed common ticket"
                  if info.type_name == "UPD"
                  else "generated standardized common ticket")
        print(f"    ticket    {action}: {plan.ticket_path.name}")
        return

    missing_update_ticket = any(
        failure == "UPD title-rights content has no matching original ticket"
        for failure in plan.failures)
    if not missing_update_ticket:
        return

    rights_ids = sorted({rights_id for decision in plan.content
                         if (rights_id := decision_rights_id(decision))})
    if len(rights_ids) != 1:
        print("    ticket    no unambiguous content RightsId")
        return
    rights_id = rights_ids[0]
    matches = [ticket for ticket in plan.group.tickets
               if ticket.rights_id.lower() == rights_id]
    if not plan.group.tickets:
        print(f"    ticket    no input ticket found for RightsId {rights_id.upper()}")
    elif not matches:
        count = len(plan.group.tickets)
        print(f"    ticket    {count} input ticket(s); none match RightsId "
              f"{rights_id.upper()}")
    else:
        reasons = sorted({rejected_ticket_reason(ticket) for ticket in matches})
        print(f"    ticket    {len(matches)} matching ticket(s) rejected: "
              f"{'; '.join(reasons)}")


def print_plan(plan: RepairPlan) -> None:
    decisions = plan.content + ([plan.meta] if plan.meta else [])
    signed = sum(item.verification.main_signature_valid for item in decisions)
    repaired = [item for item in decisions if item.outcome == Outcome.RESTORED]
    if signed == len(decisions):
        signature_status = "all Nintendo signatures valid"
    else:
        signature_status = f"{signed}/{len(decisions)} Nintendo signatures valid"
    print(f"    ncas      {len(plan.content)} content + "
          f"{1 if plan.meta else 0} Meta; {signature_status}; "
          f"{len(repaired)} repaired")
    if plan.gamecard_variant:
        print("    variant   GAMECARD")
    for decision in repaired:
        print(f"    repair    {decision.output.name}: "
              f"{display_repair_reason(decision.reason)}")
    print_ticket_status(plan)
    for warning in plan.warnings:
        print_finding(warning, indent="    ")
    for failure in plan.failures:
        print(f"    error     {failure}")


# --------------------------------------------------------------------------
# entry point

def discover_inputs(intake: Path) -> list[Path]:
    if not intake.is_dir():
        return []
    return sorted(path for path in intake.iterdir()
                  if (path.is_file() and path.suffix.lower() in
                      {".nsp", ".nsz", ".xci", ".xcz"})
                  or (path.is_dir() and path.suffix.lower() == ".nsp"))


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    intake = DROPZONE / "fixnsp"
    parser = argparse.ArgumentParser(
        prog="fixnsp",
        description="Signature-gated digital-content repair (see fixnsp.md).")
    parser.add_argument("input", nargs="*", type=Path)
    parser.add_argument("--intake", type=Path, default=intake)
    # outputs land at the dropzone ROOT: exactly where the digital ingest
    # scans, so fixnsp -> ingest needs no manual move in between.
    parser.add_argument("--out-dir", type=Path, default=DROPZONE)
    parser.add_argument("--work-dir", type=Path, default=DROPZONE / "fixnsp-work")
    parser.add_argument("--success-dir", type=Path,
                        default=DROPZONE / "fixnsp-success")
    parser.add_argument("--titledb", type=Path, default=DB_DIR / "titledb")
    parser.add_argument("--keys", type=Path,
                        default=Path.home() / ".switch" / "prod.keys")
    parser.add_argument("--title-keys", type=Path,
                        default=Path.home() / ".switch" / "title.keys")
    parser.add_argument("--cert", type=Path, default=DEFAULT_CERT)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--keep-work", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    args = parse_args(argv)
    if not args.keys.exists():
        print(f"error     prod.keys not found: {args.keys}", file=sys.stderr)
        return 2
    inputs = list(args.input) if args.input else discover_inputs(args.intake)
    if not inputs:
        print(f"no NSP/NSZ/XCI/XCZ inputs found in {args.intake}")
        return 0

    protected_sources = tuple((source.resolve(), source.is_dir()) for source in inputs)
    if len({path for path, _ in protected_sources}) != len(protected_sources):
        print("error     the same input was supplied more than once", file=sys.stderr)
        return 2
    for label, root in (("work", args.work_dir), ("output", args.out_dir),
                        ("success", args.success_dir)):
        resolved_root = root.resolve()
        for protected, is_directory in protected_sources:
            if (resolved_root == protected
                    or (is_directory and protected in resolved_root.parents)):
                print(f"error     {label} directory overlaps input source: {root}",
                      file=sys.stderr)
                return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    keys = KeySet.load(args.keys)
    title_keys = TitleKeys.load(args.title_keys)
    knowledge = CnmtKnowledgeBase(args.titledb / "cnmts.json")
    if knowledge.load_error:
        print_finding("CNMTDB unavailable; continuing without its repair "
                      f"proposals: {knowledge.load_error}", indent="")
    firmware_catalog = load_firmware_catalog(DB_DIR / "firmware_versions.json")
    attempted = completed = failed = source_failures = archive_failures = 0
    source_complete = source_partial = source_rejected = 0
    for source_index, source in enumerate(inputs, 1):
        print(f"\nInput {source_index}/{len(inputs)}: {source.name}")
        try:
            container_type, extract_dir, input_warnings = prepare_input(
                source, args.work_dir, args.keep_work)
            print(f"  input     {container_type}")
            for warning in input_warnings:
                print_finding(warning)
            inspection = inspect_container(extract_dir, container_type, keys,
                                           knowledge, firmware_catalog)
            discovery = discover_groups(source, container_type, inspection, keys)
        except (FixError, OSError, ValueError, subprocess.SubprocessError) as exc:
            source_failures += 1
            source_rejected += 1
            print(f"  error     {exc}")
            print("  source    REJECTED — no output written; input retained")
            continue

        for warning in (*inspection.warnings, *discovery.warnings):
            print_finding(warning)
        source_errors = (*inspection.errors, *discovery.errors)
        source_has_errors = bool(source_errors)
        if source_has_errors:
            source_failures += 1
            for detail in source_errors:
                print(f"  error     source inventory: {detail}")
        print(f"  titles    {len(discovery.groups)} readable CNMT group(s), "
              f"{len(discovery.failed_attempts)} unreadable")
        source_attempted = source_completed = source_failed = 0
        for detail in discovery.failed_attempts:
            attempted += 1
            failed += 1
            source_attempted += 1
            source_failed += 1
            print(f"  error     unreadable Meta/CNMT: {detail}")
        if not discovery.groups and not discovery.failed_attempts:
            if not source_has_errors:
                source_failures += 1
            source_rejected += 1
            print("  error     container contains no readable Meta/CNMT NCA")
            print("  source    REJECTED — no output written; input retained")
            continue

        source_work = args.work_dir / source.name
        for index, group in enumerate(discovery.groups, 1):
            attempted += 1
            source_attempted += 1
            try:
                info = group.meta.info
                print(f"\n  [{index}/{len(discovery.groups)}] "
                      f"{info.title_id.upper()} v{info.version} {info.type_name}")
                group_work = source_work / f"group-{index:03d}"
                plan = build_repair_plan(
                    group, group_work, keys, args.cert, title_keys)
                print_plan(plan)
                if not plan.publishable:
                    failed += 1
                    source_failed += 1
                    print("    result    REJECTED — no output written")
                    continue
                if args.inspect_only:
                    verify_plan_integrity(plan, keys)
                    print(f"    result    {display_outcome(plan.outcome)} — "
                          "inspect-only; no output written")
                else:
                    output_dir = group_output_dir(args.out_dir, group, discovery.groups)
                    if output_dir != args.out_dir:
                        print("    warning   distinct signed Meta variants share this "
                              "release; staged separately under fixnsp-variants for "
                              "manual selection")
                    destination = execute_plan(plan, group_work, output_dir,
                                               keys, args.overwrite)
                    print(f"    result    {display_outcome(plan.outcome)} -> "
                          f"{destination}")
                completed += 1
                source_completed += 1
            except (FixError, OSError, ValueError, subprocess.SubprocessError) as exc:
                failed += 1
                source_failed += 1
                print(f"    result    REJECTED — {exc}; no output written")

        source_archived = False
        if (not args.inspect_only and source_attempted > 0
                and source_completed == source_attempted and source_failed == 0
                and not source_has_errors):
            try:
                archived, moved = archive_successful_source(source, args.success_dir)
                source_archived = True
                print(f"  archive   {'moved' if moved else 'already archived'}: "
                      f"{archived}")
            except (OSError, ValueError) as exc:
                archive_failures += 1
                print(f"  error     successful source could not be archived: {exc}")

        if args.inspect_only:
            if (source_attempted > 0 and source_completed == source_attempted
                    and source_failed == 0 and not source_has_errors):
                source_complete += 1
                print(f"  source    VERIFIED — {source_completed} group(s); "
                      "input unchanged")
            elif source_completed:
                source_partial += 1
                print(f"  source    PARTIAL — {source_completed} group(s) verified, "
                      f"{source_failed} rejected; input unchanged")
            else:
                source_rejected += 1
                print("  source    REJECTED — no group verified; input unchanged")
        elif source_archived:
            source_complete += 1
            print(f"  source    COMPLETE — {source_completed} output(s) published; "
                  "input archived")
        elif source_completed:
            source_partial += 1
            print(f"  source    PARTIAL — {source_completed} output(s) published, "
                  f"{source_failed} rejected; input retained")
        else:
            source_rejected += 1
            print("  source    REJECTED — no output written; input retained")

    print(f"\nSummary: {len(inputs)} source(s) — {source_complete} complete, "
          f"{source_partial} partial, {source_rejected} rejected")
    print(f"         {attempted} group(s) — {completed} completed, "
          f"{failed} rejected")
    if source_failures or archive_failures:
        print(f"         processing errors: {source_failures}; "
              f"archive errors: {archive_failures}")
    return 1 if failed or source_failures or archive_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
