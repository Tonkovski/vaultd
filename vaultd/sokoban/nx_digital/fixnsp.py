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
Meta scalar candidates; when it is silent, db/nx_digital/firmware_versions.json
(a JSON list of released-firmware requiredSystemVersion integers) bounds the
fallback axis. Neither database can authorize output.
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
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

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

TITLE_TYPE_NAMES = {0x80: "BASE", 0x81: "UPD", 0x82: "DLC"}
NCA_CONTENT_NAMES = {0: "PROGRAM", 1: "META", 2: "CONTROL", 3: "MANUAL",
                     4: "DATA", 5: "PUBLICDATA"}
TITLE_BEARING_CNMT_TYPES = {1, 2}
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


def read_hfs0_table(path: Path, base_offset: int, container_size: int) -> list[Hfs0Entry]:
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
        if absolute < data_offset or stop < absolute or stop > container_end:
            raise FixError(f"HFS0 file extends past its container: {name}")
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


def extract_xci(path: Path, out_dir: Path) -> None:
    """In-house XCI extraction: secure and normal partitions, hash-verified.
    Trimmed and untrimmed cards both accepted; the firmware update partition
    is ignored by doctrine."""
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(0x200)
    if len(header) != 0x200 or header[0x100:0x104] != XCI_HEAD_MAGIC:
        raise FixError("no valid XCI HEAD header")
    root_offset = struct.unpack_from("<Q", header, 0x130)[0]
    if root_offset < 0x200 or root_offset >= file_size:
        raise FixError("invalid XCI root HFS0 offset")
    root_entries = read_hfs0_table(path, root_offset, file_size - root_offset)
    if not root_entries:
        raise FixError("XCI root HFS0 is empty")
    if not {entry.name.casefold() for entry in root_entries}.issubset(
            {"update", "logo", "normal", "secure"}):
        raise FixError("XCI root HFS0 has unknown partitions")
    verify_hfs0_entry_hashes(path, root_entries)

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with path.open("rb") as source:
        for partition_name in ("secure", "normal"):
            root_entry = next((entry for entry in root_entries
                               if entry.name.casefold() == partition_name), None)
            if root_entry is None:
                continue
            entries = read_hfs0_table(path, root_entry.offset, root_entry.size)
            verify_hfs0_entry_hashes(path, entries)
            if not entries:
                continue
            partition_dir = out_dir / partition_name
            partition_dir.mkdir()
            for entry in entries:
                source.seek(entry.offset)
                with (partition_dir / entry.name).open("wb") as output:
                    copy_exact(source, output, entry.size)


def pfs0_string_table_size(raw_size: int, file_count: int) -> int:
    """The nxdumptool rule: align the full header to 0x20; when already
    aligned, add a full 0x20 block."""
    unpadded_header_size = 0x10 + file_count * 0x18 + raw_size
    padding_size = PFS0_HEADER_ALIGNMENT - (unpadded_header_size % PFS0_HEADER_ALIGNMENT)
    return raw_size + padding_size


def write_pfs0(path: Path, files: list[Path]) -> None:
    names = [item.name.encode("utf-8") for item in files]
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
        for item, name_offset in zip(files, name_offsets):
            size = item.stat().st_size
            output.write(struct.pack("<QQII", relative, size, name_offset, 0))
            relative += size
        output.write(strings)
        for item in files:
            with item.open("rb") as source:
                shutil.copyfileobj(source, output, 8 * 1024 * 1024)


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
    if bytes(raw[0x200:0x204]) not in {b"NCA2", b"NCA3"}:
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
    if len(raw) != NCA_HEADER_SIZE or bytes(raw[0x200:0x204]) not in {b"NCA2", b"NCA3"}:
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
    encrypted_titlekey: bytes
    key_generation: int
    signature_class: str
    signature_valid: bool


def parse_ticket(path: Path) -> TicketInfo:
    data = path.read_bytes()
    if len(data) < 0x2C0:
        raise FixError(f"ticket too small: {path.name}")
    signature = data[4:0x104]
    signature_class = "FF" if signature == b"\xFF" * 0x100 else "NONFF"
    return TicketInfo(path=path, rights_id=data[0x2A0:0x2B0].hex(),
                      encrypted_titlekey=data[0x180:0x190],
                      key_generation=data[0x285],
                      signature_class=signature_class,
                      signature_valid=ticket_signature_valid(data))


def update_ticket_failure(ticket: TicketInfo | None) -> str | None:
    if ticket is None:
        return "UPD title-rights content has no matching original ticket"
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
    if ticket.rights_id.lower() != (header.rights_id or "").lower():
        raise FixError(f"ticket RightsId does not match NCA: {header.path.name}")
    if ticket.key_generation != header.key_generation:
        raise FixError(
            f"ticket/NCA generation mismatch for {header.path.name}: "
            f"ticket={ticket.key_generation}, NCA={header.key_generation}")
    return ecb_decrypt(keys.titlekek(max(ticket.key_generation - 1, 0)),
                       ticket.encrypted_titlekey)


def probe_titlekey(header: NcaHeader, plain_titlekey: bytes) -> bool:
    """The titlekey probe (fixnsp.md step 8): decrypt one hash region with the
    candidate key and compare against the master hash stored in the signed
    header. HierarchicalSha256 sections hash their hash table; IVFC sections
    hash their first level. True only on an exact cryptographic match."""
    for section in header.sections:
        if section.crypto_type != 3:
            continue
        fs_offset = 0x400 + section.index * 0x200
        if section.fs_type == 2:
            master = bytes(header.raw[fs_offset + 0x08:fs_offset + 0x28])
            hash_offset, hash_size = struct.unpack_from(
                "<QQ", header.raw, fs_offset + 0x30)
            if not hash_size or hash_size > 0x400000 or \
                    hash_offset + hash_size > section.size:
                continue
            region_offset, region_size = hash_offset, hash_size
        elif section.fs_type == 3:
            info = fs_offset + 0x08
            if bytes(header.raw[info:info + 4]) != IVFC_MAGIC:
                continue
            master = bytes(header.raw[info + 0xC0:info + 0xE0])
            level_offset, level_size = struct.unpack_from(
                "<QQ", header.raw, info + 0x10)
            if not level_size or level_size > 0x400000 or \
                    level_offset + level_size > section.size:
                continue
            region_offset, region_size = level_offset, level_size
        else:
            continue
        aligned_start = region_offset & ~0xF
        shift = region_offset - aligned_start
        with header.path.open("rb") as handle:
            handle.seek(section.offset + aligned_start)
            encrypted = handle.read(shift + region_size)
        if len(encrypted) != shift + region_size:
            continue
        plain = aes_ctr_crypt(encrypted, plain_titlekey, section.counter,
                              section.offset + aligned_start)
        digest = hashlib.sha256(plain[shift:shift + region_size]).digest()
        return hmac.compare_digest(digest, master)
    raise FixError(f"no probe-able hash region in {header.path.name}")


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
    if title_type in (0x80, 0x81) and len(extended) >= 0x0C:
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

    def _load(self) -> dict[str, object]:
        if self._records is None:
            if not self.path.exists():
                self._records = {}
            else:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                self._records = loaded if isinstance(loaded, dict) else {}
        return self._records

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


def memory_pfs0_first_file(data: bytes) -> tuple[int, int, str]:
    if len(data) < 0x10 or data[:4] != PFS0_MAGIC:
        raise FixError("inner Meta NCA data layer is not PFS0")
    count, string_size, reserved = struct.unpack_from("<III", data, 4)
    if count != 1 or reserved != 0:
        raise FixError(f"expected one CNMT file inside Meta NCA, found {count}")
    table_end = 0x10 + count * 0x18
    strings_end = table_end + string_size
    if strings_end > len(data):
        raise FixError("truncated inner PFS0")
    offset, size, name_offset, entry_reserved = struct.unpack_from("<QQII", data, 0x10)
    if entry_reserved or name_offset >= string_size:
        raise FixError("invalid inner PFS0 entry")
    strings = data[table_end:strings_end]
    name_end = strings.find(b"\0", name_offset)
    if name_end < 0:
        raise FixError("inner PFS0 name is not terminated")
    name = safe_member_name(strings[name_offset:name_end], 0, "PFS0")
    start = strings_end + offset
    end = start + size
    if end > len(data):
        raise FixError("inner CNMT extends past Meta NCA data layer")
    return start, end, name


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


def read_meta_payload(path: Path, keys: KeySet) -> MetaPayload:
    header = read_nca_header(path, keys)
    if header.content_type != 1 or len(header.sections) != 1:
        raise FixError(f"expected an ordinary single-section Meta NCA: {path.name}")
    section = header.sections[0]
    hash_layout = read_meta_hash_layout(header, section)
    plain = read_nca_section(header, section, keys)
    validate_meta_hash_layers(header, section, plain)
    data_offset = hash_layout.data_offset
    data_end = data_offset + hash_layout.data_size
    if plain[data_offset:data_offset + 4] != PFS0_MAGIC:
        raise FixError(f"Meta NCA data layer is not PFS0: {path.name}")
    cnmt_start, cnmt_end, cnmt_name = memory_pfs0_first_file(plain[data_offset:data_end])
    cnmt_start += data_offset
    cnmt_end += data_offset
    payload = plain[cnmt_start:cnmt_end]
    return MetaPayload(header=header, section=section, section_plain=plain,
                       hash_layout=hash_layout, data_offset=data_offset,
                       cnmt_start=cnmt_start, cnmt_end=cnmt_end,
                       cnmt_name=cnmt_name, payload=payload,
                       info=parse_cnmt_payload(payload))


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

def restore_title_rights_nca(source: Path, out_dir: Path, keys: KeySet,
                             source_hash: str | None = None) -> NcaRewrite:
    header = read_nca_header(source, keys)
    if header.has_title_rights:
        raise FixError(f"NCA already has title rights: {source.name}")
    if header.is_gamecard or header.distribution_type != 0:
        raise FixError(f"Gamecard NCA cannot establish an eShop titlekey: {source.name}")
    if header.content_type not in TITLE_BEARING_NCA_TYPES:
        raise FixError(f"NCA type is not eligible for title-rights restoration: {source.name}")
    if header.decrypted_key_area is None:
        raise FixError(f"NCA key area is unavailable: {source.name}")
    titlekey = recoverable_key_area_titlekey(header.decrypted_key_area)
    if titlekey is None:
        raise FixError(f"ambiguous NCA key-area layout: {source.name}")

    rights_generation = expected_rights_id_generation(header.key_generation)
    rights_id = f"{header.title_id}{rights_generation:016x}".lower()
    encrypted_titlekey = ecb_encrypt(keys.titlekek(header.master_key_index), titlekey)
    raw = bytearray(header.raw)
    raw[0x230:0x240] = bytes.fromhex(rights_id)
    raw[0x300:0x340] = b"\0" * 0x40

    out_dir.mkdir(parents=True, exist_ok=True)
    temporary = out_dir / source.name
    shutil.copy2(source, temporary)
    write_nca_header(temporary, raw, keys)
    old_hash = source_hash or sha256_file(source)
    new_hash = sha256_file(temporary)
    destination = out_dir / f"{new_hash[:32]}.nca"
    if destination != temporary:
        if destination.exists():
            destination.unlink()
        temporary.rename(destination)
    return NcaRewrite(source=source, output=destination, old_hash=old_hash,
                      old_id=old_hash[:32], new_hash=new_hash, new_id=new_hash[:32],
                      rights_id=rights_id, encrypted_titlekey=encrypted_titlekey)


def restore_gamecard_distribution_nca(source: Path, out_dir: Path, keys: KeySet,
                                      source_hash: str | None = None) -> NcaRewrite | None:
    header = read_nca_header(source, keys)
    if (header.has_title_rights or header.distribution_type != 0
            or header.decrypted_key_area is None):
        return None
    raw = bytearray(header.raw)
    raw[0x204] = 1
    if not nca_main_signature_valid(raw):
        return None
    old_hash = source_hash or sha256_file(source)
    out_dir.mkdir(parents=True, exist_ok=True)
    temporary = out_dir / source.name
    shutil.copy2(source, temporary)
    write_nca_header(temporary, raw, keys)
    new_hash = sha256_file(temporary)
    suffix = ".cnmt.nca" if header.content_type == 1 else ".nca"
    destination = out_dir / f"{new_hash[:32]}{suffix}"
    if destination != temporary:
        if destination.exists():
            destination.unlink()
        temporary.rename(destination)
    return NcaRewrite(source=source, output=destination, old_hash=old_hash,
                      old_id=old_hash[:32], new_hash=new_hash, new_id=new_hash[:32])


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


@dataclass(frozen=True)
class ContentScope:
    path: Path
    artifacts: dict[str, NcaArtifact]


@dataclass(frozen=True)
class InspectionResult:
    scopes: tuple[ContentScope, ...]
    warnings: tuple[str, ...]
    failed_meta_attempts: tuple[str, ...]


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
# noncanonical recovery: the bounded enumeration

def recover_noncanonical_nca(source: Path, source_hash: str, expected_id: str,
                             header: NcaHeader, recovery_dir: Path, keys: KeySet,
                             knowledge: CnmtKnowledgeBase | None,
                             firmware_catalog: tuple[int, ...]) -> NcaArtifact | None:
    if header.has_title_rights or header.decrypted_key_area is None:
        return None
    titlekey = recoverable_key_area_titlekey(header.decrypted_key_area)
    candidates: list[tuple[bytearray, str | None, bytes | None, str]] = []
    if header.distribution_type == 0:
        gamecard = bytearray(header.raw)
        gamecard[0x204] = 1
        candidates.append((gamecard, None, None, "gamecard distribution restoration"))
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
        candidates.append((rightless, None, None,
                           f"crypto generation {header.key_generation} -> {generation}"))
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
            candidates.append((
                rights_bearing, rights_id, encrypted_titlekey,
                "title-rights and crypto-generation restoration "
                f"{header.key_generation} -> {generation} "
                f"(RightsId title {rights_id[:16].upper()})"))

    recovery_dir.mkdir(parents=True, exist_ok=True)
    probe = recovery_dir / f".{source.name}.candidate"
    matches: list[tuple[bytearray, str, str | None, bytes | None, str, bytes | None]] = []
    try:
        shutil.copy2(source, probe)
        for raw, rights_id, encrypted_titlekey, reason in candidates:
            if not nca_main_signature_valid(raw):
                continue
            write_nca_header(probe, raw, keys)
            digest = sha256_file(probe)
            if digest[:32].lower() == expected_id.lower():
                matches.append((raw, digest, rights_id, encrypted_titlekey, reason, None))

        if not matches and header.content_type == 1:
            meta = read_meta_payload(source, keys)
            scalar_sets: list[tuple[dict[str, int], str]] = []
            if knowledge is not None:
                db_candidates = knowledge.scalar_candidates(meta.info)
                if db_candidates:
                    scalar_sets.append((db_candidates, "CNMTDB candidate"))
            if not scalar_sets and firmware_catalog and \
                    "requiredSystemVersion" in meta.info.field_offsets:
                for value in firmware_catalog:
                    if value != meta.info.required_system_version:
                        scalar_sets.append(
                            ({"requiredSystemVersion": value}, "firmware-catalog candidate"))
            section_key = nca_section_key(meta.header, keys)
            for scalar_candidates, origin in scalar_sets:
                patched_payload, changes = patch_cnmt_scalar_fields(
                    meta.payload, meta.info, scalar_candidates)
                scalar_reason = f"{origin} " + ", ".join(changes)
                for raw, rights_id, encrypted_titlekey, reason in candidates:
                    meta_plain, meta_raw = rebuild_meta_layers(meta, patched_payload, raw)
                    if not nca_main_signature_valid(meta_raw):
                        continue
                    write_nca_section(probe, meta.section, meta_plain, section_key)
                    write_nca_header(probe, meta_raw, keys)
                    digest = sha256_file(probe)
                    if digest[:32].lower() != expected_id.lower():
                        continue
                    matches.append((meta_raw, digest, rights_id, encrypted_titlekey,
                                    f"{reason}; {scalar_reason}", meta_plain))
                if matches:
                    break
    finally:
        probe.unlink(missing_ok=True)

    if len(matches) != 1:
        return None
    raw, digest, rights_id, encrypted_titlekey, reason, restored_plain = matches[0]
    destination = recovery_dir / source.name
    shutil.copy2(source, destination)
    if restored_plain is not None:
        meta = read_meta_payload(source, keys)
        write_nca_section(destination, meta.section, restored_plain,
                          nca_section_key(meta.header, keys))
    write_nca_header(destination, raw, keys)
    restored_header = read_nca_header(destination, keys)
    final = NcaVerification(destination, nca_main_signature_valid(restored_header.raw))
    if not final.main_signature_valid:
        raise FixError(f"restored NCA failed final Nintendo main signature: {source.name}")
    validate_rights_id_generation(restored_header)
    rewrite = NcaRewrite(source=source, output=destination, old_hash=source_hash,
                         old_id=source_hash[:32], new_hash=digest, new_id=digest[:32],
                         rights_id=rights_id, encrypted_titlekey=encrypted_titlekey)
    return NcaArtifact(path=destination, header=restored_header, verification=final,
                       sha256=digest, nca_id=digest[:32], recovery=rewrite,
                       recovery_reason=reason)


# --------------------------------------------------------------------------
# intake / inspection / discovery

# nsz via `python -c`, never its .exe shim (breaks multiprocessing spawn on
# Windows under redirected standard handles).
_NSZ_BOOTSTRAP = "import sys; from nsz import main; sys.argv[0] = 'nsz'; main()"


def decompress_nsz(source: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-c", _NSZ_BOOTSTRAP, "-D", "--machine-readable",
         "-o", str(out_dir), str(source)],
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
    parts = sorted(item for item in source_dir.iterdir()
                   if item.is_file() and re.fullmatch(r"\d{2}", item.name))
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
        extract_xci(xci, extract_dir)
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
                 firmware_catalog: tuple[int, ...]
                 ) -> tuple[dict[str, NcaArtifact], list[str], list[str]]:
    artifacts: dict[str, NcaArtifact] = {}
    warnings: list[str] = []
    failed_meta_attempts: list[str] = []
    ambiguous_ids: set[str] = set()
    recovery_dir = scope_path.parent / f"{scope_path.name}-header-recovery"

    def register(artifact: NcaArtifact, origin_name: str) -> None:
        if artifact.nca_id in ambiguous_ids:
            warnings.append(f"ambiguous duplicate content id left unused: {origin_name}")
            return
        existing = artifacts.get(artifact.nca_id)
        if existing is not None:
            if existing.sha256 == artifact.sha256:
                warnings.append(f"duplicate NCA copy left unused: {origin_name}")
            else:
                artifacts.pop(artifact.nca_id)
                ambiguous_ids.add(artifact.nca_id)
                warnings.append("content-id collision left unused: "
                                f"{existing.path.name}, {origin_name}")
            return
        artifacts[artifact.nca_id] = artifact

    for path in sorted(scope_path.rglob("*.nca")):
        try:
            digest = sha256_file(path)
            digest_id = digest[:32]
            header = read_nca_header(path, keys)
        except (FixError, OSError, ValueError) as exc:
            detail = f"unreadable NCA left unused: {path.name}: {exc}"
            (failed_meta_attempts if path.name.lower().endswith(".cnmt.nca")
             else warnings).append(detail)
            continue
        verification = NcaVerification(path, nca_main_signature_valid(header.raw))
        filename_id = path.stem.split(".", 1)[0].lower()
        if filename_id == digest_id:
            register(NcaArtifact(path, header, verification, digest, digest_id),
                     path.name)
            continue
        if verification.main_signature_valid:
            canonical_name = (f"{digest_id}.cnmt.nca" if header.content_type == 1
                              else f"{digest_id}.nca")
            recovery_dir.mkdir(parents=True, exist_ok=True)
            canonical_path = recovery_dir / canonical_name
            shutil.copy2(path, canonical_path)
            canonical_header = read_nca_header(canonical_path, keys)
            warnings.append(f"normalized signed NCA wrapper: {path.name} -> {canonical_name}")
            register(NcaArtifact(canonical_path, canonical_header,
                                 NcaVerification(canonical_path, True),
                                 digest, digest_id), path.name)
            continue
        recovered = None
        if re.fullmatch(r"[0-9a-f]{32}", filename_id):
            try:
                recovered = recover_noncanonical_nca(
                    path, digest, filename_id, header, recovery_dir, keys,
                    knowledge, firmware_catalog)
            except (FixError, OSError, ValueError):
                recovered = None
        if recovered is None:
            detail = (f"noncanonical NCA wrapper left unused: {path.name} "
                      f"should start {digest_id}")
            (failed_meta_attempts if header.content_type == 1 else warnings).append(detail)
            continue
        warnings.append(f"restored signed NCA identity: {path.name} "
                        f"({recovered.recovery_reason})")
        register(recovered, path.name)
    return artifacts, warnings, failed_meta_attempts


def inspect_container(extract_dir: Path, container_type: str, keys: KeySet,
                      knowledge: CnmtKnowledgeBase | None,
                      firmware_catalog: tuple[int, ...]) -> InspectionResult:
    scopes: list[ContentScope] = []
    warnings: list[str] = []
    failed_meta_attempts: list[str] = []
    if container_type in {"XCI", "XCZ"} and (extract_dir / "update").is_dir():
        warnings.append("XCI update partition left untouched")
    for scope_path in content_scope_paths(extract_dir, container_type):
        artifacts, scope_warnings, scope_failures = inspect_ncas(
            scope_path, keys, knowledge, firmware_catalog)
        warnings.extend(scope_warnings)
        failed_meta_attempts.extend(scope_failures)
        if artifacts:
            scopes.append(ContentScope(scope_path, artifacts))
        else:
            warnings.append(f"content scope has no readable NCAs: {scope_path.name}")
    return InspectionResult(tuple(scopes), tuple(warnings), tuple(failed_meta_attempts))


def discover_groups(source: Path, container_type: str,
                    inspection: InspectionResult, keys: KeySet) -> GroupDiscovery:
    groups: list[PackageGroup] = []
    failed_attempts: list[str] = list(inspection.failed_meta_attempts)
    warnings: list[str] = []
    for scope in inspection.scopes:
        tickets: list[TicketInfo] = []
        for path in sorted(scope.path.rglob("*.tik")):
            try:
                tickets.append(parse_ticket(path))
            except (FixError, OSError, ValueError) as exc:
                warnings.append(f"unreadable ticket left unused: {path.name}: {exc}")
        certs = tuple(sorted(scope.path.rglob("*.cert")))
        referenced: set[str] = set()
        meta_ids: set[str] = set()
        for nca_id, artifact in sorted(scope.artifacts.items()):
            if artifact.header.content_type != 1:
                continue
            meta_ids.add(nca_id)
            try:
                meta = read_meta_payload(artifact.path, keys)
            except (FixError, OSError, ValueError) as exc:
                failed_attempts.append(f"{artifact.path.name}: {exc}")
                continue
            content: list[NcaArtifact] = []
            missing: list[CnmtEntry] = []
            for entry in meta.info.content_entries:
                candidate = scope.artifacts.get(entry.nca_id.lower())
                if candidate is None:
                    missing.append(entry)
                else:
                    content.append(candidate)
                    referenced.add(entry.nca_id.lower())
            groups.append(PackageGroup(
                source=source, container_type=container_type,
                extract_dir=scope.path, meta=meta, meta_artifact=artifact,
                content=tuple(content), missing_entries=tuple(missing),
                tickets=tuple(tickets), certs=certs))
        orphaned = set(scope.artifacts) - referenced - meta_ids
        if orphaned:
            shown = [f"{item}.nca" for item in sorted(orphaned)[:5]]
            detail = ", ".join(shown)
            remainder = len(orphaned) - len(shown)
            if remainder:
                detail += f", +{remainder} more"
            warnings.append(f"{len(orphaned)} unreferenced NCA(s) left unused in "
                            f"{scope.path.name}: {detail}")
    return GroupDiscovery(tuple(groups), tuple(failed_attempts), tuple(warnings))


# --------------------------------------------------------------------------
# the plan

def matching_ticket(group: PackageGroup, rights_id: str) -> TicketInfo | None:
    matches = [ticket for ticket in group.tickets
               if ticket.rights_id.lower() == rights_id.lower()]
    if len(matches) > 1:
        raise FixError(f"multiple tickets match RightsId {rights_id}")
    return matches[0] if matches else None


def eligible_title_rights_restore(artifact: NcaArtifact, cnmt_type: int) -> bool:
    header = artifact.header
    return (not header.has_title_rights and not header.is_gamecard
            and header.distribution_type == 0
            and cnmt_type in TITLE_BEARING_CNMT_TYPES
            and header.content_type in TITLE_BEARING_NCA_TYPES)


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
                      default_cert: Path, has_cnmt_db: bool) -> RepairPlan:
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

    probe_dir = group_work / "probe"
    outcomes: list[Outcome] = []
    rewrites: list[NcaRewrite] = []
    for artifact in standard_content:
        entry = entry_by_id[artifact.nca_id]
        if artifact.verification.main_signature_valid:
            restored = artifact.recovery is not None
            decision = NcaDecision(
                artifact, artifact.path,
                Outcome.RESTORED if restored else Outcome.PRESERVE,
                artifact.verification, artifact.recovery,
                (f"{artifact.recovery_reason}; Nintendo main signature restored"
                 if restored else "Nintendo main signature valid"))
        else:
            gamecard_rewrite = restore_gamecard_distribution_nca(
                artifact.path, probe_dir, keys, artifact.sha256)
            if gamecard_rewrite is not None:
                verification = verify_nca_file(gamecard_rewrite.output, keys)
                if verification.main_signature_valid:
                    decision = NcaDecision(
                        artifact, gamecard_rewrite.output, Outcome.RESTORED,
                        verification, gamecard_rewrite,
                        "gamecard distribution restoration regained Nintendo main signature")
                else:
                    plan.failures.append(
                        "gamecard distribution restoration disagrees with final "
                        f"signature verification: {artifact.path.name}")
                    decision = NcaDecision(
                        artifact, gamecard_rewrite.output, Outcome.IMPOSSIBLE,
                        verification, gamecard_rewrite,
                        "gamecard signature recovery failed final verification")
            elif eligible_title_rights_restore(artifact, entry.content_type):
                rewrite = restore_title_rights_nca(
                    artifact.path, probe_dir, keys, artifact.sha256)
                verification = verify_nca_file(rewrite.output, keys)
                if verification.main_signature_valid:
                    decision = NcaDecision(
                        artifact, rewrite.output, Outcome.RESTORED,
                        verification, rewrite,
                        "title-rights reversal restored Nintendo main signature")
                else:
                    plan.failures.append(
                        "NCA main signature still fails after title-rights reversal: "
                        f"{artifact.path.name}")
                    decision = NcaDecision(
                        artifact, rewrite.output, Outcome.IMPOSSIBLE,
                        verification, rewrite, "signature recovery failed")
            else:
                plan.failures.append(f"NCA main signature fails: {artifact.path.name}")
                decision = NcaDecision(
                    artifact, artifact.path, Outcome.IMPOSSIBLE,
                    artifact.verification,
                    reason="unsigned NCA has no unambiguous repair")
        plan.content.append(decision)
        outcomes.append(decision.outcome)
        if decision.rewrite is not None and artifact.recovery is None:
            rewrites.append(decision.rewrite)

    if rewrites:
        output_content_headers = [
            read_nca_header(decision.output, keys) if decision.rewrite is not None
            else decision.source.header
            for decision in plan.content]
        gamecard_content = bool(output_content_headers) and all(
            is_gamecard_oriented(header) for header in output_content_headers)
        meta_rewrite = rebuild_meta_nca(
            group.meta.header.path, probe_dir, rewrites, keys,
            distribution_type=1 if gamecard_content else None)
        meta_verification = verify_nca_file(meta_rewrite.output, keys)
        if meta_verification.main_signature_valid:
            plan.meta = NcaDecision(
                group.meta_artifact, meta_rewrite.output, Outcome.RESTORED,
                meta_verification, meta_rewrite,
                "rebuilt Meta NCA regained Nintendo main signature")
        else:
            reason = "rebuilt Meta NCA main signature fails"
            plan.failures.append(reason)
            plan.meta = NcaDecision(
                group.meta_artifact, meta_rewrite.output, Outcome.IMPOSSIBLE,
                meta_verification, meta_rewrite, reason)
    elif group.meta_artifact.verification.main_signature_valid:
        restored = group.meta_artifact.recovery is not None
        plan.meta = NcaDecision(
            group.meta_artifact, group.meta.header.path,
            Outcome.RESTORED if restored else Outcome.PRESERVE,
            group.meta_artifact.verification, group.meta_artifact.recovery,
            (f"{group.meta_artifact.recovery_reason}; Meta NCA main signature restored"
             if restored else "Meta NCA main signature valid"))
    else:
        gamecard_meta = restore_gamecard_distribution_nca(
            group.meta.header.path, probe_dir, keys, group.meta_artifact.sha256)
        if gamecard_meta is not None:
            meta_verification = verify_nca_file(gamecard_meta.output, keys)
            if meta_verification.main_signature_valid:
                plan.meta = NcaDecision(
                    group.meta_artifact, gamecard_meta.output, Outcome.RESTORED,
                    meta_verification, gamecard_meta,
                    "gamecard distribution restoration regained Meta NCA signature")
            else:
                reason = "gamecard Meta signature recovery failed final verification"
                plan.failures.append(reason)
                plan.meta = NcaDecision(
                    group.meta_artifact, gamecard_meta.output, Outcome.IMPOSSIBLE,
                    meta_verification, gamecard_meta, reason)
        else:
            plan.failures.append(
                f"Meta NCA main signature fails: {group.meta.header.path.name}")
            plan.meta = NcaDecision(
                group.meta_artifact, group.meta.header.path, Outcome.IMPOSSIBLE,
                group.meta_artifact.verification, reason="Meta NCA signature invalid")
    outcomes.append(plan.meta.outcome)

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

    if not has_cnmt_db:
        detail = ("signed local CNMT remains authoritative"
                  if plan.meta.verification.main_signature_valid
                  else "unsigned local CNMT is only a structural source")
        plan.warnings.append(f"informational: CNMTDB has no same-version record; {detail}")

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
    ticket_material = next(
        (item.rewrite.encrypted_titlekey for item in plan.content
         if item.rewrite is not None and item.rewrite.encrypted_titlekey is not None),
        None)
    existing_ticket = matching_ticket(group, rights_id) if rights_id else None
    ticket_dir = group_work / "ticket"

    if rights_id and ticket_generation is None:
        plan.failures.append("title-rights content has no unambiguous NCA key generation")
    elif rights_id and info.type_name in {"BASE", "DLC"}:
        encrypted_titlekey = ticket_material or (
            existing_ticket.encrypted_titlekey if existing_ticket else None)
        if encrypted_titlekey is None:
            plan.failures.append(
                f"{info.type_name} title-rights content has no recoverable ticket/titlekey")
        else:
            courier_sourced = ticket_material is None and existing_ticket is not None
            probe_ok = True
            if courier_sourced:
                plain = ecb_decrypt(keys.titlekek(max(ticket_generation - 1, 0)),
                                    encrypted_titlekey)
                rights_header = next(
                    (header for header in output_headers
                     if header.rights_id == rights_id), None)
                try:
                    probe_ok = (rights_header is not None
                                and probe_titlekey(rights_header, plain))
                    if not probe_ok:
                        plan.failures.append(
                            "courier-sourced titlekey failed the decrypt probe "
                            "against the signed master hash")
                except FixError as exc:
                    probe_ok = False
                    plan.failures.append(f"titlekey probe unavailable: {exc}")
            if probe_ok:
                ticket_dir.mkdir(parents=True, exist_ok=True)
                plan.ticket_path = ticket_dir / f"{rights_id}.tik"
                generated = make_public_ticket(rights_id, encrypted_titlekey,
                                               ticket_generation)
                plan.ticket_path.write_bytes(generated)
                if existing_ticket is None or \
                        existing_ticket.path.read_bytes() != generated:
                    outcomes.append(Outcome.RESTORED)
                    if existing_ticket is not None and \
                            existing_ticket.key_generation != ticket_generation:
                        plan.warnings.append(
                            "ticket generation repaired from "
                            f"{existing_ticket.key_generation} to signed NCA "
                            f"generation {ticket_generation}")
    elif rights_id and info.type_name == "UPD":
        ticket_failure = update_ticket_failure(existing_ticket)
        if ticket_failure is not None:
            plan.failures.append(ticket_failure)
        elif existing_ticket is not None:
            ticket_dir.mkdir(parents=True, exist_ok=True)
            plan.ticket_path = ticket_dir / f"{rights_id}.tik"
            shutil.copy2(existing_ticket.path, plan.ticket_path)
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
                     and entry.size == decision.output.stat().st_size
                     and decision.output.name.split(".", 1)[0].lower()
                     == digest[:32].lower())
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
        if decision.output.name.split(".", 1)[0].lower() != digest[:32].lower():
            raise FixError(f"post-build NCA filename mismatch: {decision.output.name}")

    output_rights = {header.rights_id for header in
                     (read_nca_header(item.output, keys) for item in plan.content)
                     if header.rights_id}
    if plan.ticket_path is None:
        if output_rights:
            raise FixError("post-build title-rights content has no ticket")
    else:
        ticket = parse_ticket(plan.ticket_path)
        if output_rights != {ticket.rights_id.lower()}:
            raise FixError("post-build ticket RightsId does not match content NCAs")
        if plan.cert_path is None or \
                plan.cert_path.stem.lower() != ticket.rights_id.lower():
            raise FixError("post-build cert is absent or misnamed")

    failed = [item.output.name for item in plan.content + [plan.meta]
              if not item.verification.main_signature_valid]
    if failed:
        raise FixError(f"post-build signature failure: {', '.join(failed)}")


def publish_atomic(candidate: Path, destination: Path, overwrite: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise FixError(f"output exists: {destination.name} (use --overwrite)")
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        shutil.copy2(candidate, temporary)
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
    write_pfs0(candidate, files)
    table = read_pfs0_table(candidate)
    if [entry.name for entry in table] != [path.name for path in files]:
        raise FixError("post-build PFS0 order/name verification failed")
    destination = out_dir / plan.output_name
    publish_atomic(candidate, destination, overwrite)
    return destination


def print_plan(plan: RepairPlan) -> None:
    info = plan.group.meta.info
    print(f"  group:   {info.title_id.upper()} v{info.version} {info.type_name}"
          f"{' [GAMECARD]' if plan.gamecard_variant else ''}")
    for decision in plan.content + ([plan.meta] if plan.meta else []):
        print(f"    {decision.outcome.value:<10} {decision.output.name}: {decision.reason}")
    if plan.ticket_path is not None:
        print(f"    TICKET     {plan.ticket_path.name}")
    for warning in plan.warnings:
        print(f"  warn:    {warning}")
    for failure in plan.failures:
        print(f"  FAIL:    {failure}")
    print(f"  outcome: {plan.outcome.value}")


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
    parser.add_argument("--cert", type=Path, default=DEFAULT_CERT)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--keep-work", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    configure_utf8_stdio()
    args = parse_args(argv)
    if not args.keys.exists():
        print(f"FAIL: prod.keys not found: {args.keys}", file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    inputs = list(args.input) if args.input else discover_inputs(args.intake)
    if not inputs:
        print(f"no NSP/NSZ/XCI/XCZ inputs found in {args.intake}")
        return 0

    keys = KeySet.load(args.keys)
    knowledge = CnmtKnowledgeBase(args.titledb / "cnmts.json")
    firmware_catalog = load_firmware_catalog(DB_DIR / "firmware_versions.json")
    attempted = completed = failed = source_failures = archive_failures = 0
    for source in inputs:
        print(f"\n[{source.name}]")
        try:
            container_type, extract_dir, input_warnings = prepare_input(
                source, args.work_dir, args.keep_work)
            print(f"  source:  {container_type}")
            for warning in input_warnings:
                print(f"  warn:    {warning}")
            inspection = inspect_container(extract_dir, container_type, keys,
                                           knowledge, firmware_catalog)
            discovery = discover_groups(source, container_type, inspection, keys)
        except (FixError, OSError, ValueError, subprocess.SubprocessError) as exc:
            source_failures += 1
            print(f"  FAIL:    {exc}")
            continue

        for warning in (*inspection.warnings, *discovery.warnings):
            print(f"  warn:    {warning}")
        print(f"  groups:  {len(discovery.groups)} readable, "
              f"{len(discovery.failed_attempts)} unreadable")
        source_attempted = source_completed = source_failed = 0
        for detail in discovery.failed_attempts:
            attempted += 1
            failed += 1
            source_attempted += 1
            source_failed += 1
            print(f"  FAIL:    Meta/CNMT attempt failed: {detail}")
        if not discovery.groups and not discovery.failed_attempts:
            source_failures += 1
            print("  FAIL:    container contains no readable Meta/CNMT NCA")
            continue

        source_work = args.work_dir / source.name
        for index, group in enumerate(discovery.groups, 1):
            attempted += 1
            source_attempted += 1
            try:
                group_work = source_work / f"group-{index:03d}"
                has_db = knowledge.record_exists(group.meta.info)
                plan = build_repair_plan(group, group_work, keys, args.cert, has_db)
                print_plan(plan)
                if not plan.publishable:
                    failed += 1
                    source_failed += 1
                    continue
                if args.inspect_only:
                    verify_plan_integrity(plan, keys)
                    print("  output:  inspect-only; not written")
                else:
                    destination = execute_plan(plan, group_work, args.out_dir,
                                               keys, args.overwrite)
                    print(f"  output:  {destination}")
                completed += 1
                source_completed += 1
            except (FixError, OSError, ValueError, subprocess.SubprocessError) as exc:
                failed += 1
                source_failed += 1
                print(f"  FAIL:    group attempt failed: {exc}")

        if (not args.inspect_only and source_attempted > 0
                and source_completed == source_attempted and source_failed == 0):
            try:
                archived, moved = archive_successful_source(source, args.success_dir)
                print(f"  input:   {'moved' if moved else 'already archived'}: {archived}")
            except (OSError, ValueError) as exc:
                archive_failures += 1
                print(f"  FAIL:    successful source could not be archived: {exc}")

    print(f"\ndone: sources={len(inputs)}, attempted_groups={attempted}, "
          f"completed_groups={completed}, failed_groups={failed}, "
          f"source_failures={source_failures}, archive_failures={archive_failures}")
    return 1 if failed or source_failures or archive_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
