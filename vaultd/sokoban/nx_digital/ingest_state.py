"""NX ingest checkpoint: finish one payload before starting the next.

Only temporary recovery state lives in dropzone/ingest-work. The vault keeps
its existing two bookkeeping files. Ordinary commits do not rehash payloads;
a resumed commit verifies the placed payload before replaying metadata writes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from typing import Callable
import xml.etree.ElementTree as ET

from vaultd import catwrite, checksum, hashing
from vaultd.catwrite import t

METADATA = ("entities.checksum", "datmeta.xml")
Audit = Callable[[Path], list[str]]


def contained(root: Path, relative: str) -> Path:
    path = root / relative
    resolved, boundary = path.resolve(), root.resolve()
    if resolved == boundary or not resolved.is_relative_to(boundary):
        raise ValueError(f"path escapes its workspace: {relative}")
    return path


def clear_work(path: Path, root: Path) -> None:
    contained(root, str(path.relative_to(root)))
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"refusing to clear linked work directory: {path}")
    if path.exists():
        shutil.rmtree(path)


def fingerprint(path: Path) -> list[int]:
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def metadata_hashes(vault: Path) -> dict[str, str]:
    return {name: sha256((vault / name).read_bytes()) for name in METADATA}


def atomic_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def load(vault: Path, audit: Audit):
    before = metadata_hashes(vault)
    problems = audit(vault / "datmeta.xml")
    if problems:
        raise ValueError("catalog self-audit failed: " + "; ".join(problems))
    root = ET.parse(vault / "datmeta.xml").getroot()
    if root.get("name") != "nx_digital" or root.get("name") != vault.name:
        raise ValueError("catalog name must be nx_digital and match the vault directory")
    if root.get("compression") != "none":
        raise ValueError("NX digital ingest requires compression='none'")
    entries, problems = checksum.parse_file(vault / "entities.checksum")
    if problems:
        raise ValueError("; ".join(problems))
    # Compare declarations without reading archived payloads. Instance/pix
    # checksum rows are legal too; only hashed declarations are checked here.
    for entity in root.findall(f"./{t('entities')}/{t('entity')}"):
        eid = entity.get("identifier")
        files = []
        for release in entity.findall(f"./{t('releases')}/{t('release')}"):
            prefix = f"{eid}/releases/{release.get('version')}/fs/shared"
            files.extend((f"{prefix}/{fe.get('path')}", fe)
                         for fe in release.findall(f"./{t('fs')}/{t('fileshared')}"))
        for patch in entity.findall(f"./{t('patches')}/{t('patch')}"):
            prefix = f"{eid}/patches/{patch.get('name')}"
            files.extend((f"{prefix}/{fe.get('path')}", fe)
                         for fe in patch.findall(t("file")))
        for relative, fe in files:
            entry = entries.get(relative)
            if entry is None or any(str(getattr(entry, key)) != fe.get(key)
                                    for key in ("size", "crc", "md5", "sha1")):
                raise ValueError(f"catalog/checksum disagreement: {relative}")
    if metadata_hashes(vault) != before:
        raise ValueError("bookkeeping changed while loading; rerun")
    return root, entries, before


def finish(vault: Path, dropzone: Path, work: Path, audit: Audit, *,
           recovering: bool, keep_source: bool = False) -> str:
    pending = work / "pending.json"
    record = json.loads(pending.read_text(encoding="utf-8"))
    if record["vault"] != str(vault.resolve()):
        raise ValueError("pending ingest belongs to another vault")
    name = record["source"]
    if Path(name).name != name or name in {"", ".", ".."}:
        raise ValueError("invalid source name in pending ingest")
    source = contained(dropzone, name)
    dest = contained(vault / "entities", record["target"])
    if source.exists() and fingerprint(source) != record["source_stamp"]:
        raise ValueError("pending source changed; preserved for inspection")
    if fingerprint(dest) != record["target_stamp"]:
        raise ValueError("pending destination changed; preserved for inspection")
    if recovering:
        print(f"  recovery: checking placed artifact for {name}", flush=True)
        if hashing.digest(dest, crc=True, md5=True, sha1=True) != record["digest"]:
            raise ValueError("pending destination hash differs from its checkpoint")
    payloads = {}
    for filename in METADATA:
        expected = record["metadata"][filename]
        data = (work / "checkpoint" / filename).read_bytes()
        if sha256(data) != expected["after"]:
            raise ValueError(f"damaged ingest checkpoint: {filename}")
        current = sha256((vault / filename).read_bytes())
        if current not in {expected["before"], expected["after"]}:
            raise ValueError(f"{filename} changed outside pending ingest; refusing to overwrite")
        payloads[filename] = data
    for filename in METADATA:  # checksum first, XML second
        atomic_bytes(vault / filename, payloads[filename])
    problems = audit(vault / "datmeta.xml")
    if problems:
        raise ValueError("saved catalog self-audit failed: " + "; ".join(problems))
    if not record["keep_source"] and not keep_source and source.exists():
        if fingerprint(source) != record["source_stamp"]:
            raise ValueError("source changed before cleanup; preserved")
        source.unlink()
    pending.unlink()
    return name


def commit(vault: Path, dropzone: Path, work: Path, root: ET.Element,
           entries: dict[str, checksum.Entry], before: dict[str, str],
           source: Path, source_stamp: list[int], target: str, audit: Audit, *,
           keep_source: bool) -> None:
    if (work / "pending.json").exists():
        raise ValueError("an earlier ingest checkpoint is still pending")
    if fingerprint(source) != source_stamp:
        raise ValueError("source changed during ingest; retained")
    catwrite.bump_stamp(root)
    catwrite.sort_tree(root)
    checkpoint = contained(work, "checkpoint")
    checkpoint.mkdir(parents=True, exist_ok=True)
    checksum.write_file(checkpoint / "entities.checksum", entries)
    catwrite.write_xml(checkpoint / "datmeta.xml", root)
    problems = audit(checkpoint / "datmeta.xml")
    if problems:
        raise ValueError("proposed catalog self-audit failed: " + "; ".join(problems))
    if metadata_hashes(vault) != before:
        raise ValueError("bookkeeping changed during ingest; source retained")
    dest = contained(vault / "entities", target)
    entry = entries[target]
    digest = {key: getattr(entry, key) for key in ("size", "crc", "md5", "sha1")}
    stamp = fingerprint(dest)
    if stamp[2] != entry.size:
        raise ValueError("placed artifact size changed before checkpoint")
    record = {"vault": str(vault.resolve()), "source": source.name,
              "source_stamp": source_stamp, "target": target,
              "target_stamp": stamp, "digest": digest, "keep_source": keep_source,
              "metadata": {name: {"before": before[name],
                                  "after": sha256((checkpoint / name).read_bytes())}
                           for name in METADATA}}
    atomic_bytes(work / "pending.json", json.dumps(record, indent=2).encode("utf-8"))
    finish(vault, dropzone, work, audit, recovering=False)
