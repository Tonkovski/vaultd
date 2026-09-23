"""Retire custom NX labels through a logged, one-at-a-time hashdb sweep.

Every candidate logs its identity, DAT claims, decision and final outcome.
Only exclusively clean hash matches can become vanilla NSZs. Rejected or
conflicting claims keep the labeled source. Vanilla and GAMECARD entries
are outside this sweep. Interrupted checkpoints resume before new work.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
import xml.etree.ElementTree as ET

from vaultd import catwrite, checksum, hashing, locator
from vaultd.catwrite import t
from vaultd.locator import DROPZONE
from vaultd.sokoban.nx_digital import VAULT_NAME
from vaultd.sokoban.nx_digital.ingest import (
    DB_DIR, Skip, entity_for, gate_path, nsz_roundtrip, parse_name,
    rejection_reasons, rom_matches_tid, self_audit, stored_marker)


def log(message: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {message}", flush=True)


@dataclass(frozen=True)
class Candidate:
    entity: str
    version: str
    name: str
    description: str
    sha1: str

    @property
    def relative(self) -> str:
        return f"{self.entity}/releases/{self.version}/fs/shared/{self.name}"


@dataclass(frozen=True)
class Claim:
    dat: str
    game: str
    rom: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    verdict: str
    reason: str
    category: str = ''


@dataclass
class SweepReport:
    started: float = field(default_factory=time.monotonic)
    total: int | None = None
    inspected: int = 0
    skipped: Counter = field(default_factory=Counter)
    results: list[tuple[str, Decision]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    interrupted: bool = False
    fatal: bool = False

    @property
    def has_errors(self) -> bool:
        return any(decision.verdict == 'ERROR' for _, decision in self.results)

    def emit(self, *, pending: bool) -> None:
        counts = Counter(decision.verdict for _, decision in self.results)
        status = ('interrupted' if self.interrupted else 'stopped' if self.fatal else
                  'completed with errors' if self.has_errors else 'complete')
        log(f"DIGEST {status}; {time.monotonic() - self.started:.1f}s")
        if self.total is None:
            log("  Sweep: candidates not enumerated")
        else:
            log(f"  Sweep: {self.inspected}/{self.total} candidates inspected; "
                f"{self.total - self.inspected} not reached")
        log(f"  Converted to vanilla: {counts['REMATCHED']} new, {counts['RESUMED']} resumed")
        log(f"  Retained: {counts['KEPT']} unknown to hashdb, "
            f"{counts['REJECTED']} rejected, {counts['BLOCKED']} blocked")
        if counts['ERROR'] or counts['INTERRUPTED']:
            log(f"  Incomplete: {counts['ERROR']} errors, {counts['INTERRUPTED']} interrupted items")
        if self.skipped:
            log("  Skipped: " + ', '.join(f'{key}={value}' for key, value in sorted(self.skipped.items())))

        # Ordinary no-match results need only their count. List changes and
        # exceptions by cause, without replaying paths, claims or END messages.
        for verdict in ('REMATCHED', 'RESUMED'):
            subjects = [subject for subject, decision in self.results if decision.verdict == verdict]
            if subjects:
                log(f"  {'CONVERTED' if verdict == 'REMATCHED' else 'RESUMED'} ({len(subjects)})")
                for subject in sorted(subjects):
                    log(f"    {subject}")
        for verdict in ('REJECTED', 'BLOCKED', 'ERROR', 'INTERRUPTED'):
            groups = defaultdict(list)
            for subject, decision in self.results:
                if decision.verdict == verdict:
                    groups[decision.category or decision.reason].append(subject)
            for reason, subjects in sorted(groups.items()):
                log(f"  {verdict} ({len(subjects)}): {reason}")
                for subject in sorted(subjects):
                    log(f"    {subject}")
        warnings = defaultdict(list)
        for subject, reason in self.warnings:
            warnings[reason].append(subject)
        for reason, subjects in sorted(warnings.items()):
            log(f"  WARN ({len(subjects)}): scratch cleanup: {reason}")
            for subject in sorted(subjects):
                log(f"    {subject}")
        if pending:
            log("  Pending checkpoint retained; rerun to finish it before new candidates")


def candidates(root: ET.Element) -> tuple[list[Candidate], Counter]:
    result, skipped = [], Counter()
    for entity in root.findall(f"./{t('entities')}/{t('entity')}"):
        for release in entity.findall(f"./{t('releases')}/{t('release')}"):
            for file in release.findall(f"./{t('fs')}/{t('fileshared')}"):
                name = file.get("path", "")
                marker = stored_marker(name)
                if marker in {None, "", "GAMECARD"}:
                    skipped[{None: 'unrecognized', '': 'vanilla', 'GAMECARD': 'GAMECARD'}[marker]] += 1
                    continue
                result.append(Candidate(entity.get("identifier", ""), release.get("version", ""),
                                        name, entity.get("description") or "(no description)",
                                        (file.get("sha1") or "").lower()))
    return sorted(result, key=lambda c: (c.entity, c.version, c.name)), skipped


def load_claims(directory: Path, wanted: set[str]) -> dict[str, list[Claim]]:
    dats = sorted(directory.glob("*.xml"))
    if not dats:
        raise ValueError(f"no DAT files in {directory}")
    claims = {sha1: [] for sha1 in wanted}
    for dat in dats:
        log(f"DB READ {dat.name}")
        matched = 0
        for _, game in ET.iterparse(dat, events=("end",)):
            if game.tag != "game":
                continue
            for rom in game.iter("rom"):
                sha1 = (rom.get("sha1") or "").lower()
                if sha1 in claims:
                    claims[sha1].append(Claim(dat.name, game.get("name", ""),
                                              rom.get("name", ""), rejection_reasons(game, rom)))
                    matched += 1
            game.clear()
        log(f"DB READY {dat.name}: {matched} candidate claim(s)")
    return claims


def load_state(vault: Path):
    root = ET.parse(vault / "datmeta.xml").getroot()
    entries, problems = checksum.parse_file(vault / "entities.checksum")
    if problems:
        raise ValueError("; ".join(problems))
    return root, entries


def release_files(root: ET.Element, item: Candidate):
    matches = [release.find(t("fs"))
               for entity in root.findall(f"./{t('entities')}/{t('entity')}")
               if entity.get("identifier") == item.entity
               for release in entity.findall(f"./{t('releases')}/{t('release')}")
               if release.get("version") == item.version]
    if len(matches) != 1 or matches[0] is None:
        raise ValueError("catalog release is missing or ambiguous")
    return matches[0]


def contained(root: Path, relative: str) -> Path:
    path = root / Path(relative)
    if not path.resolve().is_relative_to(root.resolve()) or path.resolve() == root.resolve():
        raise ValueError(f"path escapes its workspace: {relative}")
    return path


def wipe_work(path: Path, root: Path) -> None:
    contained(root, str(path.relative_to(root)))
    if path.exists():
        shutil.rmtree(path)


def fingerprint(path: Path) -> list[int]:
    stat = path.stat()
    return [stat.st_size, stat.st_mtime_ns]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def finish_checkpoint(vault: Path, work_root: Path, *, recovering: bool) -> str:
    """Replay the two metadata writes and source cleanup idempotently."""
    pending = work_root / "pending.json"
    record = json.loads(pending.read_text(encoding="utf-8"))
    if record["vault"] != str(vault.resolve()):
        raise ValueError("pending checkpoint belongs to another vault")
    old = contained(vault / "entities", record["old"])
    new = contained(vault / "entities", record["new"])
    log(f"{'RESUME' if recovering else 'CHECKPOINT'} {record['old']} -> {new.name}")
    if old.exists() and fingerprint(old) != record["source_stamp"]:
        raise ValueError("labeled source changed; checkpoint retained for inspection")
    if fingerprint(new) != record["target_stamp"]:
        raise ValueError("placed NSZ changed; checkpoint retained for inspection")
    if recovering:
        log("  VERIFY resumed NSZ against its checkpoint hashes")
        if hashing.digest(new, crc=True, md5=True, sha1=True) != record["digest"]:
            raise ValueError("placed NSZ differs from checkpoint hashes")
    payloads = {}
    for name, expected in record["metadata"].items():
        if name not in {"datmeta.xml", "entities.checksum"}:
            raise ValueError("unexpected checkpoint metadata path")
        data = (work_root / "checkpoint" / name).read_bytes()
        if sha256_bytes(data) != expected["after"]:
            raise ValueError(f"damaged checkpoint: {name}")
        current = (vault / name).read_bytes()
        if sha256_bytes(current) not in {expected["before"], expected["after"]}:
            raise ValueError(f"{name} changed outside this checkpoint; refusing to overwrite")
        payloads[name] = data
    for name in ("entities.checksum", "datmeta.xml"):
        log(f"  SAVE {name}")
        atomic_bytes(vault / name, payloads[name])
    problems = self_audit(vault / "datmeta.xml")
    if problems:
        raise ValueError("saved catalog self-audit failed: " + "; ".join(problems))
    if old.exists():
        if fingerprint(old) != record["source_stamp"]:
            raise ValueError("labeled source changed before cleanup")
        log(f"  REMOVE committed source: {old.name}")
        old.unlink()
    pending.unlink()
    return new.name


def convert(item: Candidate, vault: Path, work_root: Path, root, entries, before) -> str:
    parsed = parse_name(Path(item.name))
    if parsed is None:
        raise ValueError("stored filename is not parseable")
    tid, version, kind, _ = parsed
    if version != item.version or entity_for(tid, kind) != item.entity:
        raise ValueError("filename identity disagrees with its catalog location")
    if Path(item.name).suffix.lower() != ".nsp":
        raise ValueError("custom-labeled source must be bare NSP; its hash must describe NSP bytes")
    fs = release_files(root, item)
    old_files = [file for file in fs.findall(t("fileshared")) if file.get("path") == item.name]
    if len(old_files) != 1:
        raise ValueError("source declaration is missing or ambiguous")
    declared = old_files[0]
    known = entries.get(item.relative)
    if known is None or any(str(getattr(known, field)) != declared.get(field)
                            for field in ("crc", "md5", "sha1", "size")):
        raise ValueError("source XML and checksum record disagree")
    old = contained(vault / "entities", item.relative)
    source_stamp = fingerprint(old)
    if source_stamp[0] != known.size:
        raise ValueError("source size differs from its catalog declaration")
    new_name = f"[{tid}][{version}][{kind}].nsz"
    new_rel = str(Path(item.relative).with_name(new_name)).replace("\\", "/")
    gate_path(new_rel, entries)
    if new_rel in entries:
        raise ValueError("target already has a checksum record")
    new = contained(vault / "entities", new_rel)
    work = work_root / "conversion"
    wipe_work(work, work_root)
    log(f"  CONVERT {item.name} -> {new_name}")
    artifact = nsz_roundtrip(old, work, item.sha1)
    log(f"  COPY and hash NSZ -> {new}")
    new.parent.mkdir(parents=True, exist_ok=True)
    temporary = new.with_name(new.name + ".dbrematch.tmp")
    with artifact.open("rb") as source, temporary.open("wb") as output:
        copied = hashing.digest_stream(source, output=output, crc=True, md5=True, sha1=True)
    log("  VERIFY copied NSZ")
    if hashing.digest(temporary, crc=True, md5=True, sha1=True) != copied:
        temporary.unlink()
        raise ValueError("copied bytes differ from verified NSZ")
    temporary.replace(new)
    if fingerprint(old) != source_stamp:
        raise ValueError("source changed during conversion")
    proposed = ET.fromstring(ET.tostring(root))
    next_fs = release_files(proposed, item)
    next_fs.remove(next(file for file in next_fs.findall(t("fileshared"))
                        if file.get("path") == item.name))
    ET.SubElement(next_fs, t("fileshared"), path=new_name,
                  **{key: str(value) for key, value in copied.items()})
    next_entries = dict(entries)
    next_entries.pop(item.relative)
    next_entries[new_rel] = checksum.Entry(path=new_rel, **copied)
    catwrite.bump_stamp(proposed)
    catwrite.sort_tree(proposed)
    checkpoint = work_root / "checkpoint"
    checkpoint.mkdir(parents=True, exist_ok=True)
    checksum.write_file(checkpoint / "entities.checksum", next_entries)
    catwrite.write_xml(checkpoint / "datmeta.xml", proposed)
    problems = self_audit(checkpoint / "datmeta.xml")
    if problems:
        raise ValueError("proposed catalog self-audit failed: " + "; ".join(problems))
    if any(sha256_bytes((vault / name).read_bytes()) != digest for name, digest in before.items()):
        raise ValueError("bookkeeping changed during conversion; source retained")
    metadata = {name: {"before": before[name],
                       "after": sha256_bytes((checkpoint / name).read_bytes())}
                for name in ("entities.checksum", "datmeta.xml")}
    record = {"vault": str(vault.resolve()), "old": item.relative, "new": new_rel,
              "source_stamp": source_stamp, "target_stamp": fingerprint(new),
              "digest": copied, "metadata": metadata}
    atomic_bytes(work_root / "pending.json", json.dumps(record, indent=2).encode("utf-8"))
    return finish_checkpoint(vault, work_root, recovering=False)


def inspect_one(item: Candidate, claims: list[Claim], vault: Path, work_root: Path) -> Decision:
    log(f"  TITLE {item.description}")
    log(f"  SHA1 (catalog) {item.sha1}")
    parsed = parse_name(Path(item.name))
    if parsed is None:
        raise ValueError("stored filename is not parseable")
    title_id = parsed[0]
    for claim in claims:
        verdict = 'REJECT' if claim.reasons else 'CLEAN'
        log(f"  DAT {verdict}: {claim.dat}")
        log(f"    game: {claim.game}")
        log(f"    rom:  {claim.rom}")
        log(f"    TID:  {'matches' if rom_matches_tid(claim.rom, title_id) else 'does not match'} [{title_id}]")
        if claim.reasons:
            log(f"    reason: {', '.join(claim.reasons)}")
    if not claims:
        return Decision('KEPT', 'SHA-1 still unknown to hashdb; source retained')
    rejected = sorted({reason for claim in claims for reason in claim.reasons})
    if rejected:
        return Decision('REJECTED', 'rejected DAT claim takes precedence; source retained',
                        ', '.join(rejected))
    if not any(rom_matches_tid(claim.rom, title_id) for claim in claims):
        return Decision('BLOCKED',
                        f'SHA-1 matches hashdb, but no ROM filename contains [{title_id}]; source retained',
                        'no hashdb ROM filename contains the input TID')
    before = {name: sha256_bytes((vault / name).read_bytes())
              for name in ('datmeta.xml', 'entities.checksum')}
    root, entries = load_state(vault)
    fs = release_files(root, item)
    if any(stored_marker(file.get("path", "")) == "" for file in fs.findall(t("fileshared"))):
        return Decision('BLOCKED', 'vanilla already exists for this release; source retained',
                        'vanilla already exists for this release')
    log(f"  MATCH clean DAT claim(s) with [{title_id}]; eligible to retire the custom label")
    return Decision('REMATCHED', convert(item, vault, work_root, root, entries, before))


def run(vault: Path, hashdb: Path, work_root: Path) -> int:
    report = SweepReport()
    active = None
    try:
        log(f"START nx_digital dbrematch; vault: {vault}")
        if (work_root / "pending.json").exists():
            active = '(pending conversion)'
            name = finish_checkpoint(vault, work_root, recovering=True)
            report.results.append((name, Decision('RESUMED', 'completed interrupted checkpoint')))
            log(f"END RESUMED {name}")
            active = None
        root, _ = load_state(vault)
        items, skipped = candidates(root)
        total = len(items)
        report.total, report.skipped = total, skipped
        log(f"SWEEP {total} custom-labeled artifact(s); skipped: "
            + ', '.join(f'{key}={value}' for key, value in sorted(skipped.items())))
        if not items:
            return 0
        log(f"LOAD candidate DAT claims: {hashdb}")
        claims = load_claims(hashdb, {item.sha1 for item in items})
        for index, item in enumerate(items, 1):
            subject = f"{item.description} — {item.name}"
            active = subject
            report.inspected += 1
            started = time.monotonic()
            log(f"INSPECT [{index}/{total}] {item.relative}")
            try:
                decision = inspect_one(item, claims[item.sha1], vault, work_root)
            except (Skip, OSError, ValueError, ET.ParseError) as exc:
                decision = Decision('ERROR', str(exc))
            report.results.append((subject, decision))
            active = None
            log(f"END {decision.verdict} [{index}/{total}] {item.name}: {decision.reason} "
                f"({time.monotonic() - started:.1f}s)")
            if (work_root / "pending.json").exists():
                report.fatal = True
                log("STOP unfinished checkpoint retained; rerun to resume this item before others")
                break
            try:
                wipe_work(work_root / 'conversion', work_root)
            except OSError as exc:
                report.warnings.append((subject, str(exc)))
                log(f"WARN scratch cleanup: {exc}")
    except KeyboardInterrupt:
        report.interrupted = True
        if active:
            report.results.append((active, Decision('INTERRUPTED', 'rerun to retry or resume this item')))
            log(f"END INTERRUPTED {active}")
        log("INTERRUPTED; completed items remain committed")
    except Exception as exc:
        report.fatal = True
        report.results.append((active or '(setup)', Decision('ERROR', str(exc))))
        log(f"STOP {exc}")
    finally:
        report.emit(pending=(work_root / 'pending.json').exists())
    if report.interrupted:
        return 130
    return 1 if report.fatal or report.has_errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-digital-dbrematch", description=__doc__)
    parser.add_argument("--locator", type=Path, default=None, help="alternate vaultd.local.toml")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    try:
        vault = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
    except locator.LocatorError as exc:
        log(f"ERROR {exc}")
        return 2
    return run(vault, DB_DIR / 'hashdb', DROPZONE / 'dbrematch-work')


if __name__ == '__main__':
    raise SystemExit(main())
