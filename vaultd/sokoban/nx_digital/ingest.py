"""NX digital keeper: ingest NSP/NSZ artifacts from the workspace dropzone.

Intake scans ONLY the dropzone root — keeper sub-areas (fixnsp*/, duplicate/,
quarantine/, ...) are invisible to it. Clean DAT TID/version hash mismatches
move to dropzone/quarantine/; label-priority losers to dropzone/duplicate/.
Conflicts, including unverified NSP/NSZ overlaps, stay in the dropzone for
manual resolution. Byte-duplicates of enrolled artifacts are DELETED. An unknown hash whose TID/version is also absent from
the clean hashdb stays in the dropzone awaiting a fresher dat or --force LABEL.
Bad-ticket, hacked and bad-dump DAT rows are absent from both lookup indexes.

Identity: every input's CNMT is read in-house (fixnsp machinery) and must
agree with the filename on title id, version and type. Entity grouping:
BASE and DLC titles are their own entities; an UPD enrolls under its base
entity (base = upd tid - 0x800) with standalone="false".

Storage lanes:
  * hashdb clean match  -> archival NSZ (nsz -C -K -l 22 -t 16), decompressed
                           and sha1-verified against the source before
                           enrollment; stored [tid][vN][TYPE].nsz
  * [GAMECARD] variant  -> no positive hashdb match required; same NSZ round-trip
  * --force LABEL       -> bypass hashdb; bare NSP as [..][TYPE][LABEL].nsp
Admission priority for one (entity, version): vanilla > [GAMECARD] > [custom
label]; distinct customs coexist; the same marker with different bytes is a
conflict (left in place, resolve by hand). If that marker is already stored
as NSZ, the incoming NSP form cannot be compared directly: report a conflict
and retain the input without compressing it or unpacking the enrolled NSZ.
Incoming NSZ bytes can be compared directly with the recorded NSZ hash.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass, field
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from vaultd import catwrite, checksum, hashing, locator, winlint
from vaultd.catwrite import t
from vaultd.locator import DB_ROOT, DROPZONE, REPO_ROOT
from vaultd.sokoban.nx_digital import VAULT_NAME
from vaultd.sokoban.nx_digital.fixnsp import (
    FixError, KeySet, copy_exact, read_meta_payload, read_pfs0_table)
from vaultd.sokoban.nx_digital import ingest_state as state
from vaultd.titledb import TitleDB

SCHEMA = REPO_ROOT / "convention" / "datmeta.xsd"
DB_DIR = DB_ROOT / VAULT_NAME
NSZ_COMPRESS_ARGS = ("-C", "-K", "-l", "22", "-t", "16")

TID_RE = re.compile(r"\[([0-9A-Fa-f]{16})\]")
VER_RE = re.compile(r"\[(v[0-9]+)\]", re.IGNORECASE)
TYPE_RE = re.compile(r"\[(BASE|UPD|DLC)\]", re.IGNORECASE)
MARKER_RE = re.compile(r"\[([A-Za-z0-9][A-Za-z0-9_-]*)\]")
LABEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
REJECT_ROW_RE = re.compile(r"\[(?:b|h)\d*\]", re.IGNORECASE)
TYPE_BY_CNMT = {0x80: "BASE", 0x81: "UPD", 0x82: "DLC"}


class Skip(Exception):
    def __init__(self, verdict: str, reason: str) -> None:
        super().__init__(reason)
        self.verdict = verdict


def parse_name(path: Path) -> tuple[str, str, str, list[str]] | None:
    """(tid, version, type, markers) from a dump filename; None if unusable."""
    stem = path.stem
    tids = TID_RE.findall(stem)
    vers = VER_RE.findall(stem)
    types = TYPE_RE.findall(stem)
    if not (len(tids) == len(vers) == len(types) == 1):
        return None
    tid, ver, type_name = tids[0].upper(), vers[0].lower(), types[0].upper()
    markers: list[str] = []
    for token in MARKER_RE.findall(stem):
        upper = token.upper()
        if re.fullmatch(r"[0-9A-F]{16}", upper) or re.fullmatch(r"V\d+", upper) \
                or upper in {"BASE", "UPD", "DLC"}:
            continue
        markers.append("GAMECARD" if upper == "GAMECARD" else token)
    if len(markers) > 1:
        return None
    return tid, ver, type_name, markers


def marker_priority(marker: str) -> int:
    if marker == "":
        return 0
    if marker == "GAMECARD":
        return 1
    return 2


def entity_for(tid: str, type_name: str) -> str:
    if type_name == "UPD":
        return f"{int(tid, 16) - 0x800:016X}"
    return tid


def rejection_reasons(game: ET.Element, rom: ET.Element) -> tuple[str, ...]:
    """Shared DAT classification for ingest and label rematching."""
    reasons = [flag for flag in ("isHack", "isBadTicket")
               if (game.findtext(flag) or "").strip().lower() in {"true", "1"}]
    for field, name in (("game", game.get("name") or ""),
                        ("rom", rom.get("name") or "")):
        reasons.extend(f"{field} {match.group()}" for match in REJECT_ROW_RE.finditer(name))
    status = (rom.get("status") or "").strip().lower()
    if status in {"baddump", "hacked"}:
        reasons.append(f"status={status}")
    return tuple(reasons)


def rom_matches_tid(rom_name: str, title_id: str) -> bool:
    """Match the exact bracketed TID token used by the local DAT filenames."""
    return f"[{title_id.upper()}]" in rom_name.upper()


@dataclass
class HashDB:
    # Only eligible rows enter either index. Rejected rows are not evidence of
    # either a known hash or a known TID/version, and cannot poison clean copies.
    by_sha1: dict[str, set[str]] = field(default_factory=dict)
    by_identity: dict[tuple[str, int], set[str]] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        for sha1, names in self.by_sha1.items():
            for name in names:
                tids, versions = TID_RE.findall(name), VER_RE.findall(name)
                if len(tids) == len(versions) == 1:
                    identity = (tids[0].upper(), int(versions[0][1:]))
                    self.by_identity.setdefault(identity, set()).add(sha1)


def load_hashdb(hashdb: Path) -> HashDB:
    """Index clean NSP hashes and their ROM names; ignore rejected DAT rows."""
    lookup: dict[str, set[str]] = {}
    dats = sorted(hashdb.glob("*.xml"))
    print(f"hashdb: {hashdb} ({len(dats)} dat(s))", flush=True)
    ignored = 0
    for dat in dats:
        for _, game in ET.iterparse(dat, events=("end",)):
            if game.tag != "game":
                continue
            for rom in game.iter("rom"):
                if rejection_reasons(game, rom):
                    ignored += 1
                    continue
                sha1 = (rom.get("sha1") or "").strip().lower()
                if not sha1:
                    continue
                if not re.fullmatch(r"[0-9a-f]{40}", sha1):
                    raise ValueError(f"{dat.name}: invalid ROM SHA-1 for {rom.get('name')!r}")
                lookup.setdefault(sha1, set()).add(rom.get("name") or "")
            game.clear()
    print(f"  {len(lookup)} clean rom hashes indexed; {ignored} rejected rows ignored", flush=True)
    return HashDB(lookup)


def admission_marker(subject_sha1: str, gate: HashDB,
                     incoming_gamecard: bool, force_label: str | None,
                     identity: str, warnings: list[str], *, title_id: str,
                     version: int) -> str:
    """Only clean DAT evidence counts; explicit force bypasses this gate."""
    if force_label is not None:
        print(f"  gate:   --force [{force_label}], hashdb bypassed")
        return force_label
    rows = gate.by_sha1.get(subject_sha1, set())
    if incoming_gamecard:
        print("  gate:   [GAMECARD] variant, positive hashdb match not required")
        return "GAMECARD"
    known_hashes = gate.by_identity.get((title_id.upper(), version), set())
    if known_hashes and subject_sha1 not in known_hashes:
        raise Skip("quarantined",
                   f"hashdb knows [{title_id.upper()}][v{version}], but NSP SHA-1 "
                   f"{subject_sha1} matches none of its {len(known_hashes)} clean recorded hash(es); "
                   "input retained in dropzone/quarantine")
    clean = sorted(rows)
    if not clean:
        raise Skip("undecided", "hashdb miss; left in dropzone (fresher dat, or --force LABEL)")
    matching = [name for name in clean if rom_matches_tid(name, title_id)]
    if not matching:
        raise Skip("conflict", f"SHA-1 matches hashdb, but no ROM filename contains "
                   f"[{title_id.upper()}]; source retained:\n"
                   + "\n".join(f"        - {name}" for name in clean))
    ignored = [name for name in clean if name not in matching]
    if ignored:
        warn = (f"{identity} ignored clean SHA-1 claimant(s) without the matching TID:\n"
                + "\n".join(f"        - {name}" for name in ignored))
        warnings.append(warn)
        print(f"  WARN: {warn}")
    if len(matching) > 1:
        warn = (f"{identity} sha1 claimed by {len(matching)} clean hashdb rows with matching TID:\n"
                + "\n".join(f"        - {name}" for name in matching))
        warnings.append(warn)
        print(f"  WARN: {warn}")
    print(f"  hashdb: {matching[0]}")
    return ""


def stored_marker(filename: str) -> str | None:
    """Marker of a stored fileshared name; None if the name is not ours."""
    parsed = parse_name(Path(filename))
    if parsed is None:
        return None
    markers = parsed[3]
    if not markers:
        return ""
    return markers[0]


def extract_cnmt_info(container: Path, work: Path, keys: KeySet):
    entries = read_pfs0_table(container)
    metas = [entry for entry in entries if entry.name.lower().endswith(".cnmt.nca")]
    if len(metas) != 1:
        raise Skip("failed", f"expected one Meta NCA in container, found {len(metas)}")
    work.mkdir(parents=True, exist_ok=True)
    staged = work / metas[0].name
    with container.open("rb") as source, staged.open("wb") as output:
        source.seek(metas[0].offset)
        copy_exact(source, output, metas[0].size)
    try:
        return read_meta_payload(staged, keys).info
    except FixError as exc:
        raise Skip("failed", f"unreadable CNMT: {exc}") from exc


def cross_check(tid: str, ver: str, type_name: str, info) -> None:
    cnmt_type = TYPE_BY_CNMT.get(info.title_type)
    if (info.title_id.upper() != tid or f"v{info.version}" != ver
            or cnmt_type != type_name):
        raise Skip("failed",
                   f"filename/CNMT identity mismatch: name says [{tid}][{ver}]"
                   f"[{type_name}], CNMT says [{info.title_id.upper()}]"
                   f"[v{info.version}][{cnmt_type}]")


# nsz is invoked via `python -c`, never via its console-script .exe shim:
# the shim breaks nsz's multiprocessing worker spawn chain on Windows when
# the parent's standard handles are redirected (WaitNamedPipe failures).
_NSZ_BOOTSTRAP = ("import sys; from vaultd.sokoban.nx_digital.nsz_codec import main; "
                  "sys.argv[0] = 'nsz'; main()")


def run_nsz(args: list[str]) -> None:
    # Always --machine-readable: nsz's progress bars are useless for this
    # workload (the slow phase shows no movement) and its enlighten bar
    # manager crashes without a real console stdin. Our own phase prints
    # are the progress report.
    def attempt() -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", _NSZ_BOOTSTRAP, "--machine-readable", *args],
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace")

    result = attempt()
    if result.returncode != 0 and "WaitNamedPipe" in (result.stderr or ""):
        result = attempt()  # spawn flake: one retry
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if "ModuleNotFoundError" in stderr and "nsz" in stderr:
            raise Skip("failed", "nsz not installed in the venv; run: uv sync")
        raise Skip("failed", f"nsz failed: {stderr[-400:]}")


def nsz_roundtrip(nsp: Path, work: Path, source_sha1: str) -> Path:
    """Compress with the archival profile; decompress; require sha1 equality.
    Returns the verified .nsz in the work directory."""
    compress_dir = work / "nsz"
    verify_dir = work / "verify"
    for directory in (compress_dir, verify_dir):
        state.clear_work(directory, work)
        directory.mkdir(parents=True)
    print(f"  nsz:    compressing (archival profile {' '.join(NSZ_COMPRESS_ARGS)})", flush=True)
    run_nsz([*NSZ_COMPRESS_ARGS, "-o", str(compress_dir), str(nsp)])
    produced = sorted(compress_dir.glob("*.nsz"))
    if len(produced) != 1:
        raise Skip("failed", f"nsz produced {len(produced)} outputs")
    print("  nsz:    round-trip verification", flush=True)
    run_nsz(["-D", "-o", str(verify_dir), str(produced[0])])
    back = sorted(verify_dir.glob("*.nsp"))
    if len(back) != 1:
        raise Skip("failed", "nsz round-trip produced no NSP")
    back_sha1 = str(hashing.digest(back[0], sha1=True)["sha1"])
    if back_sha1 != source_sha1:
        raise Skip("failed",
                   "NSZ round-trip does not reproduce the source NSP "
                   f"({back_sha1[:12]}... != {source_sha1[:12]}...)")
    state.clear_work(verify_dir, work)
    return produced[0]


def find_entity(entities_el: ET.Element, tid: str) -> ET.Element | None:
    for entity in entities_el.findall(t("entity")):
        if entity.get("identifier") == tid:
            return entity
    return None


def find_release(entity_el: ET.Element, version: str) -> ET.Element | None:
    releases_el = entity_el.find(t("releases"))
    if releases_el is None:
        return None
    for release in releases_el.findall(t("release")):
        if release.get("version") == version:
            return release
    return None


def release_files(release_el: ET.Element) -> list[ET.Element]:
    fs_el = release_el.find(t("fs"))
    return [] if fs_el is None else fs_el.findall(t("fileshared"))


def gate_path(rel_path: str, entries: dict[str, checksum.Entry]) -> None:
    issues = winlint.path_issues(rel_path)
    if issues:
        raise Skip("failed", f"gate: {'; '.join(issues)}")
    folded = rel_path.casefold()
    for existing in entries:
        if existing.casefold() == folded and existing != rel_path:
            raise Skip("failed", f"gate: case-twin of recorded path {existing}")


def check_enrolled(vdir: Path, rel_path: str, fe: ET.Element,
                   entries: dict[str, checksum.Entry]) -> None:
    """Never discard an input on the strength of a missing/stale declaration."""
    entry = entries.get(rel_path)
    if entry is None or any(str(getattr(entry, key)) != fe.get(key)
                            for key in ("size", "crc", "md5", "sha1")):
        raise Skip("failed", f"enrolled XML/checksum disagree: {rel_path}")
    dest = state.contained(vdir / "entities", rel_path)
    if not dest.is_file() or dest.stat().st_size != entry.size:
        raise Skip("failed", f"enrolled file missing or wrong size: {rel_path}")


def destination(vdir: Path, rel_path: str) -> Path:
    """Check the actual destination, including unrecorded case twins/links."""
    base = vdir / "entities"
    dest = state.contained(base, rel_path)
    current = base
    for part in Path(rel_path).parts:
        if current.is_dir():
            for child in current.iterdir():
                if child.name.casefold() == part.casefold() and child.name != part:
                    raise Skip("failed", f"gate: case-twin of physical path {child}")
        current = current / part
        if current.is_symlink() or current.is_junction():
            raise Skip("failed", f"gate: linked destination component {current}")
    return dest


def apply_metadata(entity_el: ET.Element, titledb: TitleDB | None) -> None:
    if titledb is None:
        return
    tid = entity_el.get("identifier", "")
    try:
        description, publisher, region = titledb.query(tid)
    except (AttributeError, TypeError) as exc:
        raise ValueError(f"malformed titledb metadata for {tid}: {exc}") from exc
    if description:
        print(f"  titledb: [{region}] {description}")
    if description and not entity_el.get("description"):
        entity_el.set("description", description)
    if publisher and not entity_el.get("publisher"):
        entity_el.set("publisher", publisher)


def self_audit(xml_path: Path) -> list[str]:
    from lxml import etree
    try:
        schema = etree.XMLSchema(etree.parse(str(SCHEMA)))
        if schema.validate(etree.parse(str(xml_path))):
            return []
    except etree.LxmlError as exc:
        return [str(exc)]
    return [f"line {entry.line}: {entry.message}" for entry in schema.error_log]


def ingest_one(source: Path, work_root: Path, root: ET.Element,
               entries: dict[str, checksum.Entry], vdir: Path,
               gate: HashDB, titledb: TitleDB | None,
               keys: KeySet, force_label: str | None,
               warnings: list[str]) -> str:
    parsed = parse_name(source)
    if parsed is None:
        raise Skip("failed", "filename needs one unambiguous [tid][vN][TYPE] "
                   "identity and at most one marker")
    tid, ver, type_name, markers = parsed
    incoming_gamecard = "GAMECARD" in markers
    print(f"  id:     [{tid}][{ver}][{type_name}]"
          + (f" markers={markers}" if markers else ""))

    work = work_root / source.name
    state.clear_work(work, work_root)
    work.mkdir(parents=True)

    # --- identity cross-check (every input) ---
    subject = source
    if source.suffix.lower() == ".nsz":
        print("  nsz:    decompressing input for CNMT and hashdb lookup", flush=True)
        decompress_dir = work / "decompressed"
        decompress_dir.mkdir()
        run_nsz(["-D", "-o", str(decompress_dir), str(source)])
        produced = sorted(decompress_dir.glob("*.nsp"))
        if len(produced) != 1:
            raise Skip("failed", "incoming NSZ did not decompress to one NSP")
        subject = produced[0]
    info = extract_cnmt_info(subject, work / "cnmt", keys)
    cross_check(tid, ver, type_name, info)

    print("  hash:   measuring NSP for admission", flush=True)
    subject_digest = hashing.digest(subject, sha1=True)
    subject_sha1 = str(subject_digest["sha1"]).lower()

    # --- admission gate ---
    marker = admission_marker(subject_sha1, gate, incoming_gamecard, force_label,
                              f"[{tid}][{ver}][{type_name}]", warnings,
                              title_id=info.title_id, version=info.version)

    # --- decision matrix against the enrolled release ---
    entity_tid = entity_for(tid, type_name)
    entities_el = root.find(t("entities"))
    if entities_el is None:
        entities_el = ET.SubElement(root, t("entities"))
    entity_el = find_entity(entities_el, entity_tid)
    release_el = find_release(entity_el, ver) if entity_el is not None else None
    incoming_rank = marker_priority(marker)
    rel_prefix = f"{entity_tid}/releases/{ver}"
    source_nsz_digest = None
    if release_el is not None:
        enrolled_markers: set[str] = set()
        enrolled_nsz: list[str] = []
        for fe in release_files(release_el):
            enrolled_name = fe.get("path", "")
            enrolled_marker = stored_marker(enrolled_name)
            if enrolled_marker is None:
                raise Skip("failed", f"unrecognized enrolled artifact name: {enrolled_name}")
            enrolled_identity = parse_name(Path(enrolled_name))
            if enrolled_identity is None or enrolled_identity[:3] != (tid, ver, type_name):
                raise Skip("conflict", f"release contains a different title identity: {enrolled_name}")
            check_enrolled(vdir, f"{rel_prefix}/fs/shared/{enrolled_name}", fe, entries)
            enrolled_markers.add(enrolled_marker)
            if (enrolled_marker == marker
                    and Path(enrolled_name).suffix.lower() == ".nsz"):
                enrolled_nsz.append(enrolled_name)
            if (Path(enrolled_name).suffix.lower() == subject.suffix.lower()
                    and (fe.get("sha1") or "").lower() == subject_sha1):
                raise Skip("duplicate", "NSP bytes already enrolled")
            if (source.suffix.lower() == ".nsz"
                    and Path(enrolled_name).suffix.lower() == ".nsz"):
                if source_nsz_digest is None:
                    print("  hash:   comparing input NSZ with enrolled NSZ", flush=True)
                    source_nsz_digest = hashing.digest(source, sha1=True)
                if (fe.get("sha1") or "").lower() == source_nsz_digest["sha1"]:
                    raise Skip("duplicate", "NSZ bytes already enrolled")
        if any(marker_priority(existing) < incoming_rank
               for existing in enrolled_markers):
            raise Skip("labeldup",
                       "higher-priority artifact already enrolled for this "
                       f"release; [{marker or 'vanilla'}] candidate moved to "
                       "dropzone/duplicate")
        if enrolled_nsz and source.suffix.lower() == ".nsp":
            raise Skip("conflict",
                       f"version {ver} already enrolled under '{marker or 'vanilla'}' "
                       f"as NSZ: {', '.join(sorted(enrolled_nsz))}; "
                       "NSP and NSZ hashes are not comparable; content equivalence "
                       "unverified, compression skipped; source retained for manual resolution")
        if marker in enrolled_markers:
            raise Skip("conflict",
                       f"version {ver} already enrolled under "
                       f"'{marker or 'vanilla'}' with different stored bytes; "
                       "source retained for manual resolution")

    # --- storage lane and destination gate (before compression) ---
    if marker in {"", "GAMECARD"}:
        suffix_marker = "[GAMECARD]" if marker == "GAMECARD" else ""
        stored_name = f"[{tid}][{ver}][{type_name}]{suffix_marker}.nsz"
    else:
        stored_name = f"[{tid}][{ver}][{type_name}][{marker}].nsp"

    rel_path = f"{rel_prefix}/fs/shared/{stored_name}"
    gate_path(rel_path, entries)
    if rel_path in entries:
        raise Skip("failed", f"target already recorded outside the selected release: {rel_path}")
    dest = destination(vdir, rel_path)

    # Complete metadata lookup before touching the payload. The caller supplies
    # a private catalog copy, discarded on failure.
    if entity_el is None:
        entity_el = ET.SubElement(entities_el, t("entity"), identifier=entity_tid)
    apply_metadata(entity_el, titledb)

    if marker in {"", "GAMECARD"}:
        artifact = (source if source.suffix.lower() == ".nsz"
                    else nsz_roundtrip(subject, work, subject_sha1))
    else:
        artifact = subject
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = dest.with_name(dest.name + ".ingest.tmp")
    if temporary.is_symlink() or temporary.is_junction():
        raise Skip("failed", f"linked staging path: {temporary}")
    print("  copy:   placing and checking artifact", flush=True)
    with artifact.open("rb") as incoming, temporary.open("wb") as output:
        placed = hashing.digest_stream(incoming, output=output, crc=True, md5=True, sha1=True)
    if artifact == subject and placed["sha1"] != subject_sha1:
        raise Skip("failed", "NSP changed after admission")
    if artifact == source and source_nsz_digest is not None \
            and placed["sha1"] != source_nsz_digest["sha1"]:
        raise Skip("failed", "NSZ changed after comparison")
    if hashing.digest(temporary, crc=True, md5=True, sha1=True) != placed:
        raise Skip("failed", "placed bytes differ from verified artifact")
    # Replace only this input's exact unrecorded destination (interrupted copy).
    # Never sweep other undeclared files from the release directory.
    temporary.replace(dest)

    # --- enroll phase ---
    new_release = release_el is None
    if new_release:
        releases_el = entity_el.find(t("releases"))
        if releases_el is None:
            releases_el = ET.SubElement(entity_el, t("releases"))
        release_el = ET.SubElement(releases_el, t("release"))
        release_el.set("version", ver)
        ET.SubElement(release_el, t("fs"))
    if type_name == "UPD":
        release_el.set("standalone", "false")
    fs_el = release_el.find(t("fs"))
    if fs_el is None:
        fs_el = ET.SubElement(release_el, t("fs"))
    fe = ET.SubElement(fs_el, t("fileshared"))
    fe.set("path", stored_name)
    fe.set("size", str(placed["size"]))
    fe.set("crc", str(placed["crc"]))
    fe.set("md5", str(placed["md5"]))
    fe.set("sha1", str(placed["sha1"]))
    entries[rel_path] = checksum.Entry(
        crc=str(placed["crc"]), md5=str(placed["md5"]),
        sha1=str(placed["sha1"]), size=int(placed["size"]), path=rel_path)  # type: ignore[arg-type]

    return "coexist" if not new_release else "enrolled"


def valid_force_label(label: str) -> bool:
    # These tokens would be mistaken for identity or a verified GAMECARD lane
    # on the next run, losing the meaning of the manual label.
    return (LABEL_TOKEN_RE.fullmatch(label) is not None
            and label.upper() not in {"GAMECARD", "BASE", "UPD", "DLC"}
            and re.fullmatch(r"[0-9A-Fa-f]{16}|[vV][0-9]+", label) is None)


def route_skip(source: Path, skip: Skip, *, keep_source: bool) -> None:
    if skip.verdict == "duplicate":
        if not keep_source:
            source.unlink()
        print("  source retained (--copy)" if keep_source else "  duplicate source removed")
        return
    areas = {"labeldup": "duplicate", "quarantined": "quarantine"}
    if skip.verdict not in areas:
        return
    target_dir = DROPZONE / areas[skip.verdict]
    state.contained(DROPZONE, areas[skip.verdict])
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / source.name
    number = 1
    while target.exists() or target.is_symlink():
        target = target_dir / f"{source.stem}.{number}{source.suffix}"
        number += 1
    shutil.move(str(source), str(target))
    print(f"  moved to {target}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-digital-ingest", description=__doc__)
    parser.add_argument("--copy", action="store_true",
                        help="keep dropzone sources instead of removing them on success")
    parser.add_argument("--force", metavar="LABEL", default=None,
                        help="bypass all hashdb verdicts with the "
                             "[LABEL] filename marker (bare NSP preserved)")
    parser.add_argument("--keys", type=Path,
                        default=Path.home() / ".switch" / "prod.keys")
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")
    args = parser.parse_args(argv)
    if args.force is not None and not valid_force_label(args.force):
        print(f"ERROR: invalid or reserved --force label {args.force!r}", file=sys.stderr)
        return 2

    work_root = DROPZONE / "ingest-work"
    resumed = 0
    try:
        vdir = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
        state.contained(DROPZONE, "ingest-work")
        if (work_root / "pending.json").exists():
            name = state.finish(vdir, DROPZONE, work_root, self_audit,
                                recovering=True, keep_source=args.copy)
            print(f"OK completed interrupted ingest: {name}", flush=True)
            state.clear_work(work_root / name, work_root)
            resumed = 1
        root, entries, before = state.load(vdir, self_audit)
        # Root only: keeper subdirectories are deliberately excluded.
        inputs = sorted(path for path in DROPZONE.iterdir()
                        if path.is_file() and path.suffix.lower() in {".nsp", ".nsz"})
        print(f"vault:      {vdir}")
        print(f"candidates: {len(inputs)}", flush=True)
        if not inputs:
            return 0
        if not args.keys.is_file():
            raise ValueError(f"prod.keys not found: {args.keys} (needed for CNMT identity)")
        hashdb_dir = DB_DIR / "hashdb"
        if args.force is None and not any(hashdb_dir.glob("*.xml")):
            raise ValueError(f"no hashdb dats under {hashdb_dir}; run dbsync / add dats")
        keys = KeySet.load(args.keys)
        gate = load_hashdb(hashdb_dir) if args.force is None else HashDB()
        titledb = TitleDB(DB_DIR / "titledb")
        if titledb.available():
            print(f"titledb: {DB_DIR / 'titledb'}")
        else:
            print("WARN: titledb region files not found; descriptions will be omitted")
            titledb = None
    except (OSError, ValueError, FixError, ET.ParseError, locator.LocatorError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if (work_root / "pending.json").exists():
            print("STOP pending ingest retained; rerun after resolving the reported problem")
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted before new ingest; sources retained")
        return 130

    counts = {"enrolled": 0, "coexist": 0, "duplicate": 0, "labeldup": 0,
              "conflict": 0, "quarantined": 0, "undecided": 0,
              "failed": 0}
    warnings: list[str] = []
    interrupted = False
    for index, source in enumerate(inputs, 1):
        print(f"\n[{index}/{len(inputs)}] {source.name}", flush=True)
        try:
            if source.is_symlink():
                raise ValueError("linked intake file; source retained")
            source_stamp = state.fingerprint(source)
            proposed, next_entries = deepcopy(root), dict(entries)
            try:
                lane = ingest_one(source, work_root, proposed, next_entries, vdir,
                                  gate, titledb, keys, args.force, warnings)
            except Skip as skip:
                if state.fingerprint(source) != source_stamp:
                    raise ValueError("source changed during inspection; retained")
                tag = {"duplicate": "DUP", "labeldup": "LABELDUP",
                       "conflict": "CONFLICT", "quarantined": "QUARANTINE",
                       "undecided": "UNDECIDED",
                       "failed": "FAIL"}[skip.verdict]
                print(f"{tag} {skip}", flush=True)
                route_skip(source, skip, keep_source=args.copy)
                counts[skip.verdict] += 1
                continue
            added = next_entries.keys() - entries.keys()
            if len(added) != 1:
                raise ValueError("ingest must add exactly one artifact per checkpoint")
            state.commit(vdir, DROPZONE, work_root, proposed, next_entries, before,
                         source, source_stamp, added.pop(), self_audit,
                         keep_source=args.copy)
            root, entries = proposed, next_entries
            before = state.metadata_hashes(vdir)
            counts[lane] += 1
            print("OK+ artifact added to existing release" if lane == "coexist"
                  else "OK enrolled", flush=True)
        except (OSError, ValueError, FixError, ET.ParseError) as exc:
            print(f"FAIL {type(exc).__name__}: {exc}", flush=True)
            counts["failed"] += 1
            if (work_root / "pending.json").exists():
                print("STOP pending ingest retained; rerun to finish this item first")
                break
            try:
                unchanged = state.metadata_hashes(vdir) == before
            except OSError:
                unchanged = False
            if not unchanged:
                print("STOP bookkeeping changed or became unreadable; rerun to reload it")
                break
        except KeyboardInterrupt:
            interrupted = True
            print("\nInterrupted; rerun to retry this item or finish its pending checkpoint")
            break
        finally:
            if not (work_root / "pending.json").exists():
                try:
                    state.clear_work(work_root / source.name, work_root)
                except (OSError, ValueError) as exc:
                    warnings.append(f"work cleanup for {source.name}: {exc}")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for warning in warnings:
            print(f"  WARN: {warning}")
    print(f"\nDone -- enrolled: {counts['enrolled']}, coexist: {counts['coexist']}, "
          f"duplicates: {counts['duplicate']}, label-dups: {counts['labeldup']}, "
          f"quarantined: {counts['quarantined']}, "
          f"undecided: {counts['undecided']}, "
          f"conflicts: {counts['conflict']}, failed: {counts['failed']}, "
          f"completed pending: {resumed}")
    if interrupted:
        return 130
    return 1 if counts["conflict"] or counts["failed"] or counts["quarantined"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
