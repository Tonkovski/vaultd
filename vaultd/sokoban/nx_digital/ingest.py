"""NX digital keeper: ingest NSP/NSZ artifacts from the workspace dropzone.

Intake scans ONLY the dropzone root — keeper sub-areas (fixnsp*/, duplicate/,
quarantine/, ...) are invisible to it. Anomalies are admission rejections and
are MOVED to their right position: hashdb rejection-row hits to
dropzone/quarantine/, label-priority losers to dropzone/duplicate/. Mere
byte-duplicates of enrolled artifacts are DELETED. A plain hashdb miss is
not an anomaly: the file stays in the dropzone awaiting a fresher dat or an
explicit --force LABEL.

Identity: every input's CNMT is read in-house (fixnsp machinery) and must
agree with the filename on title id, version and type. Entity grouping:
BASE and DLC titles are their own entities; an UPD enrolls under its base
entity (base = upd tid - 0x800) with standalone="false".

Storage lanes:
  * hashdb clean match  -> archival NSZ (nsz -C -K -l 22 -t 16), decompressed
                           and sha1-verified against the source before
                           enrollment; stored [tid][vN][TYPE].nsz
  * [GAMECARD] variant  -> no positive hashdb match required; known rejected
                           hashes still quarantine; same NSZ round-trip
  * --force LABEL       -> bypass every hashdb verdict (including clean and
                           rejected matches); bare NSP as [..][TYPE][LABEL].nsp
Admission priority for one (entity, version): vanilla > [GAMECARD] > [custom
label]; distinct customs coexist; the same marker with different bytes is a
conflict (left in place, resolve by hand).
"""

from __future__ import annotations

import argparse
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
    FixError, KeySet, read_meta_payload, read_pfs0_table)
from vaultd.titledb import TitleDB

SCHEMA = REPO_ROOT / "convention" / "datmeta.xsd"
DB_DIR = DB_ROOT / VAULT_NAME
NSZ_COMPRESS_ARGS = ("-C", "-K", "-l", "22", "-t", "16")

TID_RE = re.compile(r"\[([0-9A-Fa-f]{16})\]")
VER_RE = re.compile(r"\[(v\d+)\]")
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
    if not tids or not vers or not types:
        return None
    tid, ver, type_name = tids[0].upper(), vers[0], types[0].upper()
    markers: list[str] = []
    for token in MARKER_RE.findall(stem):
        upper = token.upper()
        if re.fullmatch(r"[0-9A-F]{16}", upper) or re.fullmatch(r"V\d+", upper) \
                or upper in {"BASE", "UPD", "DLC"}:
            continue
        markers.append("GAMECARD" if upper == "GAMECARD" else token)
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


def load_hashdb(hashdb: Path) -> dict[str, dict[str, bool]]:
    """sha1(lower) -> {ROM filename: is_rejection_row}.

    Identical ROM filenames across overlapping DATs collapse. Keep the actual
    filename so admission can check its bracketed title ID."""
    lookup: dict[str, dict[str, bool]] = {}
    dats = sorted(hashdb.glob("*.xml"))
    print(f"hashdb: {hashdb} ({len(dats)} dat(s))")
    for dat in dats:
        root = ET.parse(dat).getroot()
        for game in root.iter("game"):
            for rom in game.iter("rom"):
                sha1 = rom.get("sha1")
                if not sha1:
                    continue
                row_reject = bool(rejection_reasons(game, rom))
                name = rom.get("name") or ""
                rows = lookup.setdefault(sha1.lower(), {})
                rows[name] = rows.get(name, False) or row_reject
    print(f"  {len(lookup)} rom hashes indexed")
    return lookup


def admission_marker(subject_sha1: str, gate: dict[str, dict[str, bool]],
                     incoming_gamecard: bool, force_label: str | None,
                     identity: str, warnings: list[str], *, title_id: str) -> str:
    """Explicit force overrides the database; ordinary ingest rejects any bad hit."""
    if force_label is not None:
        print(f"  gate:   --force [{force_label}], hashdb bypassed")
        return force_label
    rows = gate.get(subject_sha1, {})
    rejected = sorted(name for name, reject in rows.items() if reject)
    if rejected:
        raise Skip("quarantined", "hashdb rejection row(s): " + "; ".join(rejected))
    if incoming_gamecard:
        print("  gate:   [GAMECARD] variant, positive hashdb match not required")
        return "GAMECARD"
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
        output.write(source.read(metas[0].size))
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
        if directory.exists():
            shutil.rmtree(directory)
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
    shutil.rmtree(verify_dir)
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


def sweep_unrecorded(vdir: Path, rel_prefix: str,
                     entries: dict[str, checksum.Entry]) -> None:
    release_dir = vdir / "entities" / Path(*rel_prefix.split("/"))
    if not release_dir.is_dir():
        return
    for path in sorted(release_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = f"{rel_prefix}/{path.relative_to(release_dir).as_posix()}"
        if rel not in entries:
            print(f"  note:   removing unrecorded leftover {rel}")
            path.unlink()
    for path in sorted(release_dir.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()


def apply_metadata(entity_el: ET.Element, titledb: TitleDB | None) -> None:
    if titledb is None:
        return
    tid = entity_el.get("identifier", "")
    description, publisher, region = titledb.query(tid)
    if description:
        print(f"  titledb: [{region}] {description}")
    if description and not entity_el.get("description"):
        entity_el.set("description", description)
    if publisher and not entity_el.get("publisher"):
        entity_el.set("publisher", publisher)


def self_audit(xml_path: Path) -> list[str]:
    from lxml import etree
    schema = etree.XMLSchema(etree.parse(str(SCHEMA)))
    if schema.validate(etree.parse(str(xml_path))):
        return []
    return [f"line {entry.line}: {entry.message}" for entry in schema.error_log]


def ingest_one(source: Path, work_root: Path, root: ET.Element,
               entries: dict[str, checksum.Entry], vdir: Path,
               gate: dict[str, dict[str, bool]], titledb: TitleDB | None,
               keys: KeySet, force_label: str | None,
               warnings: list[str]) -> str:
    parsed = parse_name(source)
    if parsed is None:
        raise Skip("failed", "filename lacks [tid][vN][TYPE] identity")
    tid, ver, type_name, markers = parsed
    incoming_gamecard = "GAMECARD" in markers
    print(f"  id:     [{tid}][{ver}][{type_name}]"
          + (f" markers={markers}" if markers else ""))

    work = work_root / source.name
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    # --- identity cross-check (every input) ---
    subject = source
    if source.suffix.lower() == ".nsz":
        decompress_dir = work / "decompressed"
        decompress_dir.mkdir()
        run_nsz(["-D", "-o", str(decompress_dir), str(source)])
        produced = sorted(decompress_dir.glob("*.nsp"))
        if len(produced) != 1:
            raise Skip("failed", "incoming NSZ did not decompress to one NSP")
        subject = produced[0]
    info = extract_cnmt_info(subject, work / "cnmt", keys)
    cross_check(tid, ver, type_name, info)

    subject_digest = hashing.digest(subject, crc=True, md5=True, sha1=True)
    subject_sha1 = str(subject_digest["sha1"]).lower()

    # --- admission gate ---
    marker = admission_marker(subject_sha1, gate, incoming_gamecard, force_label,
                              f"[{tid}][{ver}][{type_name}]", warnings, title_id=info.title_id)

    # --- decision matrix against the enrolled release ---
    entity_tid = entity_for(tid, type_name)
    entities_el = root.find(t("entities"))
    if entities_el is None:
        entities_el = ET.SubElement(root, t("entities"))
    entity_el = find_entity(entities_el, entity_tid)
    release_el = find_release(entity_el, ver) if entity_el is not None else None
    incoming_rank = marker_priority(marker)
    if release_el is not None:
        enrolled_markers: set[str] = set()
        for fe in release_files(release_el):
            enrolled_marker = stored_marker(fe.get("path", ""))
            if enrolled_marker is None:
                continue
            enrolled_markers.add(enrolled_marker)
            if (fe.get("sha1") or "").lower() == subject_sha1:
                raise Skip("duplicate", "bytes already enrolled; source deleted")
        if any(marker_priority(existing) < incoming_rank
               for existing in enrolled_markers):
            raise Skip("labeldup",
                       "higher-priority artifact already enrolled for this "
                       f"release; [{marker or 'vanilla'}] candidate moved to "
                       "dropzone/duplicate")
        if marker in enrolled_markers:
            raise Skip("conflict",
                       f"version {ver} already enrolled under "
                       f"'{marker or 'vanilla'}' with different content: "
                       "distinct variant, resolve by hand")

    # --- storage lane ---
    if marker in {"", "GAMECARD"}:
        if subject is source and source.suffix.lower() == ".nsz":
            artifact = source
        elif source.suffix.lower() == ".nsz":
            artifact = source  # original NSZ verified via its own decompression
        else:
            artifact = nsz_roundtrip(subject, work, subject_sha1)
        suffix_marker = "[GAMECARD]" if marker == "GAMECARD" else ""
        stored_name = f"[{tid}][{ver}][{type_name}]{suffix_marker}.nsz"
    else:
        artifact = subject
        stored_name = f"[{tid}][{ver}][{type_name}][{marker}].nsp"

    rel_prefix = f"{entity_tid}/releases/{ver}"
    rel_path = f"{rel_prefix}/fs/shared/{stored_name}"
    gate_path(rel_path, entries)
    sweep_unrecorded(vdir, rel_prefix, entries)
    dest = vdir / "entities" / Path(*rel_path.split("/"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact, dest)
    placed = hashing.digest(dest, crc=True, md5=True, sha1=True)
    expected_sha1 = (str(hashing.digest(artifact, sha1=True)["sha1"])
                     if artifact != subject else subject_sha1)
    if str(placed["sha1"]) != expected_sha1:
        dest.unlink()
        raise Skip("failed", "placed bytes differ from verified artifact")
    if release_el is not None and any(
            (fe.get("sha1") or "").lower() == str(placed["sha1"]).lower()
            for fe in release_files(release_el)):
        dest.unlink()
        raise Skip("duplicate",
                   "archival form already enrolled (deterministic NSZ); "
                   "source deleted")

    # --- enroll phase ---
    if entity_el is None:
        entity_el = ET.SubElement(entities_el, t("entity"))
        entity_el.set("identifier", entity_tid)
    apply_metadata(entity_el, titledb)
    new_release = release_el is None
    if new_release:
        releases_el = entity_el.find(t("releases"))
        if releases_el is None:
            releases_el = ET.SubElement(entity_el, t("releases"))
        release_el = ET.SubElement(releases_el, t("release"))
        release_el.set("version", ver)
        if type_name == "UPD":
            release_el.set("standalone", "false")
        ET.SubElement(release_el, t("fs"))
    fs_el = release_el.find(t("fs"))
    fe = ET.SubElement(fs_el, t("fileshared"))
    fe.set("path", stored_name)
    fe.set("size", str(placed["size"]))
    fe.set("crc", str(placed["crc"]))
    fe.set("md5", str(placed["md5"]))
    fe.set("sha1", str(placed["sha1"]))
    entries[rel_path] = checksum.Entry(
        crc=str(placed["crc"]), md5=str(placed["md5"]),
        sha1=str(placed["sha1"]), size=int(placed["size"]), path=rel_path)  # type: ignore[arg-type]

    shutil.rmtree(work, ignore_errors=True)
    return "coexist" if not new_release else "enrolled"


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

    if args.force is not None and not LABEL_TOKEN_RE.match(args.force):
        print(f"ERROR: invalid --force label {args.force!r}", file=sys.stderr)
        return 2
    if not args.keys.exists():
        print(f"ERROR: prod.keys not found: {args.keys} "
              "(needed for the CNMT identity cross-check)", file=sys.stderr)
        return 2
    try:
        vdir = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    xml_path = vdir / "datmeta.xml"
    if not xml_path.is_file():
        print(f"ERROR: missing {xml_path}", file=sys.stderr)
        return 2
    hashdb_dir = DB_DIR / "hashdb"
    if args.force is None and not any(hashdb_dir.glob("*.xml")):
        print(f"ERROR: no hashdb dats under {hashdb_dir}; run dbsync / add dats",
              file=sys.stderr)
        return 2

    keys = KeySet.load(args.keys)
    gate = load_hashdb(hashdb_dir) if args.force is None else {}
    titledb = TitleDB(DB_DIR / "titledb")
    if titledb.available():
        print(f"titledb: {DB_DIR / 'titledb'}")
    else:
        print("WARN: titledb region files not found; descriptions will be omitted")
        titledb = None

    # root-only scan: sub-directories of the dropzone are keeper territory.
    inputs = sorted(path for path in DROPZONE.iterdir()
                    if path.is_file() and path.suffix.lower() in {".nsp", ".nsz"})
    print(f"vault:      {vdir}")
    print(f"candidates: {len(inputs)}")
    if not inputs:
        return 0

    tree = ET.parse(xml_path)
    root = tree.getroot()
    ck_path = vdir / "entities.checksum"
    entries, problems = checksum.parse_file(ck_path)
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 2

    work_root = DROPZONE / "ingest-work"
    counts = {"enrolled": 0, "coexist": 0, "duplicate": 0, "labeldup": 0,
              "conflict": 0, "quarantined": 0, "undecided": 0, "failed": 0}
    warnings: list[str] = []
    for index, source in enumerate(inputs, 1):
        print(f"\n[{index}/{len(inputs)}] {source.name}")
        try:
            lane = ingest_one(source, work_root, root, entries, vdir, gate,
                              titledb, keys, args.force, warnings)
        except Skip as skip:
            tag = {"duplicate": "DUP", "labeldup": "LABELDUP",
                   "conflict": "CONFLICT", "quarantined": "QUARANTINE",
                   "undecided": "UNDECIDED", "failed": "FAIL"}[skip.verdict]
            print(f"{tag} {skip}")
            counts[skip.verdict] += 1
            if skip.verdict == "duplicate" and not args.copy:
                source.unlink()
            elif skip.verdict in {"labeldup", "quarantined"}:
                target_dir = DROPZONE / ("duplicate" if skip.verdict == "labeldup"
                                         else "quarantine")
                target_dir.mkdir(parents=True, exist_ok=True)
                target = target_dir / source.name
                if target.exists():
                    target.unlink()
                shutil.move(str(source), str(target))
                print(f"  moved to {target_dir}")
            continue
        catwrite.bump_stamp(root)
        catwrite.sort_tree(root)
        checksum.write_file(vdir / "entities.checksum", entries)
        catwrite.write_xml(xml_path, root)
        audit = self_audit(xml_path)
        if audit:
            for line in audit:
                print(f"ERROR: self-audit failed: {line}", file=sys.stderr)
            return 1
        if not args.copy:
            source.unlink()
        counts[lane] += 1
        print("OK+ artifact added to existing release" if lane == "coexist"
              else "OK enrolled")

    shutil.rmtree(work_root, ignore_errors=True)
    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for warning in warnings:
            print(f"  WARN: {warning}")
    print(f"\nDone -- enrolled: {counts['enrolled']}, coexist: {counts['coexist']}, "
          f"duplicates: {counts['duplicate']}, label-dups: {counts['labeldup']}, "
          f"quarantined: {counts['quarantined']}, undecided: {counts['undecided']}, "
          f"conflicts: {counts['conflict']}, failed: {counts['failed']}")
    return 1 if counts["conflict"] or counts["failed"] or counts["quarantined"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
