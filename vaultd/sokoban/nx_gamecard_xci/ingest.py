"""NX gamecard keeper: ingest XCI dump sets from the dropzone.

A set is one (title id, version): the XCI plus its four per-cartridge
evidence bins (Card ID Set, Card UID, Certificate, Initial Data). Identity
comes from the dump filenames — `[16-hex]` and `[vN]` anywhere in the stem;
any title prefix before them is purged by canonical renaming on store.

Gates and lanes:
  * switchtdb.xml (db/<vault>/) is a REQUIRED hash gate: an XCI whose sha1 is
    unknown to GameTDB is quarantined (left in the dropzone) — unless
    --force LABEL is given, which enrolls the miss with the file-level
    provenance marker [LABEL] appended to the stored XCI filename (no entity
    comment; gate hits still enroll vanilla). e.g. --force NoHASHDB.
  * Label system (as the old digital vault): admission priority for one
    (title, version) is vanilla > [any label]. A labeled candidate against a
    vanilla-holding release moves to dropzone/duplicate/. A later vanilla is
    still admitted and coexists as a second fileshared in the same release;
    distinct labels coexist when no vanilla blocks them; the same label with
    different bytes is a conflict. Labels never touch fileinstance names —
    instance sets belong to the cartridge, not to a label: label traffic
    never duplicates, disturbs, or removes fileinstance evidence, and Card
    UID dedup spans the whole release.
  * titledb (db/<vault>/titledb/) fills description/publisher, fill-if-empty,
    via the shared NACP-ordered ladder (vaultd.titledb.REGION_PRIORITY).
  * Same version + same XCI + known Card UID  -> duplicate cartridge, no-op.
  * Same version + same XCI + new Card UID    -> new instance set (uuid4).
  * Same version + different XCI              -> pressing/variant CONFLICT,
    resolved by a human; no destructive lane exists.
  * No release date is recorded: no trustworthy source exists.

Batch discipline (convention/datmeta.md): metadata first, land as copies,
sweep this release's unrecorded crash debris, checkpoint checksum-then-xml
atomically, self-audit, remove dropzone sources last.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

from vaultd import catwrite, checksum, hashing, locator, winlint
from vaultd.catwrite import t
from vaultd.locator import DB_ROOT, DROPZONE, REPO_ROOT
from vaultd.sokoban.nx_gamecard_xci import VAULT_NAME
from vaultd.titledb import TitleDB

SCHEMA = REPO_ROOT / "convention" / "datmeta.xsd"
DB_DIR = DB_ROOT / VAULT_NAME

TITLEID_RE = re.compile(r"\[([0-9A-Fa-f]{16})\]")
VERSION_RE = re.compile(r"\[(v\d+)\]")
PAREN_RE = re.compile(r"\(([^)]+)\)")
BIN_TYPES = ("Card ID Set", "Card UID", "Certificate", "Initial Data")
EXPECTED = frozenset(("xci", *BIN_TYPES))


class Skip(Exception):
    def __init__(self, verdict: str, reason: str) -> None:
        super().__init__(reason)
        self.verdict = verdict


def parse_file(path: Path) -> tuple[str, str, str] | None:
    """(title_id, version, kind) from a dump filename; None if unrecognised."""
    name = path.stem
    tids = TITLEID_RE.findall(name)
    vers = VERSION_RE.findall(name)
    if not tids or not vers:
        return None
    tid, ver = tids[0].upper(), vers[0]
    ext = path.suffix.lower()
    if ext == ".xci":
        return tid, ver, "xci"
    if ext == ".bin":
        groups = PAREN_RE.findall(name)
        if not groups:
            return None
        kind = groups[-1].strip()
        # nxdumptool may append a CRC32 paren group after the bin type
        if re.fullmatch(r"[0-9A-Fa-f]{8}", kind) and len(groups) >= 2:
            kind = groups[-2].strip()
        return (tid, ver, kind) if kind in BIN_TYPES else None
    return None


def group_files(paths: list[Path]) -> tuple[dict, list[Path]]:
    groups: dict[tuple[str, str], dict[str, Path]] = defaultdict(dict)
    unrecognised: list[Path] = []
    for path in paths:
        parsed = parse_file(path)
        if parsed is None:
            unrecognised.append(path)
            continue
        tid, ver, kind = parsed
        if kind in groups[(tid, ver)]:
            unrecognised.append(path)
        else:
            groups[(tid, ver)][kind] = path
    return groups, unrecognised


def load_switchtdb(path: Path) -> dict[str, list[str]]:
    """sha1(lower) -> every claiming game name.

    Identical cart content ships in several regions, so one hash may map to
    many entries — kept one-to-many so a clash surfaces as a warning instead
    of an arbitrary single name. Pure presence gate either way; versions and
    identity come from filenames, metadata from titledb."""
    print(f"switchtdb: {path}")
    lookup: dict[str, list[str]] = {}
    root = ET.parse(path).getroot()
    for game in root.iter("game"):
        for rom in game.iter("rom"):
            sha1 = rom.get("sha1")
            if sha1:
                lookup.setdefault(sha1.lower(), []).append(game.get("name") or "")
    print(f"  {len(lookup)} rom hashes indexed")
    return lookup


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


def release_shared(release_el: ET.Element) -> dict[str, str]:
    """sha1(lower) -> stored filename, for every fileshared of the release."""
    fs_el = release_el.find(t("fs"))
    if fs_el is None:
        return {}
    out: dict[str, str] = {}
    for fe in fs_el.findall(t("fileshared")):
        sha1 = fe.get("sha1")
        path = fe.get("path")
        if sha1 and path:
            out[sha1.lower()] = path
    return out


STORED_XCI_RE = re.compile(
    r"^\[[0-9A-Fa-f]{16}\]\[v\d+\](?:\[([A-Za-z0-9][A-Za-z0-9_-]*)\])?\.xci$")
LABEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def stored_label(filename: str) -> str:
    match = STORED_XCI_RE.match(filename)
    if match is None:
        return ""
    return f"[{match.group(1)}]" if match.group(1) else ""


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
    """Remove this release's crash debris: files on disk but not recorded.

    Ingest is the sole creator under entities/, so an unrecorded file inside
    the release it is about to (re)work is its own interrupted leftover."""
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


def enrolled_uids(vdir: Path, entries: dict[str, checksum.Entry],
                  tid: str, ver: str) -> list[bytes]:
    """Raw bytes of every RECORDED Card UID bin of this release."""
    prefix = f"{tid}/releases/{ver}/fs/instance/"
    uids = []
    for rel in entries:
        if rel.startswith(prefix) and rel.endswith("(Card UID).bin"):
            uids.append((vdir / "entities" / Path(*rel.split("/"))).read_bytes())
    return uids


def apply_metadata(entity_el: ET.Element, description: str | None,
                   publisher: str | None) -> None:
    if description and not entity_el.get("description"):
        entity_el.set("description", description)
    if publisher and not entity_el.get("publisher"):
        entity_el.set("publisher", publisher)


def land_file(source: Path, dest: Path) -> dict[str, object]:
    """Copy, then measure the placed product (never the source)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    return hashing.digest(dest, crc=True, md5=True, sha1=True)


def ingest_set(tid: str, ver: str, files: dict[str, Path], root: ET.Element,
               entries: dict[str, checksum.Entry], vdir: Path,
               gate: dict[str, list[str]], titledb: TitleDB | None,
               warnings: list[str], force_label: str | None) -> str:
    # --- metadata phase: no disk mutation ---
    src = hashing.digest(files["xci"], crc=True, md5=True, sha1=True)
    src_sha1 = str(src["sha1"]).lower()
    gate_names = gate.get(src_sha1)
    if gate_names is None:
        if force_label is None:
            raise Skip("quarantined",
                       f"not a known GameTDB dump (sha1 {src_sha1[:12]}...); "
                       "left in dropzone (--force LABEL to force-enroll)")
        label = f"[{force_label}]"
        print(f"  switchtdb: miss -- force-enroll with {label} marker")
    else:
        label = ""
        if len(gate_names) > 1:
            warn = (f"[{tid}][{ver}] sha1 claimed by {len(gate_names)} switchtdb "
                    f"entries: {'; '.join(gate_names)}")
            warnings.append(warn)
            print(f"  WARN: {warn}")
        print(f"  switchtdb match: {gate_names[0]}")
    description = publisher = None
    if titledb is not None:
        description, publisher, region = titledb.query(tid)
        print(f"  titledb: [{region}] {description}" if description
              else "  titledb: miss, description omitted")

    entities_el = root.find(t("entities"))
    if entities_el is None:
        entities_el = ET.SubElement(root, t("entities"))
    entity_el = find_entity(entities_el, tid)
    release_el = find_release(entity_el, ver) if entity_el is not None else None

    # --- decision matrix against the enrolled release ---
    incoming_uid = files["Card UID"].read_bytes()
    same_cartridge = release_el is not None and any(
        incoming_uid == u for u in enrolled_uids(vdir, entries, tid, ver))
    add_xci = True
    add_instance = not same_cartridge
    if release_el is not None:
        enrolled = release_shared(release_el)
        if src_sha1 in enrolled:
            add_xci = False
            if same_cartridge:
                raise Skip("duplicate", "cartridge already enrolled (Card UID match)")
        else:
            labels = {stored_label(name) for name in enrolled.values()}
            if label and "" in labels:
                raise Skip("labeldup",
                           "vanilla artifact already enrolled for this release; "
                           f"{label} candidate moved to dropzone/duplicate")
            if label in labels:
                raise Skip("conflict",
                           f"version {ver} already enrolled under the same label "
                           f"'{label or 'vanilla'}' with different content: "
                           "distinct pressing/variant, resolve by hand")
            # later higher-priority (vanilla after [NoHASHDB]): coexist.
        if not add_xci and not add_instance:
            raise Skip("duplicate", "cartridge already enrolled (Card UID match)")

    # --- landing phase ---
    rel_prefix = f"{tid}/releases/{ver}"
    sweep_unrecorded(vdir, rel_prefix, entries)

    set_uuid = str(uuid.uuid4())
    placed: dict[str, tuple[str, dict[str, object]]] = {}  # rel -> (kind, digest)

    if add_xci:
        xci_name = f"[{tid}][{ver}]{label}.xci"
        xci_rel = f"{rel_prefix}/fs/shared/{xci_name}"
        gate_path(xci_rel, entries)
        digest = land_file(files["xci"], vdir / "entities" / Path(*xci_rel.split("/")))
        if digest != src:
            (vdir / "entities" / Path(*xci_rel.split("/"))).unlink()
            raise Skip("failed", "placed XCI differs from source; nothing enrolled")
        placed[xci_rel] = ("xci", digest)

    if add_instance:
        for kind in BIN_TYPES:
            bin_name = f"[{tid}][{ver}] ({kind}).bin"
            bin_rel = f"{rel_prefix}/fs/instance/{set_uuid}/{bin_name}"
            gate_path(bin_rel, entries)
            digest = land_file(files[kind],
                               vdir / "entities" / Path(*bin_rel.split("/")))
            placed[bin_rel] = (kind, digest)

    # --- enroll phase ---
    if entity_el is None:
        entity_el = ET.SubElement(entities_el, t("entity"))
        entity_el.set("identifier", tid)
    apply_metadata(entity_el, description, publisher)

    new_release = release_el is None
    if new_release:
        releases_el = entity_el.find(t("releases"))
        if releases_el is None:
            releases_el = ET.SubElement(entity_el, t("releases"))
        release_el = ET.SubElement(releases_el, t("release"))
        release_el.set("version", ver)
        ET.SubElement(release_el, t("fs"))
    fs_el = release_el.find(t("fs"))
    for rel, (kind, digest) in placed.items():
        if kind == "xci":
            fe = ET.SubElement(fs_el, t("fileshared"))
            fe.set("path", rel.rsplit("/", 1)[-1])
            fe.set("size", str(digest["size"]))
            fe.set("crc", str(digest["crc"]))
            fe.set("md5", str(digest["md5"]))
            fe.set("sha1", str(digest["sha1"]))
    if new_release:
        for kind in BIN_TYPES:
            fi = ET.SubElement(fs_el, t("fileinstance"))
            fi.set("path", f"[{tid}][{ver}] ({kind}).bin")

    for rel, (kind, digest) in placed.items():
        entries[rel] = checksum.Entry(
            crc=str(digest["crc"]), md5=str(digest["md5"]),
            sha1=str(digest["sha1"]), size=int(digest["size"]), path=rel)  # type: ignore[arg-type]

    if not new_release and add_xci:
        return "coexist"
    return "instance" if not new_release else "enrolled"


def self_audit(xml_path: Path) -> list[str]:
    from lxml import etree
    schema = etree.XMLSchema(etree.parse(str(SCHEMA)))
    if schema.validate(etree.parse(str(xml_path))):
        return []
    return [f"line {e.line}: {e.message}" for e in schema.error_log]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-gamecard-ingest", description=__doc__)
    parser.add_argument("--recursive", action="store_true",
                        help="scan the dropzone recursively")
    parser.add_argument("--copy", action="store_true",
                        help="keep dropzone sources instead of removing them on success")
    parser.add_argument("--force", metavar="LABEL", default=None,
                        help="force-enroll switchtdb-miss sets with the "
                             "[LABEL] filename marker (e.g. --force NoHASHDB)")
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")
    args = parser.parse_args(argv)

    if args.force is not None and not LABEL_TOKEN_RE.match(args.force):
        print(f"ERROR: invalid --force label {args.force!r} "
              "(bare token, [A-Za-z0-9][A-Za-z0-9_-]*; brackets are added)",
              file=sys.stderr)
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

    gate_path_file = DB_DIR / "switchtdb.xml"
    if not gate_path_file.is_file():
        print(f"ERROR: switchtdb hash gate not found: {gate_path_file}; "
              "run dbsync first", file=sys.stderr)
        return 2
    gate = load_switchtdb(gate_path_file)

    titledb = TitleDB(DB_DIR / "titledb")
    if titledb.available():
        print(f"titledb: {DB_DIR / 'titledb'}")
    else:
        print("WARN: titledb region files not found; descriptions will be omitted")
        titledb = None

    scan = DROPZONE.rglob("*") if args.recursive else DROPZONE.glob("*")
    paths = sorted(p for p in scan if p.is_file()
                   and p.suffix.lower() in (".xci", ".bin"))
    groups, unrecognised = group_files(paths)
    for path in unrecognised:
        print(f"WARN: unrecognised: {path.name}")
    print(f"vault:      {vdir}")
    print(f"sets:       {len(groups)}")
    if not groups:
        return 0

    tree = ET.parse(xml_path)
    root = tree.getroot()
    entries, problems = checksum.parse_file(vdir / "entities.checksum")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 2

    counts = {"enrolled": 0, "instance": 0, "coexist": 0, "duplicate": 0,
              "labeldup": 0, "conflict": 0, "quarantined": 0, "failed": 0}
    warnings: list[str] = []
    for index, ((tid, ver), files) in enumerate(sorted(groups.items()), 1):
        print(f"\n[{index}/{len(groups)}] [{tid}][{ver}]")
        missing = EXPECTED - files.keys()
        if missing:
            print(f"FAIL incomplete set: missing {', '.join(sorted(missing))}")
            counts["failed"] += 1
            continue
        try:
            lane = ingest_set(tid, ver, files, root, entries, vdir, gate,
                              titledb, warnings, args.force)
        except Skip as skip:
            tag = {"duplicate": "DUP", "labeldup": "LABELDUP",
                   "conflict": "CONFLICT", "quarantined": "QUARANTINE",
                   "failed": "FAIL"}[skip.verdict]
            print(f"{tag} {skip}")
            counts[skip.verdict] += 1
            if skip.verdict == "duplicate" and not args.copy:
                for path in files.values():
                    path.unlink()
                print("  sources removed (already enrolled)")
            elif skip.verdict == "labeldup":
                duplicate_dir = DROPZONE / "duplicate"
                duplicate_dir.mkdir(parents=True, exist_ok=True)
                for path in files.values():
                    target = duplicate_dir / path.name
                    if target.exists():
                        target.unlink()
                    shutil.move(str(path), str(target))
                print(f"  set moved to {duplicate_dir}")
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
            for path in files.values():
                path.unlink()
        counts[lane] += 1
        print({"instance": "OK+ instance added",
               "coexist": "OK+ higher-priority artifact added to release",
               "enrolled": "OK enrolled"}[lane])

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for warn in warnings:
            print(f"  WARN: {warn}")
    print(f"\nDone -- enrolled: {counts['enrolled']}, "
          f"instances: {counts['instance']}, coexist: {counts['coexist']}, "
          f"duplicates: {counts['duplicate']}, label-dups: {counts['labeldup']}, "
          f"quarantined: {counts['quarantined']}, conflicts: {counts['conflict']}, "
          f"failed: {counts['failed']}")
    return 1 if counts["conflict"] or counts["failed"] or counts["quarantined"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
