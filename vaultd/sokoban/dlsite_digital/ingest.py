"""DLSite keeper: ingest dropzone zips into the vault.

Intake is the workspace dropzone/ (runtime-side; there is no source
parameter). Files are *.zip carrying exactly one DLSite product id
(RJ/BJ/VJ + 6-8 digits) in the filename; anything else is not this keeper's
business and is skipped with a warning.

Version rule: the newest date in the DLSite product page's 更新情報 block
(software works); works without that block use the API releaseDate. Both as
YYYYMMDD stamps, JST.

Ingest contract and batch discipline (convention/datmeta.md): gate names,
metadata first (strict: any remote hiccup fails the candidate, source
untouched), land as a copy, re-measure the placed product, checkpoint
checksum-then-xml atomically, self-audit against the XSD, and remove the
dropzone source last — so a Ctrl+C anywhere leaves a state the next run
carries through silently. No destructive lane exists: a differing hash under
an enrolled version is a conflict to be resolved by a human, never an
overwrite.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vaultd import catwrite, checksum, hashing, locator, winlint
from vaultd.catwrite import t
from vaultd.locator import REPO_ROOT
from vaultd.sokoban.dlsite_digital import VAULT_NAME

API_URL = "https://dlwatcher.com/product/{}.json"
FALLBACK_PAGE_URL = "https://www.dlsite.com/maniax/work/=/product_id/{}.html"
SCHEMA = REPO_ROOT / "convention" / "datmeta.xsd"

ID_RE = re.compile(r"(?i)(?<![A-Z0-9])(RJ|BJ|VJ)\d{6,8}(?![A-Z0-9])")
DATE_JP_RE = re.compile(r"([0-9]{4})年\s*([0-9]{1,2})月\s*([0-9]{1,2})日")
VERSION_UP_START = 'id="version_up"'
VERSION_UP_END = "<!-- /version up -->"
JST = timezone(timedelta(hours=9))


class Skip(Exception):
    """Candidate cannot proceed; carries the verdict label."""

    def __init__(self, verdict: str, reason: str) -> None:
        super().__init__(reason)
        self.verdict = verdict


def http_get(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": "vaultd/0.1",
        "Cookie": "adultchecked=1",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_identifier(path: Path) -> str:
    found = {m.group(0).upper() for m in ID_RE.finditer(path.stem)}
    if not found:
        raise ValueError("no DLSite product id in filename")
    if len(found) > 1:
        raise ValueError(f"multiple product ids in filename: {', '.join(sorted(found))}")
    return next(iter(found))


def latest_update_stamp(html: str) -> str | None:
    """Newest 更新情報 date as YYYYMMDD, or None when the block is absent."""
    start = html.find(VERSION_UP_START)
    if start < 0:
        return None
    end = html.find(VERSION_UP_END, start)
    block = html[start:end] if end > 0 else html[start:start + 30000]
    dates = [(int(y), int(m), int(d)) for y, m, d in DATE_JP_RE.findall(block)]
    if not dates:
        return None
    y, m, d = max(dates)
    return f"{y:04d}{m:02d}{d:02d}"


def release_date_jst(meta: dict) -> tuple[str, str]:
    """API releaseDate -> (YYYY-MM-DD attr, YYYYMMDD stamp), JST; empty if absent."""
    iso = str(meta.get("releaseDate") or "")
    if not iso:
        return "", ""
    try:
        moment = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(JST)
    except ValueError:
        return "", ""
    return moment.date().isoformat(), f"{moment.date():%Y%m%d}"


def find_entity(entities_el: ET.Element, identifier: str) -> ET.Element | None:
    for entity in entities_el.findall(t("entity")):
        if entity.get("identifier") == identifier:
            return entity
    return None


def entity_sha1s(entity_el: ET.Element) -> dict[str, str]:
    """sha1 -> release version, across every enrolled release."""
    out: dict[str, str] = {}
    releases_el = entity_el.find(t("releases"))
    if releases_el is None:
        return out
    for release in releases_el.findall(t("release")):
        fs_el = release.find(t("fs"))
        if fs_el is None:
            continue
        for fe in fs_el.findall(t("fileshared")):
            sha1 = fe.get("sha1")
            if sha1:
                out[sha1] = release.get("version", "")
    return out


def apply_metadata(entity_el: ET.Element, meta: dict) -> None:
    """Fill-if-empty: never overwrite what the catalog already says."""
    title = str(meta.get("productName") or "")
    maker = str(meta.get("makerName") or "")
    store_url = str(meta.get("storeDisplayURL") or meta.get("storeURL") or "")
    if title and not entity_el.get("description"):
        entity_el.set("description", title)
    if maker and not entity_el.get("developer"):
        entity_el.set("developer", maker)
    if store_url:
        urls_el = entity_el.find(t("urls"))
        if urls_el is None:
            urls_el = ET.SubElement(entity_el, t("urls"))
        if store_url not in {u.text for u in urls_el.findall(t("url"))}:
            ET.SubElement(urls_el, t("url")).text = store_url


def gate_path(rel_path: str, entries: dict[str, checksum.Entry]) -> None:
    """Ingest contract step 1: V2 names and case-twins never pass."""
    issues = winlint.path_issues(rel_path)
    if issues:
        raise Skip("failed", f"gate: {'; '.join(issues)}")
    folded = rel_path.casefold()
    for existing in entries:
        if existing.casefold() == folded and existing != rel_path:
            raise Skip("failed", f"gate: case-twin of recorded path {existing}")


def resolve_version(pid: str, meta: dict | None, page_html: str | None) -> str:
    if page_html is not None:
        stamp = latest_update_stamp(page_html)
        if stamp:
            return stamp
    if meta is not None:
        _, stamp = release_date_jst(meta)
        if stamp:
            return stamp
    raise Skip("failed", "cannot resolve version (no 更新情報, no releaseDate)")


def ingest_one(source: Path, pid: str, tree_root: ET.Element,
               entries: dict[str, checksum.Entry], vdir: Path,
               args: argparse.Namespace) -> str:
    meta: dict | None = None
    page_html: str | None = None

    if args.no_api:
        raise Skip("failed", "--no-api cannot resolve a version; nothing enrolled")
    try:
        meta = json.loads(http_get(API_URL.format(pid)).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - network zoo
        raise Skip("failed", f"metadata lookup failed: {exc}") from exc
    page_url = (str(meta.get("storeDisplayURL") or meta.get("storeURL") or "")
                or FALLBACK_PAGE_URL.format(pid))
    try:
        page_html = http_get(page_url).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        raise Skip("failed", f"product page fetch failed: {exc}") from exc

    version = resolve_version(pid, meta, page_html)
    print(f"  version: {version}")

    entities_el = tree_root.find(t("entities"))
    if entities_el is None:
        entities_el = ET.SubElement(tree_root, t("entities"))
    entity_el = find_entity(entities_el, pid)

    src_digest = hashing.digest(source, crc=True, md5=True, sha1=True)

    if entity_el is not None:
        known = entity_sha1s(entity_el)
        if src_digest["sha1"] in known:
            # Already enrolled identically: complete batch-discipline step 4.
            if not args.copy:
                source.unlink()
                detail = "dropzone source removed"
            else:
                detail = "source kept (--copy)"
            raise Skip("duplicate",
                       f"sha1 already enrolled as version {known[src_digest['sha1']]}; "
                       + detail)
        releases_el = entity_el.find(t("releases"))
        if releases_el is not None:
            for release in releases_el.findall(t("release")):
                if release.get("version") == version:
                    raise Skip("conflict",
                               f"version {version} enrolled with a different hash; "
                               "resolve manually")

    stored_name = f"{pid}.zip"
    rel_path = f"{pid}/releases/{version}/fs/shared/{stored_name}"
    gate_path(rel_path, entries)
    dest = vdir / "entities" / pid / "releases" / version / "fs" / "shared" / stored_name
    if dest.exists():
        # Not enrolled (checked above), so this is an interrupted run's
        # leftover; batch discipline says overwrite and carry on.
        print(f"  note:   overwriting unrecorded leftover at {rel_path}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)

    placed = hashing.digest(dest, crc=True, md5=True, sha1=True)
    if placed != src_digest:
        dest.unlink()
        raise Skip("failed", "placed bytes differ from source; nothing enrolled")

    if entity_el is None:
        entity_el = ET.SubElement(entities_el, t("entity"))
        entity_el.set("identifier", pid)
    if meta:
        apply_metadata(entity_el, meta)

    releases_el = entity_el.find(t("releases"))
    if releases_el is None:
        releases_el = ET.SubElement(entity_el, t("releases"))
    release_el = ET.SubElement(releases_el, t("release"))
    release_el.set("version", version)
    fs_el = ET.SubElement(release_el, t("fs"))
    fe = ET.SubElement(fs_el, t("fileshared"))
    fe.set("path", stored_name)
    fe.set("size", str(placed["size"]))
    fe.set("crc", placed["crc"])
    fe.set("md5", placed["md5"])
    fe.set("sha1", placed["sha1"])

    entries[rel_path] = checksum.Entry(
        crc=placed["crc"], md5=placed["md5"], sha1=placed["sha1"],
        size=placed["size"], path=rel_path)
    return version


def self_audit(xml_path: Path) -> list[str]:
    from lxml import etree
    schema = etree.XMLSchema(etree.parse(str(SCHEMA)))
    doc = etree.parse(str(xml_path))
    if schema.validate(doc):
        return []
    return [f"line {e.line}: {e.message}" for e in schema.error_log]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dlsite-ingest", description=__doc__)
    parser.add_argument("--recursive", action="store_true",
                        help="scan the dropzone recursively")
    parser.add_argument("--copy", action="store_true",
                        help="keep dropzone sources instead of removing them on success")
    parser.add_argument("--no-api", action="store_true",
                        help="skip all remote lookups (nothing can be enrolled)")
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")
    args = parser.parse_args(argv)

    try:
        vdir = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    xml_path = vdir / "datmeta.xml"
    if not xml_path.is_file():
        print(f"ERROR: missing {xml_path}", file=sys.stderr)
        return 2

    dropzone = locator.DROPZONE
    paths = dropzone.rglob("*.zip") if args.recursive else dropzone.glob("*.zip")
    candidates: list[tuple[Path, str]] = []
    for path in sorted(p for p in paths if p.is_file()):
        try:
            candidates.append((path, parse_identifier(path)))
        except ValueError as exc:
            print(f"WARN: {path.name}: {exc}")
    print(f"vault:      {vdir}")
    print(f"candidates: {len(candidates)}")
    if not candidates:
        return 0

    tree = ET.parse(xml_path)
    root = tree.getroot()
    entries, problems = checksum.parse_file(vdir / "entities.checksum")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 2

    counts = {"enrolled": 0, "duplicate": 0, "conflict": 0, "failed": 0}
    for index, (path, pid) in enumerate(candidates, 1):
        print(f"\n[{index}/{len(candidates)}] {path.name}")
        print(f"  id:     {pid}")
        try:
            version = ingest_one(path, pid, root, entries, vdir, args)
        except Skip as skip:
            label = skip.verdict.upper() if skip.verdict != "failed" else "FAIL"
            print(f"{label} {skip}")
            counts[skip.verdict] += 1
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
            path.unlink()
        counts["enrolled"] += 1
        print(f"OK enrolled as {version}")

    print(f"\nDone -- enrolled: {counts['enrolled']}, duplicates: {counts['duplicate']}, "
          f"conflicts: {counts['conflict']}, failed: {counts['failed']}")
    return 1 if counts["conflict"] or counts["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
