"""Ingest manually arranged GOG releases from dropzone/gog_digital.

Intake: <slug>/{bonus|<windows|osx|linux>#<version>}/<original files>.
Unprefixed versions infer their platform from installer extensions.
GOGDB supplies identity; custody hashes are computed locally. No source
argument, bonus reclassification, payload filename rewriting, or network requests.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import time
import xml.etree.ElementTree as ET

from lxml import etree

from vaultd import catwrite, checksum, hashing, locator, winlint
from vaultd.catwrite import t
from . import VAULT_NAME
from .metadata import AdmissionError, MetadataWarning, Products, build_date, normalize_version
from .reporting import RunReport, log, size

INTAKE = locator.DROPZONE / VAULT_NAME
DB = locator.DB_ROOT / VAULT_NAME
SCHEMA = locator.REPO_ROOT / 'convention' / 'datmeta.xsd'
INSTALLER_EXTENSIONS = frozenset({'.exe', '.bin', '.dmg', '.sh'})


def measure(path):
    return hashing.digest(path, crc=True, md5=True, sha1=True)


def safe_name(name):
    if not name or name.startswith('.') or re.search(r'[/\\:*?"<>|]', name):
        raise AdmissionError(f'unsafe name: {name!r}')
    issues = winlint.segment_issues(name)
    if issues:
        raise AdmissionError(f'{name}: {", ".join(issues)}')


def plain_path(path):
    """Refuse links/junctions along any existing portion of a payload path."""
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise AdmissionError(f'link/junction is not an intake or custody path: {part}')


def children(path):
    plain_path(path)
    result = sorted(path.iterdir(), key=lambda p: p.name)
    folded = set()
    for child in result:
        safe_name(child.name)
        plain_path(child)
        if child.name.casefold() in folded:
            raise AdmissionError(f'case-twin names under {path}')
        folded.add(child.name.casefold())
    return result


@dataclass(frozen=True)
class FileStamp:
    device: int
    inode: int
    size: int
    modified_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, info):
        if not stat.S_ISREG(info.st_mode):
            raise AdmissionError('payload must be a regular file')
        return cls(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def snapshot(path):
    plain_path(path)
    return FileStamp.from_stat(path.stat())


def unchanged(path, stamp):
    if snapshot(path) != stamp:
        raise AdmissionError(f'file changed during ingest: {path}')


def check_source(plan):
    if {p.name for p in children(plan.source)} != set(plan.files):
        raise AdmissionError(f'source inventory changed since preflight: {plan.source}')
    for name, stamp in plan.files.items():
        unchanged(plan.source / name, stamp)


def source_digest(path, stamp):
    """Hash a resubmitted source once against its catalog/checkpoint record."""
    unchanged(path, stamp)
    digest = measure(path)
    unchanged(path, stamp)
    if digest['size'] != stamp.size:
        raise AdmissionError(f'file size changed while hashing: {path}')
    return digest


def copy_payload(source, destination, stamp, *, known_digest=None):
    """Hash while copying, or reuse a source digest already checked this run."""
    unchanged(source, stamp)
    with source.open('rb') as incoming:
        opened = FileStamp.from_stat(os.fstat(incoming.fileno()))
        # Windows stat() and fstat() can disagree on ctime semantics. Compare
        # identity/size/mtime across APIs, and the full stamp within each API.
        if any(getattr(opened, key) != getattr(stamp, key)
               for key in ('device', 'inode', 'size', 'modified_ns')):
            raise AdmissionError(f'source changed before copying: {source}')
        with destination.open('wb') as outgoing:
            if known_digest is None:
                digest = hashing.digest_stream(incoming, output=outgoing, crc=True, md5=True, sha1=True)
            else:
                # A checksum-only checkpoint repair already hashed this source.
                copied = 0
                while chunk := incoming.read(1 << 20):
                    if outgoing.write(chunk) != len(chunk):
                        raise OSError('short write while copying checkpoint payload')
                    copied += len(chunk)
                if copied != stamp.size:
                    raise AdmissionError(f'source size changed while copying: {source}')
                digest = known_digest
        if FileStamp.from_stat(os.fstat(incoming.fileno())) != opened:
            raise AdmissionError(f'source changed while copying: {source}')
    shutil.copystat(source, destination)
    unchanged(source, stamp)
    if digest['size'] != stamp.size:
        raise AdmissionError(f'source size changed while copying: {source}')
    return digest


def release_name(name):
    """Normalize a release label; prepared directories must use this spelling."""
    if name == 'bonus':
        return name
    platform, sep, version = name.partition('#')
    if not sep or not version or platform not in {'windows', 'osx', 'linux'}:
        raise AdmissionError(f'{name!r}: expected bonus or <windows|osx|linux>#<version>')
    version = normalize_version(version)
    normalized = f'{platform}#{version}'
    safe_name(normalized)
    return normalized


def detect_release_name(name, filenames):
    """Honor an explicit platform; infer only when its prefix is absent."""
    if name == 'bonus' or name.startswith(('windows#', 'osx#', 'linux#')):
        return release_name(name)
    if name.casefold() == 'bonus':
        raise AdmissionError(f'{name!r}: bonus directory must be lowercase')
    extensions = {'.exe': 'windows', '.dmg': 'osx', '.sh': 'linux'}
    evidence = {}
    for filename in filenames:
        platform = extensions.get(Path(filename).suffix.lower())
        if platform:
            evidence.setdefault(platform, []).append(filename)
    if len(evidence) != 1:
        details = '; '.join(f'{platform}: {", ".join(sorted(names))}'
                            for platform, names in sorted(evidence.items()))
        reason = f'mixed platform evidence ({details})' if evidence else 'no .exe, .dmg or .sh files'
        raise AdmissionError(f'{name!r}: cannot infer platform: {reason}; add an explicit platform prefix')
    return release_name(f'{next(iter(evidence))}#{name}')


def find(parent, tag, key, value):
    return next((e for e in parent.findall(t(tag)) if e.get(key) == value), None)


def section(parent, name):
    node = parent.find(t(name))
    return node if node is not None else ET.SubElement(parent, t(name))


def validate(root):
    schema = etree.XMLSchema(etree.parse(str(SCHEMA)))
    document = etree.fromstring(ET.tostring(root))
    if not schema.validate(document):
        raise AdmissionError(f'catalog schema: {schema.error_log.last_error}')


def load_state(vault):
    for name in ('datmeta.xml', 'entities.checksum', 'entities'):
        plain_path(vault / name)
    root = ET.parse(vault / 'datmeta.xml').getroot()
    validate(root)
    if root.get('name') != VAULT_NAME or vault.name != VAULT_NAME:
        raise AdmissionError('vault identity/directory must be gog_digital')
    if root.get('compression') != 'none':
        raise AdmissionError('this keeper currently supports compression="none" only')
    entries, problems = checksum.parse_file(vault / 'entities.checksum')
    if problems:
        raise AdmissionError('; '.join(problems))
    return root, entries


@dataclass
class Release:
    source: Path
    version: str
    identifier: str
    files: dict[str, FileStamp]
    product: dict
    parent_id: str | None
    warnings: list[MetadataWarning] = field(default_factory=list)

    @property
    def prefix(self):
        return f'{self.identifier}/releases/{self.version}/fs/shared/'


def prepare(directory, products):
    """Preflight the entire slug directory before enrolling any of its releases."""
    product = products.resolve(directory.name)
    parent = products.base_game(product) if product['type'] == 'dlc' else None
    pending = []
    versions = {}
    for source in children(directory):
        if not source.is_dir():
            raise AdmissionError(f'{source}: expected a release directory')
        if product['type'] == 'pack' and source.name != 'bonus':
            raise AdmissionError(f'{source}: packages may ingest only bonus; split game/DLC installers manually')
        inventory = children(source)
        for file in inventory:
            if not file.is_file():
                raise AdmissionError(f'{file}: release contents must be original files, not directories')
        if source.name != 'bonus':
            unexpected = [file.name for file in inventory if file.suffix.lower() not in INSTALLER_EXTENSIONS]
            if unexpected:
                raise AdmissionError(f'{source}: unexpected non-bonus file(s): {", ".join(unexpected)}; '
                                     f'allowed extensions: {", ".join(sorted(INSTALLER_EXTENSIONS))}')
        version = detect_release_name(source.name, [file.name for file in inventory])
        previous = versions.get(version.casefold())
        if previous is not None:
            raise AdmissionError(f'release name clash: {previous.name!r} and {source.name!r} both resolve to {version!r}')
        versions[version.casefold()] = source
        pending.append((source, version, inventory))
    plans = []
    for source, version, inventory in pending:
        files = {file.name: snapshot(file) for file in inventory}
        # Empty directories can remain after interruption during final cleanup.
        if files:
            plans.append(Release(source, version, str(product['id']), files, product, parent))
    return plans


def declarations(release):
    if release.find(t('pix')) is not None:
        raise AdmissionError('existing release has unsupported per-copy evidence')
    fs = release.find(t('fs'))
    if fs is None:
        return {}
    result = {}
    for file in fs:
        if file.tag != t('fileshared'):
            raise AdmissionError('existing release is not a shared-file release')
        name = file.get('path')
        safe_name(name)
        result[name] = {k: file.get(k) for k in ('crc', 'md5', 'sha1')}
        result[name]['size'] = int(file.get('size'))
    return result


def case_gate(vault, plan, entries):
    proposed = plan.prefix.rstrip('/').split('/')
    for path in entries:
        parts = path.split('/')
        for a, b in zip(proposed, parts):
            if a.casefold() != b.casefold():
                break
            if a != b:
                raise AdmissionError(f'case-twin of recorded path: {path}')
    # Include physical leftovers, not only previously checkpointed paths.
    parent = vault / 'entities'
    for segment in proposed:
        plain_path(parent)
        if parent.exists():
            for child in parent.iterdir():
                if child.name.casefold() == segment.casefold() and child.name != segment:
                    raise AdmissionError(f'case-twin physical path: {child}')
        parent /= segment
    plain_path(parent)


def audit_release(vault, plan, expected, entries, stored_stamps=None):
    """Check bookkeeping, inventory and file stats; fswarmup checks stored bytes."""
    if stored_stamps is not None and set(stored_stamps) != set(expected):
        raise AdmissionError('stored file stamp inventory differs from catalog')
    current_stamps = {}
    release_dir = vault / 'entities' / plan.identifier / 'releases' / plan.version
    actual = set()
    for path in release_dir.rglob('*'):
        plain_path(path)
        if path.is_file():
            actual.add(path.relative_to(release_dir).as_posix())
    wanted = {'fs/shared/' + name for name in expected}
    if actual != wanted:
        raise AdmissionError(f'{release_dir}: physical file inventory differs from catalog')
    recorded = {p for p in entries if p.startswith(f'{plan.identifier}/releases/{plan.version}/')}
    if recorded != {plan.prefix + name for name in expected}:
        raise AdmissionError(f'{release_dir}: checksum inventory differs from catalog')
    for name, digest in expected.items():
        path = plan.prefix + name
        if entries.get(path) != checksum.Entry(path=path, **digest):
            raise AdmissionError(f'{path}: checksum disagrees with catalog')
        stored = vault / 'entities' / path
        stamp = snapshot(stored)
        if stamp.size != digest['size']:
            raise AdmissionError(f'{path}: stored size disagrees with catalog')
        if stored_stamps is not None and stamp != stored_stamps[name]:
            raise AdmissionError(f'file changed during ingest: {stored}')
        current_stamps[name] = stamp
    return current_stamps


def catalog_release(root, plan):
    entities = root.find(t('entities'))
    entity = find(entities, 'entity', 'identifier', plan.identifier) if entities is not None else None
    if entity is None:
        raise AdmissionError(f'{plan.identifier}: entity missing from catalog')
    releases = entity.find(t('releases'))
    release = find(releases, 'release', 'version', plan.version) if releases is not None else None
    if release is None:
        raise AdmissionError(f'{plan.version}: release missing from catalog')
    return release


def candidate(vault, plan, root, entries):
    """Build the proposed catalog and reject conflicts before copying payload."""
    root = copy.deepcopy(root)
    entities = section(root, 'entities')
    entity = find(entities, 'entity', 'identifier', plan.identifier)
    if entity is None:
        entity = ET.SubElement(entities, t('entity'), identifier=plan.identifier)
    for attribute, value in [('description', plan.product['title']),
                             ('developer', plan.product.get('developer') or ', '.join(sorted(plan.product.get('developers') or []))),
                             ('publisher', plan.product.get('publisher') or ', '.join(sorted(plan.product.get('publishers') or [])))]:
        if value and not entity.get(attribute):
            entity.set(attribute, value)
    urls = section(entity, 'urls')
    url = f'https://www.gogdb.org/product/{plan.identifier}'
    if url not in [node.text for node in urls]:
        ET.SubElement(urls, t('url')).text = url
    if plan.parent_id:
        marker = f'[DLC|{plan.parent_id}]'
        comment = entity.find(t('comment'))
        if comment is not None and comment.text not in (None, '', marker):
            raise AdmissionError(f'{plan.identifier}: existing comment conflicts with {marker}')
        section(entity, 'comment').text = marker
    elif (entity.findtext(t('comment')) or '').startswith('[DLC|'):
        raise AdmissionError(f'{plan.identifier}: existing DLC classification conflicts with non-DLC metadata')
    releases = section(entity, 'releases')
    for sibling in releases:
        if sibling.get('version').casefold() == plan.version.casefold() and sibling.get('version') != plan.version:
            raise AdmissionError('release name is a case-twin of an existing version')
    release = find(releases, 'release', 'version', plan.version)
    existing = release is not None
    case_gate(vault, plan, entries)
    if existing:
        expected = declarations(release)
        if any(name not in expected or expected[name]['size'] != stamp.size
               for name, stamp in plan.files.items()):
            raise AdmissionError(f'{plan.version}: immutable release conflict; use a new version')
    else:
        expected = {}
        release = ET.SubElement(releases, t('release'), version=plan.version)
        date, warning = build_date(plan.product, plan.version)
        if warning:
            plan.warnings.append(warning)
        if date is not None:
            release.set('date', date)
        ET.SubElement(release, t('fs'))
        release_dir = vault / 'entities' / plan.identifier / 'releases' / plan.version
        plain_path(release_dir)
        if release_dir.exists():
            for path in release_dir.rglob('*'):
                plain_path(path)
                if path.is_file() and path.relative_to(release_dir).as_posix() not in {'fs/shared/' + n for n in plan.files}:
                    raise AdmissionError(f'unexpected leftover file: {path}')
        prefix = f'{plan.identifier}/releases/{plan.version}/'
        for path, entry in entries.items():
            if path.startswith(prefix):
                name = path.removeprefix(plan.prefix)
                if name not in plan.files or entry.size != plan.files[name].size:
                    raise AdmissionError(f'conflicting checksum checkpoint: {path}')
                expected[name] = {key: getattr(entry, key) for key in ('size', 'crc', 'md5', 'sha1')}
    # Existing releases and checksum-only checkpoints pin exact bytes. Hash
    # submitted copies once before any rename or write; fresh files are hashed
    # while copying instead. A subset is allowed only for enrolled releases.
    for name, stamp in plan.files.items():
        if name in expected:
            digest = source_digest(plan.source / name, stamp)
            if digest != expected[name]:
                reason = 'immutable release conflict; use a new version' if existing else 'conflicting checksum checkpoint'
                raise AdmissionError(f'{plan.version}/{name}: {reason}')
    if plan.version == 'bonus':
        release.set('standalone', 'false')
    catwrite.sort_tree(root)
    validate(root)
    return root, expected, existing


def execute(vault, plan, root, entries):
    check_source(plan)
    next_root, expected, existing = candidate(vault, plan, root, entries)
    # Check the entire existing release's inventory and sizes, including files
    # already removed from intake. Never copy over an enrolled release.
    stored_stamps = {}
    if existing:
        stored_stamps = audit_release(vault, plan, expected, entries)
    check_source(plan)
    if plan.source.name != plan.version:
        # Pin inferred identity before copy/cleanup: an interrupted cleanup may
        # leave only BIN files, which cannot identify the platform on their own.
        destination = plan.source.with_name(plan.version)
        plain_path(destination)
        if destination.resolve().parent != plan.source.resolve().parent:
            raise AdmissionError('release rename escaped its product directory')
        if any(sibling.name.casefold() == plan.version.casefold()
               for sibling in children(plan.source.parent)):
            raise AdmissionError(f'release rename destination already exists: {destination}')
        plan.source = plan.source.rename(destination)
    if not existing:
        for name, stamp in plan.files.items():
            source = plan.source / name
            unchanged(source, stamp)
            dest = vault / 'entities' / (plan.prefix + name)
            plain_path(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            known = expected.get(name)
            # Trust the checkpoint for stored content; fswarmup owns readback.
            # Missing or wrong-size files can be restored from the checked source.
            if known is not None and dest.exists():
                stored_stamp = snapshot(dest)
                if stored_stamp.size == known['size']:
                    stored_stamps[name] = stored_stamp
                    continue
            if known is None:
                digest = copy_payload(source, dest, stamp)
            else:
                digest = copy_payload(source, dest, stamp, known_digest=known)
            stored_stamp = snapshot(dest)
            if stored_stamp.size != digest['size']:
                raise AdmissionError(f'copy size mismatch: {dest}')
            expected[name] = digest
            stored_stamps[name] = stored_stamp
        fs = section(catalog_release(next_root, plan), 'fs')
        for name, digest in expected.items():
            ET.SubElement(fs, t('fileshared'), path=name,
                          **{key: str(value) for key, value in digest.items()})
    next_entries = dict(entries)
    for name, digest in expected.items():
        path = plan.prefix + name
        next_entries[path] = checksum.Entry(path=path, **digest)
    catwrite.bump_stamp(next_root)
    catwrite.sort_tree(next_root)
    validate(next_root)
    check_source(plan)
    audit_release(vault, plan, expected, next_entries, stored_stamps)
    checksum.write_file(vault / 'entities.checksum', next_entries)
    catwrite.write_xml(vault / 'datmeta.xml', next_root)
    saved_root, saved_entries = load_state(vault)
    if declarations(catalog_release(saved_root, plan)) != expected:
        raise AdmissionError(f'{plan.version}: saved catalog differs from proposed files')
    audit_release(vault, plan, expected, saved_entries, stored_stamps)
    check_source(plan)
    # Per-file removal makes interruptions recoverable as an identical subset.
    for name, stamp in plan.files.items():
        source = plan.source / name
        unchanged(source, stamp)
        source.unlink()
    if not any(plan.source.iterdir()):
        plan.source.rmdir()
    return saved_root, saved_entries


def run(vault, intake, products, *, report=None):
    own_report = report is None
    report = RunReport() if own_report else report
    try:
        return _run(vault, intake, products, report)
    except KeyboardInterrupt:
        if own_report:
            report.interrupted()
        raise
    except Exception:
        report.status = 'ABORTED'
        raise
    finally:
        if own_report:
            report.emit()


def _run(vault, intake, products, report):
    root, entries = load_state(vault)
    for directory in children(intake):
        report.active = directory.name
        try:
            if not directory.is_dir():
                raise AdmissionError(f'{directory}: expected a product-slug directory')
            plans = prepare(directory, products)
            for plan in plans:
                subject = f'{directory.name} -> {plan.identifier}/{plan.version}'
                report.active = subject
                started = time.monotonic()
                total = sum(stamp.size for stamp in plan.files.values())
                log(f'START {subject}: '
                    f'{len(plan.files)} file(s), {size(total)}')
                outcome = 'not completed'
                try:
                    root, entries = execute(vault, plan, root, entries)
                except (AdmissionError, OSError, ET.ParseError, etree.LxmlError) as exc:
                    outcome = 'failed'
                    log(f'FAIL {directory.name}/{plan.source.name}: {exc}', error=True)
                    report.failures += 1
                    root, entries = load_state(vault)
                else:
                    outcome = 'ingested'
                    report.completed += 1
                    log(f'OK {subject}: {time.monotonic() - started:.1f}s')
                finally:
                    report.collect(plan, directory.name, outcome)
            if not any(directory.iterdir()):
                directory.rmdir()
        except (AdmissionError, OSError, ET.ParseError, etree.LxmlError) as exc:
            log(f'FAIL {directory.name}: {exc}', error=True)
            report.failures += 1
            # Never let a failed checkpoint contaminate the next batch element.
            root, entries = load_state(vault)
        report.active = None
    return 1 if report.failures else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gogdb', type=Path, default=DB / 'products.tar.xz',
                        help='upstream <id>/product.json directory or GOGDB .tar.xz backup')
    parser.add_argument('--locator', type=Path, default=None)
    args = parser.parse_args(argv)
    report = RunReport()
    try:
        log(f'START gog_digital ingest; loading GOGDB metadata: {args.gogdb}')
        products = Products.load(args.gogdb)
        vault = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
        return run(vault, INTAKE, products, report=report)
    except KeyboardInterrupt:
        report.interrupted()
        return 130
    except (AdmissionError, OSError, ValueError, tarfile.ReadError,
            ET.ParseError, etree.LxmlError, locator.LocatorError) as exc:
        log(f'ERROR: {exc}', error=True)
        report.status = 'ABORTED'
        report.failures += 1
        return 2
    finally:
        report.emit()


if __name__ == '__main__':
    raise SystemExit(main())
