"""Build the GOG browsing view from the offline catalog.

    ezaccess/<title> [<id>]/
      windows#<version>/       -> this release's fs/shared directory
      bonus/                   -> this product's bonus fs/shared directory
      DLC/<dlc title> [<id>]/
        windows#<version>/
        bonus/

Also preserves osx#/linux# releases and declared patches. DLC grouping uses
only [DLC|<parent-id>] comments. Package bonuses keep their own shelves.
Missing parents get titles from the local GOGDB cache, for display only.
Links are relative; installer filenames and multipart adjacency stay intact.
Regeneration touches only ezaccess, never payloads or bookkeeping.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
import tarfile

from vaultd import catalog, ezlink, locator, winlint
from . import VAULT_NAME

GOGDB = locator.DB_ROOT / VAULT_NAME / 'products.tar.xz'


class ViewError(RuntimeError):
    pass


@dataclass(frozen=True)
class View:
    shelves: int
    directories: tuple[Path, ...]  # Relative to ezaccess.
    links: tuple[tuple[Path, Path], ...]  # (relative link, absolute target).
    warnings: tuple[str, ...]


def label(identifier: str, description: str | None) -> str:
    """Alphabetical browsing, with an unabridged ID to disambiguate titles."""
    suffix = f' [{identifier}]'
    title = ezlink.sanitize(description or '', 'Untitled')
    if title.startswith('.'):
        title = '_' + title
    # Windows component limits count UTF-16 units, including non-BMP titles.
    budget = 240 - len(suffix.encode('utf-16-le')) // 2
    raw = title.encode('utf-16-le')
    if len(raw) > budget * 2:
        title = raw[:(budget - 3) * 2].decode('utf-16-le', errors='ignore').rstrip() + '...'
    return title + suffix


def safe_segment(value: str) -> None:
    if (not value or value.startswith('.') or re.search(r'[/\\:*?"<>|]', value)
            or winlint.segment_issues(value)
            or len(value.encode('utf-16-le')) > 510):
        raise ViewError(f'unsafe catalog path component: {value!r}')


def missing_parents(cat: catalog.Catalog) -> set[str]:
    known = {entity.identifier for entity in cat.entities}
    return {marker[1] for entity in cat.entities
            if (marker := re.fullmatch(r'\[DLC\|([0-9]+)\]', (entity.comment or '').strip()))
            and marker[1] not in known}


def read_parent_titles(source: Path, identifiers: set[str]) -> dict[str, str]:
    """Read only requested IDs from an optional external feed; persist nothing."""
    if not identifiers or not source.exists():
        return {}
    titles = {}

    def accept(identifier, stream):
        record = json.load(stream)
        if not isinstance(record, dict) or str(record.get('id')) != identifier:
            raise ViewError(f'GOGDB parent record does not match ID {identifier}')
        title = record.get('title')
        if isinstance(title, str) and title.strip():
            titles[identifier] = title.strip()

    if source.is_dir():
        for identifier in sorted(identifiers):
            path = source / identifier / 'product.json'
            if path.is_file():
                with path.open(encoding='utf-8') as stream:
                    accept(identifier, stream)
    else:
        # Native backup: stream without extraction or a full product index.
        pending = {f'products/{identifier}/product.json': identifier
                   for identifier in identifiers}
        with tarfile.open(source, 'r|*') as archive:
            for member in archive:
                if member.isfile() and member.name in pending:
                    identifier = pending.pop(member.name)
                    with archive.extractfile(member) as stream:
                        accept(identifier, stream)
                    if not pending:
                        break
    return titles


def plan(vault: Path, cat: catalog.Catalog, *, parent_titles: dict[str, str] | None = None) -> View:
    """Plan without reading payload bytes or changing the existing view."""
    vault = vault.resolve()
    if cat.name != VAULT_NAME:
        raise ViewError(f'expected {VAULT_NAME} catalog, got {cat.name!r}')
    if cat.compression != 'none':
        raise ViewError('GOG genezaccess currently requires compression="none"')
    entities = {}
    parents = {}
    for entity in cat.entities:
        if not re.fullmatch(r'[0-9]+', entity.identifier):
            raise ViewError(f'not a numeric GOG product ID: {entity.identifier!r}')
        safe_segment(entity.identifier)
        if entity.identifier in entities:
            raise ViewError(f'duplicate product ID: {entity.identifier}')
        entities[entity.identifier] = entity
        comment = (entity.comment or '').strip()
        marker = re.fullmatch(r'\[DLC\|([0-9]+)\]', comment)
        if marker:
            safe_segment(marker[1])
            parents[entity.identifier] = marker[1]
        elif comment.startswith('[DLC'):
            raise ViewError(f'{entity.identifier}: malformed DLC comment {comment!r}')
    for child, parent in parents.items():
        if parent in parents:
            raise ViewError(f'{child}: DLC parent {parent} is itself a DLC')

    group_ids = (set(entities) - set(parents)) | set(parents.values())
    parent_titles = parent_titles or {}
    shelves = {identifier: Path(label(identifier, entities[identifier].description
               if identifier in entities else parent_titles.get(identifier) or 'Game not in catalog'))
               for identifier in group_ids}
    directories: set[Path] = set()
    links: dict[Path, Path] = {}
    names: dict[str, tuple[Path, bool]] = {}

    def add(path: Path, target: Path | None = None) -> None:
        if path.parent != Path('.'):
            add(path.parent)
        for part in path.parts:
            safe_segment(part)
        key = path.as_posix().casefold()
        previous = names.get(key)
        if previous is not None:
            if previous != (path, False) or target is not None:
                raise ViewError(f'conflicting browsing paths: {previous[0]} and {path}')
            return
        names[key] = (path, target is not None)
        if target is None:
            directories.add(path)
        else:
            # Inspect only directory metadata; do not walk or hash payloads.
            for part in (target, *target.parents):
                if part == vault:
                    break
                if part.is_symlink() or part.is_junction():
                    raise ViewError(f'linked custody path: {part}')
            if not target.is_dir():
                raise ViewError(f'declared payload directory is missing: {target}')
            links[path] = target

    for shelf in sorted(shelves.values()):
        add(shelf)
    for identifier, entity in sorted(entities.items()):
        shelf = (shelves[parents[identifier]] / 'DLC' / label(identifier, entity.description)
                 if identifier in parents else shelves[identifier])
        add(shelf)  # Keep childless/MIA products visible as empty shelves.
        for release in sorted(entity.releases, key=lambda r: r.version):
            safe_segment(release.version)
            if release.instances or release.pix_items:
                raise ViewError(f'{identifier}/{release.version}: GOG view supports shared files only')
            target = vault / 'entities' / identifier / 'releases' / release.version / 'fs' / 'shared'
            add(shelf / release.version, target if release.shared or release.dirs else None)
        for patch in sorted(entity.patches, key=lambda p: p.name):
            safe_segment(patch.name)
            target = vault / 'entities' / identifier / 'patches' / patch.name
            add(shelf / 'patches' / patch.name, target if patch.files else None)

    warnings = tuple(f'no title available for parent {identifier}; DLCs grouped under '
                     f'"{shelves[identifier]}"'
                     for identifier in sorted(group_ids - set(entities))
                     if not parent_titles.get(identifier))
    return View(len(shelves), tuple(sorted(directories)), tuple(sorted(links.items())), warnings)


def check_existing_view(root: Path) -> None:
    """Inspect the entire old view before removing any links; never follow them."""
    if root.is_symlink() or root.is_junction():
        raise ViewError(f'ezaccess root must be a real directory: {root}')
    if not root.exists():
        return
    pending = [root]
    while pending:
        directory = pending.pop()
        if not directory.is_dir():
            raise ViewError(f'regular file inside ezaccess, refusing to wipe: {directory}')
        for path in directory.iterdir():
            if path.is_symlink():
                continue
            if path.is_junction():
                raise ViewError(f'junction inside ezaccess, refusing to wipe: {path}')
            if not path.is_dir():
                raise ViewError(f'regular file inside ezaccess, refusing to wipe: {path}')
            pending.append(path)


def rebuild(vault: Path, cat: catalog.Catalog, *, parent_titles: dict[str, str] | None = None) -> View:
    vault = vault.resolve()
    view = plan(vault, cat, parent_titles=parent_titles)
    root = vault / 'ezaccess'
    check_existing_view(root)
    # Fixed, resolved vault child, checked above before any recursive removal.
    ezlink.safe_wipe(root)
    root.mkdir(exist_ok=True)
    for directory in view.directories:
        (root / directory).mkdir(parents=True, exist_ok=True)
    for link, target in view.links:
        ezlink.relative_symlink(root / link, target)
    return view


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='gog-digital-genezaccess', description=__doc__)
    parser.add_argument('--locator', type=Path, default=None, help='alternate vaultd.local.toml')
    parser.add_argument('--gogdb', type=Path, default=GOGDB,
                        help='local GOGDB backup or product directory, used only for missing parent titles')
    args = parser.parse_args(argv)
    try:
        vault = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
        print(f'{VAULT_NAME}: rebuilding ezaccess from local catalog', flush=True)
        cat = catalog.load(vault / 'datmeta.xml')
        missing = missing_parents(cat)
        if missing and args.gogdb.exists():
            print(f'{VAULT_NAME}: resolving {len(missing)} parent title(s) from local GOGDB', flush=True)
        parent_titles = read_parent_titles(args.gogdb, missing)
        view = rebuild(vault, cat, parent_titles=parent_titles)
    except KeyboardInterrupt:
        print('Interrupted; rerun to rebuild ezaccess.', file=sys.stderr)
        return 130
    except (locator.LocatorError, catalog.CatalogError, RuntimeError, OSError, ValueError, tarfile.TarError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        if isinstance(exc, OSError) and getattr(exc, 'winerror', None) == 1314:
            print('Enable Windows Developer Mode or run with symlink privilege.', file=sys.stderr)
        return 1
    print(f'{VAULT_NAME}: ezaccess rebuilt — {view.shelves} shelf/shelves, '
          f'{len(cat.entities)} product(s), {len(view.links)} directory link(s)', flush=True)
    for warning in view.warnings:
        print(f'WARN: {warning}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
