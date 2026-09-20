"""Read upstream GOGDB product JSON without network I/O."""
from __future__ import annotations

import json
import re
import tarfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


class AdmissionError(ValueError):
    """Input requires an operator decision before admission."""


def normalize_version(version: str) -> str:
    """Apply the same per-character replacement to intake and feed versions."""
    return re.sub(r'[/\\:*?"<>|\x00-\x1f]', '_', version)


@dataclass(frozen=True)
class MetadataWarning:
    category: str
    message: str


def build_date(product, release: str) -> tuple[str | None, MetadataWarning | None]:
    """Return one publication day, or an explanatory warning; bonus is undated."""
    if release == 'bonus':
        return None, None
    platform, _, version = release.partition('#')
    matches = [build for build in product.get('builds') or []
               if str(build.get('product_id')) == str(product['id'])
               and build.get('os') == platform
               and isinstance(build.get('version'), str)
               and normalize_version(build['version']) == version]
    if not matches:
        return None, MetadataWarning('no-build', 'no matching GOGDB build')
    # Prefer currently listed builds of this exact product/platform/version.
    # Historical matches remain usable when that version has no listed build.
    listed = [build for build in matches if build.get('listed') is True]
    if listed:
        matches = listed
    days = set()
    invalid = []
    details = []
    for build in matches:
        published = build.get('date_published')
        detail = f'build {build.get("id", "?")}={published!r}'
        details.append(detail)
        try:
            if not isinstance(published, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T.+)?', published):
                raise ValueError('not an ISO publication date')
            # Preserve the calendar day recorded by GOGDB, independent of the
            # host timezone. Validate the full timestamp, not just its prefix.
            days.add(datetime.fromisoformat(published).date().isoformat())
        except ValueError:
            invalid.append(detail)
    if invalid:
        return None, MetadataWarning('invalid-date', 'missing or invalid GOGDB publication date: ' + '; '.join(sorted(invalid)))
    if len(days) != 1:
        return None, MetadataWarning('conflicting-date', 'conflicting GOGDB build dates: ' + '; '.join(sorted(details)))
    return next(iter(days)), None


class Products:
    def __init__(self, records):
        self.by_id = {}
        self.by_slug = defaultdict(list)
        for record in records:
            if not isinstance(record, dict):
                raise AdmissionError('GOGDB product record must be a JSON object')
            identifier = str(record.get('id', ''))
            if not re.fullmatch(r'[1-9][0-9]*', identifier):
                raise AdmissionError('GOGDB product has an invalid ID')
            if identifier in self.by_id:
                raise AdmissionError(f'duplicate GOGDB product ID: {identifier}')
            if record.get('slug') is not None and not isinstance(record['slug'], str):
                raise AdmissionError(f'GOGDB product {identifier} has an invalid slug')
            self.by_id[identifier] = record
            self.by_slug[record.get('slug')].append(record)

    @classmethod
    def load(cls, path: Path, *, progress=None):
        if path.is_dir():
            files = sorted(path.glob('*/product.json'))
            if not files:
                raise AdmissionError(f'no <id>/product.json records in {path}')
            def records():
                for count, file in enumerate(files, 1):
                    yield json.loads(file.read_text(encoding='utf-8'))
                    if progress is not None:
                        progress(count)
            return cls(records())
        # Native GOGDB backup: parse product records only, never extract paths.
        with tarfile.open(path, 'r|*') as archive:
            return cls.from_archive(archive, progress=progress)

    @classmethod
    def from_archive(cls, archive, *, progress=None):
        """Parse an open upstream TAR stream, without extracting its members."""
        records = []
        for member in archive:
            if member.isfile() and re.fullmatch(r'products/[0-9]+/product.json', member.name):
                with archive.extractfile(member) as stream:
                    records.append(json.load(stream))
            if progress is not None:
                progress(len(records))
        if not records:
            raise AdmissionError('no GOGDB product records in archive')
        return cls(records)

    def resolve(self, slug: str):
        candidates = self.by_slug.get(slug, [])
        if not candidates:
            raise AdmissionError(f'{slug!r}: no GOGDB product matches this slug')
        # Packages can own bonus content. Resolve the full slug index before
        # checking release eligibility; neither type nor availability breaks ties.
        if len(candidates) > 1:
            matches = '; '.join(
                f'ID {p["id"]} (type={p.get("type")!r}, access={p.get("access")!r}, '
                f'title={p.get("title")!r}) https://www.gogdb.org/product/{p["id"]}'
                for p in sorted(candidates, key=lambda p: int(p['id']))
            )
            raise AdmissionError(f'{slug!r}: GOGDB slug clash: {len(candidates)} products: {matches}')
        product = candidates[0]
        if product.get('type') not in {'game', 'dlc', 'pack'}:
            raise AdmissionError(f'{slug}: {product.get("type")} is not a game, DLC or package')
        if not product.get('title'):
            raise AdmissionError(f'{slug}: product title missing')
        return product

    def base_game(self, product):
        bases = set()

        def visit(identifier, ancestors):
            identifier = str(identifier)
            if identifier in ancestors:
                raise AdmissionError(f'cyclic DLC dependency at {identifier}')
            record = self.by_id.get(identifier)
            if record is None:
                raise AdmissionError(f'missing dependency metadata: {identifier}')
            if record.get('type') == 'game':
                bases.add(identifier)
                return
            if record.get('type') != 'dlc' or not record.get('requires'):
                raise AdmissionError(f'cannot resolve base game through {identifier}')
            for dependency in record['requires']:
                visit(dependency, ancestors | {identifier})

        if not product.get('requires'):
            raise AdmissionError(f'DLC {product["id"]}: no requires relationship')
        for dependency in product['requires']:
            visit(dependency, {str(product['id'])})
        if len(bases) != 1:
            raise AdmissionError(f'DLC {product["id"]}: expected one base game, found {sorted(bases)}')
        return next(iter(bases))
