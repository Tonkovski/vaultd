"""Refresh db/gog_digital/products.tar.xz from the newest GOGDB bulk backup.

Download to a temporary file, validate XZ/TAR and product records, then replace
the cache atomically. Ingest remains offline. No archive members are extracted.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
from http.client import HTTPException
import json
import lzma
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from vaultd.locator import DB_ROOT
from . import VAULT_NAME
from .metadata import AdmissionError, Products

BACKUPS_URL = 'https://www.gogdb.org/backups_v3/products/'
FILELIST_URL = BACKUPS_URL + 'filelist.txt'
CACHE_NAME = 'products.tar.xz'
STATE_NAME = 'products.sync.json'
CHUNK_SIZE = 1 << 20
MAX_FILELIST = 2 << 20


class SyncError(ValueError):
    pass


def request(url, headers=None):
    return urlopen(Request(url, headers={'User-Agent': 'vaultd/0.1',
                                        'Accept-Encoding': 'identity', **(headers or {})}), timeout=60)


def content_length(response):
    value = response.headers.get('Content-Length')
    if value is None:
        return None
    if not re.fullmatch(r'[0-9]+', value):
        raise SyncError('invalid HTTP Content-Length')
    return int(value)


def latest_snapshot(listing: str) -> str:
    candidates = []
    for line in listing.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'([0-9]{4}-[0-9]{2})/gogdb_([0-9]{4}-[0-9]{2}-[0-9]{2})\.tar\.xz', line)
        if not match or match[1] != match[2][:7]:
            raise SyncError(f'unexpected GOGDB backup-list entry: {line!r}')
        candidates.append((date.fromisoformat(match[2]), line))
    if not candidates:
        raise SyncError('GOGDB backup list is empty')
    return BACKUPS_URL + max(candidates)[1]


def discover_snapshot():
    with request(FILELIST_URL) as response:
        if response.status != 200:
            raise SyncError(f'backup list returned HTTP {response.status}')
        payload = response.read(MAX_FILELIST + 1)
        if len(payload) > MAX_FILELIST:
            raise SyncError('GOGDB backup list exceeds size limit')
        expected = content_length(response)
        if expected is not None and len(payload) != expected:
            raise SyncError('incomplete GOGDB backup list')
    return latest_snapshot(payload.decode('utf-8'))


def plain_path(path):
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise SyncError(f'linked path is not a feed cache: {part}')


def cached_headers(cache, state_path, url):
    """Use HTTP validators only when the cache still matches our last download."""
    if not cache.is_file() or not state_path.is_file():
        return {}
    try:
        state = json.loads(state_path.read_text(encoding='utf-8'))
    except (ValueError, OSError):
        return {}
    if not isinstance(state, dict) or state.get('url') != url or state.get('size') != cache.stat().st_size:
        return {}
    with cache.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != state.get('sha256'):
            return {}
    headers = {}
    for key, header in [('etag', 'If-None-Match'), ('last_modified', 'If-Modified-Since')]:
        if isinstance(state.get(key), str) and state[key]:
            headers[header] = state[key]
    return headers


def validate_snapshot(path):
    # Drain the decompressor after TAR's end marker so a truncated or corrupt
    # XZ footer cannot pass just because all product JSON was readable.
    with lzma.open(path, 'rb') as stream:
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            products = Products.from_archive(archive)
        while stream.read(CHUNK_SIZE):
            pass
    return len(products.by_id)


def save_state(path, state):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.gogdb-state-', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(state, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def sync(db_dir: Path):
    cache = db_dir / CACHE_NAME
    state_path = db_dir / STATE_NAME
    for path in (cache, state_path):
        plain_path(path)
    url = discover_snapshot()
    print(f'gogdb: latest snapshot {url}', flush=True)
    headers = cached_headers(cache, state_path, url)
    try:
        response = request(url, headers)
    except HTTPError as exc:
        if exc.code == 304 and headers:
            exc.close()
            print(f'gogdb: unchanged -> {cache}')
            return
        raise
    temporary = None
    try:
        with response:
            if response.status != 200:
                raise SyncError(f'snapshot returned HTTP {response.status}')
            expected = content_length(response)
            db_dir.mkdir(parents=True, exist_ok=True)
            print('gogdb: downloading snapshot', flush=True)
            digest = hashlib.sha256()
            size = 0
            with tempfile.NamedTemporaryFile(dir=db_dir, prefix='.gogdb-download-', suffix='.tmp', delete=False) as stream:
                temporary = Path(stream.name)
                while chunk := response.read(CHUNK_SIZE):
                    stream.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if expected is not None and size != expected:
                raise SyncError(f'incomplete snapshot: expected {expected} bytes, received {size}')
            state = {'url': url, 'size': size, 'sha256': digest.hexdigest(),
                     'etag': response.headers.get('ETag'),
                     'last_modified': response.headers.get('Last-Modified')}
        print('gogdb: validating snapshot', flush=True)
        state['products'] = validate_snapshot(temporary)
        # Publish the validated archive before its HTTP cache metadata. If a
        # process dies between them, ingest still sees a complete valid archive;
        # the mismatching state causes a fresh download on the next sync.
        plain_path(cache)
        temporary.replace(cache)
        plain_path(state_path)
        save_state(state_path, state)
        print(f'gogdb: {state["products"]} products, {size} bytes -> {cache}')
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        sync(DB_ROOT / VAULT_NAME)
    except KeyboardInterrupt:
        print('ABORTED: GOGDB sync interrupted', file=sys.stderr)
        return 130
    except (AdmissionError, OSError, ValueError, EOFError, HTTPException,
            tarfile.TarError, lzma.LZMAError) as exc:
        print(f'ERROR: GOGDB sync failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
