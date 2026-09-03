"""Shared plumbing for keeper-owned ezaccess generators.

Keepers own the shape of their ezaccess view (grouping, naming, what gets
linked); this module owns the mechanics: sanitizing free text into link-safe
names, wiping generated content safely, and creating relative symlinks so a
vault relocates as a unit.
"""

from __future__ import annotations

import os
from pathlib import Path

from vaultd import winlint

_FORBIDDEN = set('/\\:*?"<>|')


def sanitize(text: str, fallback: str = "") -> str:
    """Free text (descriptions, patch names) -> link-safe name; never dies."""
    out = "".join("_" if ch in _FORBIDDEN or ord(ch) < 32 else ch for ch in text)
    out = out.strip().rstrip(". ")
    if not out:
        return fallback
    if out.split(".", 1)[0].upper() in winlint.RESERVED:
        out = "_" + out
    return out


def safe_wipe(root: Path) -> None:
    """Remove generated content only: symlinks and (then-)empty directories.

    A regular file anywhere under root aborts with RuntimeError — ezaccess is
    disposable by convention, but never assume; protect what we didn't make.
    """
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
        here = Path(dirpath)
        for name in filenames:
            path = here / name
            if not path.is_symlink():
                raise RuntimeError(f"regular file inside ezaccess, refusing to wipe: {path}")
            path.unlink()
        for name in dirnames:
            path = here / name
            if path.is_symlink():
                try:
                    path.unlink()
                except OSError:
                    os.rmdir(path)
            else:
                os.rmdir(path)


def relative_symlink(link: Path, target: Path) -> None:
    rel = os.path.relpath(target, link.parent)
    os.symlink(rel, link, target_is_directory=target.is_dir())
