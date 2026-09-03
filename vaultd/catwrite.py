"""datmeta.xml write-side helpers: sorting, atomic output, stamp bump.

Reading stays in vaultd.catalog; every writer (initvault aside, which writes a
bare header) goes through sort_tree + write_xml so documents always land in
the Ordering-rule shape, atomically.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

from vaultd.catalog import NS

ET.register_namespace("", NS)


def t(name: str) -> str:
    return f"{{{NS}}}{name}"


_ENTITY_CHILD_ORDER = {t("urls"): 0, t("comment"): 1, t("releases"): 2, t("patches"): 3}
_RELEASE_CHILD_ORDER = {t("fs"): 0, t("pix"): 1}
_FS_KIND_ORDER = {t("dir"): 0, t("fileshared"): 1, t("fileinstance"): 2}


def sort_tree(root: ET.Element) -> None:
    """Apply the Ordering rule (convention/datmeta.md) to a vault tree."""
    entities_el = root.find(t("entities"))
    if entities_el is None:
        return
    entities_el[:] = sorted(entities_el, key=lambda e: e.get("identifier", ""))
    for entity in entities_el:
        entity[:] = sorted(entity, key=lambda e: _ENTITY_CHILD_ORDER.get(e.tag, 99))
        urls_el = entity.find(t("urls"))
        if urls_el is not None:
            urls_el[:] = sorted(urls_el, key=lambda e: e.text or "")
        releases_el = entity.find(t("releases"))
        if releases_el is not None:
            releases_el[:] = sorted(releases_el, key=lambda e: e.get("version", ""))
            for release in releases_el:
                release[:] = sorted(release, key=lambda e: _RELEASE_CHILD_ORDER.get(e.tag, 99))
                fs_el = release.find(t("fs"))
                if fs_el is not None:
                    fs_el[:] = sorted(
                        fs_el,
                        key=lambda e: (_FS_KIND_ORDER.get(e.tag, 99), e.get("path", "")))
                pix_el = release.find(t("pix"))
                if pix_el is not None:
                    pix_el[:] = sorted(pix_el, key=lambda e: e.get("name", ""))
        patches_el = entity.find(t("patches"))
        if patches_el is not None:
            patches_el[:] = sorted(patches_el, key=lambda e: e.get("name", ""))
            for patch in patches_el:
                patch[:] = sorted(patch, key=lambda e: e.get("path", ""))


def bump_stamp(root: ET.Element) -> None:
    root.set("version", f"{date.today():%Y%m%d}")


def write_xml(path: Path, root: ET.Element) -> None:
    """Serialize with 2-space indent, LF, XML declaration — atomically."""
    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="unicode")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n',
                   encoding="utf-8", newline="\n")
    tmp.replace(path)
