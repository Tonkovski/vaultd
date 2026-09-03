"""datmeta.xml catalog model (read side).

Structural validity is xsdvalidate's job (lxml + datmeta.xsd); this loader is
deliberately tolerant of anything the schema already rejects, and only raises
CatalogError for documents it cannot make sense of at all.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

NS = "http://tonkovski.github.io/vaultd/datmeta"


def _t(name: str) -> str:
    return f"{{{NS}}}{name}"


class CatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class HashedFile:
    """A reproducible artifact declaration: <fileshared> or patch <file>."""
    path: str
    size: int
    crc: str
    md5: str
    sha1: str


@dataclass(frozen=True)
class InstanceFile:
    path: str
    size: int | None
    required: bool


@dataclass(frozen=True)
class Release:
    version: str
    date: str | None
    standalone: bool
    dirs: tuple[str, ...]
    shared: tuple[HashedFile, ...]
    instances: tuple[InstanceFile, ...]
    pix_items: tuple[str, ...]


@dataclass(frozen=True)
class Patch:
    name: str
    target: str | None
    files: tuple[HashedFile, ...]


@dataclass(frozen=True)
class Entity:
    identifier: str
    description: str | None
    releases: tuple[Release, ...]
    patches: tuple[Patch, ...]


@dataclass(frozen=True)
class Catalog:
    name: str
    version: str
    compression: str
    entities: tuple[Entity, ...]


def _req(path: Path, el: ET.Element, attr: str) -> str:
    value = el.get(attr)
    if value is None:
        tag = el.tag.rsplit("}", 1)[-1]
        raise CatalogError(f"{path}: <{tag}> missing required @{attr}")
    return value


def _hashed(path: Path, el: ET.Element) -> HashedFile:
    return HashedFile(
        path=_req(path, el, "path"),
        size=int(_req(path, el, "size")),
        crc=_req(path, el, "crc"),
        md5=_req(path, el, "md5"),
        sha1=_req(path, el, "sha1"),
    )


def load(path: Path) -> Catalog:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise CatalogError(f"{path}: {exc}") from exc
    if root.tag != _t("vault"):
        raise CatalogError(f"{path}: root element is {root.tag}, expected vault")

    entities: list[Entity] = []
    ents_el = root.find(_t("entities"))
    if ents_el is not None:
        for ent_el in ents_el.findall(_t("entity")):
            releases: list[Release] = []
            rels_el = ent_el.find(_t("releases"))
            if rels_el is not None:
                for rel_el in rels_el.findall(_t("release")):
                    dirs: list[str] = []
                    shared: list[HashedFile] = []
                    instances: list[InstanceFile] = []
                    fs_el = rel_el.find(_t("fs"))
                    if fs_el is not None:
                        dirs = [_req(path, d, "path") for d in fs_el.findall(_t("dir"))]
                        shared = [_hashed(path, f) for f in fs_el.findall(_t("fileshared"))]
                        for f in fs_el.findall(_t("fileinstance")):
                            size = f.get("size")
                            instances.append(InstanceFile(
                                path=_req(path, f, "path"),
                                size=int(size) if size is not None else None,
                                required=f.get("required", "false") == "true",
                            ))
                    pix_el = rel_el.find(_t("pix"))
                    pix_items = ([_req(path, i, "name") for i in pix_el.findall(_t("item"))]
                                 if pix_el is not None else [])
                    releases.append(Release(
                        version=_req(path, rel_el, "version"),
                        date=rel_el.get("date"),
                        standalone=rel_el.get("standalone", "true") == "true",
                        dirs=tuple(dirs),
                        shared=tuple(shared),
                        instances=tuple(instances),
                        pix_items=tuple(pix_items),
                    ))
            patches: list[Patch] = []
            pats_el = ent_el.find(_t("patches"))
            if pats_el is not None:
                for pat_el in pats_el.findall(_t("patch")):
                    patches.append(Patch(
                        name=_req(path, pat_el, "name"),
                        target=pat_el.get("target"),
                        files=tuple(_hashed(path, f) for f in pat_el.findall(_t("file"))),
                    ))
            entities.append(Entity(
                identifier=_req(path, ent_el, "identifier"),
                description=ent_el.get("description"),
                releases=tuple(releases),
                patches=tuple(patches),
            ))

    return Catalog(
        name=_req(path, root, "name"),
        version=_req(path, root, "version"),
        compression=_req(path, root, "compression"),
        entities=tuple(entities),
    )
