"""Create a new vault skeleton: directories, fresh catalog, empty checksum.

The vault lands where the locator resolves its name (override if set, else
root/name). The generated datmeta.xml is validated against the schema before
success is reported — no tool leaves an unaudited product behind.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path
from xml.sax.saxutils import quoteattr

from vaultd import locator, winlint
from vaultd.locator import REPO_ROOT

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SUBDIRS = ("entities", "ezaccess")
DEFAULT_SCHEMA = REPO_ROOT / "convention" / "datmeta.xsd"


def _catalog_xml(name: str, compression: str, author: str | None,
                 description: str | None) -> str:
    attrs = [f'name="{name}"',
             f'version="{date.today():%Y%m%d}"']
    if author:
        attrs.append(f"author={quoteattr(author)}")
    if description:
        attrs.append(f"description={quoteattr(description)}")
    attrs.append(f'compression="{compression}"')
    joined = "\n       ".join(attrs)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<vault xmlns="http://tonkovski.github.io/vaultd/datmeta"\n'
            f'       {joined}/>\n')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="initvault", description=__doc__)
    parser.add_argument("name", help="vault name (and directory name)")
    parser.add_argument("--compression", choices=("none", "7z"), default="none")
    parser.add_argument("--author")
    parser.add_argument("--description")
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA,
                        help="alternate schema file for the self-audit")
    ns = parser.parse_args(argv)

    if not NAME_RE.match(ns.name):
        print(f"ERROR: invalid vault name {ns.name!r} "
              "(must match [A-Za-z0-9][A-Za-z0-9._-]*)", file=sys.stderr)
        return 2
    issues = winlint.segment_issues(ns.name)
    if issues:
        print(f"ERROR: vault name {ns.name!r}: {'; '.join(issues)}", file=sys.stderr)
        return 2

    try:
        root, overrides = locator.load(ns.locator)
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    target = overrides.get(ns.name, root / ns.name)

    if target.exists() and any(target.iterdir()):
        print(f"ERROR: {target} already exists and is not empty", file=sys.stderr)
        return 2

    target.mkdir(parents=True, exist_ok=True)
    for sub in SUBDIRS:
        (target / sub).mkdir(exist_ok=True)
    xml_path = target / "datmeta.xml"
    xml_path.write_text(
        _catalog_xml(ns.name, ns.compression, ns.author, ns.description),
        encoding="utf-8", newline="\n")
    (target / "entities.checksum").write_text("", encoding="utf-8")

    # Self-audit: refuse to report success on an invalid product.
    try:
        from lxml import etree
    except ImportError:
        print("ERROR: missing dependency lxml; run: uv sync", file=sys.stderr)
        return 2
    try:
        schema = etree.XMLSchema(etree.parse(str(ns.schema)))
    except (OSError, etree.LxmlError) as exc:
        print(f"ERROR: cannot load schema {ns.schema}: {exc}", file=sys.stderr)
        return 2
    doc = etree.parse(str(xml_path))
    if not schema.validate(doc):
        for entry in schema.error_log:
            print(f"ERROR: self-audit failed: line {entry.line}: {entry.message}",
                  file=sys.stderr)
        return 1

    print(f"{ns.name}: created at {target} (compression {ns.compression}, "
          "catalog self-audit OK)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
