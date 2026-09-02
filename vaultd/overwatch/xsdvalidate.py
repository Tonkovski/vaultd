"""Validate vault catalogs against convention/datmeta.xsd."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vaultd.locator import REPO_ROOT
from vaultd.overwatch import _common

DEFAULT_SCHEMA = REPO_ROOT / "convention" / "datmeta.xsd"


def main(argv: list[str] | None = None) -> int:
    _common.setup_io()
    parser = argparse.ArgumentParser(
        prog="xsdvalidate", description=__doc__)
    _common.add_vault_args(parser)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA,
                        help="alternate schema file")
    ns = parser.parse_args(argv)

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

    vaults = _common.resolve_vaults(ns)
    if vaults is None:
        return 2

    all_ok = True
    for name, vdir in vaults.items():
        report = _common.Report(name)
        xml_path = vdir / "datmeta.xml"
        if not xml_path.is_file():
            report.error(f"missing {xml_path}")
        else:
            try:
                doc = etree.parse(str(xml_path))
            except etree.XMLSyntaxError as exc:
                report.error(f"not well-formed: {exc}")
            else:
                if not schema.validate(doc):
                    for entry in schema.error_log:
                        report.error(f"line {entry.line}: {entry.message}")
        all_ok &= report.emit()
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
