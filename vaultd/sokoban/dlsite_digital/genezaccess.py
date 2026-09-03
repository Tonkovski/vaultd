"""DLSite keeper: generate the ezaccess browsing view.

Shape (keeper-owned):

    ezaccess/
      [<id>] <description>/
        [<version>] <filename>   -> ../../entities/<id>/releases/<version>/fs/shared/...
        [patch] <name>/          -> ../../entities/<id>/patches/<name>

Derived and disposable: regeneration wipes the previous view (symlinks and
empty dirs only — a regular file in ezaccess aborts) and rebuilds from the
catalog. Links are relative, so the vault relocates as a unit.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path, PurePosixPath

from vaultd import catalog, ezlink, locator
from vaultd.sokoban.dlsite_digital import VAULT_NAME


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dlsite-genezaccess", description=__doc__)
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")
    args = parser.parse_args(argv)

    try:
        vdir = locator.resolve([VAULT_NAME], args.locator)[VAULT_NAME]
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        cat = catalog.load(vdir / "datmeta.xml")
    except catalog.CatalogError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    ez = vdir / "ezaccess"
    try:
        ezlink.safe_wipe(ez)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    ez.mkdir(exist_ok=True)

    entities_dir = vdir / "entities"
    links = 0
    try:
        for ent in cat.entities:
            desc = ezlink.sanitize(ent.description or "")
            label = f"[{ent.identifier}] {desc}".rstrip()
            ent_ez = ez / label
            made_any = False
            for rel in ent.releases:
                rel_dir = entities_dir / ent.identifier / "releases" / rel.version
                for f in rel.shared:
                    target = rel_dir / "fs" / "shared" / Path(*PurePosixPath(f.path).parts)
                    name = f"[{rel.version}] {PurePosixPath(f.path).name}"
                    ent_ez.mkdir(exist_ok=True)
                    ezlink.relative_symlink(ent_ez / name, target)
                    links += 1
                    made_any = True
            for pat in ent.patches:
                target = entities_dir / ent.identifier / "patches" / pat.name
                name = f"[patch] {ezlink.sanitize(pat.name, pat.name)}"
                ent_ez.mkdir(exist_ok=True)
                ezlink.relative_symlink(ent_ez / name, target)
                links += 1
                made_any = True
            if not made_any:
                ent_ez.mkdir(exist_ok=True)  # MIA entity: empty shelf, still visible
    except OSError as exc:
        print(f"ERROR: cannot create symlink: {exc}", file=sys.stderr)
        print("       on Windows, enable Developer Mode or run with symlink privilege",
              file=sys.stderr)
        return 1

    print(f"{VAULT_NAME}: ezaccess rebuilt — {len(cat.entities)} entit"
          f"{'y' if len(cat.entities) == 1 else 'ies'}, {links} link(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
