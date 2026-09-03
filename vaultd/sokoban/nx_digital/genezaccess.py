"""NX digital keeper: generate the ezaccess browsing view.

Shape (keeper-owned): one shelf per APPLICATION GROUP — base, updates and
DLC combined, the way the collection is actually browsed:

    ezaccess/
      [<app tid>] <description>/
        [<tid>][vN][TYPE](...).nsz|nsp   -> ../../entities/<tid>/releases/...
        [patch] <name>/                  -> ../../entities/<tid>/patches/<name>

Grouping arithmetic is shared with nxlookup (dumper-pinned). Derived and
disposable: regeneration wipes the previous view (symlinks and empty dirs
only — a regular file aborts) and rebuilds from the catalog. Links are
relative, so the vault relocates as a unit.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path, PurePosixPath

from vaultd import catalog, ezlink, locator
from vaultd.sokoban.nx_digital import VAULT_NAME
from vaultd.sokoban.nx_digital.nxlookup import classify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nx-digital-genezaccess",
                                     description=__doc__)
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

    # group entities by application id; shelf name prefers the app entity's
    # own description, then any group member's.
    groups: dict[str, list[catalog.Entity]] = {}
    for entity in cat.entities:
        _, app_id = classify(entity.identifier)
        groups.setdefault(app_id, []).append(entity)

    entities_dir = vdir / "entities"
    links = 0
    try:
        for app_id in sorted(groups):
            members = groups[app_id]
            description = next(
                (member.description for member in members
                 if member.identifier == app_id and member.description),
                None) or next(
                (member.description for member in members if member.description),
                "")
            label = f"[{app_id}] {ezlink.sanitize(description)}".rstrip()
            shelf = ez / label
            shelf.mkdir(exist_ok=True)
            for member in members:
                for release in member.releases:
                    release_dir = (entities_dir / member.identifier
                                   / "releases" / release.version)
                    for shared in release.shared:
                        target = release_dir / "fs" / "shared" / Path(
                            *PurePosixPath(shared.path).parts)
                        ezlink.relative_symlink(
                            shelf / PurePosixPath(shared.path).name, target)
                        links += 1
                for patch in member.patches:
                    target = entities_dir / member.identifier / "patches" / patch.name
                    name = f"[patch] {ezlink.sanitize(patch.name, patch.name)}"
                    ezlink.relative_symlink(shelf / name, target)
                    links += 1
    except OSError as exc:
        print(f"ERROR: cannot create symlink: {exc}", file=sys.stderr)
        print("       on Windows, enable Developer Mode or run with symlink "
              "privilege", file=sys.stderr)
        return 1

    print(f"{VAULT_NAME}: ezaccess rebuilt — {len(groups)} group(s), "
          f"{links} link(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
