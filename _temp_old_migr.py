"""One-shot: feed the old NX-Digital vault's NSZs to the fixnsp intake.

Moves every *.nsz under the old vault's entities/ into dropzone/fixnsp/,
one by one (same-volume rename: atomic, Ctrl-C ready — rerun to continue).
Patch trees are evacuated FIRST to testfield/old-nx-patches/<entity>/ so
they never get orphaned by the drain. Directories emptied by the drain are
purged bottom-up, even when interrupted.

Temporary script; delete after the migration completes.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

OLD_ENTITIES = Path(r"E:\vaultd.bak\vault\NX-Digital\entities")
FIXNSP_INTAKE = Path(r"E:\vaultd\dropzone\fixnsp-task")
PATCH_REFUGE = Path(r"E:\vaultd\testfield\old-nx-patches")


def purge_empty(root: Path) -> int:
    removed = 0
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
            removed += 1
    return removed


def main() -> int:
    if not OLD_ENTITIES.is_dir():
        print(f"ERROR: {OLD_ENTITIES} not found", file=sys.stderr)
        return 2
    FIXNSP_INTAKE.mkdir(parents=True, exist_ok=True)

    # Phase A: evacuate patch trees before anything else.
    for patches_dir in sorted(OLD_ENTITIES.glob("*/patches")):
        entity = patches_dir.parent.name
        refuge = PATCH_REFUGE / entity
        if refuge.exists():
            print(f"patches: {entity} already evacuated, skipping")
            continue
        PATCH_REFUGE.mkdir(parents=True, exist_ok=True)
        shutil.move(str(patches_dir), str(refuge))
        print(f"patches: {entity} -> {refuge}")

    # Phase B: drain NSZs and labeled NSPs one by one.
    targets = sorted([*OLD_ENTITIES.rglob("*.nsz"), *OLD_ENTITIES.rglob("*.nsp")])
    print(f"files to move: {len(targets)}")
    moved = skipped = 0
    interrupted = False
    try:
        for index, source in enumerate(targets, 1):
            dest = FIXNSP_INTAKE / source.name
            if dest.exists():
                print(f"[{index}/{len(targets)}] SKIP (exists): {source.name}")
                skipped += 1
                continue
            os.rename(source, dest)
            moved += 1
            print(f"[{index}/{len(targets)}] {source.name}", flush=True)
    except KeyboardInterrupt:
        interrupted = True
        print("\ninterrupted — rerun to continue where this left off")
    finally:
        removed = purge_empty(OLD_ENTITIES)
        print(f"\nmoved: {moved}, skipped: {skipped}, "
              f"empty dirs purged: {removed}, "
              f"remaining nsz: {len(list(OLD_ENTITIES.rglob('*.nsz')))}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
