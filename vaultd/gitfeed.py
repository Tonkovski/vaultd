"""Shared git-feed sync for keeper dbsync tools.

Clones a feed repository shallowly (one branch, depth 1) or delta-updates an
existing clone (fetch --depth 1 + reset --hard). git runs as a subprocess
with output streaming to the terminal; a missing git binary is a clean
failure. Interruption-safe: git's own transaction model covers everything.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def run_git(args: list[str], git: str) -> int:
    print(f"$ git {' '.join(args)}")
    try:
        return subprocess.run([git, *args]).returncode
    except OSError as exc:
        print(f"ERROR: cannot run git: {exc}", file=sys.stderr)
        return -1


def sync_git_feed(target: Path, url: str, branch: str) -> bool:
    git = shutil.which("git")
    if git is None:
        print("ERROR: git not found on PATH; install git or fix PATH, "
              "then rerun dbsync", file=sys.stderr)
        return False
    if (target / ".git").exists():
        print(f"{target.name}: updating {target}")
        code = run_git(["-C", str(target), "fetch", "--depth", "1",
                        "origin", branch], git)
        if code == 0:
            code = run_git(["-C", str(target), "reset", "--hard",
                            f"origin/{branch}"], git)
    elif target.exists() and any(target.iterdir()):
        print(f"ERROR: {target} exists without .git; refusing to touch it",
              file=sys.stderr)
        return False
    else:
        print(f"{target.name}: cloning {url} (shallow, {branch} only)")
        code = run_git(["clone", "--depth", "1", "--single-branch",
                        "--branch", branch, url, str(target)], git)
    if code != 0:
        print(f"ERROR: git exited with status {code}", file=sys.stderr)
        return False
    return True
