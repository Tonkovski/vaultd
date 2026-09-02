"""Shared plumbing for overwatch modules."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vaultd import locator


def setup_io() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def add_vault_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("vaults", nargs="*", metavar="VAULT",
                        help="vault names; default: every vault under the locator root")
    parser.add_argument("--locator", type=Path, default=None,
                        help="alternate vaultd.local.toml")


def resolve_vaults(ns: argparse.Namespace) -> dict[str, Path] | None:
    """Resolve targets or print the failure; None means exit 2."""
    try:
        vaults = locator.resolve(ns.vaults or None, ns.locator)
    except locator.LocatorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return None
    if not vaults:
        print("no vaults found")
    return vaults


class Report:
    """Per-vault findings accumulator."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def emit(self, ok_detail: str = "") -> bool:
        """Print findings and verdict; True when the vault passed."""
        for msg in self.errors:
            print(f"  ERROR: {msg}")
        for msg in self.warnings:
            print(f"  WARN: {msg}")
        if self.errors:
            print(f"{self.name}: FAIL ({len(self.errors)} error(s), "
                  f"{len(self.warnings)} warning(s))")
            return False
        detail = f" ({ok_detail})" if ok_detail else ""
        print(f"{self.name}: OK{detail}")
        return True
