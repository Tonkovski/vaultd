"""Resolve vault locations from vaultd.local.toml (see convention/file_hierarchy.md)."""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCATOR = REPO_ROOT / "vaultd.local.toml"


class LocatorError(RuntimeError):
    pass


def load(locator: Path | None = None) -> tuple[Path, dict[str, Path]]:
    path = locator or DEFAULT_LOCATOR
    if not path.is_file():
        raise LocatorError(
            f"locator not found: {path} (copy vaultd.local.toml.example and adjust)")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise LocatorError(f"{path}: {exc}") from exc
    if "root" not in data:
        raise LocatorError(f"{path}: missing required key 'root'")
    root = Path(data["root"])
    overrides = {name: Path(loc) for name, loc in data.get("overrides", {}).items()}
    return root, overrides


def resolve(names: list[str] | None = None, locator: Path | None = None) -> dict[str, Path]:
    """Map vault name -> vault directory.

    With explicit names, each must exist. Without, every directory under root
    that carries a datmeta.xml is a vault, plus all overrides.
    """
    root, overrides = load(locator)
    vaults: dict[str, Path] = {}
    if names:
        for name in names:
            vdir = overrides.get(name, root / name)
            if not vdir.is_dir():
                raise LocatorError(f"vault '{name}' not found at {vdir}")
            vaults[name] = vdir
        return vaults
    if root.is_dir():
        for child in sorted(root.iterdir()):
            if child.is_dir() and (child / "datmeta.xml").is_file():
                vaults[child.name] = child
    for name, vdir in sorted(overrides.items()):
        vaults[name] = vdir
    return vaults
