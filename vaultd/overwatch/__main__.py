"""Dispatch: python -m vaultd.overwatch {xsdvalidate|fswarmup|datverify} ..."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    modules = ("xsdvalidate", "fswarmup", "datverify")
    if not argv or argv[0] not in modules:
        print(f"usage: python -m vaultd.overwatch {{{'|'.join(modules)}}} ...",
              file=sys.stderr)
        return 2
    if argv[0] == "xsdvalidate":
        from vaultd.overwatch.xsdvalidate import main as module_main
    elif argv[0] == "fswarmup":
        from vaultd.overwatch.fswarmup import main as module_main
    else:
        from vaultd.overwatch.datverify import main as module_main
    return module_main(argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
