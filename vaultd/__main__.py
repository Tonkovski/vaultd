"""Entry point: python -m vaultd <layer> ..."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "overwatch":
        from vaultd.overwatch.__main__ import main as overwatch_main
        return overwatch_main(argv[1:])
    print("usage: python -m vaultd overwatch {xsdvalidate|fswarmup|datverify} ...",
          file=sys.stderr)
    print("       (sokoban keepers: not implemented yet)", file=sys.stderr)
    return 2


raise SystemExit(main())
