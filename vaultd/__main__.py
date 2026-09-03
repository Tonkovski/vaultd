"""Entry point: python -m vaultd <layer> ..."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "overwatch":
        from vaultd.overwatch.__main__ import main as overwatch_main
        return overwatch_main(argv[1:])
    if argv and argv[0] == "initvault":
        from vaultd.initvault import main as initvault_main
        return initvault_main(argv[1:])
    print("usage: python -m vaultd overwatch {xsdvalidate|fswarmup|datverify} ...",
          file=sys.stderr)
    print("       python -m vaultd initvault NAME [--compression {none,7z}] ...",
          file=sys.stderr)
    print("       (sokoban keepers: not implemented yet)", file=sys.stderr)
    return 2


raise SystemExit(main())
