"""Keeper for the Nintendo Switch digital (NSP/NSZ) vault.

The vault name is the keeper's module name — the locator toml is the only
binding (override key = this name; absent that, root/<name>).

This package ships two pinned artifacts:
  * default.cert — the canonical shared certificate chain for FF public
    tickets (sha256 3c4f20dca231655e90c75b3e9689e4dd38135401029ab1f2ea32d1c2573f1dfe)
  * fixnsp.md — the repair-engine walkthrough: the summed lessons of the old
    project's trials, against the nxdumptool de-facto conventions
"""

VAULT_NAME = __name__.rsplit(".", 1)[-1]
