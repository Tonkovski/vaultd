"""Keeper for the DLSite digital-works vault.

The vault name is the keeper's module name — no hardcode: the locator toml
is the only binding (override key = this name; absent that, root/<name>).
"""

VAULT_NAME = __name__.rsplit(".", 1)[-1]
