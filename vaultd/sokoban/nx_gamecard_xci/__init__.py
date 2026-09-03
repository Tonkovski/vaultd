"""Keeper for the Nintendo Switch gamecard (XCI) vault.

The vault name is the keeper's module name — the locator toml is the only
binding (override key = this name; absent that, root/<name>).
"""

VAULT_NAME = __name__.rsplit(".", 1)[-1]
