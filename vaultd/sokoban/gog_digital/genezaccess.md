# GOG browsing view

Run from the runtime checkout:

```powershell
uv run python -m vaultd.sokoban.gog_digital.genezaccess
```

`--locator <file>` optionally selects another library locator. Grouping and links
come from the vault's `datmeta.xml` and existing directories. Missing parent
titles are looked up by ID in the local `db/gog_digital/products.tar.xz` cache;
`--gogdb <path>` selects another backup or `<id>/product.json` directory. No
internet connection, hashing, copying or ingest is involved.

```text
ezaccess/
  Game title [1234567890]/
    bonus/                         -> game's bonus files
    windows#1.0/                   -> original installer and BIN parts together
    windows#1.1/
    osx#1.1/
    linux#1.1/
    DLC/
      DLC title [2345678901]/
        bonus/                     -> this DLC's bonus files
        windows#1.1/
    patches/
      <declared patch name>/
  Package title [3456789012]/
    bonus/
```

Titles come first for alphabetical browsing. Numeric IDs distinguish duplicate
titles; Windows-forbidden title characters become underscores. Very long titles
are shortened in the view only, with the full ID retained. Release labels and
payload filenames retain their catalog spelling, including lowercase `bonus`.
No version is guessed to be the latest or hidden.

DLCs group solely by the catalog's `[DLC|<parent-id>]` comment. Their own titles,
IDs, versions and bonuses remain separate. A package or other product without
a DLC marker keeps its own shelf, even if it only has bonus content. There is no
package-membership inference from titles or slugs. When a DLC's parent is absent
from the catalog, the generator uses its GOGDB title to create the normal
`Game title [<parent-id>]` shelf, holding the DLCs beside the missing base game.
This creates no catalog entity or base-game release. A missing base alone is
not a warning. Catalog titles always take precedence over external names.

Only missing parent IDs are consulted in the feed, and only their titles are
used. No derived metadata file is written. Without a usable parent title,
`Game not in catalog [<parent-id>]` remains the fallback with a warning; a missing
cache does not prevent generation. An unreadable or malformed cache fails before
clearing the old view. Childless catalog entries remain visible.

Each populated release is a relative directory symlink to its `fs/shared/`
directory. Opening it shows the original files, with multipart installers and
any nested content kept together. Declared patches similarly link to their
stored directories. The whole vault can move without breaking these links.
These are views of the archived files: editing a file through a link edits the
original. Windows needs Developer Mode or symlink privilege.

Regeneration checks the catalog layout and target directories before clearing
the old view. It refuses regular files and junctions anywhere in the old view,
and refuses a linked `ezaccess` root. Only generated symlinks and empty directories
are removed. Interruption during rebuilding can leave a partial view; rerunning
rebuilds it. Payloads, catalog and checksum are never modified.

This keeper currently handles plain (`compression="none"`) shared-file releases
and patches. Compressed vaults and per-copy instance/PIX declarations fail before
the old view is cleared.
