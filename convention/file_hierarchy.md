# File Hierarchy

## Workspace (git repo)

The repo holds the runtime and the bookkeeper layer only. Payload never enters
version control.

```text
vaultd/                    repo root (E:\vaultd)
  convention/              contracts: datmeta.xsd, datmeta.md, this file
  vaultd/                  python package, run as `python -m` from repo root
    __main__.py
    sokoban/               per-library keepers (ingest and vault-specific work)
      nx_digital/
      nx_gamecard_xci/
      dlsite_digital/
    overwatch/             verification layer (warmup, audits, semantics V1-V4)
  vault/                   payload staging, gitignored; destined for the NAS
  vaultd.local.toml        machine-local library locator, gitignored
```

Package directory names use `_` where a vault name uses `-` (Python module
names cannot contain `-`).

## Library locator (`vaultd.local.toml`)

Machine-local, never versioned, rests at the workdir root:

```toml
root = "E:/vaultd/vault"           # every vault dir is assumed inside root

[overrides]                        # relocated vaults only
NX-Digital = "//nas/vaultd/NX-Digital"
```

Resolution: a vault named `N` lives at `overrides[N]` if set, else `root/N`.
Keys in `[overrides]` are vault names as declared in `datmeta.xml`. Paths use
forward slashes.

## Library

One vault = one self-contained directory, located via the library locator.
The vault is deliberately self-describing: catalog and checksum travel with
the payload, so a library survives without the repo.

```text
<vault-name>/
  db/                      trusted offline metadata feeds (keeper-owned layout)
  dropzone/                raw inputs, experiments, quarantine (keeper-owned)
  entities/                the only required storage root for archived payload
  ezaccess/                generated human-friendly view; derived, disposable
  datmeta.xml              declared catalog (see datmeta.md)
  entities.checksum        physical mirror   (see datmeta.md)
```

* `db/` and `dropzone/` internal structure is owned by that vault's keeper
  scripts, not by this convention.
* `ezaccess/` is regenerable from catalog + entities at any time and is never
  part of truth. Deleting it loses nothing. (Link mechanism to be redesigned
  with SMB/NAS in mind.)

## entities/ layouts by compression

Every vault uses the structured release layout. Paths in `entities.checksum`
are relative to `entities/`.

### compression="none"

```text
entities/
  <identifier>/
    releases/
      <version>/
        fs/
          shared/          <fileshared> files
          instance/
            <set>/         one dir per physical copy; <fileinstance> files
        pix/
          <item>/          one dir per declared <pix> item
    patches/
      <patch-name>/
```

* `<set>` directories are UUIDv4-named, one per physical copy (see
  datmeta.md); a declared `<fileinstance>` path may appear in any number of
  sets. `required="true"` means at least one set must carry it for the
  release to be complete.
* `<dir>` declarations mark empty directories that must exist under
  `fs/shared/`.
* `<fileshared>` files are hashed in XML and checksum; patch files likewise.

### compression="7z"

```text
entities/
  <identifier>/
    releases/
      <version>.7z         contains fs/... and pix/... exactly as the plain
    patches/                 <version>/ directory would; hashed in checksum only
      <patch-name>/        always plain, never inside a container
```

## Compatibility requirements

* Enable Windows long-path support for deep release trees and long
  human-readable names.
* `ezaccess/` generation needs link-creation privileges (Developer Mode) on
  Windows; its future NAS-aware form is an open design item.
