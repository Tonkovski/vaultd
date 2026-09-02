# Datmeta Convention

The contract for VaultD catalogs. `convention/datmeta.xsd` enforces the syntax;
everything in this document that the schema cannot express is a semantic rule,
owned by overwatch (verification) and sokoban (ingest). XSD = syntax, tools =
semantics.

## The two documents

Every vault carries exactly two bookkeeping files:

* `datmeta.xml` — the **declared catalog**: what the vault protects and what
  those artifacts must be. Validates against `datmeta.xsd`. This is the
  showable document ("hey, check out what I got") — submittable to No-Intro or
  compared against another owner's copy.
* `entities.checksum` — the **physical mirror**: what actually exists on disk
  under `entities/`, one line per physical file:

  ```
  <CRC32> <md5> <sha1> <size> <path relative to entities/>
  ```

  CRC32 uppercase hex, md5/sha1 lowercase hex, size in bytes (decimal),
  single spaces, forward slashes. Parsers take four fixed fields, then the
  remainder of the line is the path — paths may contain spaces.

## Truth doctrine

1. `datmeta.xml` declares hashes **only for reproducible artifacts** — content
   someone else could independently hold an identical copy of and compare:
   `<fileshared>` and patch `<file>` entries. Full trio (crc/md5/sha1),
   computed at ingest.
2. `<fileinstance>` and `<pix>` are **per-copy evidence** (keys, signatures,
   card data; scans, photos). Nobody else has your copy, so their integrity is
   custody work: `entities.checksum` in plain vaults, the container hash in
   compressed vaults. They are declared in the XML (presence, not hashes).
   A `<fileinstance>` may carry `size` when the size is fixed across copies —
   that is shared intel; hashes never.
3. In an **uncompressed** vault, `entities.checksum` mirrors every stored file.
   In a **compressed** vault, it mirrors the release containers (`<version>.7z`)
   and any plain-stored files (patches). Content truth lives in the XML;
   container truth lives in the checksum. The container is a transport wrapper
   and is opaque — no attempt is made to make it byte-reproducible.

## Vault attributes

| attribute     | meaning                                                        |
|---------------|----------------------------------------------------------------|
| `name`        | vault identity; MUST equal the vault directory name (V2)       |
| `version`     | catalog revision stamp `YYYYMMDD`; the only date field         |
| `author`      | optional                                                       |
| `description` | optional                                                       |
| `compression` | `none` \| `7z` — see Compression profiles                      |

Every vault uses the same structured release layout (`fs/shared`,
`fs/instance/<set>`, `pix/<item>` — see file_hierarchy.md); there is no
storage-form switch.

## Instance semantics

* One release, one namespace: a declared path is either `<fileshared>` or
  `<fileinstance>`, never both. A file's classification is part of its
  identity (schema-enforced).
* `<dir>` declarations root at `fs/shared/`; per-copy empty directories
  cannot be declared.
* The `<fileinstance>` list is a whitelist: every physical file under
  `fs/instance/<set>/` must match a declared path; undeclared files are a
  violation (V4).
* A `<set>` is one physical copy and may be partial — it carries whatever
  evidence that copy has. Set directories are named with a UUIDv4 (lowercase,
  hyphenated), assigned at ingest.
* `required="true"` means the release is complete only if at least one set
  carries the file.
* Declared `size`, when present, must match every physical occurrence in
  every set.

## Compression profiles

* `none`: releases are stored as plain directory trees.
* `7z`: each release is stored as one `<version>.7z`. Profile, pinned:
  * created by 7-Zip (LZMA/LZMA2 methods);
  * per-member CRC32 table present and readable — always;
  * no password, no encrypted header (either would hide the member table);
  * member paths inside the archive follow the same layout a plain vault
    would use for that release.

Patches are never wrapped in release containers: `patches/<name>/` stays a
plain directory tree in every vault, and its files appear individually in
`entities.checksum`.

## Ingest contract

A compressed archive is never a foreign object. Raw content enters via the
dropzone; **ingest is the sole creator and the first auditor** of everything
under `entities/`:

1. compute the full trio on the raw content — these become the XML
   declarations;
2. pack with the pinned toolchain (compressed vaults);
3. audit its own product: read back the archive member table — paths, sizes,
   CRC32s — against step 1;
4. enroll: write the XML entry and the `entities.checksum` line(s).

No lane exists for accepting an archive that ingest did not build.

## Audit tiers (overwatch)

1. **Warmup** — hash physical files, compare against `entities.checksum`.
   Both vault kinds, same code.
2. **Directory audit** (compressed vaults) — read the container's member table
   and match it against the XML declarations: path/size/CRC32 for
   `<fileshared>` members; path-whitelist membership plus declared size for
   `fs/instance/<set>/` members; path membership under declared items for
   `pix/` members. No extraction. The
   trust chain: tier 1 verified the container bytes, which include the member
   table, so the table is authentic. For uncompressed vaults this tier is
   direct: hash files, match the XML.
3. **Deep audit** (on demand) — extract and verify the full trio against the
   XML.

Open: which of the three hashes the routine sanitizing runs query (all are
declared; the lane split is a later decision).

## Verifier obligations

Rules the schema cannot express; overwatch MUST enforce V1, V3 and V4, and
SHOULD lint V2:

* **V1** — vault `name` equals the vault directory name.
* **V2** — path segments are Windows-safe: no reserved device names
  (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), no trailing dot
  or space, no control characters. (The schema already blocks `/ \ : * ? " < >
  |`, leading dots and `.`/`..` segments.)
* **V3** — compressed vaults: every release container carries a readable
  per-member CRC32 table (ingest guarantees it; overwatch re-checks it).
* **V4** — instance whitelist: every physical file under `fs/instance/<set>/`
  matches a declared `<fileinstance>` path; declared `size` matches every
  occurrence; `required` files appear in at least one set.

Deliberately NOT enforced: childless entities and empty `<fs>`/`<release>`
elements are legal — an MIA known only by title may be enrolled.

## Open decisions

* Sanitizing-run hash lane split (see Audit tiers).
