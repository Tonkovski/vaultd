# GOG digital ingest

The operator assigns ownership, bonus classification and versions before intake.
Platforms may be explicit or inferred from installer extensions. The keeper
preserves original payload filenames.

```text
dropzone/gog_digital/
  <game-or-dlc-slug>/
    bonus/
      <original files, including installer-shaped bonuses>
    windows#<version>/
      <original installer.exe>
      <original installer-1.bin>
    osx#<version>/
      <original files>
    linux#<version>/
      <original files>
  <package-slug>/
    bonus/
      <original package bonus files>
```

Every release contains files directly, with no nested directories. Releases
need not all be present. The lowercase `bonus` spelling is mandatory. Bonus
releases carry `standalone="false"`; other releases retain their existing
standalone behavior, including DLC installer releases. Platform comes first,
followed by `#`, then the version. Only the first `#` is the separator;
any later `#` belongs to the version. Version labels are taken literally
from the prepared directory, including old versions absent from current feeds.
There is no language restriction; version strings are never derived from payload filenames.

Files directly under a slug are rejected: they must be arranged in release
directories first. Outside lowercase `bonus/`, every file must end in `.exe`,
`.bin`, `.dmg` or `.sh`, compared case-insensitively. The rule applies to both
explicit and inferred platform directories. Unexpected files, including
extensionless files, fail preflight with their names in the diagnostic and
retain the entire slug before hashing, copying or renaming any release.
Other slugs can continue. `bonus/` permits arbitrary extensions and extensionless
files, subject to the existing flat-layout and filename-safety rules. This is
a layout check; it does not inspect installer contents or impose an OS-specific
extension subset.

For every directory except `bonus`, first recognize the exact prefixes
`windows#`, `osx#` or `linux#`. An explicit prefix is authoritative and must
have a nonempty version. Without one, inspect the immediate files using
case-insensitive extensions: `.exe` means Windows, `.dmg` means macOS (`osx`),
and `.sh` means Linux. GOG confirms its `.sh` installer format in its
[support instructions](https://support.gog.com/hc/en-us/articles/213527989-Afterlife).
Exactly one detected platform is required; mixed platforms or no recognized
extension fail preflight with a diagnostic. Extensions identify a proposed
platform, not installer integrity. Scripts are never executed for detection.

The entire unprefixed directory name becomes the version: `1.6.1/setup.exe`
resolves to `windows#1.6.1`. The detected name is reported and used automatically.
If two source directories resolve to the same release, including case twins,
the slug fails preflight before hashing or ingest. `bonus/` bypasses platform
detection and retains its existing classification.

When preparing a version label, replace each Windows-forbidden character
(`/`, `\`, `:`, `*`, `?`, `"`, `<`, `>`, `|`, and control characters U+0000–U+001F)
with one `_`. For example, `N/A` becomes `N_A`, giving the directory and catalog
release `windows#N_A`. Existing underscores and other valid characters remain
unchanged. The manually prepared directory must already use this spelling;
ingest does not reinterpret nested paths as version strings. Other path safety
rules still apply. Payload filenames retain their original spelling.

## Metadata and custody

- Numeric GOG product ID becomes the entity identifier. Slugs are internal
  intake lookup keys only; they are not catalog identifiers or descriptions.
- Exact slug lookup includes package (`pack`) records when checking for
  clashes. The unique match must be a game, DLC or package; historical records
  still count and neither type nor availability breaks a tie. Release contents
  do not break a tie either. A clash reports every ID, type, access status, title and GOGDB URL,
  and retains the entire slug directory before hashing or ingesting any release.
  Other slugs continue, but the run exits with failure status. Missing slugs
  also fail; a unique historical game/DLC remains eligible for admission.
- Game and DLC records are accepted regardless of standalone store listing.
  Packages can ingest their own lowercase `bonus` release under their own ID.
  Any other release directory under a package fails the entire slug preflight;
  split game/DLC installers into their actual owning products manually.
  Package bonuses are undated and non-standalone, including installer-shaped
  bonus files. A package's `requires` or included products do not reclassify it
  as a DLC or create a `[DLC|...]` comment.
- A separate goodies product stays a separate entity. Its files are never
  reassigned to a main game automatically.
- GOGDB title/developer/publisher fill empty catalog attributes. The exact
  `https://www.gogdb.org/product/<id>` URL is added to the entity's URLs.
- A new non-bonus release gets `date="YYYY-MM-DD"` from `builds[].date_published`,
  matching its own product ID, exact platform and normalized version. The same
  illegal-character replacement applies to feed versions; spelling and case
  otherwise remain significant. Among these exact matches, prefer builds whose
  `listed` field is explicitly `true`. When no match is listed, use all matching
  historical records, including records with an absent listing flag. All builds
  in the selected group must have valid publication dates and agree on one
  calendar day. A conflicting or invalid listed group does not fall back to
  unlisted builds. Missing matches, invalid dates or conflicting days
  produce a warning and leave `date` unset; other admission checks continue.
  Diagnostics identify the product/release and conflicting or invalid build
  records. The day is taken as recorded, without conversion to the host timezone.
  This is a build publication date. Product/store dates, observation timestamps
  and parent-game dates are not fallbacks. `bonus` stays undated without a warning.
  Existing releases retain their original date, including an absent date, on reruns.
- DLC `requires` chains must resolve to one base game. The entity comment is
  `[DLC|<base-product-id>]`. Missing records, cycles, package dependencies,
  multiple base games and conflicting existing comments fail admission.
- There is no external DAT/hashdb gate. Ingest computes CRC32/MD5/SHA1 from
  each source once for the local catalog and checksum mirror. Stored payloads
  are never hashed or read back by ingest; `fswarmup` owns stored-byte checks.
  Ingest checks file inventory, sizes, stamps and bookkeeping before cleanup.
  These checks do not establish publisher authenticity or installer integrity.
- Payloads are admitted without installer signatures, embedded BIN checksum
  checks, decompression tests or bonus ZIP tests. Windows, macOS and Linux use
  the same ingest procedure. No external installer verifier is required.
- Plain vaults only. Stored files become reproducible `fileshared` declarations
  under `entities/<id>/releases/<prepared-version>/fs/shared/`.

## Invocation

Refresh the local feed independently of ingest:

```powershell
python -m vaultd.sokoban.gog_digital.dbsync
```

`dbsync` reads GOGDB's
[backup file list](https://www.gogdb.org/backups_v3/products/filelist.txt), selects
the newest dated snapshot and downloads it to `db/gog_digital/products.tar.xz`.
It follows GOGDB's [bulk-download guidance](https://www.gogdb.org/moreinfo).
The full XZ stream, TAR and product JSON are validated before atomic replacement;
members are never extracted. A failed download or validation preserves the
previous cache. Temporary downloads are removed on ordinary errors and Ctrl+C;
an abrupt process kill may leave an unused temporary file, which ingest ignores.

`products.sync.json` records the source URL, byte count, SHA256 and HTTP cache
validators. An unchanged snapshot uses conditional HTTP requests, after checking
that the local archive still matches that record. Missing/corrupt bookkeeping or
a changed archive triggers a full download. If interruption occurs between archive
and bookkeeping publication, the valid archive remains usable and the next sync
refreshes it. These hashes check the feed cache, independently of payload integrity.
The command takes no arguments and exits 0 on success, 1 on failure, 130 on Ctrl+C.

Ingest uses that local snapshot by default:

```powershell
python -m vaultd.sokoban.gog_digital.ingest
```

To select another local feed:

```powershell
python -m vaultd.sokoban.gog_digital.ingest --gogdb <GOGDB-backup.tar.xz>
```

`--gogdb` also accepts an upstream directory containing `<id>/product.json`;
its default is `db/gog_digital/products.tar.xz`. The native backup is streamed without
extracting it. `--locator` optionally selects another vault locator. Explicit relative CLI
paths follow the caller's working directory; default paths anchor to the repo.

Ingest makes no network requests and writes no derived feed cache.
External feeds belong in `db/`; experiments and synthetic fixtures belong in
`testfield/`. There is no CLI source override: intake is always the keeper's
fixed dropzone directory. Feed refresh/setup is separate from ingest.

## Batch and restart behavior

Only one product entity is active at a time. The next slug is not resolved,
preflighted, hashed or copied until the current entity's releases have each
completed or failed. Loading the shared GOGDB identity index happens once
before that serial loop and is announced by the single run-start line.

The slug directory is preflighted for layout and metadata, recording each
source file's identity, size and nanosecond timestamps without reading its
contents. Its releases run sequentially in codepoint order, each with independent conflict and
custody checks. Failed versions remain in place while passing versions
continue. This is per-release checkpointing, not an atomic transaction
spanning all versions of a product.

For an inferred release, catalog and source checks are followed by renaming
its source directory to the canonical `<platform>#<version>` name. The destination is
checked again before renaming. This pins its identity for reruns even if an
interrupted cleanup leaves only BIN files. Failures before renaming leave the
original source name; interruptions afterward can leave the canonical name.

For a fresh release: check catalog conflicts and source stability, pin any
inferred source name, then compute CRC32/MD5/SHA1 while copying each file.
This uses one full payload read per file, combining hashing and copying.
Check destination sizes with stat; there is no destination readback and no
separate source hashing pass during preflight or cleanup. Payloads are copied,
not moved, so the source remains until the release checkpoint succeeds.

After copying, recheck inventories and file stamps, checkpoint checksum then
XML atomically, and reload and validate both. The final audit checks the saved
file declarations, checksum entries, complete physical inventory and the file
sizes and stamps captured after copying, without reading stored payloads.
Source stability checks compare device/file identity, size and nanosecond
mtime/ctime. The whole source inventory is checked before cleanup, and each
file's stamp is checked again immediately before its removal. Sources are
removed last. These metadata checks assume files are not modified while
preserving their identity, size and timestamps.

A Ctrl+C during copying leaves source files and possibly partial destination
files available for a rerun. A Ctrl+C between bookkeeping writes leaves a
checksum checkpoint: rerun hashes the sources once against that checkpoint
and reuses stored files with matching sizes. Missing or wrong-size checkpoint
files are recopied using that run's already computed source digest, without
hashing again. Such repairs need an additional source read for copying only.
Checkpoint conflicts are rejected before any payload write.

A Ctrl+C during source cleanup leaves an identical subset. For an enrolled
release, rerun hashes each submitted source once against its declaration and
checks the complete archived inventory and sizes, including files no longer
in intake. An identical resubmission skips copying. The final bookkeeping
audit reuses that run's file stamps; they are never persisted across runs.
Same-size stored corruption is left for a separate `fswarmup` run, whose
default CRC32 mode or full-hash mode checks the recorded source hashes.

Existing release names are immutable: differing bytes or additional filenames
under the same release fail, including `bonus`. Identical subset resubmission
can finish interrupted cleanup. Unexpected leftover files are never deleted;
unrecorded expected files can be replaced from the retained source. Links,
junctions, unsafe names and case-twin paths are refused.

The script trusts the operator's grouping. It does not prove that all advertised
bonuses were supplied, and does not match payloads to
GOG's approximate download sizes. Patch-specific catalog placement remains
unimplemented pending its own decision.

## Console output

Output is limited to ingest boundaries. The run-start line announces the local
GOGDB feed before loading. Each nonempty release then gets one START line with
slug, product ID, canonical version, file count and total size; one OK line
follows successful checkpointing and source cleanup, with elapsed time.
Failures get an immediate FAIL line with the reason. Slug preflight failures
also print FAIL. All lines have local timestamps and are flushed immediately.
There are no per-file, byte-progress, metadata-stage or checkpoint messages.

Warnings are collected in memory and printed as a grouped list after the final
completed/failed/warning counts. Categories distinguish no matching GOGDB build,
missing or invalid publication dates, and conflicting publication dates. Entries
identify the slug/product/release, outcome and exact GOGDB URL; invalid/conflicting
dates retain their build details. Identical warnings are listed once. Failed or
interrupted attempts are labeled accordingly; a warning never claims such an
attempt was ingested. The list is scoped to the current run, with no report file
or derived database written.

Ctrl+C prints an interruption message and accumulated warning summary, then
exits 130 without a Python traceback. Completed checkpoints are kept. Remaining
source files stay in intake, and the same command can be rerun. It does not
start another entity after interruption. These reporting changes add no payload
scans, hashes or destination readback.

## Development verification

Synthetic sync, metadata, recovery, read-count and admission tests live in
`testfield/gog_digital_probe/test_*.py`. They use temporary directories inside
testfield, synthetic payloads and mocked HTTP.
The sync validator has also read the existing upstream 2026-09-07 backup
successfully (15,136 products). Development has not run ingest on the real
dropzone or vault.
