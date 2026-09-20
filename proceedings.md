# VaultD Proceedings — AI handoff digest

Written 2026-09-04 at the operator's order, for migration to another AI.
Repo: `E:\vaultd` (runtime, git). Old project: `E:\vaultd.bak` — lessons,
raw bytes and oracle ONLY; the reboot is a start-over, not a structure
migration. Read `convention/datmeta.md`, `convention/file_hierarchy.md`
and the keeper walkthrough `vaultd/sokoban/nx_digital/fixnsp.md` before
touching anything — this file is the map, those are the law.

## 1. Contract with the operator (non-negotiable)

- Operator gives orders; AI handles detail. One thing at a time. No TL;DR
  padding. When something seems wrong, question AT ONCE.
- **No decision, no implement.** Anything not explicitly ordered or nodded
  gets a pindown sheet and waits. Un-nodded features get removed as "fake
  quested features".
- **Git is manual-only.** AI never runs state-changing git; read-only git
  is fine. The operator pushes the red button.
- "Make bak" = copy `<file>.bak-<stamp>` before risky edits — script-level
  version control between the operator's commits. NOT a runtime feature.
- Runtime is always a git checkout (`package = false` in pyproject is
  doctrine). Vault contents are destined for NAS; `db/` and `dropzone/`
  stay runtime-side (SSD vs HDD reasoning).

## 2. Core convention (short form; the .md files are authoritative)

- Two bookkeeping files per vault: `datmeta.xml` (declared catalog,
  validates against `convention/datmeta.xsd`) and `entities.checksum`
  (physical mirror, lines `CRC MD5 SHA1 SIZE PATH` — four fixed fields,
  then the path, which may contain spaces).
- Truth doctrine: full hash trio only for reproducible artifacts
  (`fileshared`, patch `file`); `fileinstance`/`pix` are per-copy custody
  evidence (declared presence, never hashes; `size` optional shared intel).
- Ordering rule: every list-like sequence sorted by its main key.
- Compression `none | 7z`; 7z profile pinned (readable CRC table
  mandatory, no encryption). All four vaults currently `none`.
- Batch discipline: linear, self-contained elements — metadata work, land
  payload as copy, checkpoint (checksum then xml, atomic, self-audit),
  remove source LAST. Ctrl-C anywhere is recoverable by rerunning.
  Parallelism rejected (RomVault precedent).
- Ingest is the sole creator and first auditor of `entities/`. Verifier
  obligations V1–V4 in datmeta.md. Childless entities (MIA known by title)
  are legal.
- Locator: `vaultd.local.toml` at repo root is the only binding (`root` +
  `[overrides]`); vault name = keeper module name; no default may depend
  on cwd.

## 3. Layout

- `vaultd/` shared: `locator`, `checksum`, `hashing`, `catalog`,
  `catwrite`, `winlint`, `ezlink`, `gitfeed` (pure git-calling module),
  `titledb` (NACP-order `REGION_PRIORITY` ladder + `TitleDB` lazy reader,
  now takes optional `priority` sequence), `initvault`.
- `vaultd/overwatch/`: `xsdvalidate`, `fswarmup` (`--speed 0–4`),
  `datverify`.
- `vaultd/sokoban/<keeper>/`: `dlsite_digital`, `nx_gamecard_xci`,
  `nx_digital`, `gog_digital` (new, tools not yet written).
- `vault/<name>/` four vaults; `db/<keeper>/` synced sources;
  `dropzone/` public intake at repo root.

## 4. NX digital keeper — state

- Migration from the old vault is COMPLETE: 842 entities, 963/963
  checksum-line parity, 27/27 byte-identity pipeline proof beforehand.
- Label system: `--force LABEL` marks fileshared filename only; priority
  vanilla > `[GAMECARD]` > custom; labeled digital artifacts stay bare NSP
  (compression deferred = cost saving); `dbrematch` retires labels.
  `[MIA]` is the preferred mark; old `[NoHASHDB]` names persist on some
  artifacts until dats catch up.
- nsz: invoke via `python -c "import sys; from nsz import main;
  sys.argv[0]='nsz'; main()"` — never the .exe shim — and ALWAYS
  `--machine-readable` (enlighten bars crash on redirected stdio and were
  ruled useless). Archival profile `-C -K -l 22 -t 16` proven optimal by
  parameter sweep; round-trip verified.
- Title arithmetic pinned from nxdumptool `title.h`: patch = app + 0x800;
  AOC base = (app & 0xFFFFFFFFFFFFF000) + 0x1000, DLC ids in
  [base+1, base+2000].
- **fixnsp** (`fixnsp.py` + walkthrough `fixnsp.md`): strict-only, nsz -D
  the sole external, in-house RSA-PSS the sole verifier. Step 5 = bounded
  enumeration of the composed transform space (distribution byte ×
  keygen pairs × rights forms ≈ 80 headers; CNMT scalar axis for Metas —
  CNMTDB first, firmware catalog fallback). **Best effort was redefined
  this session**: BOTH lanes run the full enumeration; the noncanonical
  lane (hash ≠ declared id) oracles on signature + expected id, the
  hash-consistent lane (`restore_signed_header_nca`) on the signature
  alone — it pins exact bytes, at most one candidate can pass. The old
  linear ladder (isolated gamecard flip / single rights reversal) is
  purged. Every NCA exits signature-valid or honestly IMPOSSIBLE.
- Forgery casework (live): dropzone/fixnsp holds 24 Atelier Yumia KR DLC
  NSPs (DLC 200–220, 701–703) judged IMPOSSIBLE — hacPack-family repacks,
  never Nintendo-signed. Fingerprints: SDK field `00110c00` (tool
  constant), sections packed at block 6 instead of Nintendo's 0x20,
  re-authored unsigned CNMTs. Sibling DLC 704 was a genuine NCA with only
  header mutilation → enumeration restored it (`0 → 18` + rights) and it
  published. The 24 stay admission-rejected; only a canonical dump closes
  those gaps. Operator disposes of the files.
- **nxlookup** (rewritten this session): reports every owned group's gaps
  (BASE/UPD/DLC), anchored by base app id; healthy groups/lines hidden;
  owned artifacts never shown regardless of label. Gap source = titledb
  ONLY, as the union of every id titledb knows (cnmts.json keys +
  versions.json keys + regex over all region catalogs — each source alone
  is partial; cnmts-only blindness hid e.g. MH Rise's 9 missing packs).
  hashdb is optional and lazily consulted solely to mint `[MIA]` marks
  (dat `game_id`/`version1`). No arguments accepted, ever.
- Display localization: per-tool `DISPLAY_REGION_PRIORITY` constants —
  one in `nxlookup.py`, an independent one in `genezaccess.py` — merged
  as prepend over the shared NACP spine (`REGION_PRIORITY` in
  `vaultd/titledb.py`, never edited per script). Operator currently runs
  HK.zh/CN.zh first. Presentation only: ingest writes canonical
  descriptions into datmeta.

## 5. Other keepers

- `dlsite_digital`: ingest strict against dlwatcher API; version = newest
  更新情報 date (manga/audio have none → release date). genezaccess done.
- `nx_gamecard_xci`: switchtdb-gated ingest, Card UID dedup, label
  system, rename-based dbrematch. Vault holds 8 cart entities.
- Test batteries live in the session scratchpad (test_overwatch,
  test_gamecard 49, test_nxdigital 20, test_nxlookup 8 checks) — they are
  SESSION-LOCAL and will not survive migration; recreate on demand or ask
  the operator whether to enshrine them in-repo.

## 6. GOG keeper — the active front (agreements pending)

Operator background rulings, given verbatim intent: two kinds to archive,
**game and dlc**; the previous attempt keyed off datvault's OhMyGOG dat,
which sometimes archives *packages* instead of game/dlc — unserious; this
attempt uses **the dat only as hashdb, all other metadata from GOGDB**.

GOGDB intel (probed 2026-09-04, https://www.gogdb.org/moreinfo):

- All data machine-readable JSON; site explicitly says no scraping and
  prefers bulk pulls. Refresh every 2 h (00:45 UTC + ~15 min).
- Bulk: monthly dumps under `/backups_v3/products/<YYYY-MM>/`
  (+ `filelist.txt`). Spot: `/data/products/<id>/product.json`
  (+ `prices.json`, `changes.json`).
- Model: `type` ∈ game | dlc | pack; linkage `dlcs[]`, `requires[]`,
  `is_included_in[]` — packs are detectable and refusable at the gate.
- Payload metadata: `dl_installer[]` (os, language, version string like
  `0.74.B.5`, per-file ids + sizes + downlinks), `dl_patch[]` (deltas),
  `dl_bonus[]` (extras — a DLC's whole payload may be bonus files),
  `dl_langpack[]`, Galaxy `builds[]`. **No hashes anywhere** — the dat
  stays sole hash authority. (GOG's authenticated downlink API serves
  per-file md5 XMLs; parked.)
- Vault inited 2026-09-04: `vault/gog_digital/` (compression none, author
  Tonkovski) + keeper package `vaultd/sokoban/gog_digital/__init__.py`
  (VAULT_NAME only). xsdvalidate passes all four vaults.

**PENDING agreement sheet — do not implement before the operator rules:**

1. Identifier: GOG numeric product id as entity `identifier`; game and
   dlc each their own entity; `pack` refused at the gate; dlc→game
   linkage db-derived, never written into datmeta.
2. Artifact scope: offline installers (surely), bonus/extras (proposed
   yes), langpacks (?), delta patches (? — GOG installers are always
   full, deltas arguably redundant).
3. OS/language scope: everything gogdb lists vs a pinned subset.
4. Version semantics: release version = installer version string
   (`0.74.B.5` style, non-numeric).
5. Hashdb gate policy: same label system as NX (`--force`, `[MIA]`
   reporting) or GOG-specific.

## 7. Parked / housekeeping

- `testfield/` is not in .gitignore (nxdumptool clone would ship) —
  flagged, unruled.
- No-Intro dats are stale (~3 months); refresh flips some `[MIA]` and
  feeds dbrematch label retirement.
- `dropzone/fixnsp-work/` holds extracted forgery evidence from the
  Yumia analysis; `dropzone/fixnsp-success/` holds the DLC 704 source;
  disposal is the operator's.
- `_temp_old_migr.py` / `_temp_earned_enroll.py` (migration one-shots)
  already deleted by the operator.
- The operator runs all state-changing commands themselves — including
  genezaccess regeneration and every git action.
