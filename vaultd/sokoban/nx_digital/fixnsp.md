# fixnsp — the repair-engine walkthrough

The linear specification for the fixnsp rewrite: the old engine's accumulated
jurisprudence (100% hashdb-match record; every anomaly met so far is codified
here) compressed into one pipeline, checked against the de-facto rebuild
convention — nxdumptool's own source. The old `fixnsp.py` is evidence, not the
artifact: it is not carried; this document plus its named lessons are.

Scope rulings: **strict-only** — no permissive mode, no BestEffort lane.
External dependencies: **`nsz -D` as decompression codec, nothing else**
(nstool is retired; see Duplications). Every byte-changing and every
verdict-bearing operation is in-house. `[NoHASHDB]` remains the MIA-recovery
lane and receives full rigor.

## Step 0 — Trust boundary

Inputs are never modified; all work happens on staged copies. `prod.keys`
(~/.switch) is trusted infrastructure. Nintendo's signatures — the NCA
main-header RSA-PSS and the ticket RSA against the pinned
`Root-CA00000003-XS00000020` issuer key — are the only authorities that can
approve bytes. Databases (CNMTDB, titledb) propose; signatures dispose.

> Lesson: install success proves nothing. Forged output that boots is still
> forged. The archival decision boundary is hash match against a trusted DAT
> or a clean hardware wash — never "it works".

## Step 1 — Intake

Accept NSP, NSZ, XCI, XCZ. NSZ/XCZ decompress via `nsz -D` into staging.
FAT32-split NSP directories (contiguous numeric parts, consistent chunk size)
are rejoined as part of intake — no separate utility. PFS0 and HFS0 tables
are parsed by in-house bounds-checked readers; a trimmed XCI whose nominal
card capacity exceeds EOF is bounds-checked, not rejected; an XCI's firmware
`update` partition is ignored. XCI is only a container source: admission is
decided from the referenced NCA headers, never the input extension.

## Step 2 — Group discovery

Every readable Meta/CNMT NCA is one independent repair attempt producing at
most one normalized NSP. A malformed group never blocks other groups in the
same container. Unreadable, duplicate, and unreferenced files are reported
and left unused. An identifiable Meta that cannot be read is a failed group,
never downgraded to an unused-wrapper warning.

## Step 3 — Meta parsing under declared geometry

The Meta NCA's HierarchicalSha256 layout — block size, hash offset/size,
data offset/size — is read from the declared section header, never assumed;
`hash_size` must equal `ceil(data_size / block_size) * 0x20`; every data
block hash, the master hash, and the section-header digest are verified.
Alignment gaps belong to neither declared layer and are never touched. The
inner PFS0 is located by its declared offset.

> Lesson (Valiant Hearts / Child of Light, recovered from the fix): multi-NCA
> titles overflow one hash block; tiny AddOnContent metas pad the other way
> (PFS0 observed at 0x200). The assumed "one 0x20 hash, then PFS0" geometry
> fails in both directions. **Declared geometry over assumed convention — for
> wrappers and for NCA-internal layers alike.**

## Step 4 — CNMT invariant and content census

For every content entry: id = first 16 bytes of the content NCA's sha256,
hash = the full sha256, size = exact byte size. No exemptions — DLC included.

Content is partitioned into standard members and type-6 delta fragments.
Carried fragments are excluded from Standard NSP output but reported
forensically (how many match local CNMT hash/size; how many are signed).
Missing content: a UPD missing only type-6 references is informational
(worded per CNMT signature status); any other missing entry is a hard
failure — payloads are never invented.

> Lesson (Calculator): a rewritten NCA with an un-rebuilt CNMT is internally
> stale — it installs, then fails at dump time. Enrolled-UPD survey: 49/57
> carried CNMT refs absent from the package, all type-6.

## Step 5 — Header repair by bounded enumeration

Signature-valid NCAs short-circuit to PRESERVE. For the rest, the linear
ladder is replaced by **systematic enumeration of the composed transform
space**. Admitted axes — each a deterministic inverse with zero free
parameters:

* distribution byte (GameCard/Download, `0x204`): 2 values
* (crypto_type, key_generation) canonical pairs: ~20 values
* rights form (title-rights vs keyblock): 2 values, each with deterministic
  reconstruction — RightsId = title id + generation by the suffix law
  (gen 0–2 → zero suffix, gen ≥ 3 → suffix = gen), keyblock zeroed, titlekey
  moved by fixed rule; includes the update-title candidate (base + 0x800)

Cross product ≈ 80 candidate headers per NCA. **Oracle discipline**: each
candidate costs one in-house RSA-PSS verify (microseconds); full-file hashing
runs only for signature-passing candidates, of which at most one can exist —
the signature pins exact bytes. Cost: milliseconds per NCA, combo-complete.
The old linear ladder tested transforms in isolation and could not reach
composed mutilations (de-rights'd AND downgraded AND flag-flipped); the
enumeration reaches every point of the space.

Direction law: the title-rights reversal runs forward only (key area →
ticket). The inverse — stuffing a ticket key into the key area — is the
homebrew mutilation itself, never canonical. Proven gamecard content never
gains a fabricated eShop titlekey; the gamecard axis and the rights axis do
not cross.

**The true boundary**: body tampering — ROM hacks, patched code, altered
sections — is information-theoretically unrecoverable from local material
(the space is astronomical and the only oracle, CNMT sha256 under a signed
Meta, requires the exact bytes to begin with). Those groups are IMPOSSIBLE:
wash through hardware or wait for a canonical source. Axis admission rule
for the future: a new mutilation joins the enumeration only when reduced to
a deterministic inverse over a finite public value set; anything with a free
parameter is out of scope by definition.

> Lesson (DAVE `[h]`): the reversal gate cannot be fooled — homebrew-born
> content is structurally coherent under reversal, decrypts to the same
> payload, and the signature still never returns, because no signed form of
> it ever existed.

## Step 6 — Meta rebuild and CNMT scalars

If any content was rewritten: patch the CNMT in place (refuse to resize),
recompute per-block hashes over the same declared geometry, then master
hash, then section-header digest; re-encrypt; the rebuilt Meta must regain
Nintendo's signature or the group fails.

`RequiredSystemVersion` / `RequiredApplicationVersion` (CNMT extended
header — protected transitively by the Meta signature; tampering is detected
for free): restoration is candidate enumeration under the same oracle —
**CNMTDB records first; when the DB is silent, the released-firmware
catalog** (a finite public list, a few hundred values) bounds the axis. Each
candidate costs one small-Meta rebuild plus one RSA verify. DB and catalog
both silent → honest failure. The firmware-catalog fallback exists precisely
for the MIA lane, where CNMTDB is most likely silent. A valid signed local
Meta/CNMT always remains the authoritative metadata source; DB values never
change acceptance or naming on their own.

Footnote: the NCA header's `sdk_addon_version` (0x21C, signed, informational,
no bootability effect) has no axis today; if a real tampered instance ever
surfaces it is the same shape (finite SDK-release list, same oracle) and
waits for that instance before existing.

## Step 7 — Group coherence

All rights-bearing output NCAs must agree on exactly one RightsId and one
key generation; the suffix law is validated from headers. Plurality or
disagreement → hard failure. An orphan ticket with no rights-bearing output
is omitted with a warning.

## Step 8 — The ticket lane (the distribution asymmetry, as doctrine)

**BASE/DLC** — purchased content ships console-personalized tickets,
inherently non-reproducible; the FF common ticket is the dumper convention
that makes dumps reproducible. Therefore every input ticket is untrusted as
an artifact and used only as a **titlekey courier**. Titlekey values come
from key-area derivation (deterministic from prod.keys) or from the courier —
and every courier-sourced value passes the **titlekey probe**: decrypt the
section's hash-table region with the candidate key and compare against the
master hash stored in the signed NCA header. Exact cryptographic pass/fail,
microseconds, in-house, no base-NCA dependency (BKTR exists only in UPD,
which never takes this path). The output ticket is always regenerated:
canonical FF public ticket (0x2C0, issuer `Root-CA00000003-XS00000020`,
Permanent, one RightsId, one encrypted titlekey, zero sections) from
RightsId + titlekey + generation-from-signed-header, with the pinned
`default.cert` (sha256
`3c4f20dca231655e90c75b3e9689e4dd38135401029ab1f2ea32d1c2573f1dfe`).

**UPD** — updates ship free to every console with Nintendo's own common
ticket: identical bytes everywhere, non-FF signature, reproducible by
preservation. Verify the ticket RSA against the pinned issuer key (this
authenticates the titlekey field itself — no probe needed) and copy it
verbatim. FF, unsupported-issuer, or cryptographically invalid UPD tickets
are irreparable; a missing UPD ticket cannot be synthesized. **Scope,
evidence-corrected**: card-shipped updates are NOT rightsless — a card with a
pre-installed patch carries the patch as title-rights content plus Nintendo's
signed common ticket in the secure partition (observed live:
`0100C9F009F7A800 v65536` rode its card with `…0005.tik`, RSA-valid). They
take this same UPD lane — verify and copy — and publish as plain `[UPD].nsp`,
byte-reproducible because the common ticket is identical on every card.

> Lessons: NieR — non-FF update ticket bytes are precious; pad-only repack
> with the real ticket matched hashdb, generated-ticket material never can.
> Xenoblade 2 — one stale ticket byte (keygen 0x285) breaks canonical form;
> hence always regenerate BASE/DLC tickets. The probe closes the one gap
> regeneration leaves open — a corrupted titlekey inside the courier — which
> is what keeps the [NoHASHDB] MIA lane titlekey-tight where no hashdb can
> catch it. The original engine's full payload walk was self-contained (its
> only waiver, "requires base NCA", is BKTR-and-therefore-UPD-only, where
> the ticket signature is the stronger proof); the probe preserves that
> firewall with none of the plumbing.

## Step 9 — GAMECARD groups

nxdumptool dumps titles from any NCM storage; an inserted card is storage.
Card *application* content is rightsless — key-area crypto, no ticket — and
its honest rip is the fully signed `[GAMECARD]` canonical form. Card-shipped
*patches* are the exception: title-rights content with Nintendo's common
ticket carried on the card (see step 8), so they publish as plain `[UPD]`,
never `[GAMECARD]`. The dumper's "set download
distribution" option flips signed-region byte 0x204 and breaks the main
signature by construction; the enumeration's gamecard axis reverses exactly
this. An all-gamecard, rightsless, fully signed group publishes as
`[TITLEID][vN][TYPE][GAMECARD].nsp` — BASE, UPD, or DLC — with no ticket.
The GAMECARD mark is never anything but fully signed. Mixed
gamecard/download groups are rejected.

Version labels (from the dumper's own naming code): a card's `[vN]` is the
patch's version when the card carries a pre-installed patch, else the
application's own version. Both non-v0 causes are real and legitimate:
base-v0 + card-shipped patch (a reproducible rights-bearing UPD title with
its ticket on the card), and cards mastered with the application itself at
non-v0 (observed: `[010097F018538000][v131072][BASE][GAMECARD]`). eShop
BASEs at non-v0 exist too. Version always comes from the CNMT; filenames are
derived, never the reverse. A patched card therefore yields TWO groups —
`[BASE][GAMECARD]` plus a plain `[UPD]` with its card-carried ticket — and
the shared-scope ticket correctly raises the orphan warning on the BASE
group alone.

## Step 10 — Outcome and naming

Lattice: `IMPOSSIBLE > RESTORED > PRESERVE`; any failure anywhere →
IMPOSSIBLE → unpublishable. Every NCA counts, Meta included: a changed
content NCA is not a success unless the rebuilt Meta also verifies.
Naming: `[TITLEID][vN][TYPE].nsp`, plus `[GAMECARD]` per step 9.

## Step 11 — Pack and publish

PFS0 to the nxdumptool convention (confirmed in both codebases —
`pfs.c` and the old engine implement identical arithmetic): members in CNMT
content-record order, then Meta (`.cnmt.nca`), then `.tik`, then `.cert`;
string table padded so the full header (0x10 + 0x18·entries + names) aligns
to 0x20, **with a full extra 0x20 block when already aligned**; no duplicate
names; contiguous offsets. Post-build, the engine re-reads its own output's
PFS0 table and confirms order and names — audit your own product.
Publication is atomic; a source container is archived only when every
discovered group in it succeeded; failures leave the source in place. No
terminal hash ceremony: ingest measures the product at enrollment.

> Lessons: Lydie — content order follows raw CNMT order, not type-sorted
> order. Rain World / Calculator — string tables of 0xB0, 0x100, 0x128 all
> arise from the one padding rule; never force a fixed size.

## Interface to ingest

**fixnsp is the gatekeeper.** The `[GAMECARD]` mark is minted only here,
under full verification (every NCA gamecard-oriented, rightsless, validly
signed — re-checked at publication). Ingest honors the minted marker plus
its own CNMT identity cross-check and does not re-verify gamecard-ness;
the dropzone is invitation-only by standing doctrine.

Ingest's hashdb gate is the archival authority — including **sole authority
over ticket bytes** for hashdb-matched content. Admission priority for one
TitleID/version: `vanilla > [GAMECARD] > [custom tag]`. `[NoHASHDB]` /
`[BadHASHDB]` are file-level provenance markers for MIA work; hashdb
`[h]`/isHack and bad-ticket rows are rejection records, not admission
records. Enrollment stores round-trip-verified NSZ (archival profile
`-K -l 22 -t 16`); the round-trip sha1 check is ingest's own-product audit,
not a duplication of engine work.

## Duplications eliminated (and what is kept deliberately)

Removed: the nstool dependency entirely (final NCA verification — in-house
RSA + CNMT sha256 under signed Meta cover it; XCI extraction — the in-house
HFS0 parser; ticket fstree probing — the titlekey probe); the full payload
hash walk and its "requires base NCA" tolerance machinery; terminal
whole-NSP hashing at publication; repeated Meta re-parsing within a run
(parse once per group); the standalone split-rejoin utility (intake);
the multi-tool UTF-8 wrapper (one external remains); `fixnsp_legacy.py`,
`probe_nsp_pattern.py`, `migrate_variant_markers.py`, and all
permissive/BestEffort machinery.

Kept deliberately: plan/execute separation with re-verification at execute
time; the post-build PFS0 table re-read; CNMT-invariant checking alongside
signature checking (bytes-match-declaration vs declaration-is-Nintendo's);
ingest's NSZ round-trip audit.
