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
The Python bootstrap runs through local `nsz_codec.main`, which corrects
NSZ 5.0's decompressed-member size calculation without changing the installed
package or its decoder. A first NCZ section can overlap the preserved 16 KiB
prefix or begin after it; the output extent is the final contiguous section
end. Counting the prefix twice produces false PFS0 sizes and shifts subsequent
file offsets. Invalid section geometry and container bounds still fail.
FAT32-split NSP directories (contiguous numeric parts, consistent chunk size)
are rejoined as part of intake — no separate utility. PFS0 and HFS0 tables
are parsed by in-house bounds-checked readers; a trimmed XCI whose nominal
card capacity exceeds EOF is bounds-checked, not rejected; an XCI's firmware
`update` partition is ignored. XCI is only a container source: admission is
decided from the referenced NCA headers, never the input extension.

An outer PFS0 whose structural header is readable but whose declared member
extents cross EOF or overlap enters bounded salvage. Its names, offsets and
sizes are carving hints only: stage solely members whose complete declared
extents lie inside the physical file and overlap no sibling. Record every
skipped member as a source-level error, then require the normal Nintendo NCA
signature and signed-CNMT hash/size gates before a staged member may publish.
The source remains in place even when an unrelated complete group publishes.
Never shorten an entry to EOF, fill missing bytes, infer a boundary, or salvage
an invalid header, unsafe/duplicate name, or ambiguous data region.

A root HFS0 partition may declare unused trailing bytes beyond physical EOF.
Accept this only after its nested HFS0 table, every declared member extent and
all hashed regions are verified within the real file. Keep nested/leaf bounds
strict: never shorten an NCA or synthesize missing bytes. Validate all selected
partitions before touching extraction output, and report the omitted tail size.
This also checks a trimmed ignored partition before treating its tail as padding.

> Lesson (`010051F0207B2000`): the root `secure` extent exceeds EOF by 512 bytes,
> but its final Meta NCA ends exactly at EOF and every HFS0 prefix hash verifies.
> The XCI header's valid-data end agrees with EOF; rejecting the root extent alone
> incorrectly rejected complete game content.

## Step 2 — One input inventory, two recovery passes, then grouping

NSP, NSZ, XCI and XCZ all use the same workflow after unpacking. An inventory
belongs to exactly one input container. XCI `secure` and `normal` content
participate together; firmware `update` is excluded. Retain original paths,
partition provenance, tickets and certificates. Never borrow from another input.

Hash and inspect each NCA, then run signature-based best-effort recovery on all
content NCAs before attempting any Meta NCA. Recovery is independent of wrapper
names, including apparently correct hash names. Identical input bytes are repaired
once. Index resulting candidates by full SHA-256, deduplicate identical results,
and retain their origins and recovery histories. Distinct full hashes stay
separate even if their short IDs or release identities coincide.

Each unique signed Meta/CNMT selects its members from that shared inventory by
actual ID, full SHA-256 and exact size. Complementary partitions may supply one
group; several CNMTs may reference the same NCA object. No per-group staging
copies are needed. Original names remain diagnostic labels; canonical member
names are generated only when writing the output NSP. A malformed or incomplete
group does not block unrelated complete groups. An unrecoverable identifiable
Meta remains a failed attempt. Unreferenced signed candidates are reported,
never guessed into a group. Unreadable NCAs, unsupported container members,
unreadable tickets and unreferenced signed NCAs are source-level errors: valid
independent groups may still publish, but the source container is not archived.
Grouping and publication do not rerun recovery.

The sole explicit formatter omission is `*.cnmt.xml`: it is a dumping tool's
restatement of the Meta NCA, not a Standard NSP member. Report it as a notice
and leave it out of the output. Any other unsupported member remains a
source-level error.

## Step 3 — Meta parsing under declared geometry

Only NCA3 is admitted. NCA2 uses different XTS sector numbering and has no
authentic conversion into an NCA3 Standard NSP; it is rejected explicitly.

The Meta NCA's HierarchicalSha256 layout — block size, hash offset/size,
data offset/size — is read from the declared section header, never assumed;
`hash_size` must equal `ceil(data_size / block_size) * 0x20`; every data
block hash, the master hash, and the section-header digest are verified.
The inner PFS0 is located by its declared offset and every member is bounds
checked. Exactly one member ending in `.cnmt` must exist; other inner members
do not displace it. Its `Application` / `Patch` / `AddOnContent` / `DataPatch`
name and title ID must agree with the parsed payload. Thus neither outer NCA
order nor inner PFS0 position determines the group.

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

Distribution restoration composes with every rightsless generation/key-area
candidate, in both directions (Download/GameCard). Keep the unchanged header
as a candidate for Meta-only repair and deduplicate candidates by their full
header bytes. Rights restoration remains restricted to the digital lane.

> Lesson (`0100AC400CD82000`): the implementation previously tried a standalone
> distribution flip and separate generation inverses, missing their combination.
> Combining GameCard distribution with generation 8 restores the sample's Control
> and Manual signatures. Recovery failures must report signature/identity failure
> or the actual recovery exception, rather than presenting them as mere bad names.

**Best effort, defined**: every signature-failing NCA3 uses one supported
signature-driven enumeration before grouping. There is no expected-filename-ID
lane and no second fallback pass. A successful candidate receives its actual
hash-derived ID. A restored header is not proof of its body: publication still
requires a valid signed local CNMT referencing the exact ID, full hash and size.
Partial recoveries are reported without calling the entire package repaired.

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

During the second recovery pass, a signature-failing Meta may use exact
content recoveries from anywhere in this input. Propose CNMT changes in place
(refuse to resize), recompute hashes under the declared geometry, and require
the Meta's Nintendo signature to return. Once signed, convention-defined bytes
outside Nintendo's signed/hash-covered regions are canonicalized: signature 2,
unused fs-header slots, and decrypted section bytes outside the hash table and
data region are zero. Signed geometry is never rewritten: section 0 must be the
only section, start at `0xC00`, and end at NCA EOF, or the Meta is rejected.
Canonicalization is re-read through the same signature, hash-layer, PFS0 and
CNMT checks before the changed hash-derived Meta ID is admitted.

`RequiredSystemVersion` / `RequiredApplicationVersion` (CNMT extended
header — protected transitively by the Meta signature; tampering is detected
for free): restoration is candidate enumeration under the same oracle —
**same-title CNMTDB records first**, then the finite set of system-version
values observed in other local CNMTDB records and the optional released-firmware
catalog. Observed values are deduplicated, restricted to uint32 integers and
capped at 1,000 distinct proposals. A missing same-title record or optional
firmware file does not discard the evidence available in the remaining records.
If a title-specific proposal fails, the bounded fallback still runs. Each
candidate costs one small-Meta rebuild plus one RSA verify. No candidate source
→ honest failure when a scalar repair is needed. A valid signed local
Meta/CNMT always remains the authoritative metadata source; DB values never
change acceptance or naming on their own.

Some repacks overwrite CNMT hashes and/or IDs with those of modified NCAs.
A candidate correction requires an exact match between the CNMT's full hash
and a recovery's recorded input hash (or an intact signed candidate's actual
hash for an ID-only correction), equal size, and one unambiguous signed candidate. Propose that candidate's actual full hash and ID together.
All retained recovery histories participate, even when several modified inputs
converge on identical recovered bytes. This composes with header and scalar
restoration; only the Meta signature approves the result. Other CNMT bytes,
including its trailing digest, remain as supplied.

> Lesson (Monument Valley 3): restoring generation 18 alone was insufficient.
> Three CNMT hashes described the damaged content and requiredSystemVersion was
> zero. Composing the recovered content hashes with the locally observed
> 20.0.1 value restored the Meta's signature and exact original ID
> `e4ca1e440fce0adef4222ac64d4384dc`. Discovery must allow that proof to run.

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
from signed key-area recovery (deterministic from prod.keys) or from the courier.
Courier and `title.keys` values must pass the **titlekey proof**. Across every
rights-bearing NCA, try every independently readable section: hash type 2 uses
the hash table; hash type 3 uses the first block of the first level, zero-padded
to its block size; sparse sections use the first sparse-table node. AES-CTR-EX
is not independently readable. The rule is existential — one opening proof is
enough; an attempted set with no opening proof rejects the key. Signed key-area
recovery material may be used when no independent proof exists, but is rejected
if any readable proof is attempted and all fail. The output ticket is always
regenerated:
canonical FF public ticket (0x2C0, issuer `Root-CA00000003-XS00000020`,
Permanent, one RightsId, one encrypted titlekey, zero sections) from
RightsId + titlekey + generation-from-signed-header, with the pinned
`default.cert` (sha256
`3c4f20dca231655e90c75b3e9689e4dd38135401029ab1f2ea32d1c2573f1dfe`).

**UPD** — updates ship free to every console with Nintendo's own common
ticket: identical bytes everywhere, non-FF signature, reproducible by
preservation. Verify the ticket RSA against the pinned issuer key (this
authenticates the titlekey field itself) and run the same independent proof
set. A readable proof that fails rejects the ticket. When no independent proof
exists, the valid pinned Nintendo RSA signature is sufficient and the limitation
is reported. Copy the ticket verbatim. FF, unsupported-issuer, or
cryptographically invalid UPD tickets are irreparable; a missing UPD ticket
cannot be synthesized. **Scope,
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
> catch it. The bounded proof set preserves that firewall without a full
> payload walk: independently readable hash/sparse proofs decide courier keys;
> AES-CTR-EX limitations are explicit and never turn an untrusted courier into
> evidence.

Tickets are gathered across the input inventory and identical bytes deduplicated.
Match RightsId to signed content. For UPD, require the signed content's generation
and a valid original Nintendo ticket signature; distinct valid tickets remain
an explicit ambiguity. For BASE/DLC couriers, accept exactly one distinct proven
key (or one unprobeable key backed by signed NCA recovery). A genuine non-FF
BASE/DLC ticket is not silently blanked: StandardNSP only defines verbatim
preservation for Patch/DataPatch, so this unresolved convention case halts for
review. A bad or misnamed ticket cannot hide a valid candidate.

Ticket titlekey type is checked before any courier decryption. Only common
(type 0) tickets expose a 16-byte encrypted titlekey. Personalized (type 1)
tickets carry a console-specific RSA-OAEP block and are never treated as common
ticket material. When the matching RightsId exists in optional `title.keys`, its
conventional titlekek-encrypted value is decrypted for the same signed NCA
generation and must pass the shared existential proof set before it can
regenerate a BASE/DLC public ticket. Without that external entry, conversion is
reported as unsupported rather than misdiagnosing the wrapped bytes as a corrupt
titlekey. Unknown titlekey types are likewise unusable. UPD still requires its
original signed common ticket; `title.keys` cannot synthesize it. Final output
tickets must be common. The parser rejects unsupported signature layouts rather
than interpreting their bytes at RSA-2048/SHA-256 offsets.

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

Patch (0x81) and DataPatch (0x84) CNMTs both use the `UPD` lane. Version labels
(from the dumper's own naming code): a card's `[vN]` is the
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
names; contiguous offsets. While packing, hash each copied member against
its approved full SHA-256 and require the declared byte count exactly. This
uses the existing copy pass and catches files changed since inspection.
Read back the candidate's table, sizes, every NCA header/signature, and the
complete Meta/ticket/certificate hashes. Repeat this bounded readback on the
publication temporary file before its atomic rename; a failure leaves any
existing destination intact. Large content bodies get no extra readback pass.
Publication is atomic; a source container is archived only when every
discovered group in it succeeded; failures leave the source in place. No
terminal hash ceremony: ingest measures the product at enrollment.

Distinct signed Meta variants with the same TID/version/type remain separate.
Their outputs go to `fixnsp-variants/<full-Meta-SHA256>/` under the output directory,
using the normal NSP filename inside. This keeps them outside automatic ingest
until the operator chooses their labels; `--overwrite` cannot replace a sibling
variant. Single-variant releases continue publishing directly to the output root.

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
`[BadHASHDB]` are file-level provenance markers for MIA work.

Bad-ticket, hacked and bad-dump DAT rows are **ignored as if absent**. The
loader excludes explicit `isHack` / `isBadTicket` booleans, `[h]` / `[b]`
markers (including numbered forms) in both game and ROM names, and ROM
`hacked` / `baddump` status. Exclusion happens before either the SHA-1 index
or the TID/version index is built. A rejected row cannot veto a clean row
for the same hash or establish that a version is known. `[BASE]` is not a
rejection marker. Startup reports the number of excluded rows.

Normal hashdb admission also requires a clean matching ROM filename containing
the input CNMT's exact `[TID]` token, case-insensitively. Other clean claimants
are reported but cannot authorize admission. If none has the TID, the source
moves to `dropzone/conflict/` for manual resolution. Updates use their own TID, not the base
entity ID. Input filenames must have one unambiguous TID/version/type and
at most one provenance marker; the CNMT must agree with that identity.

The clean DAT ROM filenames also index recorded NSP hashes by `[TID][vN]`:

- **Real database mismatch:** clean rows exist for the input CNMT's TID/version,
  but none has the input NSP SHA-1. Move to `dropzone/quarantine/` before
  compression or enrollment, even if the version has never been ingested.
- **No eligible reference:** neither an eligible hash match nor a clean record
  for the TID/version exists. Leave `UNDECIDED` in the dropzone root for a
  fresher DAT or an explicit forced label. Rejected-only references count
  as absent.
- **Enrollment conflict:** the admitted incoming artifact collides with an
  enrolled release and marker. Different comparable bytes and an unverified
  NSP/NSZ overlap both report `CONFLICT`, with the specific reason in the log.
  Move the source to `dropzone/conflict/` for manual resolution. An overlap
  does not assert different content or a database mismatch; no compression
  or decompression of the enrolled copy is attempted.

An incoming NSZ uses its decompressed NSP for the database gate, then its
original compressed bytes for comparison with an enrolled NSZ. An identical
NSZ is a duplicate; different compressed bytes under the same marker remain
a conflict for manual resolution. Multiple clean DAT hashes for one identity
are allowed. These checks retain the existing exact-TID rule, without adding
content re-verification. The verified `[GAMECARD]` lane keeps its no-positive-
match rule because card bytes can differ from the digital release.

Conflict, quarantine and label-duplicate moves preserve existing
same-named files by choosing a numbered filename. Exact duplicates are
removed only after checking the enrolled file's presence/size and agreement
between XML and checksum metadata. `--copy` retains sources on success and
exact duplication; it does not suppress keeper-area routing.

`--force LABEL` remains the operator's explicit hashdb override, including
the DAT filename TID check and known-version hash mismatch. It does not
require or load DATs. CNMT identity, existing-release priority/conflict checks,
copying and bookkeeping audits still apply. It preserves a bare labeled NSP,
decompressing an NSZ input first. Labels that impersonate identity tokens or
the verified `GAMECARD` marker are refused. Normal NSP enrollment compresses
and round-trip verifies NSZ with `-C -K -l 22 -t 16`; an incoming NSZ is
preserved after its own decompressed NSP passes the gate.

Ingest remains a linear, one-artifact-at-a-time sweep. Each item works on a
private catalog copy, so a failed item cannot leak declarations into a later
commit. Metadata lookup precedes placement. An unrecorded canonical destination
is never replaced automatically; it stops for inspection. Other undeclared
release files are never swept away. Copying hashes the bytes accepted by the
destination stream in that one pass; the source stays until bookkeeping has
passed its audit.

The proposed catalog is validated before either live bookkeeping file changes.
A temporary checkpoint in `dropzone/ingest-work/` records the pending item,
source/destination fingerprints and the proposed metadata. It is saved before
the checksum-then-XML writes. On interruption, the next run verifies the placed
artifact, finishes those writes and removes the original source last, before
starting new candidates. Changed source/destination fingerprints or outside
bookkeeping edits stop recovery for inspection. Ordinary commits add no recovery hash pass;
that pass runs only for an interrupted checkpoint. The vault still has just
`datmeta.xml` and `entities.checksum` as its bookkeeping files.

Malformed containers and per-item I/O failures are logged and counted without
aborting unrelated candidates. An unfinished checkpoint stops the batch to
preserve ordering. The final digest separates real quarantine, `UNDECIDED`
for missing clean hashdb evidence, conflicts (including format overlaps), and
failures. Conflicts return a nonzero exit status; their sources remain in `dropzone/conflict/`.

## Duplications eliminated (and what is kept deliberately)

Removed: the nstool dependency entirely (final NCA verification — in-house
RSA + CNMT sha256 under signed Meta cover it; XCI extraction — the in-house
HFS0 parser; ticket fstree probing — the bounded titlekey proof set); the full payload
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
