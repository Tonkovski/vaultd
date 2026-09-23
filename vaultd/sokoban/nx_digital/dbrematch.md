# NX digital dbrematch

Run `python -m vaultd.sokoban.nx_digital.dbrematch` from the checkout.
`--locator PATH` selects another locator. The command modifies the bound NX
digital vault; it has no force option.

The sweep targets custom-labeled files such as `[NoHASHDB]` and `[BadTicket]`.
Vanilla and `[GAMECARD]` entries are skipped and counted. Only a labeled bare
NSP can be converted: a stored NSZ hash cannot be compared with an NSP DAT hash.

The catalog supplies the SHA-1 lookup. Before a conversion is accepted, NSZ's
decompression round trip must reproduce that SHA-1. XML/checksum declarations,
source size and filename/location identity must also agree.
At least one clean hash claimant's ROM filename must contain the stored input's
exact `[TID]` token, case-insensitively. An update uses its own TID, not its base
entity ID. This does not compare DAT versions/types or add hash checks.

## Sequential decisions and logging

The command first lists the candidate count and logs each DAT as it loads the
candidate claims. It then processes candidates in entity/version/filename order,
finishing each candidate before starting the next. It does not precompress a batch.

Each `INSPECT [n/total]` logs the stored path, catalog description and SHA-1.
Every claiming DAT record is printed with its DAT filename, game name, ROM name,
clean/rejected classification and rejection reasons. The classifier is shared
with normal ingest and recognizes `isHack`, `isBadTicket`, `[h]`/`[b]` markers
and numbered forms, and `hacked`/`baddump` status. `[BASE]` is not a rejection marker.

* `KEPT`: no hash match; retain the custom label and source.
* `REJECTED`: any rejected claim, even alongside clean claims; retain the source.
* `BLOCKED`: no clean claimant has the input TID, or vanilla already exists;
  retain the source.
* `REMATCHED`: clean claims only, with a matching TID; convert to vanilla NSZ
  and retire the source.
* `ERROR`: the candidate could not complete; the log explains the failure.

Eligible candidates log conversion, round-trip verification, copy/hash, copy
verification, metadata saves and source removal. Every candidate has an immediate
`END` outcome and elapsed time. Output is flushed.

The final `DIGEST` summarizes the run status, elapsed time, candidates inspected
versus not reached, new conversions, resumed checkpoints and retained labels.
Routine unknown hashes are counted without listing them again. Successful
conversions are listed by catalog title and source filename; rejected or blocked
items are grouped by cause (including the actual rejection flags, TID mismatch,
or existing vanilla), with each cause printed once above its affected titles.
Errors, interruptions and scratch-cleanup warnings are grouped likewise. Full
paths and DAT claims stay in the live log. A pending checkpoint is called out.
Recovery is counted separately from the new sweep, including on Ctrl-C or setup
failure; a failed recovery cannot inflate the inspected count.

## Checkpoint and interruption behavior

Only the current conversion uses `dropzone/dbrematch-work/conversion/`.
An unrelated file in the release directory is never swept away.

After copying and verifying the NSZ, the command prepares complete XML and
checksum snapshots under `dropzone/dbrematch-work/checkpoint/`, validates the
proposed XML, then atomically writes `pending.json`. It publishes checksums first,
then XML, audits the saved catalog, removes the labeled NSP last, and clears the
pending record. The vault keeps its existing two-file bookkeeping structure.

Rerunning finishes a pending conversion before looking for new candidates. It
checks the bound vault, source/target file stamps, target hashes, snapshot hashes
and the current metadata. Metadata must match either the pre-conversion or
post-conversion snapshot; external changes stop recovery instead of being
overwritten. `RESUMED` identifies a completed recovery in the final digest.

A failure before the pending record leaves the original catalog/source intact
and may leave an unrecorded output that the next attempt replaces. Once a pending
record exists, any failure stops the sweep: later candidates cannot overwrite
the recovery material. Keep `dbrematch-work` until the pending item is resolved.

Exit codes: 0 for a completed sweep (including kept/rejected/blocked items),
1 for errors, 2 for locator/argument setup errors, and 130 for interruption.
