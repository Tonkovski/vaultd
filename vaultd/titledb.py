"""Shared titledb (blawar/titledb) reader for NX keepers.

REGION_PRIORITY is the single project-wide ladder — keepers import it, never
copy it. The old project drifted into four divergent per-script ladders; this
constant ends that.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Description/publisher lookup order.
#
# The spine is Nintendo's own NACP language-entry order (the fixed slot order
# of application title entries in control.nacp), mapped onto titledb region
# files:
#
#   0 AmericanEnglish      -> US.en        8 Dutch             -> NL.nl
#   1 BritishEnglish       -> GB.en        9 CanadianFrench    -> CA.fr
#   2 Japanese             -> JP.ja       10 Portuguese        -> PT.pt
#   3 French               -> FR.fr       11 Russian           -> RU.ru
#   4 German               -> DE.de       12 Korean            -> KR.ko
#   5 LatinAmericanSpanish -> MX.es       13 TraditionalChinese-> HK.zh
#   6 Spanish              -> ES.es       14 SimplifiedChinese -> CN.zh
#   7 Italian              -> IT.it       15 BrazilianPortuguese-> BR.pt
#
# Between JP.ja (slot 2) and French (slot 3) an alphabetical sweep of every
# other *.en region file is inserted: digital records often exist in some
# non-US/GB English storefront only, and without the sweep such a title would
# take a German/French description while an English one exists. Miss
# everywhere -> description omitted (no placeholder).
REGION_PRIORITY = [
    "US.en", "GB.en", "JP.ja",
    "AR.en", "AU.en", "BG.en", "BR.en", "CA.en", "CL.en", "CN.en", "CO.en",
    "CY.en", "CZ.en", "DK.en", "EE.en", "FI.en", "GR.en", "HR.en", "HU.en",
    "IE.en", "IL.en", "JP.en", "LT.en", "LV.en", "MT.en", "MX.en", "NO.en",
    "NZ.en", "PE.en", "PL.en", "RO.en", "SE.en", "SI.en", "SK.en", "ZA.en",
    "FR.fr", "DE.de", "MX.es", "ES.es", "IT.it", "NL.nl", "CA.fr", "PT.pt",
    "RU.ru", "KR.ko", "HK.zh", "CN.zh", "BR.pt",
]


class TitleDB:
    """Lazy region-json reader: query(title_id) -> (name, publisher, region).

    `priority` overrides the lookup sequence for this instance; None means
    the project-wide REGION_PRIORITY. Keepers that personalize presentation
    build their sequence locally and pass it here — the ladder constant
    itself is never edited per script.
    """

    def __init__(self, dirpath: Path,
                 priority: list[str] | None = None) -> None:
        self.dir = Path(dirpath)
        self.priority = list(priority) if priority is not None else REGION_PRIORITY
        self._cache: dict[str, dict[str, tuple[str, str]]] = {}

    def available(self) -> bool:
        return any((self.dir / f"{region}.json").exists()
                   for region in self.priority)

    def _region(self, region: str) -> dict[str, tuple[str, str]]:
        if region in self._cache:
            return self._cache[region]
        mapping: dict[str, tuple[str, str]] = {}
        path = self.dir / f"{region}.json"
        if path.exists():
            try:
                with path.open(encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError) as exc:
                print(f"titledb: failed to load {path.name}: {exc}", file=sys.stderr)
                data = {}
            for record in data.values():
                title_id = record.get("id")
                if not title_id:
                    continue
                mapping.setdefault(
                    title_id.upper(),
                    (record.get("name") or "", record.get("publisher") or ""))
        self._cache[region] = mapping
        return mapping

    def query(self, title_id: str) -> tuple[str | None, str | None, str | None]:
        tid = title_id.upper()
        for region in self.priority:
            hit = self._region(region).get(tid)
            if hit and hit[0]:
                return hit[0], hit[1], region
        return None, None, None
