from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List, Optional

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.safety import validate_darkweb_import
from cyberdeck.schemas import SourceStatus, ThreatEvent


class DarkwebAuthorizedCollector(Collector):
    name = "Dark web autorizada"

    def __init__(self, import_path: Optional[str] = None, enabled: bool = False, allow_tor: bool = False):
        self.import_path = import_path
        self.enabled = enabled
        self.allow_tor = allow_tor

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        if not self.import_path:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No se adjunto archivo autorizado y redactado para contrastar dark web."))
        path = validate_darkweb_import(self.import_path, allow_tor=self.allow_tor)
        events = _load_redacted(path)
        return CollectionResult(SourceStatus(name=self.name, status="ok", records=len(events), mode="authorized_redacted"), events)


def _load_redacted(path: Path) -> List[ThreatEvent]:
    rows = []
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data if isinstance(data, list) else data.get("events", [])
    else:
        with path.open("r", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    events: List[ThreatEvent] = []
    for index, row in enumerate(rows):
        events.append(
            ThreatEvent(
                id=str(row.get("id") or f"AUTHORIZED-DW-{index}"),
                title=str(row.get("title") or "Metadato dark web autorizado y redactado"),
                category=str(row.get("category") or "darkweb_authorized"),
                source="Dark web autorizada",
                source_weight=float(row.get("source_weight") or 0.70),
                confidence=float(row.get("confidence") or 0.65),
                age_days=int(row.get("age_days") or 0),
                severity=float(row.get("severity") or 0.65),
                epss=float(row.get("epss") or 0.05),
                cvss=float(row.get("cvss") or 0.0),
                actor=row.get("actor") or "unknown",
                technique=row.get("technique") or "T1589",
                tags=["darkweb_authorized", "redacted"],
                evidence_url=row.get("evidence_url"),
                demo=False,
            )
        )
    return events
