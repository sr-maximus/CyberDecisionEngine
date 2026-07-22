from __future__ import annotations

from typing import Iterable, List

from cyberdeck.enrichment.evidence_pipeline import process_evidence_records
from cyberdeck.schemas import ThreatEvent


def deduplicate_events(events: Iterable[ThreatEvent]) -> List[ThreatEvent]:
    return process_evidence_records(events).records
