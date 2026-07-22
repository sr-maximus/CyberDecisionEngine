from __future__ import annotations

from typing import Iterable, List

from cyberdeck.schemas import ThreatEvent
from cyberdeck.safety import redact_text


def normalize_events(events: Iterable[ThreatEvent]) -> List[ThreatEvent]:
    normalized = []
    for event in events:
        event.title = redact_text(event.title).strip()[:240]
        event.tags = sorted(set(tag.lower().strip() for tag in event.tags if tag))
        normalized.append(event)
    return normalized
