from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable

from cyberdeck.schemas import ThreatEvent


def summarize_trends(events: Iterable[ThreatEvent]) -> Dict[str, Dict[str, int]]:
    event_list = list(events)
    return {
        "by_category": dict(Counter(event.category for event in event_list)),
        "by_source": dict(Counter(event.source for event in event_list)),
        "by_actor": dict(Counter(event.actor or "unknown" for event in event_list)),
        "by_technique": dict(Counter(event.technique or "unmapped" for event in event_list)),
    }
