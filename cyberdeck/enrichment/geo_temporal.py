from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable

from cyberdeck.schemas import ThreatEvent


def temporal_summary(events: Iterable[ThreatEvent]) -> Dict[str, int]:
    buckets = Counter()
    for event in events:
        if event.age_days <= 7:
            buckets["0-7d"] += 1
        elif event.age_days <= 30:
            buckets["8-30d"] += 1
        else:
            buckets["31d+"] += 1
    return dict(buckets)
