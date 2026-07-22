from __future__ import annotations

from typing import Iterable, List

from cyberdeck.schemas import ThreatEvent


def cves_from_events(events: Iterable[ThreatEvent]) -> List[str]:
    return sorted({event.cve for event in events if event.cve})
