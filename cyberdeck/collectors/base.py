from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List

from cyberdeck.schemas import SourceStatus, ThreatEvent


@dataclass
class CollectionResult:
    status: SourceStatus
    events: List[ThreatEvent] = field(default_factory=list)


class Collector(ABC):
    name = "collector"

    @abstractmethod
    async def collect(self) -> CollectionResult:
        ...


def demo_event(event_id: str, title: str, category: str, source: str, tags: List[str]) -> ThreatEvent:
    return ThreatEvent(
        id=event_id,
        title=title,
        category=category,
        source=source,
        source_weight=0.55,
        confidence=0.62,
        age_days=3,
        severity=0.65,
        epss=0.08,
        cvss=6.8,
        actor="cybercrime",
        technique="T1566",
        tags=tags,
        evidence_url=None,
        demo=True,
    )
