from __future__ import annotations

import os

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus


class ShodanPassiveCollector(Collector):
    name = "Shodan Passive"

    async def collect(self) -> CollectionResult:
        if not os.getenv("SHODAN_API_KEY"):
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="SHODAN_API_KEY not configured; passive exposure disabled."), [])
        return CollectionResult(SourceStatus(name=self.name, status="configured", records=0, mode="real", warning="Passive query enabled only for authorized scope."), [])
