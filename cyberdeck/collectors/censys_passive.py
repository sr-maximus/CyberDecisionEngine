from __future__ import annotations

import os

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus


class CensysPassiveCollector(Collector):
    name = "Censys Passive"

    async def collect(self) -> CollectionResult:
        if not (os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET")):
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="CENSYS_API_ID/CENSYS_API_SECRET not configured; passive exposure disabled."), [])
        return CollectionResult(SourceStatus(name=self.name, status="configured", records=0, mode="real", warning="Passive query enabled only for authorized scope."), [])
