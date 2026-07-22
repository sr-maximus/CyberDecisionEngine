from __future__ import annotations

import os

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus


class MispCollector(Collector):
    name = "MISP"

    async def collect(self) -> CollectionResult:
        if not (os.getenv("MISP_URL") and os.getenv("MISP_API_KEY")):
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="MISP_URL/MISP_API_KEY not configured."), [])
        return CollectionResult(SourceStatus(name=self.name, status="configured", records=0, mode="real", warning="Connector ready; add authorized event pull policy before use."), [])
