from __future__ import annotations

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus


class StixTaxiiCollector(Collector):
    name = "STIX/TAXII"

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    async def collect(self) -> CollectionResult:
        status = "configured" if self.enabled else "disabled"
        warning = "Base client placeholder; configure authorized TAXII collection URL for production ingestion." if self.enabled else None
        return CollectionResult(SourceStatus(name=self.name, status=status, records=0, mode="real", warning=warning), [])
