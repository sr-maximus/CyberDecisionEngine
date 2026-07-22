from __future__ import annotations

from cyberdeck.collectors.base import CollectionResult, Collector, demo_event
from cyberdeck.schemas import SourceStatus


class FraudIntelligenceCollector(Collector):
    name = "Fraud Intelligence"

    async def collect(self) -> CollectionResult:
        events = [
            demo_event("FRAUD-DEMO-001", "Fraude digital: BEC, phishing y transferencias no autorizadas", "fraud", self.name, ["fraud", "bec", "phishing", "demo"]),
            demo_event("FRAUD-DEMO-002", "Account takeover y abuso de identidad digital en canales financieros", "account_takeover", self.name, ["fraud", "identity", "ato", "demo"]),
            demo_event("FRAUD-DEMO-003", "Mule accounts y dispersion de fondos posterior al compromiso", "transaction_fraud", self.name, ["fraud", "mules", "graph_risk", "demo"]),
        ]
        for event in events:
            event.source_weight = 0.70
            event.confidence = 0.68
            event.severity = 0.74
            event.technique = "T1566"
        return CollectionResult(
            SourceStatus(
                name=self.name,
                status="demo",
                records=len(events),
                mode="demo",
                warning="Fraud intelligence seeded from public FBI IC3, ENISA, ACFE, NIST identity guidance and academic fraud-detection literature.",
            ),
            events,
        )
