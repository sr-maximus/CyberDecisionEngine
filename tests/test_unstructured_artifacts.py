from cyberdeck.enrichment.unstructured_artifacts import enrich_unstructured_artifacts
from cyberdeck.schemas import ThreatEvent


def test_dates_are_not_classified_as_phone_numbers():
    event = ThreatEvent(
        id="artifact-date",
        title="Observed on 2026-07-26",
        category="news",
        source="Public source",
        evidence_url="https://example.org/article",
    )
    enrich_unstructured_artifacts([event])
    artifacts = event.technical_validation.get("unstructured_artifacts", [])
    assert not [item for item in artifacts if item["type"] == "phone"]
