from cyberdeck.analysis.sector_intelligence import build_sector_intelligence
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


def _organization() -> OrganizationProfile:
    return OrganizationProfile(
        name="Example Group",
        sector="Energy infrastructure",
        subsector="Ports, pipelines and logistics",
        country="Canada",
        countries_of_operation=["Colombia", "Canada"],
        author="Test",
        language="es",
        authorized_scope=True,
    )


def test_sector_intelligence_separates_declared_and_observed_context() -> None:
    events = [
        ThreatEvent(
            id="oil-1",
            title="Oil and gas producer expands operations in Colombia",
            category="news",
            source="Official release",
            evidence_url="https://example.com/oil",
            relationship_to_scope="direct",
            evidence_status=EvidenceStatus.VALIDATED,
            tags=["official_source"],
        ),
        ThreatEvent(
            id="port-1",
            title="Port logistics operator expands cargo terminal capacity",
            category="news",
            source="Industry news",
            evidence_url="https://example.net/port",
            relationship_to_scope="related",
            evidence_status=EvidenceStatus.RELATED,
        ),
    ]

    result = build_sector_intelligence(events, _organization())

    assert result["declared_sectors"] == ["Energy infrastructure"]
    assert result["declared_subsector"] == "Ports, pipelines and logistics"
    rows = {row["code"]: row for row in result["evidence_supported_sectors"]}
    assert rows["B"]["records"] == 1
    assert rows["B"]["status"] == "supported_sector_context"
    assert rows["B"]["evidence_ids"] == ["oil-1"]
    assert rows["H"]["records"] == 1
    assert rows["H"]["evidence_links"][0]["label"] == "example.net"


def test_sector_intelligence_deduplicates_and_ignores_query_and_generic_cyber_terms() -> None:
    events = [
        ThreatEvent(
            id="one",
            canonical_id="same",
            title="Cybersecurity technology update for Example Energy",
            category="news",
            source="Public source",
            relationship_to_scope="related",
            tags=["query:banking", "sector:financial services"],
        ),
        ThreatEvent(
            id="two",
            canonical_id="same",
            title="Cybersecurity technology update for Example Energy",
            category="news",
            source="Public source",
            relationship_to_scope="related",
            tags=["query:banking"],
        ),
    ]

    result = build_sector_intelligence(events, _organization())

    assert result["evidence_supported_sectors"] == []


def test_sector_intelligence_keeps_context_only_records_separate() -> None:
    event = ThreatEvent(
        id="context",
        title="Banking sector faces a regional phishing campaign",
        category="news",
        source="Threat news",
        relationship_to_scope="contextual",
        evidence_status=EvidenceStatus.RELATED,
    )

    result = build_sector_intelligence([event], _organization())

    assert result["evidence_supported_sectors"] == []
    assert result["contextual_sector_mentions"][0]["code"] == "K"
