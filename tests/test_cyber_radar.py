from cyberdeck.analysis.cyber_radar import build_cyber_risk_radar
from cyberdeck.schemas import EvidenceStatus, ThreatEvent


def _event(**overrides) -> ThreatEvent:
    values = {
        "id": "risk-event-1",
        "title": "APT29 phishing campaign targets a related sector",
        "category": "phishing",
        "source": "Public cyber news",
        "actor": "APT29",
        "tags": ["phishing", "sector_campaign"],
        "evidence_url": "https://news.example/risk-event",
        "relationship_to_scope": "sector",
        "evidence_status": EvidenceStatus.DIRECT,
    }
    values.update(overrides)
    return ThreatEvent(**values)


def test_risk_radar_preserves_no_data_instead_of_publishing_zero_risk():
    result = build_cyber_risk_radar([], [])

    assert result["status"] == "no_data"
    assert all(row["score"] is None for row in result["rows"])
    assert all(row["heat"] == "no_data" for row in result["rows"])
    assert all(row["max_residual_risk"] is None for row in result["rows"])


def test_risk_radar_scores_only_the_dimension_supported_by_direct_records():
    result = build_cyber_risk_radar([_event()], [])
    rows = {row["key"]: row for row in result["rows"]}

    assert result["status"] == "evidence_backed"
    assert rows["fraud"]["score"] is not None
    assert rows["fraud"]["evidence_count"] == 1
    assert rows["fraud"]["value_status"] == "evidence_backed"
    assert rows["ransomware"]["score"] is None
    assert rows["ransomware"]["value_status"] == "no_data"
