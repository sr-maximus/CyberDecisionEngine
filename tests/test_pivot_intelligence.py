from cyberdeck.analysis.pivot_intelligence import build_pivot_intelligence
from cyberdeck.schemas import EvidenceStatus, ThreatEvent


def _event(
    event_id: str,
    source: str,
    artifact_type: str,
    value: str,
    *,
    status: EvidenceStatus = EvidenceStatus.DIRECT,
) -> ThreatEvent:
    return ThreatEvent(
        id=event_id,
        title=f"Record {event_id}",
        category="osint",
        source=source,
        evidence_status=status,
        relationship_to_scope="direct",
        evidence_url=f"https://evidence.example.invalid/{event_id}",
        technical_validation={
            "unstructured_artifacts": [{"type": artifact_type, "value": value}]
        },
    )


def test_pivot_requires_corroboration_for_decision_relevance():
    result = build_pivot_intelligence(
        [
            _event("one", "source-a", "email", "security@example.invalid"),
            _event("two", "source-b", "email", "security@example.invalid"),
        ]
    )

    row = result["entities"][0]
    assert row["corroborated"] is True
    assert row["decision_relevant"] is True
    assert row["source_count"] == 2
    assert row["risk_contribution"] == "supports_confidence"


def test_single_raw_artifact_remains_context_only():
    result = build_pivot_intelligence(
        [_event("raw", "source-a", "phone", "+12025550101", status=EvidenceStatus.RAW)]
    )

    row = result["entities"][0]
    assert row["corroborated"] is False
    assert row["decision_relevant"] is False
    assert row["risk_contribution"] == "context_only"


def test_secret_indicators_are_not_exposed_as_pivots():
    result = build_pivot_intelligence(
        [_event("secret", "source-a", "secret_indicator", "sk-example")]
    )

    assert result["total_entities"] == 0
    assert result["entities"] == []
