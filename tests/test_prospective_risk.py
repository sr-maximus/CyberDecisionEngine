from __future__ import annotations

from cyberdeck.analysis.prospective_risk import build_prospective_attack_risk
from cyberdeck.schemas import EvidenceStatus, ThreatEvent


def _event(
    event_id: str,
    *,
    status: EvidenceStatus = EvidenceStatus.DIRECT,
    age_days: int = 0,
    source: str = "source-a",
    category: str = "attack_surface",
    vulnerability_status: str = "not_assessed",
    tags: list[str] | None = None,
) -> ThreatEvent:
    return ThreatEvent(
        id=event_id,
        title=f"Evidence {event_id}",
        category=category,
        source=source,
        evidence_status=status,
        relationship_to_scope="direct",
        confidence_score=0.85,
        severity=0.8,
        age_days=age_days,
        vulnerability_status=vulnerability_status,
        tags=tags or [],
        evidence_url=f"https://example.test/{event_id}",
    )


def test_prospective_model_does_not_publish_probability_without_calibration():
    result = build_prospective_attack_risk(
        [_event("kev", vulnerability_status="kev_exposed", tags=["kev"])],
        [],
        sector="Energy",
        source_coverage={"unique_records": 1, "source_health_score": 0.8},
    )

    assert result["status"] == "assessed"
    assert result["pressure_index_30d"] > 0
    assert result["attack_probability"]["value"] is None
    assert result["attack_probability"]["status"] == "not_calibrated"
    assert result["prediction_is_calibrated"] is False
    assert result["trend"]["direction"] == "rising"


def test_raw_records_do_not_create_prospective_pressure():
    result = build_prospective_attack_risk(
        [_event("raw", status=EvidenceStatus.RAW)],
        [],
    )

    assert result["status"] == "insufficient_evidence"
    assert result["pressure_index_30d"] is None
    assert result["attack_probability"]["value"] is None


def test_controls_only_reduce_pressure_when_explicitly_declared():
    events = [
        _event("current", age_days=1, source="source-a"),
        _event("previous", age_days=12, source="source-b"),
    ]
    baseline = build_prospective_attack_risk(events, [])
    controlled = build_prospective_attack_risk(events, [], controls={"detection": 0.9, "response": 0.9})

    assert baseline["pressure_index_30d"] >= controlled["pressure_index_30d"]
    assert baseline["pressure_index_30d"] > 0
