from cyberdeck.analysis.evidence_review import build_evidence_review_summary
from cyberdeck.schemas import EvidenceStatus, ThreatEvent


def _event(event_id: str, **changes: object) -> ThreatEvent:
    payload = {
        "id": event_id,
        "title": "Public phishing signal",
        "category": "brand_fraud",
        "source": "public-index",
        "evidence_url": f"https://evidence.example/{event_id}",
        "relationship_to_scope": "explicit_mention",
        "evidence_status": EvidenceStatus.RELATED,
    }
    payload.update(changes)
    return ThreatEvent(**payload)


def test_manual_review_preserves_evidence_and_requires_human_decision() -> None:
    event = _event("manual")
    before = event.model_dump()

    summary = build_evidence_review_summary([event], "manual")

    assert summary["automatic_validation"] is False
    assert summary["pending_human_decision_count"] == 1
    assert summary["proposals"][0]["recommendation"] == "manual_review_required"
    assert event.model_dump() == before


def test_ai_assisted_review_proposes_but_does_not_validate() -> None:
    event = _event("assisted")

    summary = build_evidence_review_summary([event], "ai_assisted")

    assert summary["provider"] == "deterministic_grounded_triage"
    assert summary["automatic_validation"] is False
    assert summary["proposals"][0]["recommendation"] == "retain_for_human_validation"
    assert event.evidence_status == EvidenceStatus.RELATED
    assert event.human_reviewed is False


def test_missing_url_or_scope_relationship_is_flagged_for_human_review() -> None:
    event = _event(
        "weak-signal",
        evidence_url=None,
        relationship_to_scope="unrelated",
    )

    summary = build_evidence_review_summary([event], "ai_assisted")

    assert summary["proposals"][0]["recommendation"] == "possible_false_positive"
    assert summary["pending_human_decision_count"] == 1
