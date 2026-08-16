from cyberdeck.analysis.narratives import build_narrative_intelligence
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


def _organization() -> OrganizationProfile:
    return OrganizationProfile(name="Example Group", primary_domains=["example.com"], sector="Finance", country="CO", author="QA")


def _event(event_id: str, title: str, tags: list[str], status: EvidenceStatus = EvidenceStatus.RAW) -> ThreatEvent:
    return ThreatEvent(
        id=event_id,
        title=title,
        category="public_record",
        source="Public source",
        observed_at="2026-07-20T10:00:00+00:00",
        tags=tags,
        evidence_url=f"https://example.org/{event_id}",
        evidence_status=status,
        relationship_to_scope="direct",
    )


def test_related_unverified_signal_remains_visible_for_review():
    result = build_narrative_intelligence([_event("complaint-1", "Customer complaint about Example Group", ["complaint"])], _organization())

    assert result["claimCount"] == 1
    assert result["groups"]["under_review"][0]["contentType"] == "user_complaint"
    assert result["groups"]["under_review"][0]["truthStatus"] == "unverified"
    assert result["groups"]["under_review"][0]["disarmEligible"] is False


def test_false_and_coordinated_are_not_inferred_from_missing_corroboration():
    result = build_narrative_intelligence([_event("rumor-1", "Unverified rumor", ["rumor"])], _organization())
    claim = result["claims"][0]

    assert claim["truthStatus"] == "unverified"
    assert claim["coordinationStatus"] == "insufficient_data"
    assert claim["status"] == "under_review"


def test_disarm_requires_multiple_explicit_coordination_indicators():
    event = _event(
        "coord-1",
        "Repeated narrative activity",
        ["potential_disinformation", "coordinated_amplification", "temporal_burst"],
        EvidenceStatus.VALIDATED,
    )
    result = build_narrative_intelligence([event], _organization())
    claim = result["claims"][0]

    assert claim["coordinationStatus"] == "probable"
    assert claim["disarmEligible"] is True
    assert claim["truthStatus"] == "mostly_supported"


def test_generic_contextual_fraud_news_is_not_attached_to_subject():
    event = _event("generic-1", "How to avoid a generic online scam", ["fraud"])
    event.relationship_to_scope = "contextual"
    event.technical_validation = {"query": "latest scam alerts"}

    result = build_narrative_intelligence([event], _organization())

    assert result["claimCount"] == 0


def test_fake_recruitment_signal_is_classified_for_the_subject():
    event = _event(
        "jobs-1",
        "Example Group warns about fake job and recruitment scam offers",
        ["fake_recruitment"],
    )
    event.relationship_to_scope = "direct"

    result = build_narrative_intelligence([event], _organization())

    assert result["claimCount"] == 1
    assert result["claims"][0]["contentType"] == "fake_recruitment"


def test_contextual_result_with_subject_in_content_remains_visible():
    event = _event("related-1", "Customer warning about suspicious Example Group messages", ["fraud"])
    event.relationship_to_scope = "contextual"
    event.technical_validation = {"query": '"example.com" fraud'}

    result = build_narrative_intelligence([event], _organization())

    assert result["claimCount"] == 1
    assert result["groups"]["under_review"][0]["status"] == "under_review"


def test_subject_specific_query_does_not_make_unrelated_result_a_claim():
    event = _event("query-only-1", "Generic technology job posting", ["brand_impersonation"])
    event.relationship_to_scope = "related"
    event.technical_validation = {"query": '"example.com" fraud'}

    result = build_narrative_intelligence([event], _organization())

    assert result["claimCount"] == 0


def test_short_domain_label_does_not_match_inside_unrelated_word():
    organization = OrganizationProfile(
        name="ABC",
        primary_domains=["abc.example.invalid"],
        sector="Energy",
        country="ZZ",
        author="QA",
    )
    event = _event("substring-1", "Buscamos tecnólogos para formación", ["brand_impersonation"])
    event.relationship_to_scope = "related"

    result = build_narrative_intelligence([event], organization)

    assert result["claimCount"] == 0


def test_passive_brand_index_record_is_not_mislabeled_as_reputational_criticism():
    event = _event("index-1", "Public index detected example.com", ["brand_monitoring"])
    event.category = "brand_reputation"

    result = build_narrative_intelligence([event], _organization())

    assert result["claimCount"] == 0
