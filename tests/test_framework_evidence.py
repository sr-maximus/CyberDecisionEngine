from cyberdeck.analysis.framework_evidence import build_framework_evidence_mapping
from cyberdeck.analysis.threat_news import build_threat_news
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


def _org() -> OrganizationProfile:
    return OrganizationProfile(
        name="Example Group",
        sector="financial",
        country="Colombia",
        author="test",
        authorized_scope=True,
        primary_domains=["example.com"],
    )


def _event(**overrides) -> ThreatEvent:
    values = {
        "id": "event-1",
        "title": "APT29 phishing campaign targets the financial sector",
        "category": "phishing",
        "source": "Public cyber news",
        "actor": "APT29",
        "tags": ["campaign", "phishing", "sector_campaign"],
        "evidence_url": "https://news.example/article",
        "relationship_to_scope": "sector",
        "evidence_status": EvidenceStatus.DIRECT,
    }
    values.update(overrides)
    return ThreatEvent(**values)


def test_framework_crosswalk_counts_current_run_records_without_percentages():
    result = build_framework_evidence_mapping([_event()], [], _org())

    assert result["status"] == "evidence_backed"
    assert result["record_count"] == 1
    assert result["validated_count"] == 0
    assert result["mappings"]
    assert all("record_count" in row for row in result["mappings"])
    assert all(row["evidence_ids"] == ["event-1"] for row in result["mappings"])
    assert all(
        row["direct_relationship_evidence_ids"] == []
        for row in result["mappings"]
    )
    assert all("score" not in row and "percentage" not in row for row in result["mappings"])


def test_false_positive_is_excluded_from_framework_and_news():
    event = _event(evidence_status=EvidenceStatus.FALSE_POSITIVE)

    assert build_framework_evidence_mapping([event], [], _org())["record_count"] == 0
    assert build_threat_news([event])["record_count"] == 0


def test_threat_news_requires_both_cyber_action_and_attribution():
    business = _event(
        id="business",
        title="Example Group publishes sustainability report",
        actor=None,
        tags=["news"],
        category="news",
    )

    result = build_threat_news([business, _event()])

    assert result["record_count"] == 1
    assert result["rows"][0]["actor"] == "APT29"
    assert result["rows"][0]["observed_attack"] is False


def test_generic_marketing_campaign_is_not_threat_news():
    event = _event(
        id="marketing",
        title="FTC challenges influencer campaign for a video game",
        actor="unattributed",
        category="news",
        tags=["campaign"],
        relationship_to_scope="contextual",
    )

    assert build_threat_news([event])["record_count"] == 0


def test_global_contextual_kev_without_technology_match_is_not_mapped():
    event = _event(
        id="global-kev",
        title="CVE-2026-1234 affects an unrelated product",
        actor="unattributed",
        category="vulnerability",
        tags=["kev", "cve"],
        relationship_to_scope="contextual",
        evidence_status=EvidenceStatus.CONTEXTUAL,
        vulnerability_status="not_assessed",
    )

    assert build_framework_evidence_mapping([event], [], _org())["record_count"] == 0


def test_atlas_requires_ai_specific_evidence():
    result = build_framework_evidence_mapping([_event()], [], _org())

    assert not any(row["framework"] == "MITRE ATLAS" for row in result["mappings"])
