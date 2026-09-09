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


def test_framework_catalog_is_complete_even_when_run_has_no_related_records():
    result = build_framework_evidence_mapping([], [], _org())
    catalog = {item["name"]: item for item in result["framework_catalog"]}

    assert {
        "NIST CSF",
        "ISO 27001",
        "PCI DSS",
        "SOC 2",
        "GDPR",
        "CIS Controls",
        "MITRE ATT&CK Enterprise",
        "MITRE ATT&CK ICS",
        "MITRE ATT&CK Mobile",
        "MITRE EMB3D",
        "MITRE D3FEND",
        "MITRE ATLAS",
        "MITRE F3",
        "MITRE AADAPT",
        "MITRE CAPEC",
        "MITRE CWE",
        "MITRE INFORM",
        "DISARM",
        "COBIT 2019",
    } == set(catalog)
    assert all(item["status"] == "no_data" for item in catalog.values())
    assert all(item["mapping_count"] == 0 for item in catalog.values())


def test_f3_attribution_does_not_create_an_attack_framework_label():
    event = _event(
        id="f3-event",
        title="FIN7 fraud campaign uses impersonation",
        category="fraud",
        technical_validation={"f3_mappings": [{"id": "F3-candidate"}]},
    )

    row = build_threat_news([event])["rows"][0]

    assert "MITRE F3" in row["frameworks"]
    assert not any("ATT&CK" in framework for framework in row["frameworks"])


def test_threat_traceability_preserves_campaign_multiple_ttps_and_d3fend_crosswalk():
    event = _event(
        technique="T1566",
        technique_refs=["T1078"],
        technical_validation={"campaign_names": ["Operation Example"]},
    )

    result = build_threat_news([event])
    row = result["rows"][0]

    assert row["campaigns"] == ["Operation Example"]
    assert [item["id"] for item in row["attack_techniques"]] == ["T1566", "T1078"]
    assert {item["id"] for item in row["d3fend"]} >= {"D3-PH", "D3-MFA"}
    assert result["campaign_count"] == 1
    assert result["actors"][0]["campaigns"] == ["Operation Example"]
    assert result["actors"][0]["techniques"] == ["T1078", "T1566"]
    assert result["actors"][0]["urls"] == ["https://news.example/article"]


def test_aadapt_requires_explicit_digital_asset_context():
    generic = build_framework_evidence_mapping([_event()], [], _org())
    assert not any(row["framework"] == "MITRE AADAPT" for row in generic["mappings"])

    digital_asset = _event(
        id="aadapt-event",
        title="Digital asset wallet fraud affects payment users",
        category="fraud",
        tags=["digital asset", "wallet", "sector_campaign"],
        framework_refs=["MITRE AADAPT"],
    )
    mapped = build_framework_evidence_mapping([digital_asset], [], _org())
    assert any(row["framework"] == "MITRE AADAPT" for row in mapped["mappings"])


def test_disarm_maps_explicit_influence_evidence_only():
    event = _event(
        id="disarm-event",
        title="Coordinated amplification supports a disinformation narrative",
        category="disinformation",
        tags=["coordinated_amplification", "sector_campaign"],
        framework_refs=["DISARM"],
    )
    result = build_framework_evidence_mapping([event], [], _org())
    assert any(row["framework"] == "DISARM" and row["axis"] == "influence" for row in result["mappings"])


def test_inform_stays_reference_only_without_explicit_maturity_evidence():
    generic = build_framework_evidence_mapping([_event()], [], _org())
    assert not any(row["framework"] == "MITRE INFORM" for row in generic["mappings"])

    maturity = _event(
        id="inform-event",
        title="Threat-informed maturity assessment identifies a coverage gap",
        category="governance",
        tags=["threat-informed maturity", "sector_campaign"],
        framework_refs=["MITRE INFORM"],
    )
    mapped = build_framework_evidence_mapping([maturity], [], _org())
    assert any(row["framework"] == "MITRE INFORM" for row in mapped["mappings"])
