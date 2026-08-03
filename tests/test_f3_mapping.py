from cyberdeck.analysis.f3_mapping import build_f3_profile, enrich_f3_mappings
from cyberdeck.analysis.framework_evidence import build_framework_evidence_mapping
from cyberdeck.frameworks.f3 import load_f3_catalog
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


def _event(**overrides) -> ThreatEvent:
    values = {
        "id": "event-f3",
        "title": "Validated fake recruitment page impersonates the organization",
        "category": "fake_recruitment",
        "source": "Public search",
        "tags": ["fake_recruitment", "brand_impersonation"],
        "evidence_url": "https://evidence.example/fake-job",
        "relationship_to_scope": "direct",
        "evidence_status": EvidenceStatus.VALIDATED,
        "confidence_score": 0.84,
    }
    values.update(overrides)
    return ThreatEvent(**values)


def test_f3_catalog_matches_official_v1_1_shape():
    catalog = load_f3_catalog()
    assert catalog["version"] == "1.1"
    assert len(catalog["tactics"]) == 8
    assert len(catalog["techniques"]) == 123
    assert catalog["sha256"]


def test_f3_maps_only_explicit_assured_fraud_evidence():
    validated = _event()
    generic = _event(
        id="generic",
        title="General article mentioning fraud trends",
        category="news",
        tags=[],
        evidence_status=EvidenceStatus.RAW,
    )
    summary = enrich_f3_mappings([validated, generic])

    assert summary["mapped_event_count"] == 1
    mappings = validated.technical_validation["f3_mappings"]
    assert mappings[0]["id"] == "F1032"
    assert mappings[0]["mapping_status"] == "evidence_supported_candidate"
    assert "f3_mappings" not in generic.technical_validation


def test_f3_profile_and_control_matrix_share_the_same_evidence():
    event = _event()
    enrich_f3_mappings([event])
    profile = build_f3_profile([event])
    organization = OrganizationProfile(
        name="Example Group",
        sector="financial",
        country="CO",
        primary_domains=["example.com"],
        author="CyberDecisionEngine test",
    )
    matrix = build_framework_evidence_mapping([event], [], organization)
    f3_rows = [item for item in matrix["mappings"] if item["framework"] == "MITRE F3"]

    assert profile["mapped_record_count"] == 1
    assert profile["techniques"][0]["id"] == "F1032"
    assert f3_rows
    assert {row["axis"] for row in f3_rows}.issuperset({"fraud"})


def test_generic_fraud_word_does_not_create_f3_mapping():
    event = _event(
        title="Fraud is a business concern",
        category="news",
        tags=[],
        evidence_status=EvidenceStatus.DIRECT,
    )
    enrich_f3_mappings([event])
    assert "f3_mappings" not in event.technical_validation
