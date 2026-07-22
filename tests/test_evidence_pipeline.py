from cyberdeck.analysis.pestel import build_pestel
from cyberdeck.analysis.porter import build_porter
from cyberdeck.cli import _build_general_findings
from cyberdeck.enrichment.evidence_pipeline import canonicalize_url, process_evidence_records
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RecordKind, SourceStatus, ThreatEvent


def _event(event_id: str, **overrides) -> ThreatEvent:
    values = {
        "id": event_id,
        "title": "Public record",
        "category": "open_web",
        "source": "Public search",
        "evidence_url": "https://example.com/news?id=7&utm_source=test",
        "tags": ["domain:example.com"],
    }
    values.update(overrides)
    return ThreatEvent(**values)


def _organization() -> OrganizationProfile:
    return OrganizationProfile(
        name="Example",
        sector="",
        country="",
        author="test",
        authorized_scope=True,
        primary_domains=["example.com"],
    )


def test_canonical_url_removes_tracking_and_deduplicates_changed_titles():
    first = _event("one", title="First title")
    second = _event("two", title="Updated title", evidence_url="https://EXAMPLE.com/news?utm_medium=social&id=7#fragment")

    result = process_evidence_records([first, second], ["example.com"])

    assert canonicalize_url(first.evidence_url) == "https://example.com/news?id=7"
    assert len(result.records) == 1
    assert result.records[0].duplicate_count == 1
    assert result.summary["duplicates_removed"] == 1


def test_transient_dns_error_is_potential_evidence_not_a_finding():
    event = _event(
        "dns-timeout",
        title="SPF could not be queried",
        category="attack_surface",
        evidence_url=None,
        severity=0.8,
        tags=["domain:example.com", "email_security"],
        validation_result="temporary_resolution_error",
        technical_validation={"validation_result": "temporary_resolution_error"},
    )

    processed = process_evidence_records([event], ["example.com"]).records[0]

    assert processed.evidence_status == EvidenceStatus.POTENTIAL
    assert processed.record_kind == RecordKind.CONTEXTUAL_SIGNAL
    assert _build_general_findings([processed], _organization()) == []


def test_cve_without_confirmed_product_version_remains_candidate():
    event = _event(
        "cve-candidate",
        category="vulnerability",
        cve="CVE-2026-0001",
        tags=["domain:example.com", "technology_observed"],
    )

    processed = process_evidence_records([event], ["example.com"]).records[0]

    assert processed.vulnerability_status == "cve_candidate"
    assert processed.record_kind != RecordKind.APPLICABLE_VULNERABILITY
    assert _build_general_findings([processed], _organization()) == []


def test_attack_mapping_requires_validated_behavior_evidence():
    contextual = _event("context", technique="T1566", evidence_url="https://example.com/context")
    observed = _event(
        "observed",
        technique="T1566",
        evidence_url="https://example.com/observed",
        validation_result="validated",
        technical_validation={"validation_result": "validated"},
        tags=["domain:example.com", "telemetry"],
    )

    records = process_evidence_records([contextual, observed], ["example.com"]).records
    statuses = {record.id: record.attack_mapping_status for record in records}

    assert statuses["context"] == "potentially_relevant_technique"
    assert statuses["observed"] == "observed_adversary_behavior"


def test_source_status_distinguishes_success_no_data_timeout_and_disabled():
    no_data = SourceStatus(name="empty", status="empty", records=0)
    timeout = SourceStatus(name="timeout", status="timeout", records=0)
    disabled = SourceStatus(name="disabled", status="disabled", records=0)

    assert no_data.queried and no_data.success and no_data.no_data
    assert timeout.queried and timeout.timed_out and not timeout.success
    assert disabled.disabled and not disabled.queried
    assert no_data.source_health_score > timeout.source_health_score >= disabled.source_health_score


def test_pestel_and_porter_do_not_create_scores_or_scenarios_without_evidence():
    pestel = build_pestel([], "", [])
    porter = build_porter([], "", [])

    assert pestel["assessment_status"] == "insufficient_evidence"
    assert porter["assessment_status"] == "insufficient_evidence"
    assert pestel["index"] is porter["index"] is None
    assert pestel["scenarios"] == porter["scenarios"] == []
    assert pestel["is_risk_score"] is porter["is_risk_score"] is False


def test_context_lenses_do_not_convert_fraud_labels_into_strategic_news_scores():
    raw_fraud = _event("raw-fraud", category="fraud", evidence_url="https://unrelated.invalid/raw", tags=[])
    validated_fraud = _event(
        "validated-fraud",
        category="fraud",
        evidence_url="https://example.com/validated",
        tags=["domain:example.com"],
        validation_result="validated",
        technical_validation={"validation_result": "validated"},
    )
    raw_fraud, validated_fraud = process_evidence_records([raw_fraud, validated_fraud], ["example.com"]).records

    pestel = build_pestel([raw_fraud, validated_fraud], "CO", [])
    porter = build_porter([raw_fraud, validated_fraud], "financial", [])

    assert pestel["signal_count"] == 0
    assert porter["signal_count"] == 0
    assert pestel["index"] is None
    assert porter["index"] is None
    assert pestel["scenarios"] == porter["scenarios"] == []


def test_declared_sector_does_not_increase_risk_without_explicit_targeting():
    event = _event(
        "validated-surface",
        title="Validated external control gap for example.com",
        category="attack_surface",
        evidence_url="dns://example.com/TXT",
        severity=0.65,
        tags=["domain:example.com", "email_security"],
        validation_result="confirmed_missing",
        technical_validation={"validation_result": "confirmed_missing"},
    )
    processed = process_evidence_records([event], ["example.com"]).records[0]
    organization = _organization().model_copy(update={"sector": "financial"})

    finding = _build_general_findings([processed], organization)[0]

    assert finding.likelihood_inputs["sector_context"] == 0
