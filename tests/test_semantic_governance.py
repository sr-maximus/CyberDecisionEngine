from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from cyberdeck.enrichment.evidence_pipeline import process_evidence_records
from cyberdeck.schemas import EvidenceStatus, RiskFinding, ThreatEvent
from cyberdeck.semantics import Claim, SemanticValidationError, build_claim_evidence_bundle, get_term_registry


def test_confirmed_claim_requires_evidence_ids():
    with pytest.raises(ValidationError):
        Claim(
            claim_id="C-1",
            statement="Confirmed condition",
            subject_entity_ids=["example.com"],
            scope="domain:example.com",
            claim_type="finding",
            claim_status="confirmed",
            confidence=0.9,
            evidence_ids=[],
            validation_method="tls_handshake",
            validator="engine",
            last_validated_at="2026-07-19T00:00:00Z",
            confirmation_threshold_passed=True,
        )


def test_validated_claim_requires_method():
    with pytest.raises(ValidationError):
        Claim(
            claim_id="C-2",
            statement="Validated condition",
            subject_entity_ids=["example.com"],
            scope="domain:example.com",
            claim_type="finding",
            claim_status="validated",
            confidence=0.8,
            evidence_ids=["E-1"],
            validator="engine",
            last_validated_at="2026-07-19T00:00:00Z",
        )


@pytest.mark.parametrize(
    ("term_id", "payload"),
    [
        ("direct_evidence", {"claim_id": "C", "direct_relationship": True, "validation_method": "text_match", "source_id": "S"}),
        ("alert", {"alert_rule_id": "A", "threshold": 0, "owner": "SOC", "recommended_action": "Review", "status": "open"}),
        ("risk", {"control_effectiveness": 0.2, "evidence_confidence": 0.8}),
        ("probability", {"prediction_is_calibrated": False, "defined_outcome": "incident", "calibration_metrics": {"brier": 0.2}, "model_version": "1"}),
        ("attack_observed", {"adversary_telemetry": [], "behavior": "T1059", "timestamp": "now", "asset": "host", "evidence_ids": ["E"]}),
        ("observed_zero", {"value_status": "no_data", "successful_query": False, "valid_denominator": 0, "adequate_coverage": False}),
        ("collected_records", {"source_id": "S", "collected_at": "now", "state": "validated"}),
        ("authorized_collection", {"scope_id": "scope", "authorization_status": "authorized", "state": "validated_finding"}),
    ],
)
def test_prohibited_semantic_claims_fail(term_id, payload):
    with pytest.raises(SemanticValidationError):
        get_term_registry().validate(term_id, payload)


def test_textual_domain_match_is_not_direct_evidence():
    event = ThreatEvent(
        id="E-1",
        title="Reference to example.com",
        category="news",
        source="public-search",
        evidence_url="https://example.com/article",
        technical_validation={"validation_method": "text_match", "direct_relationship": False},
    )
    record = process_evidence_records([event], ["example.com"]).records[0]
    assert record.evidence_status != EvidenceStatus.DIRECT


def test_frontend_and_report_term_artifacts_share_registry():
    subprocess.run([sys.executable, "scripts/generate_semantic_terms.py", "--check"], check=True)
    executive = Path("cyberdeck/reporting/templates/executive_report.html.j2").read_text(encoding="utf-8")
    dashboard = Path("web/src/components/StrategicDashboard.tsx").read_text(encoding="utf-8")
    assert "terms.signal_pressure_index" in executive
    assert 'semanticLabel("signal_pressure_index"' in dashboard


def test_report_renderer_does_not_require_opencti():
    source = Path("cyberdeck/reporting/html_report.py").read_text(encoding="utf-8").lower()
    assert "opencti" not in source


@pytest.mark.parametrize(
    ("subject_entity_ids", "scope"),
    [
        (["example.com"], "domain:example.com"),
        (["Grupo Ejemplo", "example.com"], "organization:Grupo Ejemplo"),
        (["Persona Autorizada"], "person:Persona Autorizada"),
    ],
)
def test_claim_evidence_model_is_subject_agnostic(subject_entity_ids, scope):
    event = ThreatEvent(
        id="E-SUBJECT-1",
        title="Registro público relacionado con el alcance",
        category="public_record",
        source="authorized-public-source",
        evidence_url="https://example.net/evidence/1",
        evidence_status=EvidenceStatus.VALIDATED,
        confidence_score=0.84,
        technical_validation={"validation_method": "reproducible_http_query"},
    )
    finding = RiskFinding(
        finding_id="F-SUBJECT-1",
        title="Condición externa validada",
        category="external_exposure",
        likelihood=0.5,
        impact=0.6,
        inherent_risk=0.3,
        residual_risk=0.24,
        matrix_score=12,
        matrix_label="medium",
        evidence_status=EvidenceStatus.VALIDATED,
        confidence_score=0.84,
        linked_evidence_ids=["E-SUBJECT-1"],
        validation_method="reproducible_http_query",
    )

    bundle = build_claim_evidence_bundle([event], [finding], subject_entity_ids, scope)

    assert bundle.claims[0].subject_entity_ids == subject_entity_ids
    assert bundle.claims[0].scope == scope
    assert bundle.claims[0].evidence_ids == ["E-SUBJECT-1"]
    assert bundle.links[0].claim_id == "F-SUBJECT-1"


def test_finding_without_resolvable_evidence_remains_candidate():
    finding = RiskFinding(
        title="Unresolved observation",
        category="attack_surface",
        likelihood=0.2,
        impact=0.4,
        inherent_risk=8.0,
        residual_risk=4.0,
        matrix_score=4,
        matrix_label="low",
        evidence=["unresolved free text"],
        evidence_status=EvidenceStatus.VALIDATED,
        validation_method="analytical_review",
    )

    bundle = build_claim_evidence_bundle([], [finding], ["example.org"], "organization:Example")

    assert bundle.claims[0].claim_status == "candidate"
    assert bundle.claims[0].evidence_ids == []


def test_claim_link_can_be_recovered_only_from_exact_evidence_reference():
    event = ThreatEvent(
        id="E-EXACT-1",
        title="Respuesta HTTP del activo",
        category="external_surface",
        source="authorized-public-source",
        evidence_url="https://example.com/security.txt",
        evidence_status=EvidenceStatus.VALIDATED,
        confidence_score=0.9,
        technical_validation={"validation_method": "reproducible_http_query"},
    )
    finding = RiskFinding(
        finding_id="F-EXACT-1",
        title="Condición técnica reproducible",
        category="external_exposure",
        likelihood=0.5,
        impact=0.4,
        inherent_risk=0.2,
        residual_risk=0.16,
        matrix_score=8,
        matrix_label="medium",
        evidence=["https://example.com/security.txt"],
        linked_evidence_ids=[],
        evidence_status=EvidenceStatus.VALIDATED,
        confidence_score=0.9,
        validation_method="reproducible_http_query",
    )

    bundle = build_claim_evidence_bundle([event], [finding], ["example.com"], "domain:example.com")

    assert bundle.claims[0].claim_status == "validated"
    assert bundle.claims[0].evidence_ids == ["E-EXACT-1"]
    assert bundle.links[0].evidence_id == "E-EXACT-1"
    assert "registro validado" in bundle.interpretations[0].what_demonstrates
