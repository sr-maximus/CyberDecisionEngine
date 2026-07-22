import pytest
from pydantic import ValidationError

from cyberdeck.scenarios import ScenarioDefinition


def _scenario_payload(status: str = "active") -> dict:
    kinds = [
        "positive",
        "negative",
        "boundary",
        "missing_data",
        "duplicate",
        "stale_evidence",
        "contradiction",
        "source_failure",
        "tenant_isolation",
    ]
    return {
        "scenarioId": "SCN-TEST-001",
        "version": "1.0.0",
        "name": "Evidence-backed domain impersonation",
        "status": status,
        "domain": "brand_fraud",
        "investigativeObjective": "Validate a suspected lookalike domain.",
        "hypothesis": "A public domain imitates an authorized brand asset.",
        "scopeApplicability": ["organization"],
        "requiredEvidenceTypes": ["dns", "http_content"],
        "optionalEvidenceTypes": ["certificate"],
        "positiveIndicators": [{"field": "edit_distance", "operator": "lte", "value": 2}],
        "negativeIndicators": [{"field": "owner_validated", "operator": "eq", "value": True}],
        "exclusions": [],
        "minimumEvidenceGate": 2,
        "independentSourceGate": 2,
        "timeWindow": "30d",
        "deduplicationPolicy": "canonical_url_and_content_hash",
        "scoringMethodId": "risk-residual-v1",
        "confidenceMethodId": "evidence-confidence-v1",
        "severityMethodId": "business-impact-v1",
        "frameworkMappings": [{"framework": "ATT&CK", "id": "T1583.001"}],
        "falsePositiveConditions": ["authorized campaign domain"],
        "outputTemplate": "brand-domain-investigation-v1",
        "recommendedActions": ["Validate ownership before escalation."],
        "references": [],
        "owner": "Threat Intelligence",
        "tests": [
            {"test_id": f"test-{kind}", "kind": kind, "fixture": f"fixtures/{kind}.json", "expected_status": "supported"}
            for kind in kinds
        ],
        "effectiveFrom": "2026-07-19",
        "deprecatedBy": None,
    }


def test_active_scenario_requires_complete_test_matrix():
    scenario = ScenarioDefinition.model_validate(_scenario_payload())
    assert scenario.scenario_id == "SCN-TEST-001"

    incomplete = _scenario_payload()
    incomplete["tests"] = incomplete["tests"][:-1]
    with pytest.raises(ValidationError, match="tenant_isolation"):
        ScenarioDefinition.model_validate(incomplete)


def test_reference_template_is_not_an_executable_scenario_status():
    payload = _scenario_payload(status="preventive_template")
    with pytest.raises(ValidationError):
        ScenarioDefinition.model_validate(payload)
