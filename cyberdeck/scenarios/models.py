from __future__ import annotations

from datetime import date
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator


ScenarioStatus = Literal["draft", "active", "disabled", "deprecated"]
ScenarioTestKind = Literal[
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


class ScenarioTestCase(BaseModel):
    test_id: str
    kind: ScenarioTestKind
    fixture: str
    expected_status: str


class ScenarioDefinition(BaseModel):
    """Executable scenario contract; reference catalog combinations do not satisfy it."""

    scenario_id: str = Field(alias="scenarioId")
    version: str
    name: str
    status: ScenarioStatus
    domain: str
    investigative_objective: str = Field(alias="investigativeObjective")
    hypothesis: str
    scope_applicability: list[str] = Field(alias="scopeApplicability")
    required_evidence_types: list[str] = Field(alias="requiredEvidenceTypes", min_length=1)
    optional_evidence_types: list[str] = Field(alias="optionalEvidenceTypes", default_factory=list)
    positive_indicators: list[dict[str, Any]] = Field(alias="positiveIndicators", min_length=1)
    negative_indicators: list[dict[str, Any]] = Field(alias="negativeIndicators", default_factory=list)
    exclusions: list[dict[str, Any]] = Field(default_factory=list)
    minimum_evidence_gate: int = Field(alias="minimumEvidenceGate", ge=1)
    independent_source_gate: int = Field(alias="independentSourceGate", ge=1)
    time_window: str = Field(alias="timeWindow")
    deduplication_policy: str = Field(alias="deduplicationPolicy")
    scoring_method_id: str = Field(alias="scoringMethodId")
    confidence_method_id: str = Field(alias="confidenceMethodId")
    severity_method_id: str = Field(alias="severityMethodId")
    framework_mappings: list[dict[str, str]] = Field(alias="frameworkMappings", default_factory=list)
    false_positive_conditions: list[str] = Field(alias="falsePositiveConditions", default_factory=list)
    output_template: str = Field(alias="outputTemplate")
    recommended_actions: list[str] = Field(alias="recommendedActions", min_length=1)
    references: list[str] = Field(default_factory=list)
    owner: str
    tests: list[ScenarioTestCase]
    effective_from: date = Field(alias="effectiveFrom")
    deprecated_by: Optional[str] = Field(alias="deprecatedBy", default=None)

    @model_validator(mode="after")
    def validate_active_scenario_tests(self) -> "ScenarioDefinition":
        if self.status != "active":
            return self
        required = {
            "positive",
            "negative",
            "boundary",
            "missing_data",
            "duplicate",
            "stale_evidence",
            "contradiction",
            "source_failure",
            "tenant_isolation",
        }
        present = {test.kind for test in self.tests}
        missing = sorted(required - present)
        if missing:
            raise ValueError(f"active scenario is missing required tests: {', '.join(missing)}")
        return self
