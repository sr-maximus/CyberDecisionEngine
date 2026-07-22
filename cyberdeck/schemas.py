from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceStatus(str, Enum):
    RAW = "raw"
    CONTEXTUAL = "contextual"
    POTENTIAL = "potential"
    RELATED = "related"
    DIRECT = "direct"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DISCARDED = "discarded"


class ConfidenceLevel(str, Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class RecordKind(str, Enum):
    RAW_DATA = "raw_data"
    COLLECTED_RECORD = "collected_record"
    UNIQUE_RECORD = "unique_record"
    OBSERVED_ASSET = "observed_asset"
    CONTEXTUAL_SIGNAL = "contextual_signal"
    RELATED_EVIDENCE = "related_evidence"
    DIRECT_EVIDENCE = "direct_evidence"
    VALIDATED_TECHNICAL_EVIDENCE = "validated_technical_evidence"
    FINDING = "finding"
    APPLICABLE_VULNERABILITY = "applicable_vulnerability"
    RISK = "risk"
    PREVENTIVE_SCENARIO = "preventive_scenario"
    ACTIVATED_SCENARIO = "activated_scenario"
    OBSERVED_ADVERSARY_ACTIVITY = "observed_adversary_activity"
    CONFIRMED_INCIDENT = "confirmed_incident"
    FALSE_POSITIVE = "false_positive"
    SOURCE_LIMITATION = "source_limitation"


class ScenarioStatus(str, Enum):
    LIBRARY = "library"
    PREVENTIVE = "preventive"
    CANDIDATE = "candidate"
    PARTIALLY_SUPPORTED = "partially_supported"
    ACTIVATED = "activated"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    DISCARDED = "discarded"


class SourceStatus(BaseModel):
    name: str
    status: str
    records: int = 0
    mode: str = "real"
    warning: Optional[str] = None
    enabled: bool = True
    configured: bool = True
    authenticated: Optional[bool] = None
    queried: bool = False
    success: bool = False
    partial: bool = False
    rate_limited: bool = False
    timed_out: bool = False
    no_data: bool = False
    not_applicable: bool = False
    disabled: bool = False
    failed: bool = False
    registered: bool = True
    eligible: bool = False
    attempted: bool = False
    succeeded: bool = False
    productive: bool = False
    empty: bool = False
    degraded: bool = False
    skipped: bool = False
    unconfigured: bool = False
    coverage_score: float = Field(default=0.0, ge=0.0, le=1.0)
    source_health_score: float = Field(default=0.0, ge=0.0, le=1.0)
    source_completeness_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def derive_connector_state(self) -> "SourceStatus":
        state = (self.status or "").strip().lower().replace(" ", "_")
        warning = (self.warning or "").lower()
        self.registered = True
        self.queried = self.queried or state in {"ok", "success", "partial", "searched", "empty", "no_data", "timeout", "rate_limited", "failed", "error"}
        self.success = self.success or state in {"ok", "success", "searched", "empty", "no_data"}
        self.partial = self.partial or state == "partial"
        self.rate_limited = self.rate_limited or state == "rate_limited" or "rate limit" in warning
        self.timed_out = self.timed_out or state == "timeout"
        self.no_data = self.no_data or state in {"empty", "no_data"} or (self.queried and self.success and self.records == 0)
        self.not_applicable = self.not_applicable or state == "not_applicable"
        unavailable_by_configuration = state == "skipped" and any(
            marker in warning for marker in {"not configured", "no configur", "disabled", "no domains", "sin dominios"}
        )
        self.disabled = self.disabled or state == "disabled" or unavailable_by_configuration
        self.failed = self.failed or state in {"failed", "error"}
        if state == "skipped" and not unavailable_by_configuration:
            self.queried = True
            self.partial = self.partial or self.rate_limited or bool(self.warning)
            self.no_data = self.no_data or self.records == 0
        if state == "missing" or "not configured" in warning or "no configur" in warning:
            self.configured = False
        if self.disabled:
            self.enabled = False
        if state in {"configured", "missing"}:
            self.queried = False
        self.unconfigured = not self.configured or state == "missing"
        self.eligible = bool(
            self.enabled
            and self.configured
            and not self.disabled
            and not self.not_applicable
        )
        self.attempted = bool(self.eligible and self.queried)
        self.skipped = bool(state == "skipped" and not self.attempted)
        self.succeeded = bool(self.attempted and self.success and not self.failed)
        self.productive = bool(self.attempted and self.records > 0 and (self.success or self.partial))
        self.empty = bool(self.attempted and self.records == 0 and (self.success or self.no_data))
        self.degraded = bool(
            self.attempted
            and not self.failed
            and (self.partial or self.rate_limited or self.timed_out)
        )
        if not self.coverage_score:
            self.coverage_score = 1.0 if self.success else 0.65 if self.partial else 0.25 if self.queried else 0.0
        if not self.source_health_score:
            self.source_health_score = 1.0 if self.success else 0.3 if self.rate_limited or self.timed_out else 0.65 if self.partial else 0.0
        if not self.source_completeness_score:
            self.source_completeness_score = 1.0 if self.success and not self.no_data else 0.85 if self.success else 0.55 if self.partial else 0.0
        return self


class EvidenceCapture(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    screenshot_id: str = Field(alias="screenshotId")
    run_id: str = Field(alias="runId")
    evidence_id: str = Field(alias="evidenceId")
    source_id: str = Field(alias="sourceId")
    original_page_url: str = Field(alias="originalPageUrl")
    page_title: str = Field(default="", alias="pageTitle")
    capture_timestamp: str = Field(alias="captureTimestamp")
    final_url: str = Field(alias="finalUrl")
    response_status: Optional[int] = Field(default=None, alias="responseStatus")
    content_type: Optional[str] = Field(default=None, alias="contentType")
    viewport: Dict[str, int] = Field(default_factory=dict)
    full_page: bool = Field(default=True, alias="fullPage")
    capture_type: str = Field(default="full_page", alias="captureType")
    image_path: Optional[str] = Field(default=None, alias="imagePath")
    image_hash: Optional[str] = Field(default=None, alias="imageHash")
    image_format: str = Field(default="png", alias="imageFormat")
    image_size_bytes: Optional[int] = Field(default=None, ge=1, alias="imageSizeBytes")
    dimensions: Dict[str, int] = Field(default_factory=dict)
    browser_engine: str = Field(default="internal_browser", alias="browserEngine")
    browser_engine_version: str = Field(default="unknown", alias="browserEngineVersion")
    validation_status: str = Field(default="not_captured", alias="validationStatus")
    errors: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = Field(default=None, alias="failureReason")
    redaction_applied: bool = Field(default=False, alias="redactionApplied")
    redaction_notes: List[str] = Field(default_factory=list, alias="redactionNotes")
    related_evidence_id: str = Field(alias="relatedEvidenceId")

    @model_validator(mode="after")
    def validate_capture(self) -> "EvidenceCapture":
        if self.validation_status in {"captured", "verified"}:
            if not self.image_path or not self.image_hash or not self.capture_timestamp or not self.image_size_bytes:
                raise ValueError("A captured evidence image requires path, hash, timestamp and size")
            if not self.dimensions.get("width") or not self.dimensions.get("height"):
                raise ValueError("A captured evidence image requires width and height")
        if self.evidence_id != self.related_evidence_id:
            raise ValueError("Capture evidenceId and relatedEvidenceId must match")
        if self.validation_status == "failed" and not (self.errors or self.failure_reason):
            raise ValueError("A failed capture requires an error or failure reason")
        return self


class ThreatEvent(BaseModel):
    id: str
    title: str
    category: str
    source: str
    source_weight: float = 0.5
    confidence: float = 0.5
    age_days: int = 0
    severity: float = 0.5
    epss: float = 0.05
    cvss: float = 5.0
    cve: Optional[str] = None
    actor: Optional[str] = None
    technique: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    evidence_url: Optional[str] = None
    observed_at: str = Field(default_factory=utcnow_iso)
    demo: bool = False
    canonical_id: Optional[str] = None
    content_hash: Optional[str] = None
    record_kind: RecordKind = RecordKind.COLLECTED_RECORD
    evidence_status: EvidenceStatus = EvidenceStatus.RAW
    confidence_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    relationship_to_scope: str = "unassessed"
    validation_result: str = "not_validated"
    technical_validation: Dict[str, Any] = Field(default_factory=dict)
    asset: Optional[str] = None
    host: Optional[str] = None
    indicator: Optional[str] = None
    external_id: Optional[str] = None
    source_refs: List[str] = Field(default_factory=list)
    duplicate_count: int = 0
    vulnerability_status: str = "not_assessed"
    attack_mapping_status: str = "preventive_reference"
    scenario_support: str = "none"
    incident_confirmed: bool = False
    human_reviewed: bool = False
    contradiction_count: int = 0
    captures: List[EvidenceCapture] = Field(default_factory=list)

    @model_validator(mode="after")
    def synchronize_confidence(self) -> "ThreatEvent":
        if self.confidence_score == 0.5 and self.confidence != 0.5:
            self.confidence_score = max(0.0, min(1.0, float(self.confidence)))
        else:
            self.confidence = self.confidence_score
        score = self.confidence_score
        if score < 0.2:
            self.confidence_level = ConfidenceLevel.VERY_LOW
        elif score < 0.4:
            self.confidence_level = ConfidenceLevel.LOW
        elif score < 0.65:
            self.confidence_level = ConfidenceLevel.MEDIUM
        elif score < 0.85:
            self.confidence_level = ConfidenceLevel.HIGH
        else:
            self.confidence_level = ConfidenceLevel.VERY_HIGH
        if not self.source_refs:
            self.source_refs = [self.source]
        return self


class RiskFinding(BaseModel):
    title: str
    category: str
    likelihood: float
    impact: float
    inherent_risk: float
    residual_risk: float
    matrix_score: int
    matrix_label: str
    evidence: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    owner: str = "CISO"
    demo: bool = False
    finding_id: Optional[str] = None
    evidence_status: EvidenceStatus = EvidenceStatus.VALIDATED
    confidence_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    linked_evidence_ids: List[str] = Field(default_factory=list)
    likelihood_inputs: Dict[str, float] = Field(default_factory=dict)
    impact_inputs: Dict[str, float] = Field(default_factory=dict)
    control_inputs: Dict[str, float] = Field(default_factory=dict)
    assumptions: List[str] = Field(default_factory=list)
    validation_method: str = "analytical_review"
    closure_evidence: List[str] = Field(default_factory=list)
    incident_confirmed: bool = False
    vulnerability_status: str = "not_applicable"


class OrganizationProfile(BaseModel):
    name: str
    entity_type: str = "organization"
    subject_aliases: List[str] = Field(default_factory=list)
    legal_name: Optional[str] = None
    sector: str
    subsector: Optional[str] = None
    country: str
    author: str
    language: str = "es"
    authorized_scope: bool = False
    allow_tor: bool = False
    analysis_window: str = "30d"
    lookback_hours: int = 720
    lookback_days: int = 30
    scan_time_budget_minutes: int = 0
    report_display_at: Optional[str] = None
    primary_domains: List[str] = Field(default_factory=list)
    comparison_domains: List[str] = Field(default_factory=list)
    business_units: List[str] = Field(default_factory=list)
    brands: List[str] = Field(default_factory=list)
    subsidiaries: List[str] = Field(default_factory=list)
    parent_organizations: List[str] = Field(default_factory=list)
    joint_ventures: List[str] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)
    strategic_assets: List[str] = Field(default_factory=list)
    critical_suppliers: List[str] = Field(default_factory=list)
    declared_competitors: List[str] = Field(default_factory=list)
    countries_of_operation: List[str] = Field(default_factory=list)
    entity_aliases: List[Dict[str, Any]] = Field(default_factory=list)
    crown_jewels: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    risk_appetite: Dict[str, float] = Field(default_factory=dict)
    control_maturity: Dict[str, float] = Field(default_factory=dict)
    fraud_maturity: Dict[str, float] = Field(default_factory=dict)


class RunContext(BaseModel):
    organization: OrganizationProfile
    mode: str
    lookback_days: int
    lookback_hours: int = 720
    analysis_window: str = "30d"
    generated_at: str = Field(default_factory=utcnow_iso)
    report_display_at: Optional[str] = None
    source_statuses: List[SourceStatus] = Field(default_factory=list)
    raw_events: List[ThreatEvent] = Field(default_factory=list)
    risk_findings: List[RiskFinding] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    references: List[Dict[str, str]] = Field(default_factory=list)
    processing_summary: Dict[str, Any] = Field(default_factory=dict)
    connector_coverage: Dict[str, Any] = Field(default_factory=dict)
    incidents_confirmed: int = 0
    false_positive_count: int = 0
    decision_snapshot: Dict[str, Any] = Field(default_factory=dict)
    knowledge_backend: Dict[str, Any] = Field(default_factory=dict)
    claim_evidence_model_version: str = ""
    claims: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    claim_evidence_links: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    interpretations: List[Dict[str, Any]] = Field(default_factory=list)
    decisions: List[Dict[str, Any]] = Field(default_factory=list)
