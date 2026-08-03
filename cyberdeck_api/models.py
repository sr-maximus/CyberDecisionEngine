from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


AnalysisWindow = Literal["1h", "24h", "7d", "30d", "180d", "365d"]
SubjectType = Literal["organization", "person"]
EvidenceReviewStatus = Literal["pending", "validated", "false_positive"]

ANALYSIS_WINDOW_HOURS: Dict[str, int] = {
    "1h": 1,
    "24h": 24,
    "7d": 168,
    "30d": 720,
    "180d": 4320,
    "365d": 8760,
}


def normalize_analysis_window(request: "DomainAnalysisRequest") -> "DomainAnalysisRequest":
    hours = ANALYSIS_WINDOW_HOURS.get(request.analysis_window, request.lookback_hours)
    request.lookback_hours = max(1, min(8760, int(hours)))
    request.lookback_days = max(1, min(365, math.ceil(request.lookback_hours / 24)))
    return request


class DomainAnalysisRequest(BaseModel):
    domains: List[str] = Field(default_factory=list, max_length=50)
    competitor_domains: List[str] = Field(default_factory=list, max_length=50)
    organization_name: Optional[str] = None
    subject_type: SubjectType = "organization"
    person_name: Optional[str] = None
    person_aliases: List[str] = Field(default_factory=list, max_length=100)
    legal_name: Optional[str] = None
    sector: str = ""
    subsector: str = ""
    country: str = ""
    brands: List[str] = Field(default_factory=list, max_length=100)
    subsidiaries: List[str] = Field(default_factory=list, max_length=100)
    parent_organizations: List[str] = Field(default_factory=list, max_length=50)
    products: List[str] = Field(default_factory=list, max_length=100)
    strategic_assets: List[str] = Field(default_factory=list, max_length=100)
    critical_suppliers: List[str] = Field(default_factory=list, max_length=100)
    declared_competitors: List[str] = Field(default_factory=list, max_length=100)
    countries_of_operation: List[str] = Field(default_factory=list, max_length=100)
    entity_aliases: List[Dict[str, object]] = Field(default_factory=list, max_length=200)
    financial_risk_inputs: Dict[str, object] = Field(default_factory=dict)
    scenario_risk_inputs: Dict[str, object] = Field(default_factory=dict)
    author: str = "CyberDecisionEngine Web"
    language: Literal["es", "en"] = "es"
    mode: Literal["snapshot", "deep"] = "deep"
    analysis_window: AnalysisWindow = "365d"
    lookback_hours: int = Field(default=8760, ge=1, le=8760)
    lookback_days: int = Field(default=365, ge=1, le=365)
    real_only: bool = True
    authorized_scope: bool = False
    allow_tor: bool = True
    scan_time_budget_minutes: int = Field(default=30, ge=0, le=240)
    report_display_at: Optional[str] = None
    scope_profile_source_run_id: Optional[str] = None
    scope_profile_applied_fields: List[str] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def domains_cannot_be_empty(cls, value: List[str]) -> List[str]:
        return value

    @field_validator("report_display_at")
    @classmethod
    def normalize_report_display_at(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            return None
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("report_display_at must be an ISO date/time.") from exc
        return parsed.isoformat(timespec="minutes")

    @model_validator(mode="after")
    def scope_requires_authorized_subject(self) -> "DomainAnalysisRequest":
        has_domain = any(item and item.strip() for item in self.domains)
        has_organization = bool(self.organization_name and self.organization_name.strip())
        has_person = bool(self.person_name and self.person_name.strip())
        if has_person and not has_organization and self.subject_type == "organization":
            self.subject_type = "person"
        if self.subject_type == "person" and not has_person:
            raise ValueError("A person name is required when subject_type=person.")
        if not has_domain and not has_organization and not has_person:
            raise ValueError("At least one domain, organization/brand name, or person name is required.")
        return self

    @property
    def subject_name(self) -> Optional[str]:
        if self.subject_type == "person":
            return self.person_name.strip() if self.person_name and self.person_name.strip() else None
        return self.organization_name.strip() if self.organization_name and self.organization_name.strip() else None


class ReportSummary(BaseModel):
    path: str
    url: str
    download_url: Optional[str] = None
    technical_path: Optional[str] = None
    technical_url: Optional[str] = None
    technical_download_url: Optional[str] = None
    generated_at: str = Field(default_factory=utcnow_iso)
    validation_status: Optional[Literal["approved", "approved_with_observations", "rejected"]] = None
    validation_path: Optional[str] = None
    final: bool = True


class EvidenceReviewRequest(BaseModel):
    status: EvidenceReviewStatus
    reviewer: str = Field(default="authorized_user", min_length=2, max_length=120)
    reason: str = Field(default="", max_length=1000)


class ReportCatalogItem(BaseModel):
    name: str
    path: str
    url: str
    download_url: str
    size_bytes: int
    modified_at: str
    report_type: Literal["executive", "technical"]
    run_id: Optional[str] = None


class EmployeeRiskRunResponse(BaseModel):
    id: str
    status: Literal["completed", "failed"]
    stage: str
    report_url: Optional[str] = None
    download_url: Optional[str] = None
    output_urls: Dict[str, str] = Field(default_factory=dict)
    employee_count: int = 0
    evidence_count: int = 0
    max_risk: float = 0.0
    command_output: str = ""


class MitreGroup(BaseModel):
    id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class KpiSummary(BaseModel):
    active_domains: int = 0
    new_events: int = 0
    raw_records: int = 0
    unique_records: int = 0
    validated_evidence: int = 0
    validated_findings: int = 0
    confirmed_findings: int = 0
    confirmed_incidents: int = 0
    false_positives: int = 0
    max_residual_risk: Optional[float] = None
    avg_residual_risk: Optional[float] = None
    healthy_sources: int = 0
    total_sources: int = 0
    eligible_sources: int = 0
    queried_sources: int = 0
    successful_sources: int = 0
    productive_sources: int = 0
    registered_sources: int = 0
    empty_sources: int = 0
    degraded_sources: int = 0
    failed_sources: int = 0
    skipped_sources: int = 0


class DomainSignal(BaseModel):
    domain: str
    events: int = 0
    findings: int = 0
    max_residual_risk: Optional[float] = None
    last_seen: Optional[str] = None


class AnalysisSummary(BaseModel):
    kpis: KpiSummary = Field(default_factory=KpiSummary)
    domain_signals: List[DomainSignal] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    records: List[Dict[str, Any]] = Field(default_factory=list)
    source_statuses: List[Dict[str, Any]] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    processing_summary: Dict[str, Any] = Field(default_factory=dict)
    decision_snapshot: Dict[str, Any] = Field(default_factory=dict)
    claims: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    claim_evidence_links: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    interpretations: List[Dict[str, Any]] = Field(default_factory=list)
    decisions: List[Dict[str, Any]] = Field(default_factory=list)
    semantic_registry_version: str = "1.0.0"
    claim_evidence_model_version: str = ""


class RunRecord(BaseModel):
    id: str
    status: Literal["queued", "running", "completed", "failed"] = "queued"
    stage: str = "Queued"
    created_at: str = Field(default_factory=utcnow_iso)
    updated_at: str = Field(default_factory=utcnow_iso)
    request: DomainAnalysisRequest
    domains: List[str] = Field(default_factory=list)
    progress: int = Field(default=0, ge=0, le=100)
    estimated_seconds: int = Field(default=120, ge=30, le=14400)
    error: Optional[str] = None
    report: Optional[ReportSummary] = None
    summary: AnalysisSummary = Field(default_factory=AnalysisSummary)


MonitoringCadence = Literal["manual", "1h", "6h", "24h", "7d", "continuous"]
MonitoringStatus = Literal["active", "paused", "disabled"]
AlertStatus = Literal["open", "acknowledged", "closed", "false_positive"]
PlatformLogLevel = Literal["info", "warning", "error"]


class MonitoringProfileRequest(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    request: DomainAnalysisRequest
    cadence: MonitoringCadence = "24h"
    collection_duration_minutes: int = Field(default=30, ge=5, le=1440)
    enabled: bool = True
    created_by: str = "system"


class MonitoringProfileUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=120)
    cadence: Optional[MonitoringCadence] = None
    collection_duration_minutes: Optional[int] = Field(default=None, ge=5, le=1440)
    enabled: Optional[bool] = None


class MonitoringProfile(BaseModel):
    id: str
    name: str
    request: DomainAnalysisRequest
    cadence: MonitoringCadence = "24h"
    collection_duration_minutes: int = 30
    status: MonitoringStatus = "active"
    created_by: str = "system"
    created_at: str = Field(default_factory=utcnow_iso)
    updated_at: str = Field(default_factory=utcnow_iso)
    last_run_id: Optional[str] = None
    last_started_at: Optional[str] = None
    last_completed_at: Optional[str] = None
    next_run_at: Optional[str] = None
    processed_run_ids: List[str] = Field(default_factory=list)
    seen_fingerprints: List[str] = Field(default_factory=list)
    alert_count: int = 0
    new_signal_count: int = 0
    last_error: Optional[str] = None


class MonitoringAlert(BaseModel):
    id: str
    profile_id: str
    run_id: str
    fingerprint: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    title: str
    category: str
    evidence_url: Optional[str] = None
    validation: str = ""
    created_at: str = Field(default_factory=utcnow_iso)
    status: AlertStatus = "open"


class MonitoringAlertUpdate(BaseModel):
    status: AlertStatus
    user: str = Field(default="system", max_length=120)


class PlatformLogEntry(BaseModel):
    id: str
    level: PlatformLogLevel = "info"
    component: str = "platform"
    message: str
    run_id: Optional[str] = None
    profile_id: Optional[str] = None
    user: Optional[str] = None
    created_at: str = Field(default_factory=utcnow_iso)


class SupportTicketRequest(BaseModel):
    subject: str = Field(min_length=4, max_length=160)
    description: str = Field(min_length=8, max_length=4000)
    user: str = Field(default="user", max_length=120)
    run_id: Optional[str] = None
    severity: Literal["low", "medium", "high"] = "medium"


class SupportTicket(BaseModel):
    id: str
    subject: str
    description: str
    user: str
    run_id: Optional[str] = None
    severity: Literal["low", "medium", "high"] = "medium"
    status: Literal["open", "in_review", "resolved"] = "open"
    created_at: str = Field(default_factory=utcnow_iso)
    updated_at: str = Field(default_factory=utcnow_iso)


class SupportTicketUpdate(BaseModel):
    status: Literal["open", "in_review", "resolved"]
    user: str = Field(default="system", max_length=120)


class MonitoringOverview(BaseModel):
    generated_at: str = Field(default_factory=utcnow_iso)
    profiles: List[MonitoringProfile] = Field(default_factory=list)
    alerts: List[MonitoringAlert] = Field(default_factory=list)
    logs: List[PlatformLogEntry] = Field(default_factory=list)
    support_tickets: List[SupportTicket] = Field(default_factory=list)


AIProvider = Literal["openai", "azure_openai", "anthropic", "gemini", "mistral", "local_openai_compatible", "openclaw_gateway"]
AIChatScope = Literal[
    "overview",
    "evidence",
    "risk",
    "scenarios",
    "frameworks",
    "osint",
    "socmint",
    "darkweb",
    "attack_surface",
    "brand_fraud",
    "disinformation",
    "geography",
    "vulnerabilities",
]


class AIAnalysisRequest(BaseModel):
    run_id: str
    providers: List[AIProvider] = Field(default_factory=lambda: ["openai"], min_length=1, max_length=6)
    audience: Literal["executive", "technical", "board", "incident", "fraud"] = "executive"
    depth: Literal["standard", "deep", "board"] = "deep"
    objective: str = "decision_intelligence"
    language: Literal["es", "en"] = "es"
    input_token_budget: int = Field(default=12000, ge=2000, le=64000)
    output_token_budget: int = Field(default=4000, ge=1000, le=32000)
    include_findings_limit: int = Field(default=12, ge=1, le=40)
    include_events_limit: int = Field(default=30, ge=1, le=120)
    custom_instructions: Optional[str] = Field(default=None, max_length=4000)


class AIProviderPayload(BaseModel):
    provider: AIProvider
    endpoint_hint: str
    model_hint: str
    headers_required: List[str]
    body: Dict[str, Any]


class AIAnalysisPackage(BaseModel):
    id: str
    status: Literal["draft", "approved"] = "draft"
    prompt_version: str
    generated_at: str = Field(default_factory=utcnow_iso)
    run_id: str
    subject: str
    token_estimate: Dict[str, int]
    token_policy: Dict[str, Any]
    system_prompt: str
    user_prompt: str
    context_digest: Dict[str, Any]
    evidence_manifest: Dict[str, Any]
    guardrails: List[str]
    output_schema: Dict[str, Any]
    provider_payloads: List[AIProviderPayload]
    approval_question: str


class AIExecutionRequest(BaseModel):
    run_id: str
    approved: Literal[True]
    language: Literal["es", "en"] = "es"
    system_prompt: str = Field(min_length=20, max_length=30000)
    user_prompt: str = Field(min_length=20, max_length=120000)
    output_schema: Dict[str, Any] = Field(default_factory=dict)
    output_token_budget: int = Field(default=4000, ge=500, le=8000)


class AIChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class AIChatRequest(BaseModel):
    run_id: str
    message: str = Field(min_length=2, max_length=4000)
    language: Literal["es", "en"] = "es"
    audience: Literal["executive", "technical", "board", "incident", "fraud"] = "executive"
    scopes: List[AIChatScope] = Field(default_factory=lambda: ["overview"], min_length=1, max_length=13)
    history: List[AIChatTurn] = Field(default_factory=list, max_length=12)
    output_token_budget: int = Field(default=800, ge=500, le=1200)
    analysis_mode: Literal["interactive", "deep"] = "interactive"


class AIExecutionResult(BaseModel):
    id: str
    run_id: str
    status: Literal["completed", "completed_with_limitations", "failed"]
    provider: str = "OpenClaw + Ollama"
    model: str
    prompt_version: str
    generated_at: str = Field(default_factory=utcnow_iso)
    analysis: Dict[str, Any] = Field(default_factory=dict)
    raw_text: Optional[str] = None
    evidence_validation: Dict[str, Any] = Field(default_factory=dict)
    agent_trace: List[Dict[str, Any]] = Field(default_factory=list)
    usage: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    service: str = "cyberdecisionengine-api"
    generated_at: str = Field(default_factory=utcnow_iso)
