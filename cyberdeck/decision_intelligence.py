from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from cyberdeck.schemas import EvidenceStatus, RunContext


ValueStatus = Literal[
    "valid_value",
    "observed_zero",
    "no_data",
    "insufficient_evidence",
    "source_unavailable",
    "not_applicable",
    "not_calculated",
    "stale_data",
    "partial_data",
    "error",
]

SNAPSHOT_VERSION = "1.4.0"


class DecisionMetric(BaseModel):
    metric_id: str
    label: str
    value: Optional[float] = None
    unit: str = "count"
    value_status: ValueStatus = "valid_value"
    numerator: Optional[float] = None
    denominator: Optional[float] = None
    period: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    definition: str = ""
    formula: str = ""
    evidence_ids: List[str] = Field(default_factory=list)


class SnapshotReportContext(BaseModel):
    run_id: str
    snapshot_version: str
    engine_version: str
    generated_at: str
    report_date: str
    language: str
    analysis_window: str
    lookback_hours: int
    organization_name: str
    subject_name: str
    subject_type: str = "organization"
    organization_identity_status: str
    group_name: Optional[str] = None
    group_validated: bool = False
    legal_entity_names: List[str] = Field(default_factory=list)
    commercial_names: List[str] = Field(default_factory=list)
    report_title: str
    report_subtitle: str
    report_type: str
    primary_country: str
    countries: List[str] = Field(default_factory=list)
    primary_domains: List[str]
    comparison_domains: List[str]
    sector: str
    subsector: str = ""
    country: str
    reporting_window: Dict[str, Any]
    comparison_window: Optional[Dict[str, Any]] = None
    confidentiality: str = "Confidential"
    tlp: str = "TLP:AMBER"
    owner: str = ""
    data_basis: str


class DomainDecisionRow(BaseModel):
    domain: str
    canonical_entity: str = ""
    ownership_status: str = "unknown"
    validation_status: str = "declared"
    first_seen: Optional[str] = None
    last_validated: Optional[str] = None
    source_coverage: Optional[float] = None
    raw_records: int = 0
    unique_records: int = 0
    related_evidence: int = 0
    record_count: int = 0
    direct_evidence_count: int = 0
    validated_evidence_count: int = 0
    validated_findings_count: int = 0
    supported_scenarios_count: int = 0
    validated_scenarios_count: int = 0
    materialized_scenarios_count: int = 0
    candidate_signals: int = 0
    max_residual_risk: Optional[float] = None
    risk_value_status: ValueStatus = "no_data"
    source_count: int = 0
    last_observed_at: Optional[str] = None
    top_signal: str = ""
    active_web_assets: int = 0
    observed_subdomains: int = 0
    mail_security_status: str = "not_calculated"
    applicable_vulnerabilities: int = 0
    open_actions: int = 0
    limitations: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)


class EvidenceReference(BaseModel):
    evidence_id: str
    record_type: str
    title: str
    relationship: str
    validation_status: str
    confidence: float
    domain: Optional[str] = None
    source: str = ""
    url: Optional[str] = None
    observed_at: Optional[str] = None


class ScenarioDecision(BaseModel):
    scenario_id: str
    title: str
    status: str
    framework: str
    domain: str
    rationale: str
    decision_question: str
    decision_possibility: str
    owner_role: str
    due_window: str
    success_measure: str
    confidence: float
    evidence_ids: List[str] = Field(default_factory=list)


class DecisionAction(BaseModel):
    decision_id: str
    status: str
    title: str
    question: str = ""
    recommendation: str = ""
    alternatives: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    linked_findings: List[str] = Field(default_factory=list)
    linked_scenarios: List[str] = Field(default_factory=list)
    linked_strategic_events: List[str] = Field(default_factory=list)
    rationale: str
    business_impact: str = ""
    urgency: str = ""
    owner_role: str
    due_window: str
    success_measure: str
    cost_level: str = "medium"
    effort_level: str = "medium"
    dependencies: List[str] = Field(default_factory=list)
    closure_evidence: List[str] = Field(default_factory=list)
    confidence: float
    evidence_ids: List[str] = Field(default_factory=list)


class StrategicDriver(BaseModel):
    driver_id: str
    title: str
    canonical_name: str = ""
    driver_type: str
    event_cluster_ids: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    business_dimension: str = ""
    relationship: str
    confidence: float
    magnitude: Optional[float] = None
    value_status: ValueStatus = "valid_value"
    source_count: int = 0
    source_quality: float = 0.0
    recency: float = 0.0
    direction: float = 0.0
    current_period_count: int = 0
    previous_period_count: int = 0
    delta: Optional[int] = None
    evidence_ids: List[str] = Field(default_factory=list)


class DecisionIntelligenceSnapshot(BaseModel):
    schema_version: str = "decision-intelligence-snapshot-v1.1"
    report_context: SnapshotReportContext
    analyzed_entities: List[Dict[str, Any]]
    analyzed_domains: List[str]
    validated_domains: List[str]
    collection_window: Dict[str, Any]
    comparison_window: Optional[Dict[str, Any]] = None
    previous_snapshot: Optional[Dict[str, Any]] = None
    source_health: Dict[str, Any]
    coverage: Dict[str, Any]
    validated_findings: List[Dict[str, Any]]
    pending_signals: List[Dict[str, Any]]
    metrics: Dict[str, DecisionMetric]
    domains: List[DomainDecisionRow]
    evidence_references: List[EvidenceReference]
    scenario_funnel: Dict[str, int]
    scenario_counts: Dict[str, int]
    supported_scenarios: List[ScenarioDecision]
    scenario_instances: List[ScenarioDecision]
    decisions: List[DecisionAction]
    decision_items: List[DecisionAction]
    action_plan: List[DecisionAction]
    risk_summary: Dict[str, Any]
    strategic_news: Dict[str, Any]
    pestel: Dict[str, Any]
    porter: Dict[str, Any]
    strategic_drivers: List[StrategicDriver]
    strategic_models: Dict[str, Any]
    chart_eligibility: Dict[str, Dict[str, Any]]
    limitations: List[str]
    metric_definitions: Dict[str, Dict[str, Any]]
    reference_integrity: Dict[str, Any]
    formula_versions: Dict[str, str]
    generated_at: str
    run_id: str
    engine_version: str
    snapshot_hash: str = ""


METRIC_CATALOG: Dict[str, Dict[str, Any]] = {
    "active_targets": {
        "label": "Objetivos en alcance",
        "definition": "Sujeto principal declarado y dominios primarios persistidos en la corrida.",
        "formula": "count(distinct declared_subject + primary_domains)",
        "unit": "targets",
    },
    "active_domains": {
        "label": "Dominios en alcance",
        "definition": "Dominios primarios persistidos en la corrida; no incluye comparativos.",
        "formula": "count(distinct primary_domains)",
        "unit": "domains",
    },
    "raw_records": {
        "label": "Registros brutos",
        "definition": "Registros recibidos antes de normalizacion y deduplicacion.",
        "formula": "processing_summary.raw_records_collected",
        "unit": "records",
    },
    "unique_records": {
        "label": "Registros unicos",
        "definition": "Registros restantes despues de normalizacion, descarte y deduplicacion.",
        "formula": "raw_records - duplicates_removed - discarded_records",
        "unit": "records",
    },
    "validated_evidence": {
        "label": "Evidencia validada",
        "definition": "Registros con relacion directa y validacion reproducible en la corrida.",
        "formula": "count(events where evidence_status in {validated, confirmed})",
        "unit": "evidence",
    },
    "direct_evidence": {
        "label": "Evidencia directa",
        "definition": "Registros relacionados directamente con el alcance, aun pendientes de validacion tecnica.",
        "formula": "count(events where evidence_status = direct)",
        "unit": "evidence",
    },
    "validated_findings": {
        "label": "Hallazgos validados",
        "definition": "Condiciones de riesgo con estado validado o confirmado.",
        "formula": "count(findings where evidence_status in {validated, confirmed})",
        "unit": "findings",
    },
    "confirmed_incidents": {
        "label": "Incidentes confirmados",
        "definition": "Hallazgos con evidencia de materializacion adversa confirmada.",
        "formula": "count(findings where incident_confirmed = true)",
        "unit": "incidents",
    },
    "healthy_sources": {
        "label": "Fuentes exitosas",
        "definition": "Conectores elegibles que fueron consultados y finalizaron correctamente.",
        "formula": "count(source_statuses where succeeded = true)",
        "unit": "sources",
    },
    "queried_sources": {
        "label": "Fuentes consultadas",
        "definition": "Conectores elegibles que intentaron una consulta, con exito, resultado parcial o fallo.",
        "formula": "count(source_statuses where attempted = true)",
        "unit": "sources",
    },
    "total_sources": {
        "label": "Fuentes elegibles",
        "definition": "Conectores habilitados, configurados y aplicables al alcance de la corrida.",
        "formula": "count(source_statuses where eligible = true)",
        "unit": "sources",
    },
    "productive_sources": {
        "label": "Fuentes productivas",
        "definition": "Conectores consultados que aportaron al menos un registro normalizado aceptado.",
        "formula": "count(source_statuses where productive = true)",
        "unit": "sources",
    },
    "registered_sources": {
        "label": "Fuentes registradas",
        "definition": "Conectores presentes en el catalogo de la corrida, sin afirmar que fueron elegibles o consultados.",
        "formula": "count(source_statuses where registered = true)",
        "unit": "sources",
    },
    "max_residual_risk": {
        "label": "Riesgo residual maximo",
        "definition": "Mayor riesgo residual entre hallazgos validados; no se calcula sin hallazgos.",
        "formula": "max(validated_findings.residual_risk)",
        "unit": "risk_points",
    },
    "avg_residual_risk": {
        "label": "Riesgo residual promedio",
        "definition": "Promedio de riesgo residual entre hallazgos validados; no se calcula sin hallazgos.",
        "formula": "sum(validated_findings.residual_risk) / count(validated_findings)",
        "unit": "risk_points",
    },
    "supported_scenarios": {
        "label": "Escenarios soportados",
        "definition": "Escenarios deduplicados con evidencia directa o hallazgo validado en esta corrida.",
        "formula": "count(distinct supported_scenario_id)",
        "unit": "scenarios",
    },
    "pending_decisions": {
        "label": "Decisiones pendientes",
        "definition": "Decisiones trazables que requieren actuar, validar o monitorear y que incluyen responsable y criterio de cierre.",
        "formula": "count(decision_items where status in {act_now, validate_first, monitor})",
        "unit": "decisions",
    },
}

for _metric_id, _definition in METRIC_CATALOG.items():
    _definition.setdefault("numerator", _definition["formula"])
    _definition.setdefault("denominator", "not_applicable")
    _definition.setdefault("range", "0..n")
    _definition.setdefault("source", "DecisionIntelligenceSnapshot")
    _definition.setdefault("update", "once per completed analysis run")
    _definition.setdefault("missing_data_status", "no_data")
    _definition.setdefault("dashboards", ["strategic_dashboard"])
    _definition.setdefault("reports", ["executive", "technical", "json", "csv"])

METRIC_CATALOG["healthy_sources"].update({"numerator": "count(succeeded=true)", "denominator": "count(eligible=true)", "range": "0..eligible_sources"})
METRIC_CATALOG["queried_sources"].update({"numerator": "count(attempted=true)", "denominator": "count(eligible=true)", "range": "0..eligible_sources"})
METRIC_CATALOG["productive_sources"].update({"numerator": "count(productive=true)", "denominator": "count(attempted=true)", "range": "0..attempted_sources"})
METRIC_CATALOG["max_residual_risk"].update({"range": "0..100", "missing_data_status": "no_data"})
METRIC_CATALOG["avg_residual_risk"].update({"range": "0..100", "missing_data_status": "no_data"})


def build_decision_snapshot(context: RunContext, run_id: str = "") -> DecisionIntelligenceSnapshot:
    domains = _dedupe(context.organization.primary_domains)
    subject_type = context.organization.entity_type if context.organization.entity_type in {"organization", "person"} else "organization"
    has_named_subject = bool(
        context.organization.name.strip()
        and not context.organization.name.lower().startswith("domain intelligence:")
    )
    findings = [
        item
        for item in context.risk_findings
        if item.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    evidence_refs, finding_reference_ids, event_reference_ids = _build_references(context, domains, findings)
    scenarios = _build_supported_scenarios(
        findings,
        domains,
        finding_reference_ids,
        context.organization.name if has_named_subject else "scope",
    )
    domain_rows = _build_domain_rows(
        context,
        domains,
        findings,
        scenarios,
        finding_reference_ids,
        event_reference_ids,
    )
    decisions = _build_decisions(scenarios)
    metrics = _build_metrics(context, domains, findings, scenarios, decisions)
    decision_evidence_ids = sorted({evidence_id for row in [*scenarios, *decisions] for evidence_id in row.evidence_ids})
    for metric_id in {"validated_findings", "max_residual_risk", "avg_residual_risk", "supported_scenarios", "pending_decisions"}:
        metrics[metric_id].evidence_ids = decision_evidence_ids
    strategic_drivers = _build_strategic_drivers(context, evidence_refs)
    strategic_models = _strategic_models(context)
    charts = _chart_eligibility(context, findings, strategic_drivers)
    limitations = _limitations(context, charts, findings)
    referenced_ids = {
        evidence_id
        for row in [*domain_rows, *scenarios, *decisions, *strategic_drivers]
        for evidence_id in row.evidence_ids
    }
    known_ids = {row.evidence_id for row in evidence_refs}
    integrity = {
        "reference_count": len(known_ids),
        "claim_reference_count": len(referenced_ids),
        "orphan_reference_ids": sorted(referenced_ids - known_ids),
        "unreferenced_evidence_ids": sorted(known_ids - referenced_ids),
        "orphan_claims": 0 if all(row.evidence_ids for row in decisions) else sum(1 for row in decisions if not row.evidence_ids),
        "orphan_references": len(known_ids - referenced_ids),
        "invalid_reference_ids": len(referenced_ids - known_ids),
        "unsupported_executive_claims": 0 if all(row.evidence_ids for row in decisions) else sum(1 for row in decisions if not row.evidence_ids),
        "status": "pass" if referenced_ids <= known_ids else "fail",
    }
    display_dt = _parse_datetime(context.report_display_at or context.generated_at)
    window_start = display_dt - timedelta(hours=context.lookback_hours)
    subject_validated = bool(
        context.organization.authorized_scope
        and has_named_subject
    )
    group_validated = subject_validated and subject_type == "organization"
    report_date = display_dt.date().isoformat()
    language = "en" if context.organization.language.lower().startswith("en") else "es"
    if language == "en" and subject_type == "person" and subject_validated:
        report_title = f"Authorized digital intelligence report — {context.organization.name}"
        report_subtitle = f"Person scope · {window_start.date().isoformat()} to {display_dt.date().isoformat()}"
    elif language == "en":
        report_title = (
            f"Strategic cyber intelligence report — {context.organization.name}"
            if group_validated
            else "Strategic multi-domain cyber intelligence report"
        )
        report_subtitle = (
            f"{len(domains)} analysed domains · {window_start.date().isoformat()} to {display_dt.date().isoformat()}"
            if group_validated and domains
            else f"Declared organization scope · {window_start.date().isoformat()} to {display_dt.date().isoformat()}"
            if group_validated
            else _multi_domain_subtitle(domains, language="en")
        )
    elif subject_type == "person" and subject_validated:
        report_title = f"Informe autorizado de inteligencia digital — {context.organization.name}"
        report_subtitle = f"Alcance de persona · {window_start.date().isoformat()} a {display_dt.date().isoformat()}"
    else:
        report_title = (
            f"Informe estratégico de ciberinteligencia — {context.organization.name}"
            if group_validated
            else "Informe estratégico multidominio"
        )
        report_subtitle = (
            f"{len(domains)} dominios analizados · {window_start.date().isoformat()} a {display_dt.date().isoformat()}"
            if group_validated and domains
            else f"Alcance de organización declarado · {window_start.date().isoformat()} a {display_dt.date().isoformat()}"
            if group_validated
            else _multi_domain_subtitle(domains, language="es")
        )
    countries = _dedupe([context.organization.country, *context.organization.countries_of_operation])
    legal_names = _dedupe([context.organization.legal_name or "", *context.organization.subsidiaries])
    commercial_names = _dedupe([*context.organization.brands, *context.organization.products])
    reporting_window = {
        "start": window_start.isoformat(),
        "end": display_dt.isoformat(),
        "hours": context.lookback_hours,
        "label": context.analysis_window,
    }
    report_context = SnapshotReportContext(
        run_id=run_id,
        snapshot_version=SNAPSHOT_VERSION,
        engine_version="evidence-pipeline-v3",
        generated_at=context.generated_at,
        report_date=report_date,
        language=language,
        analysis_window=context.analysis_window,
        lookback_hours=context.lookback_hours,
        organization_name=context.organization.name,
        subject_name=context.organization.name,
        subject_type=subject_type,
        organization_identity_status="owner_validated" if subject_validated else "declared_scope",
        group_name=context.organization.name if group_validated else None,
        group_validated=group_validated,
        legal_entity_names=legal_names,
        commercial_names=commercial_names,
        report_title=report_title,
        report_subtitle=report_subtitle,
        report_type="executive_and_technical",
        primary_country=countries[0] if countries else context.organization.country,
        countries=countries,
        primary_domains=domains,
        comparison_domains=_dedupe(context.organization.comparison_domains),
        sector=context.organization.sector,
        subsector=context.organization.subsector or "",
        country=context.organization.country,
        reporting_window=reporting_window,
        comparison_window=None,
        owner=context.organization.author,
        data_basis="current_run_persisted_evidence",
    )
    funnel = {
        "reference_templates": _scenario_reference_template_count(),
        "defined": 0,
        "executable": 0,
        "tested": 0,
        "applicable": len(scenarios),
        "preventive": 0,
        "candidate": len(scenarios),
        "supported": len(scenarios),
        "validated": sum(1 for row in scenarios if row.status == "validated"),
        "materialized": sum(1 for row in scenarios if row.status == "confirmed"),
        "confirmed": sum(1 for row in scenarios if row.status == "confirmed"),
        "discarded": 0,
    }
    validated_domains = [row.domain for row in domain_rows if row.validated_findings_count or row.validated_evidence_count]
    validated_findings = [
        {
            "finding_id": finding.finding_id or f"F-{index + 1:03d}",
            "title": finding.title,
            "category": finding.category,
            "residual_risk": finding.residual_risk,
            "evidence_status": finding.evidence_status.value,
            "confidence": finding.confidence_score,
            "domain": _matching_domain(" ".join([finding.title, *finding.evidence]), domains),
            "evidence_ids": finding_reference_ids.get(index, []),
        }
        for index, finding in enumerate(findings)
    ]
    pending_signals = [
        {
            "signal_id": event.id,
            "title": event.title,
            "domain": _matching_domain(_event_text(event), domains),
            "status": event.evidence_status.value,
            "confidence": event.confidence_score,
            "evidence_ids": [event_reference_ids[event.id]] if event.id in event_reference_ids else [],
        }
        for event in context.raw_events
        if event.evidence_status == EvidenceStatus.DIRECT
    ]
    source_health = {
        "healthy": int(metrics["healthy_sources"].value or 0),
        "queried": int(metrics["queried_sources"].value or 0),
        "total": int(metrics["total_sources"].value or 0),
        "value_status": "partial_data" if int(metrics["healthy_sources"].value or 0) < int(metrics["total_sources"].value or 0) else "valid_value",
        "definition": METRIC_CATALOG["healthy_sources"]["definition"],
    }
    risk_summary = {
        "max_residual_risk": metrics["max_residual_risk"].model_dump(mode="json"),
        "avg_residual_risk": metrics["avg_residual_risk"].model_dump(mode="json"),
        "validated_findings": len(findings),
        "domains_with_findings": len({row.domain for row in domain_rows if row.validated_findings_count}),
        "confirmed_incidents": int(metrics["confirmed_incidents"].value or 0),
    }
    strategic_news = context.metrics.get("strategic_news", {}) or {}
    snapshot = DecisionIntelligenceSnapshot(
        report_context=report_context,
        analyzed_entities=[
            {
                "entity_id": "PER-001" if subject_type == "person" else "ORG-001",
                "canonical_name": context.organization.name,
                "entity_type": "person" if subject_type == "person" else "organization" if group_validated else "declared_scope",
                "validation_status": "owner_validated" if subject_validated else "declared",
                "aliases": context.organization.subject_aliases,
                "domains": domains,
            }
        ],
        analyzed_domains=domains,
        validated_domains=validated_domains,
        collection_window=reporting_window,
        comparison_window=None,
        previous_snapshot=None,
        source_health=source_health,
        coverage=context.connector_coverage or context.metrics.get("source_coverage", {}) or {},
        validated_findings=validated_findings,
        pending_signals=pending_signals,
        metrics=metrics,
        domains=domain_rows,
        evidence_references=evidence_refs,
        scenario_funnel=funnel,
        scenario_counts=funnel,
        supported_scenarios=scenarios,
        scenario_instances=scenarios,
        decisions=decisions,
        decision_items=decisions,
        action_plan=decisions,
        risk_summary=risk_summary,
        strategic_news=strategic_news,
        pestel=strategic_models["pestel"],
        porter=strategic_models["porter"],
        strategic_drivers=strategic_drivers,
        strategic_models=strategic_models,
        chart_eligibility=charts,
        limitations=limitations,
        metric_definitions=METRIC_CATALOG,
        reference_integrity=integrity,
        formula_versions={
            "evidence_assurance": "1.0.0",
            "residual_risk": "2.0.0",
            "scenario_deduplication": "1.0.0",
            "strategic_news": str(
                (context.metrics.get("strategic_news") or {}).get("registry_versions", {}).get("model")
                or (context.metrics.get("strategic_news") or {}).get("version")
                or "unversioned"
            ),
        },
        generated_at=context.generated_at,
        run_id=run_id,
        engine_version="evidence-pipeline-v3",
    )
    canonical = snapshot.model_dump_json(exclude={"snapshot_hash"})
    snapshot.snapshot_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return snapshot


def snapshot_from_context(context: RunContext, run_id: str = "") -> DecisionIntelligenceSnapshot:
    existing = context.decision_snapshot or {}
    if (
        existing
        and existing.get("report_context", {}).get("snapshot_version") == SNAPSHOT_VERSION
        and (not run_id or existing.get("report_context", {}).get("run_id") == run_id)
    ):
        try:
            return DecisionIntelligenceSnapshot(**existing)
        except Exception:
            pass
    return build_decision_snapshot(context, run_id)


def _build_metrics(
    context: RunContext,
    domains: List[str],
    findings: List[Any],
    scenarios: List[ScenarioDecision],
    decisions: List[DecisionAction],
) -> Dict[str, DecisionMetric]:
    processing = context.processing_summary or {}
    statuses = context.source_statuses
    residuals = [float(row.residual_risk) for row in findings]
    validated_events = [
        row
        for row in context.raw_events
        if row.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    direct_events = [row for row in context.raw_events if row.evidence_status == EvidenceStatus.DIRECT]
    values: Dict[str, Optional[float]] = {
        "active_targets": float(len(domains) + (1 if context.organization.name and not context.organization.name.lower().startswith("domain intelligence:") else 0)),
        "active_domains": float(len(domains)),
        "raw_records": float(processing.get("raw_records_collected", len(context.raw_events))),
        "unique_records": float(processing.get("unique_records", len(context.raw_events))),
        "validated_evidence": float(len(validated_events)),
        "direct_evidence": float(len(direct_events)),
        "validated_findings": float(len(findings)),
        "confirmed_incidents": float(sum(1 for row in findings if row.incident_confirmed)),
        "healthy_sources": float(sum(1 for row in statuses if row.succeeded)),
        "queried_sources": float(sum(1 for row in statuses if row.attempted)),
        "total_sources": float(sum(1 for row in statuses if row.eligible)),
        "productive_sources": float(sum(1 for row in statuses if row.productive)),
        "registered_sources": float(len(statuses)),
        "max_residual_risk": max(residuals) if residuals else None,
        "avg_residual_risk": sum(residuals) / len(residuals) if residuals else None,
        "supported_scenarios": float(len(scenarios)),
        "pending_decisions": float(len(decisions)),
    }
    metrics: Dict[str, DecisionMetric] = {}
    period = context.analysis_window
    for metric_id, value in values.items():
        config = METRIC_CATALOG[metric_id]
        if value is None:
            status: ValueStatus = "no_data"
        elif value == 0:
            status = "observed_zero"
        else:
            status = "valid_value"
        denominator = None
        numerator = None
        if metric_id in {"healthy_sources", "queried_sources"}:
            numerator = value
            denominator = values["total_sources"]
        elif metric_id == "productive_sources":
            numerator = value
            denominator = values["queried_sources"]
        metrics[metric_id] = DecisionMetric(
            metric_id=metric_id,
            label=config["label"],
            value=round(value, 4) if value is not None else None,
            unit=config["unit"],
            value_status=status,
            numerator=numerator,
            denominator=denominator,
            period=period,
            confidence=1.0 if metric_id not in {"max_residual_risk", "avg_residual_risk"} else (0.5 if findings else 0.0),
            definition=config["definition"],
            formula=config["formula"],
        )
    return metrics


def _build_references(
    context: RunContext,
    domains: List[str],
    findings: List[Any],
) -> tuple[List[EvidenceReference], Dict[int, List[str]], Dict[str, str]]:
    refs: List[EvidenceReference] = []
    finding_ids: Dict[int, List[str]] = {}
    event_ids: Dict[str, str] = {}
    for index, finding in enumerate(findings, 1):
        evidence_id = f"E-F{index:03d}"
        domain = _matching_domain(" ".join([finding.title, *finding.evidence]), domains)
        refs.append(
            EvidenceReference(
                evidence_id=evidence_id,
                record_type="validated_finding",
                title=finding.title,
                relationship="direct",
                validation_status=str(finding.evidence_status.value),
                confidence=float(finding.confidence_score),
                domain=domain,
                source="validated_finding",
                url=_first_url(finding.evidence),
            )
        )
        finding_ids[index - 1] = [evidence_id]
    for event in context.raw_events:
        if event.evidence_status not in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}:
            continue
        evidence_id = f"E-R{len(event_ids) + 1:03d}"
        domain = _matching_domain(_event_text(event), domains)
        refs.append(
            EvidenceReference(
                evidence_id=evidence_id,
                record_type="evidence_record",
                title=event.title,
                relationship=event.relationship_to_scope,
                validation_status=event.evidence_status.value,
                confidence=float(event.confidence_score),
                domain=domain,
                source=event.source,
                url=event.evidence_url,
                observed_at=event.observed_at,
            )
        )
        event_ids[event.id] = evidence_id
    return refs, finding_ids, event_ids


def _build_supported_scenarios(
    findings: List[Any],
    domains: List[str],
    finding_reference_ids: Dict[int, List[str]],
    default_entity: str = "scope",
) -> List[ScenarioDecision]:
    email_groups: Dict[str, Dict[str, Any]] = {}
    scenarios: List[ScenarioDecision] = []
    for index, finding in enumerate(findings):
        text = " ".join([finding.title, finding.category, *finding.evidence]).lower()
        domain = _matching_domain(text, domains) or default_entity
        if re.search(r"\b(?:spf|dmarc|dkim)\b", text):
            group = email_groups.setdefault(domain, {"evidence_ids": [], "confidence": [], "controls": set()})
            group["evidence_ids"].extend(finding_reference_ids.get(index, []))
            group["confidence"].append(float(finding.confidence_score))
            for control in ("SPF", "DMARC", "DKIM"):
                if control.lower() in text:
                    group["controls"].add(control)
            continue
        scenarios.append(
            ScenarioDecision(
                scenario_id=f"SCN-{len(scenarios) + 1:03d}",
                title=finding.title,
                status="supported",
                framework="Risk evidence",
                domain=domain,
                rationale="Hallazgo validado persistido en la corrida; requiere verificacion de tratamiento antes de elevarlo a incidente.",
                decision_question="¿Se requiere corregir, aceptar o monitorear esta condicion validada?",
                decision_possibility="Validar criticidad con el propietario del activo y definir tratamiento con evidencia de cierre.",
                owner_role=finding.owner or "Responsable del activo",
                due_window="15 dias",
                success_measure="Hallazgo cerrado, aceptado formalmente o monitoreado con evidencia reproducible.",
                confidence=float(finding.confidence_score),
                evidence_ids=finding_reference_ids.get(index, []),
            )
        )
    for domain, group in sorted(email_groups.items()):
        controls = ", ".join(sorted(group["controls"])) or "autenticacion de correo"
        scenarios.append(
            ScenarioDecision(
                scenario_id=f"SCN-{len(scenarios) + 1:03d}",
                title=f"Exposicion de autenticacion de correo en {domain}",
                status="supported",
                framework="NIST CSF / CIS Controls",
                domain=domain,
                rationale=f"Se agrupan en un unico escenario los hallazgos validados de {controls}; no se duplican por control.",
                decision_question="¿La configuracion de autenticacion de correo reduce de forma suficiente el riesgo de suplantacion?",
                decision_possibility="Verificar la politica publicada, corregir la configuracion y repetir la consulta DNS como evidencia de cierre.",
                owner_role="Responsable de seguridad de correo y DNS",
                due_window="15 dias",
                success_measure="SPF/DMARC/DKIM aplicables publicados y validados, o excepcion documentada.",
                confidence=round(sum(group["confidence"]) / max(1, len(group["confidence"])), 3),
                evidence_ids=_dedupe(group["evidence_ids"]),
            )
        )
    return scenarios


def _build_decisions(scenarios: List[ScenarioDecision]) -> List[DecisionAction]:
    decisions: List[DecisionAction] = []
    for scenario in scenarios:
        status = "act_now" if scenario.confidence >= 0.65 else "validate_first"
        decisions.append(
            DecisionAction(
                decision_id=f"DEC-{len(decisions) + 1:03d}",
                status=status,
                title=scenario.title,
                question=scenario.decision_question,
                recommendation=scenario.decision_possibility,
                alternatives=[
                    "Corregir y validar",
                    "Aceptar temporalmente con monitoreo y fecha de revision",
                    "Solicitar evidencia adicional antes de decidir",
                ],
                affected_entities=[scenario.domain],
                linked_findings=scenario.evidence_ids,
                linked_scenarios=[scenario.scenario_id],
                rationale=scenario.rationale,
                business_impact="Reduce la posibilidad de suplantacion y mejora la trazabilidad del control externo." if "correo" in scenario.title.lower() else "Reduce una condicion de riesgo externo validada.",
                urgency="validate_first" if status == "validate_first" else "immediate",
                owner_role=scenario.owner_role,
                due_window=scenario.due_window,
                success_measure=scenario.success_measure,
                dependencies=["Acceso autorizado a la configuracion del activo", "Propietario tecnico identificado"],
                closure_evidence=[scenario.success_measure],
                confidence=scenario.confidence,
                evidence_ids=scenario.evidence_ids,
            )
        )
    return decisions


def _build_domain_rows(
    context: RunContext,
    domains: List[str],
    findings: List[Any],
    scenarios: List[ScenarioDecision],
    finding_reference_ids: Dict[int, List[str]],
    event_reference_ids: Dict[str, str],
) -> List[DomainDecisionRow]:
    rows: List[DomainDecisionRow] = []
    for domain in domains:
        events = [row for row in context.raw_events if _matching_domain(_event_text(row), [domain])]
        direct = [row for row in events if row.evidence_status == EvidenceStatus.DIRECT]
        validated = [
            row
            for row in events
            if row.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        ]
        domain_findings = [
            (index, row)
            for index, row in enumerate(findings)
            if _matching_domain(" ".join([row.title, *row.evidence]), [domain])
        ]
        residuals = [float(row.residual_risk) for _, row in domain_findings]
        related = [row for row in events if row.evidence_status == EvidenceStatus.RELATED]
        subdomains = {
            (row.host or urlparse(row.evidence_url or "").hostname or "").lower()
            for row in events
            if (row.host or urlparse(row.evidence_url or "").hostname or "").lower().endswith(f".{domain}")
        }
        active_assets = {
            row.host or row.asset or urlparse(row.evidence_url or "").hostname
            for row in events
            if row.category.startswith("attack_surface") and (row.host or row.asset or row.evidence_url)
        }
        applicable_vulnerabilities = sum(
            1
            for row in events
            if row.vulnerability_status in {"cve_applicable", "cve_confirmed", "kev_exposed", "exploitation_observed"}
        )
        evidence_ids = [event_reference_ids[row.id] for row in events if row.id in event_reference_ids]
        for index, _ in domain_findings:
            evidence_ids.extend(finding_reference_ids.get(index, []))
        top_event = max(events, key=lambda row: (row.confidence_score, row.severity), default=None)
        rows.append(
            DomainDecisionRow(
                domain=domain,
                canonical_entity=context.organization.name,
                ownership_status="managed" if context.organization.authorized_scope else "unknown",
                validation_status="technically_validated" if domain_findings or validated else "declared",
                first_seen=min((row.observed_at for row in events), default=None),
                last_validated=max((row.observed_at for row in validated), default=context.generated_at if domain_findings else None),
                source_coverage=round(len({row.source for row in events}) / max(1, sum(1 for row in context.source_statuses if row.queried)), 4),
                raw_records=len(events),
                unique_records=len(events),
                related_evidence=len(related),
                record_count=len(events),
                direct_evidence_count=len(direct),
                validated_evidence_count=len(validated),
                validated_findings_count=len(domain_findings),
                supported_scenarios_count=sum(1 for row in scenarios if row.domain == domain),
                validated_scenarios_count=sum(1 for row in scenarios if row.domain == domain and row.status == "validated"),
                materialized_scenarios_count=sum(1 for row in scenarios if row.domain == domain and row.status == "confirmed"),
                candidate_signals=len(direct),
                max_residual_risk=round(max(residuals), 4) if residuals else None,
                risk_value_status="valid_value" if residuals else "no_data",
                source_count=len({row.source for row in events}),
                last_observed_at=max((row.observed_at for row in events), default=None),
                top_signal=top_event.title if top_event else "",
                active_web_assets=len({item for item in active_assets if item}),
                observed_subdomains=len({item for item in subdomains if item}),
                mail_security_status="control_gap_validated" if any(row.domain == domain and "correo" in row.title.lower() for row in scenarios) else "not_calculated",
                applicable_vulnerabilities=applicable_vulnerabilities,
                open_actions=sum(1 for row in scenarios if row.domain == domain),
                limitations=[] if events else ["Sin registros relacionados con el dominio en la ventana analizada."],
                evidence_ids=_dedupe(evidence_ids),
            )
        )
    return sorted(
        rows,
        key=lambda row: (
            row.max_residual_risk is not None,
            row.max_residual_risk or 0.0,
            row.validated_findings_count,
            row.supported_scenarios_count,
        ),
        reverse=True,
    )


def _build_strategic_drivers(context: RunContext, refs: List[EvidenceReference]) -> List[StrategicDriver]:
    strategic = context.metrics.get("strategic_news", {}) or {}
    reference_by_url = {row.url: row.evidence_id for row in refs if row.url}
    drivers: List[StrategicDriver] = []
    for cluster in strategic.get("clusters", []) or []:
        evidence_ids = [reference_by_url[url] for url in cluster.get("evidence_urls", []) if url in reference_by_url]
        drivers.append(
            StrategicDriver(
                driver_id=str(cluster.get("event_cluster_id") or f"DRV-{len(drivers) + 1:03d}"),
                title=str(cluster.get("canonical_event_name") or cluster.get("event_type") or "Strategic event"),
                canonical_name=str(cluster.get("canonical_event_name") or cluster.get("event_type") or "Strategic event"),
                driver_type=str(cluster.get("event_type") or "other"),
                event_cluster_ids=[str(cluster.get("event_cluster_id"))] if cluster.get("event_cluster_id") else [],
                affected_entities=list(cluster.get("entity_ids") or []),
                business_dimension=str(cluster.get("business_dimension") or cluster.get("event_type") or "other"),
                relationship=str(cluster.get("relationship") or "unassessed"),
                confidence=float(cluster.get("confidence", 0.0) or 0.0),
                magnitude=float(cluster.get("magnitude", 0.0) or 0.0),
                source_count=int(cluster.get("independent_source_count", 0) or 0),
                source_quality=float(cluster.get("source_quality", 0.0) or 0.0),
                recency=float(cluster.get("recency", 0.0) or 0.0),
                direction=float(cluster.get("direction", 0.0) or 0.0),
                current_period_count=int(cluster.get("article_count", 0) or 0),
                previous_period_count=int(cluster.get("previous_article_count", 0) or 0),
                delta=int(cluster.get("article_count", 0) or 0) - int(cluster.get("previous_article_count", 0) or 0),
                evidence_ids=evidence_ids,
            )
        )
    return drivers


def _strategic_models(context: RunContext) -> Dict[str, Any]:
    if context.organization.entity_type == "person":
        language = "en" if context.organization.language.lower().startswith("en") else "es"
        interpretation = (
            "This corporate strategy model does not apply to a person-only scope."
            if language == "en"
            else "Este modelo de estrategia corporativa no aplica a un alcance exclusivo de persona."
        )
        return {
            key: {
                "value": None,
                "value_status": "not_applicable",
                "confidence": 0.0,
                "coverage_ratio": 0.0,
                "cluster_count": 0,
                "dimensions": [],
                "interpretation": interpretation,
            }
            for key in ("pestel", "porter")
        }

    output: Dict[str, Any] = {}
    for key in ("pestel", "porter"):
        model = context.metrics.get(key, {}) or {}
        value_status = (
            "valid_value"
            if model.get("index") is not None
            else "evidence_available_unscored"
            if model.get("cluster_count", 0)
            else "insufficient_evidence"
        )
        output[key] = {
            "value": model.get("index"),
            "signalScore": model.get("signalScore", model.get("signal_score")),
            "validatedPressure": model.get("validatedPressure", model.get("index")),
            "value_status": value_status,
            "confidence": float(model.get("overall_confidence", 0.0) or 0.0),
            "coverage_ratio": float(model.get("coverage_ratio", 0.0) or 0.0),
            "evidence_coverage_ratio": float(model.get("evidence_coverage_ratio", 0.0) or 0.0),
            "assessment_status": model.get("assessment_status", "insufficient_evidence"),
            "cluster_count": int(model.get("cluster_count", 0) or 0),
            "dimensions": model.get("dimensions", []),
            "interpretation": model.get("interpretation", ""),
        }
    return output


def _chart_eligibility(context: RunContext, findings: List[Any], drivers: List[StrategicDriver]) -> Dict[str, Dict[str, Any]]:
    risk_categories = {row.category for row in findings}
    risk_eligible = len(risk_categories) >= 3 and len(findings) >= 3
    coverage = context.connector_coverage or context.metrics.get("source_coverage", {}) or {}
    common = {
        "period": context.analysis_window,
        "updated_at": context.generated_at,
        "coverage": {
            "coverage_score": coverage.get("coverage_score"),
            "source_health_score": coverage.get("source_health_score"),
            "source_completeness_score": coverage.get("source_completeness_score"),
        },
        "evidence_url": None,
    }
    pestel_model = context.metrics.get("pestel", {}) or {}
    porter_model = context.metrics.get("porter", {}) or {}

    def strategic_chart_state(model: Dict[str, Any]) -> tuple[bool, int]:
        evidence_ids = {
            evidence_id
            for dimension in model.get("dimensions", [])
            if dimension.get("signalScore") is not None
            for evidence_id in dimension.get("evidence_ids", [])
        }
        return bool(evidence_ids), len(evidence_ids)

    pestel_eligible, pestel_evidence_count = strategic_chart_state(pestel_model)
    porter_eligible, porter_evidence_count = strategic_chart_state(porter_model)
    return {
        "executive_risk_radar": {
            **common,
            "eligible": risk_eligible,
            "decision_question": "¿Existen al menos tres dimensiones de riesgo validadas y comparables?",
            "metric_definition": "Intensidad relativa por categoria calculada solo con hallazgos validados.",
            "sources": ["validated_findings"],
            "confidence": min(1.0, len(risk_categories) / 3),
            "value_status": "valid_value" if risk_eligible else "insufficient_evidence",
            "reason": "Requiere al menos tres categorias con hallazgos validados." if not risk_eligible else "Evidencia suficiente.",
            "evidence_count": len(findings),
        },
        "risk_heatmap": {
            **common,
            "eligible": risk_eligible,
            "decision_question": "¿Qué combinaciones de plausibilidad e impacto requieren priorizacion?",
            "metric_definition": "Distribucion de hallazgos validados en una matriz de plausibilidad e impacto.",
            "sources": ["validated_findings"],
            "confidence": min(1.0, len(risk_categories) / 3),
            "value_status": "valid_value" if risk_eligible else "insufficient_evidence",
            "reason": "No se dibuja calor con celdas sin evidencia validada." if not risk_eligible else "Evidencia suficiente.",
            "evidence_count": len(findings),
        },
        "pestel": {
            **common,
            "eligible": pestel_eligible,
            "decision_question": "¿Qué aspectos macroestrategicos respaldados por evidencia afectan el alcance?",
            "metric_definition": "Cobertura y presion contextual PESTEL derivadas de registros publicos corporativos, regulatorios, sectoriales y noticiosos relacionados y deduplicados.",
            "sources": ["strategic_evidence_clusters", "corporate_public_records", "regulatory_and_sector_sources", "news_sources"],
            "confidence": float(pestel_model.get("overall_confidence", 0.0) or 0.0) / 100,
            "value_status": "valid_value" if pestel_eligible else "insufficient_evidence",
            "reason": "Hay dimensiones con SignalScore y evidencia trazable; la presion validada puede permanecer N/D." if pestel_eligible else "Requiere evidencia estrategica relacionada y trazable.",
            "evidence_count": pestel_evidence_count,
        },
        "porter": {
            **common,
            "eligible": porter_eligible,
            "decision_question": "¿Qué aspectos competitivos respaldados por evidencia afectan el alcance?",
            "metric_definition": "Cobertura y presion contextual Porter derivadas de registros publicos corporativos, regulatorios, sectoriales y noticiosos relacionados y deduplicados.",
            "sources": ["strategic_evidence_clusters", "corporate_public_records", "regulatory_and_sector_sources", "news_sources"],
            "confidence": float(porter_model.get("overall_confidence", 0.0) or 0.0) / 100,
            "value_status": "valid_value" if porter_eligible else "insufficient_evidence",
            "reason": "Hay fuerzas con SignalScore y evidencia trazable; la presion validada puede permanecer N/D." if porter_eligible else "Requiere evidencia estrategica relacionada y trazable.",
            "evidence_count": porter_evidence_count,
        },
    }


def _limitations(context: RunContext, charts: Dict[str, Dict[str, Any]], findings: List[Any]) -> List[str]:
    limitations: List[str] = []
    if not findings:
        limitations.append("No hubo hallazgos validados; los valores de riesgo permanecen sin calcular.")
    if not charts["executive_risk_radar"]["eligible"]:
        limitations.append("El radar ejecutivo y el mapa de calor se omiten por cobertura insuficiente de categorias validadas.")
    strategic_states = {charts["pestel"]["value_status"], charts["porter"]["value_status"]}
    if "evidence_available_unscored" in strategic_states:
        limitations.append(
            "PESTEL y Porter muestran cobertura y aspectos respaldados; la presion agregada permanece N/D "
            "hasta cumplir corroboracion, diversidad y confianza minima."
        )
    elif "insufficient_evidence" in strategic_states:
        limitations.append(
            "PESTEL y Porter permanecen N/D cuando no existe evidencia estrategica relacionada, "
            "deduplicada y trazable."
        )
    failed = [row.name for row in context.source_statuses if row.failed or row.timed_out or row.rate_limited]
    if failed:
        limitations.append(f"Fuentes con limitacion tecnica: {', '.join(failed)}.")
    limitations.append("Los escenarios son posibilidades de decision soportadas por evidencia; no confirman un ataque ni sustituyen validacion interna.")
    return limitations


def _scenario_reference_template_count() -> int:
    try:
        from cyberdeck.settings import PROJECT_ROOT

        import json

        path = PROJECT_ROOT / "data" / "scenarios" / "cyber_scenario_library.json"
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8"))
            rows = payload.get("scenarios", payload if isinstance(payload, list) else [])
            return sum(1 for row in rows if row.get("status") == "preventive_template")
    except Exception:
        return 0
    return 0


def _event_text(event: Any) -> str:
    return " ".join(
        [
            event.title,
            event.category,
            event.source,
            event.evidence_url or "",
            event.asset or "",
            event.host or "",
            event.indicator or "",
            " ".join(event.tags or []),
        ]
    ).lower()


def _matching_domain(text: str, domains: List[str]) -> Optional[str]:
    lowered = text.lower()
    for domain in sorted(domains, key=len, reverse=True):
        if domain.lower() in lowered:
            return domain
    try:
        host = (urlparse(text).hostname or "").lower()
        for domain in domains:
            if host == domain or host.endswith(f".{domain}"):
                return domain
    except ValueError:
        pass
    return None


def _first_url(values: List[str]) -> Optional[str]:
    for value in values:
        match = re.search(r"https?://[^\s<>'\"]+", value)
        if match:
            return match.group(0).rstrip(".,);]")
    return None


def _dedupe(values: List[str]) -> List[str]:
    output: List[str] = []
    seen = set()
    for value in values:
        cleaned = str(value).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return output


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _multi_domain_subtitle(domains: List[str], *, language: str = "es") -> str:
    if not domains:
        return "No domains persisted in scope" if language == "en" else "Sin dominios persistidos en el alcance"
    visible = domains[:3]
    remainder = max(0, len(domains) - len(visible))
    suffix = (
        f" and {remainder} additional domains"
        if language == "en" and remainder
        else f" y {remainder} dominios adicionales"
        if remainder
        else ""
    )
    return f"{', '.join(visible)}{suffix}"
