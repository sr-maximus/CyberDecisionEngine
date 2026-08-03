from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from cyberdeck_api.models import RunRecord


@dataclass(frozen=True)
class AgentSpec:
    agent_id: str
    label_es: str
    label_en: str
    purpose: str
    scopes: tuple[str, ...]
    metric_keys: tuple[str, ...]


AGENT_REGISTRY: dict[str, AgentSpec] = {
    "CollectionQualityAgent": AgentSpec(
        agent_id="CollectionQualityAgent",
        label_es="Calidad de recolección",
        label_en="Collection quality",
        purpose="Measure source lifecycle, coverage and collection gaps without treating volume as evidence.",
        scopes=("overview", "evidence", "osint", "socmint", "darkweb"),
        metric_keys=("source_coverage", "evidence_summary"),
    ),
    "SourceReliabilityAgent": AgentSpec(
        agent_id="SourceReliabilityAgent",
        label_es="Confiabilidad de fuentes",
        label_en="Source reliability",
        purpose="Separate attempted, successful, productive, empty and failed sources.",
        scopes=("evidence", "osint", "socmint", "darkweb"),
        metric_keys=("source_coverage",),
    ),
    "StrategicEvidenceAgent": AgentSpec(
        agent_id="StrategicEvidenceAgent",
        label_es="Evidencia estratégica",
        label_en="Strategic evidence",
        purpose="Identify which statements are supported by validated evidence and which remain contextual.",
        scopes=("overview", "evidence", "geography"),
        metric_keys=("evidence_summary", "geographic_intelligence", "strategic_news"),
    ),
    "CyberCausalAnalysisAgent": AgentSpec(
        agent_id="CyberCausalAnalysisAgent",
        label_es="Relaciones y causalidad",
        label_en="Relations and causality",
        purpose="Review traceable relations among assets, technologies, threats and control families.",
        scopes=("frameworks", "attack_surface", "vulnerabilities"),
        metric_keys=(
            "framework_mapping",
            "control_assessment",
            "vulnerability_intelligence",
            "public_entity_intelligence",
        ),
    ),
    "NarrativeIntelligenceAgent": AgentSpec(
        agent_id="NarrativeIntelligenceAgent",
        label_es="Narrativas y señales sociales",
        label_en="Narratives and social signals",
        purpose="Review public narratives, brand signals and social records without inferring intent from mentions alone.",
        scopes=("socmint", "brand_fraud", "disinformation"),
        metric_keys=("narrative_intelligence", "fraud_pressure", "f3"),
    ),
    "FactCheckContradictionAgent": AgentSpec(
        agent_id="FactCheckContradictionAgent",
        label_es="Contradicciones y falsos positivos",
        label_en="Contradictions and false positives",
        purpose="Surface contradictions, validation gaps and false-positive risk.",
        scopes=("evidence", "disinformation", "brand_fraud"),
        metric_keys=("narrative_intelligence", "evidence_summary", "f3"),
    ),
    "ScenarioBuilderAgent": AgentSpec(
        agent_id="ScenarioBuilderAgent",
        label_es="Escenarios",
        label_en="Scenarios",
        purpose="Match evidence-supported scenarios and keep candidate scenarios separate from validated ones.",
        scopes=("scenarios", "risk", "frameworks"),
        metric_keys=(
            "scenario_matches",
            "layered_scenario_risk",
            "forecast",
            "prospective_attack_risk",
            "framework_mapping",
        ),
    ),
    "RiskExplanationAgent": AgentSpec(
        agent_id="RiskExplanationAgent",
        label_es="Riesgo y presión prospectiva",
        label_en="Risk and prospective pressure",
        purpose="Explain risk, confidence and prospective signal pressure without presenting uncalibrated values as probability.",
        scopes=("risk", "attack_surface", "vulnerabilities"),
        metric_keys=(
            "risk_heat_radar",
            "forecast",
            "prospective_attack_risk",
            "vulnerability_intelligence",
            "control_assessment",
        ),
    ),
    "ExecutiveBriefAgent": AgentSpec(
        agent_id="ExecutiveBriefAgent",
        label_es="Síntesis ejecutiva",
        label_en="Executive brief",
        purpose="Translate supported results into concise decision context.",
        scopes=("overview",),
        metric_keys=("pestel", "porter", "prospective_attack_risk", "strategic_news"),
    ),
    "ReportReviewAgent": AgentSpec(
        agent_id="ReportReviewAgent",
        label_es="Control de consistencia",
        label_en="Consistency review",
        purpose="Check that conclusions, evidence, limitations and decision options remain aligned.",
        scopes=("overview", "evidence", "risk", "scenarios"),
        metric_keys=(),
    ),
}


SCOPE_AGENT_ORDER: dict[str, tuple[str, ...]] = {
    "overview": ("ExecutiveBriefAgent", "StrategicEvidenceAgent"),
    "evidence": ("StrategicEvidenceAgent", "SourceReliabilityAgent"),
    "risk": ("RiskExplanationAgent", "ScenarioBuilderAgent"),
    "scenarios": ("ScenarioBuilderAgent", "RiskExplanationAgent"),
    "frameworks": ("CyberCausalAnalysisAgent", "ScenarioBuilderAgent"),
    "osint": ("CollectionQualityAgent", "SourceReliabilityAgent"),
    "socmint": ("NarrativeIntelligenceAgent", "SourceReliabilityAgent"),
    "darkweb": ("SourceReliabilityAgent", "StrategicEvidenceAgent"),
    "attack_surface": ("CyberCausalAnalysisAgent", "RiskExplanationAgent"),
    "brand_fraud": ("NarrativeIntelligenceAgent", "FactCheckContradictionAgent"),
    "disinformation": ("FactCheckContradictionAgent", "NarrativeIntelligenceAgent"),
    "geography": ("StrategicEvidenceAgent",),
    "vulnerabilities": ("RiskExplanationAgent", "CyberCausalAnalysisAgent"),
}


def plan_agent_specs(
    scopes: Iterable[str],
    *,
    audience: str = "executive",
    deep: bool = False,
) -> list[AgentSpec]:
    ordered_ids: list[str] = []
    secondary_ids: list[str] = []
    for scope in scopes:
        candidates = SCOPE_AGENT_ORDER.get(scope, ("StrategicEvidenceAgent",))
        _append_once(ordered_ids, candidates[0])
        for agent_id in candidates[1:]:
            _append_once(secondary_ids, agent_id)
    for agent_id in secondary_ids:
        _append_once(ordered_ids, agent_id)

    if audience in {"technical", "incident", "fraud"}:
        _append_once(ordered_ids, "FactCheckContradictionAgent")
    if deep:
        for agent_id in (
            "CollectionQualityAgent",
            "StrategicEvidenceAgent",
            "CyberCausalAnalysisAgent",
            "RiskExplanationAgent",
            "ScenarioBuilderAgent",
            "ReportReviewAgent",
        ):
            _append_once(ordered_ids, agent_id)

    limit = 6 if deep else 3
    return [AGENT_REGISTRY[agent_id] for agent_id in ordered_ids[:limit]] or [
        AGENT_REGISTRY["StrategicEvidenceAgent"]
    ]


def build_agent_briefs(
    run: RunRecord,
    scopes: Iterable[str],
    *,
    audience: str = "executive",
    deep: bool = False,
) -> list[dict[str, Any]]:
    scope_list = list(dict.fromkeys(scopes)) or ["overview"]
    specs = plan_agent_specs(scope_list, audience=audience, deep=deep)
    lifecycle = _source_lifecycle(run)
    findings = run.summary.findings
    events = run.summary.events
    briefs: list[dict[str, Any]] = []

    for spec in specs:
        selected_scopes = [scope for scope in scope_list if scope in spec.scopes]
        metrics = {
            key: _metric_digest(run.summary.metrics.get(key), row_limit=4 if deep else 2)
            for key in spec.metric_keys
            if run.summary.metrics.get(key) is not None
        }
        selected_findings = [
            _compact_finding(item)
            for item in findings
            if _record_matches_scopes(item, selected_scopes or scope_list)
        ][: 2 if deep else 1]
        selected_events = [
            _compact_event(item)
            for item in events
            if _record_matches_scopes(item, selected_scopes or scope_list)
        ][: 3 if deep else 2]
        evidence_refs = sorted(
            {
                ref
                for item in [*selected_findings, *selected_events]
                for ref in _evidence_refs(item)
            }
        )[:12]
        limitations: list[str] = []
        if not selected_findings and not selected_events and not metrics:
            limitations.append("No scoped data was available for this specialist.")
        if int(run.summary.kpis.validated_findings or 0) == 0:
            limitations.append("No validated findings are available; collected records remain context.")

        briefs.append(
            {
                "agent_id": spec.agent_id,
                "label": spec.label_es if run.request.language == "es" else spec.label_en,
                "purpose": spec.purpose,
                "execution_mode": "deterministic_specialist_reducer",
                "status": "limited" if limitations else "completed",
                "scopes": selected_scopes or scope_list,
                "authoritative_facts": _agent_facts(spec.agent_id, run, lifecycle),
                "metrics": metrics,
                "top_findings": selected_findings,
                "top_records": selected_events,
                "evidence_refs": evidence_refs,
                "limitations": limitations,
            }
        )
    return briefs


def agent_trace_from_briefs(
    briefs: list[dict[str, Any]],
    *,
    synthesis_status: str,
    evidence_validation: dict[str, Any] | None = None,
    synthesis_agent_id: str = "OpenClawSynthesisAgent",
    synthesis_label: str = "Síntesis OpenClaw",
    synthesis_mode: str = "single_local_model_synthesis",
) -> list[dict[str, Any]]:
    trace = [
        {
            "agent_id": str(brief.get("agent_id")),
            "label": str(brief.get("label")),
            "status": str(brief.get("status") or "completed"),
            "execution_mode": str(brief.get("execution_mode")),
            "scopes": list(brief.get("scopes") or []),
            "evidence_refs": list(brief.get("evidence_refs") or []),
            "limitations": list(brief.get("limitations") or []),
        }
        for brief in briefs
    ]
    trace.append(
        {
            "agent_id": synthesis_agent_id,
            "label": synthesis_label,
            "status": synthesis_status,
            "execution_mode": synthesis_mode,
            "scopes": sorted({scope for brief in briefs for scope in brief.get("scopes", [])}),
            "evidence_refs": [],
            "limitations": [],
        }
    )
    if evidence_validation is not None:
        trace.append(
            {
                "agent_id": "EvidenceVerifierAgent",
                "label": "Verificación de referencias",
                "status": "completed" if evidence_validation.get("all_refs_valid") else "limited",
                "execution_mode": "deterministic_post_validation",
                "scopes": ["evidence"],
                "evidence_refs": list(evidence_validation.get("validated_refs") or []),
                "limitations": (
                    []
                    if evidence_validation.get("all_refs_valid")
                    else ["The synthesis referenced identifiers outside the selected run."]
                ),
            }
        )
    return trace


def _source_lifecycle(run: RunRecord) -> dict[str, int]:
    source_coverage = run.summary.metrics.get("source_coverage") or {}
    lifecycle = source_coverage.get("source_lifecycle") if isinstance(source_coverage, dict) else {}
    if isinstance(lifecycle, dict) and lifecycle:
        return {
            key: int(lifecycle.get(key) or 0)
            for key in (
                "registered",
                "configured",
                "enabled",
                "eligible",
                "attempted",
                "succeeded",
                "productive",
                "empty",
                "degraded",
                "failed",
                "skipped",
                "disabled",
                "unconfigured",
            )
        }
    kpis = run.summary.kpis
    return {
        "registered": int(kpis.registered_sources or 0),
        "configured": 0,
        "enabled": 0,
        "eligible": int(kpis.total_sources or 0),
        "attempted": int(kpis.queried_sources or 0),
        "succeeded": int(kpis.healthy_sources or 0),
        "productive": int(kpis.productive_sources or 0),
        "empty": 0,
        "degraded": 0,
        "failed": 0,
        "skipped": 0,
        "disabled": 0,
        "unconfigured": 0,
    }


def _agent_facts(agent_id: str, run: RunRecord, lifecycle: dict[str, int]) -> dict[str, Any]:
    kpis = run.summary.kpis
    common = {
        "run_id": run.id,
        "unique_records": int(kpis.unique_records or kpis.new_events or 0),
        "validated_evidence": int(kpis.validated_evidence or 0),
        "validated_findings": int(kpis.validated_findings or 0),
        "confirmed_incidents": int(kpis.confirmed_incidents or 0),
    }
    if agent_id in {"CollectionQualityAgent", "SourceReliabilityAgent"}:
        return {**common, "source_lifecycle": lifecycle}
    if agent_id == "RiskExplanationAgent":
        return {
            **common,
            "max_residual_risk": kpis.max_residual_risk,
            "avg_residual_risk": kpis.avg_residual_risk,
        }
    if agent_id == "ScenarioBuilderAgent":
        snapshot = run.summary.decision_snapshot or {}
        return {**common, "scenario_funnel": _bounded(snapshot.get("scenario_funnel"))}
    return common


def _record_matches_scopes(item: dict[str, Any], scopes: list[str]) -> bool:
    if "overview" in scopes or "evidence" in scopes:
        return True
    text = " ".join(
        str(item.get(key) or "")
        for key in ("category", "source", "title", "actor", "mitre_attack")
    ).casefold()
    aliases = {
        "risk": ("risk", "riesgo", "vulnerab", "attack"),
        "scenarios": ("scenario", "escenario", "attack", "fraud"),
        "frameworks": ("mitre", "framework", "control", "nist", "iso", "cis", "cobit"),
        "osint": ("osint", "public", "web", "news"),
        "socmint": ("socmint", "social", "mention"),
        "darkweb": ("dark", "tor", "ransom", "leak"),
        "attack_surface": ("surface", "dns", "tls", "whois", "port", "technology"),
        "brand_fraud": ("brand", "fraud", "phishing", "lookalike"),
        "disinformation": ("disinformation", "narrative", "influence"),
        "geography": ("country", "region", "city", "geo"),
        "vulnerabilities": ("vulnerab", "cve", "kev", "epss", "exploit"),
    }
    return any(any(alias in text for alias in aliases.get(scope, (scope,))) for scope in scopes)


def _compact_finding(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": _short(item.get("title")),
        "category": item.get("category"),
        "residual_risk": item.get("residual_risk"),
        "validation_status": item.get("validation_status") or item.get("evidence_status"),
        "evidence": list(item.get("evidence") or [])[:4],
    }


def _compact_event(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "title": _short(item.get("title")),
        "category": item.get("category"),
        "source": item.get("source"),
        "observed_at": item.get("observed_at"),
        "evidence_status": item.get("evidence_status"),
        "evidence_url": item.get("evidence_url") or item.get("url"),
    }


def _evidence_refs(item: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    for key in ("id", "evidence_url", "url"):
        value = item.get(key)
        if value:
            output.add(str(value))
    evidence = item.get("evidence")
    if isinstance(evidence, list):
        output.update(str(value) for value in evidence if value)
    return output


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return None
    if isinstance(value, dict):
        return {
            str(key): _bounded(item, depth + 1)
            for key, item in list(value.items())[:10]
            if item is not None
        }
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:4]]
    if isinstance(value, str):
        return _short(value)
    return value


def _metric_digest(value: Any, *, row_limit: int) -> Any:
    if not isinstance(value, dict):
        return _bounded(value)
    preferred_scalars = (
        "version",
        "model",
        "value",
        "score",
        "signalScore",
        "validatedPressure",
        "value_status",
        "confidence",
        "evidence_count",
        "record_count",
        "candidate_count",
        "supported_count",
        "validated_count",
        "materialized_count",
        "reference_templates",
        "risk_level",
        "level",
        "label",
        "summary",
    )
    digest = {
        key: _short(item, 120) if isinstance(item, str) else item
        for key in preferred_scalars
        if (item := value.get(key)) is not None and not isinstance(item, (dict, list))
    }
    for key in (
        "dimensions",
        "horizons",
        "factors",
        "drivers",
        "categories",
        "scenario_funnel",
        "source_lifecycle",
    ):
        item = value.get(key)
        if isinstance(item, dict):
            digest[key] = {
                str(child_key): child_value
                for child_key, child_value in list(item.items())[:12]
                if isinstance(child_value, (int, float, bool)) or child_value is None
            }
        elif isinstance(item, list):
            digest[key] = [
                {
                    str(child_key): (
                        _short(child_value, 100)
                        if isinstance(child_value, str)
                        else child_value
                    )
                    for child_key, child_value in row.items()
                    if child_key
                    in {
                        "key",
                        "label",
                        "value",
                        "score",
                        "signalScore",
                        "validatedPressure",
                        "value_status",
                        "confidence",
                        "evidence_count",
                        "record_count",
                        "status",
                    }
                    and not isinstance(child_value, (dict, list))
                }
                for row in item[:row_limit]
                if isinstance(row, dict)
            ]
            digest[f"{key}_count"] = len(item)
    if not digest:
        scalar_items = [
            (key, item)
            for key, item in value.items()
            if isinstance(item, (str, int, float, bool)) or item is None
        ][:10]
        digest = {
            str(key): _short(item, 120) if isinstance(item, str) else item
            for key, item in scalar_items
        }
    return digest


def _short(value: Any, limit: int = 180) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)
