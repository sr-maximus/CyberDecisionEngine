from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from cyberdeck_api.ai_agents import (
    agent_trace_from_briefs,
    build_agent_briefs,
    plan_agent_specs,
)
from cyberdeck_api.models import (
    AIAnalysisPackage,
    AIAnalysisRequest,
    AIChatRequest,
    AIExecutionRequest,
    AIExecutionResult,
    AIProviderPayload,
    RunRecord,
    utcnow_iso,
)


PROMPT_VERSION = "CDE-AI-STRATEGIC-2026.07-V2"
CHAT_PROMPT_VERSION = "CDE-AI-AUDITOR-2026.07-V1"

OPENCLAW_ANALYSIS_TASKS = [
    "CollectionQualityAgent",
    "SourceReliabilityAgent",
    "StrategicEvidenceAgent",
    "CyberCausalAnalysisAgent",
    "NarrativeIntelligenceAgent",
    "FactCheckContradictionAgent",
    "ScenarioBuilderAgent",
    "RiskExplanationAgent",
    "ExecutiveBriefAgent",
    "ReportReviewAgent",
]
OPENCLAW_CHAT_TASKS = {
    "overview": "ExecutiveBriefAgent",
    "evidence": "StrategicEvidenceAgent",
    "risk": "RiskExplanationAgent",
    "scenarios": "ScenarioBuilderAgent",
    "frameworks": "CyberCausalAnalysisAgent",
    "osint": "CollectionQualityAgent",
    "socmint": "NarrativeIntelligenceAgent",
    "darkweb": "SourceReliabilityAgent",
    "attack_surface": "CyberCausalAnalysisAgent",
    "brand_fraud": "NarrativeIntelligenceAgent",
    "disinformation": "FactCheckContradictionAgent",
    "geography": "StrategicEvidenceAgent",
    "vulnerabilities": "RiskExplanationAgent",
}
SEARCH_PLANNING_OBJECTIVES = {
    "evidence_search_planning",
    "search_augmentation",
    "collector_remediation",
    "openclaw_search_planning",
}

CHAT_SCOPE_METRICS = {
    "overview": {
        "source_coverage",
        "strategic_news",
        "threat_news",
    },
    "evidence": {"source_coverage", "evidence_capture"},
    "risk": {
        "forecast",
        "risk_heat_radar",
        "fraud_pressure",
        "layered_scenario_risk",
        "control_assessment",
        "control_priorities",
    },
    "scenarios": {"scenario_matches", "layered_scenario_risk", "forecast", "game_theory", "monte_carlo"},
    "frameworks": {"framework_mapping", "control_scores", "control_assessment", "mitre", "d3fend", "atlas", "f3"},
    "osint": {"public_entity_intelligence", "source_coverage", "evidence_summary"},
    "socmint": {"narrative_intelligence", "public_entity_intelligence", "source_coverage"},
    "darkweb": {"source_coverage", "evidence_summary", "fraud_pressure"},
    "attack_surface": {"vulnerability_intelligence", "source_coverage", "risk_heat_radar"},
    "brand_fraud": {"fraud_pressure", "fraud_notes", "narrative_intelligence", "f3"},
    "disinformation": {"narrative_intelligence", "strategic_news", "f3"},
    "geography": {"geographic_intelligence"},
    "vulnerabilities": {"vulnerability_intelligence", "threat_news", "control_priorities"},
}

PROVIDER_CATALOG = [
    {
        "key": "openai",
        "label": "OpenAI",
        "endpoint_hint": "https://api.openai.com/v1/responses",
        "model_hint": "configured-openai-model",
        "headers_required": ["Authorization: Bearer OPENAI_API_KEY"],
    },
    {
        "key": "azure_openai",
        "label": "Azure OpenAI",
        "endpoint_hint": "https://{resource}.openai.azure.com/openai/responses?api-version={api-version}",
        "model_hint": "configured-azure-deployment",
        "headers_required": ["api-key: AZURE_OPENAI_API_KEY"],
    },
    {
        "key": "anthropic",
        "label": "Anthropic Claude",
        "endpoint_hint": "https://api.anthropic.com/v1/messages",
        "model_hint": "configured-anthropic-model",
        "headers_required": ["x-api-key: ANTHROPIC_API_KEY", "anthropic-version"],
    },
    {
        "key": "gemini",
        "label": "Google Gemini",
        "endpoint_hint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "model_hint": "configured-gemini-model",
        "headers_required": ["x-goog-api-key: GEMINI_API_KEY"],
    },
    {
        "key": "mistral",
        "label": "Mistral AI",
        "endpoint_hint": "https://api.mistral.ai/v1/chat/completions",
        "model_hint": "configured-mistral-model",
        "headers_required": ["Authorization: Bearer MISTRAL_API_KEY"],
    },
    {
        "key": "local_openai_compatible",
        "label": "Local/OpenAI compatible",
        "endpoint_hint": "http://localhost:{port}/v1/chat/completions",
        "model_hint": "configured-local-model",
        "headers_required": ["Optional Authorization header"],
    },
    {
        "key": "openclaw_gateway",
        "label": "OpenClaw Gateway",
        "endpoint_hint": "http://openclaw-gateway:18789/v1/responses",
        "model_hint": "cyberdecision-cti · Ollama local",
        "headers_required": ["Authorization: Bearer OPENCLAW_GATEWAY_TOKEN"],
        "mode": "analysis_only_until_admin_approval",
    },
]

GUARDRAILS_ES = [
    "No inventes datos, fuentes, URLs, actores, CVE, TTP, países, sectores ni cifras.",
    "Toda afirmación debe estar marcada como evidencia observada, inferencia trazable o dato faltante.",
    "Si la evidencia no soporta una conclusión, dilo explícitamente y solicita información adicional.",
    "Prioriza decisiones accionables, riesgos residuales sustentados, escenarios soportados por evidencia y controles verificables.",
    "No recomiendes acciones ofensivas, intrusivas o ilegales; el uso es defensivo y autorizado.",
]

GUARDRAILS_EN = [
    "Do not invent data, sources, URLs, actors, CVEs, TTPs, countries, sectors or figures.",
    "Every claim must be labeled as observed evidence, traceable inference or missing data.",
    "If evidence does not support a conclusion, say so explicitly and request additional information.",
    "Prioritize actionable decisions, residual risks, likely scenarios and verifiable controls.",
    "Do not recommend offensive, intrusive or illegal actions; use is defensive and authorized.",
]


def ai_orchestration_config() -> dict[str, Any]:
    return {
        "prompt_version": PROMPT_VERSION,
        "chat_prompt_version": CHAT_PROMPT_VERSION,
        "provider_catalog": _provider_catalog(),
        "token_policy": {
            "context_budget_strategy": "compress-first",
            "default_input_budget": 2500,
            "default_output_budget": 1000,
            "hard_input_budget": 64000,
            "hard_output_budget": 32000,
            "evidence_selection": "highest residual risk, newest events, source diversity",
        },
        "approval_required": True,
        "automation_default": "on_demand_with_run_scope",
        "openclaw_gateway": _openclaw_gateway_config(),
        "ollama_chat": {
            "provider": "ollama_local",
            "mode": "interactive_read_only",
            "model": os.getenv("OLLAMA_CHAT_MODEL", "cyberdecision-cti-chat").strip(),
        },
        "analysis_tasks": OPENCLAW_ANALYSIS_TASKS,
        "agent_architecture": {
            "mode": "hybrid_specialist_orchestration",
            "specialist_execution": "deterministic_parallel_reducers",
            "synthesis": "deterministic_interactive_or_single_openclaw_deep",
            "interactive_synthesis": "deterministic_specialist_synthesis",
            "deep_synthesis": "single_openclaw_local_model",
            "post_validation": "deterministic_evidence_verifier",
            "max_interactive_agents": 3,
            "max_deep_agents": 6,
        },
        "assistant_capabilities": [
            "run_scoped_conversation",
            "executive_explanation",
            "technical_explanation",
            "evidence_traceability",
            "decision_options",
            "contradiction_review",
            "source_quality_review",
            "deep_multi_role_analysis",
            "dashboard_navigation",
            "deterministic_report_request",
        ],
    }


async def ollama_runtime_status(model_env: str = "OLLAMA_MODEL") -> dict[str, Any]:
    default_model = "cyberdecision-cti-chat" if model_env == "OLLAMA_CHAT_MODEL" else "cyberdecision-cti"
    configured_model = os.getenv(model_env, default_model).strip()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
            response = await client.get(
                f"{_ollama_base_url()}/api/tags",
                headers={"Authorization": "Bearer ollama-local"},
            )
            response.raise_for_status()
        model_names = _ollama_model_names(response)
        model_status = "available" if configured_model in model_names else "not_configured"
        return {
            "runtime_status": "ready",
            "ready": model_status == "available",
            "model_status": model_status,
            "model": configured_model,
            "model_count": len(model_names),
        }
    except Exception as exc:
        return {
            "runtime_status": "unavailable",
            "ready": False,
            "model_status": "not_checked",
            "model": configured_model,
            "error": type(exc).__name__,
        }


async def openclaw_runtime_status() -> dict[str, Any]:
    enabled = _openclaw_gateway_enabled()
    if not enabled:
        return {"runtime_status": "disabled", "ready": False, "model_status": "not_checked"}
    endpoint = _openclaw_gateway_endpoint()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
            readiness = await client.get(f"{endpoint}/readyz")
            readiness.raise_for_status()
            token = _openclaw_gateway_token()
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            models_response = await client.get(f"{endpoint}/v1/models", headers=headers)
        ollama = await ollama_runtime_status("OLLAMA_MODEL")
        return {
            "runtime_status": "ready",
            "ready": ollama.get("ready", False),
            "model_status": ollama.get("model_status", "not_checked"),
            "model": ollama.get("model"),
            "gateway_model_count": _model_count(models_response),
            "health_endpoint": f"{endpoint}/readyz",
        }
    except Exception as exc:
        return {
            "runtime_status": "unavailable",
            "ready": False,
            "model_status": "not_checked",
            "error": type(exc).__name__,
        }


async def execute_openclaw_analysis(
    run: RunRecord,
    request: AIExecutionRequest,
) -> AIExecutionResult:
    runtime = await openclaw_runtime_status()
    if not runtime.get("ready"):
        return AIExecutionResult(
            id=f"ai-run-{uuid4().hex[:12]}",
            run_id=run.id,
            status="failed",
            model=str(runtime.get("model") or os.getenv("OLLAMA_MODEL", "cyberdecision-cti")),
            prompt_version=PROMPT_VERSION,
            limitations=["El gateway OpenClaw o el modelo Ollama local no está disponible."],
        )

    endpoint = _openclaw_gateway_endpoint()
    token = _openclaw_gateway_token()
    headers = {
        "Content-Type": "application/json",
        "x-openclaw-agent-id": "cyberdecision",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    required_response_instruction = (
        f"{request.system_prompt}\n\n"
        "Esta ejecución de análisis siempre requiere una respuesta JSON útil. "
        "No uses NO_REPLY ni una respuesta vacía. Si faltan datos, devuelve las "
        "limitaciones explícitas dentro del JSON."
    )
    body = {
        "model": "openclaw",
        "instructions": required_response_instruction,
        "input": request.user_prompt,
        "max_output_tokens": min(request.output_token_budget, 2400),
        "temperature": 0.1,
        "metadata": {
            "run_id": run.id,
            "prompt_version": PROMPT_VERSION,
            "execution_mode": "analysis_only",
            "analysis_roles": ",".join(OPENCLAW_ANALYSIS_TASKS),
        },
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(930.0, connect=10.0)) as client:
            response = await client.post(f"{endpoint}/v1/responses", headers=headers, json=body)
            response.raise_for_status()
        payload = response.json()
        raw_text = _response_output_text(payload)
        runtime_error = _detect_model_runtime_error(raw_text)
        if runtime_error:
            return AIExecutionResult(
                id=f"ai-run-{uuid4().hex[:12]}",
                run_id=run.id,
                status="failed",
                model=str(runtime.get("model") or "cyberdecision-cti"),
                prompt_version=PROMPT_VERSION,
                limitations=[runtime_error],
            )
        analysis, parse_limitation = _parse_analysis_json(raw_text)
        evidence_validation = _validate_ai_evidence_refs(run, analysis)
        limitations = []
        if parse_limitation:
            limitations.append(parse_limitation)
        if evidence_validation["unknown_refs"]:
            limitations.append(
                "La salida contiene referencias no presentes en la corrida; se conservaron como borrador no validado."
            )
        status = "completed_with_limitations" if limitations else "completed"
        return AIExecutionResult(
            id=f"ai-run-{uuid4().hex[:12]}",
            run_id=run.id,
            status=status,
            model=str(runtime.get("model") or "cyberdecision-cti"),
            prompt_version=PROMPT_VERSION,
            analysis=analysis,
            raw_text=raw_text if parse_limitation else None,
            evidence_validation=evidence_validation,
            usage=payload.get("usage", {}) if isinstance(payload, dict) else {},
            limitations=limitations,
        )
    except Exception as exc:
        return AIExecutionResult(
            id=f"ai-run-{uuid4().hex[:12]}",
            run_id=run.id,
            status="failed",
            model=str(runtime.get("model") or "cyberdecision-cti"),
            prompt_version=PROMPT_VERSION,
            limitations=[f"OpenClaw no completó el análisis local: {type(exc).__name__}."],
        )


async def execute_ollama_chat(run: RunRecord, request: AIChatRequest) -> AIExecutionResult:
    briefs = build_agent_briefs(
        run,
        request.scopes,
        audience=request.audience,
        deep=request.analysis_mode == "deep",
    )
    deterministic_analysis = _deterministic_chat_analysis(run, request)
    if request.analysis_mode == "interactive":
        analysis = deterministic_analysis or _chat_parse_fallback(run, request)
        evidence_validation = _validate_ai_evidence_refs(run, analysis)
        return AIExecutionResult(
            id=f"ai-chat-{uuid4().hex[:12]}",
            run_id=run.id,
            status="completed",
            provider="CyberDecisionEngine · agentes especializados",
            model="deterministic-specialist-synthesis",
            prompt_version=CHAT_PROMPT_VERSION,
            analysis=analysis,
            evidence_validation=evidence_validation,
            agent_trace=agent_trace_from_briefs(
                briefs,
                synthesis_status="completed",
                evidence_validation=evidence_validation,
                synthesis_agent_id="DeterministicSynthesisAgent",
                synthesis_label="Síntesis verificable",
                synthesis_mode="deterministic_specialist_synthesis",
            ),
            usage={
                "mode": (
                    "authoritative_run_facts"
                    if deterministic_analysis is not None
                    else "grounded_specialist_fallback"
                )
            },
        )

    execution_request = build_ai_chat_execution_request(run, request)
    openclaw_result = await _execute_openclaw_chat(run, request, execution_request)
    if openclaw_result.status != "failed":
        return openclaw_result
    analysis = deterministic_analysis or _chat_parse_fallback(run, request)
    evidence_validation = _validate_ai_evidence_refs(run, analysis)
    return AIExecutionResult(
        id=f"ai-chat-{uuid4().hex[:12]}",
        run_id=run.id,
        status="completed_with_limitations",
        provider="CyberDecisionEngine · agentes especializados",
        model=str(openclaw_result.model),
        prompt_version=CHAT_PROMPT_VERSION,
        analysis=analysis,
        evidence_validation=evidence_validation,
        agent_trace=agent_trace_from_briefs(
            briefs,
            synthesis_status="failed",
            evidence_validation=evidence_validation,
        ),
        usage={"mode": "grounded_deep_fallback"},
        limitations=[
            *openclaw_result.limitations,
            "La síntesis profunda no terminó; se publicó únicamente la reducción verificable de los especialistas.",
        ],
    )


async def _execute_openclaw_chat(
    run: RunRecord,
    request: AIChatRequest,
    execution_request: AIExecutionRequest,
) -> AIExecutionResult:
    runtime = await openclaw_runtime_status()
    configured_model = (
        os.getenv("OLLAMA_MODEL", "cyberdecision-cti")
        if request.analysis_mode == "deep"
        else os.getenv("OLLAMA_CHAT_MODEL", "cyberdecision-cti-chat")
    )
    model = configured_model.removeprefix("ollama/")
    if not runtime.get("ready"):
        return AIExecutionResult(
            id=f"ai-chat-{uuid4().hex[:12]}",
            run_id=run.id,
            status="failed",
            provider="OpenClaw local",
            model=model,
            prompt_version=CHAT_PROMPT_VERSION,
            limitations=["OpenClaw no está disponible para la conversación analítica."],
        )

    endpoint = _openclaw_gateway_endpoint()
    token = _openclaw_gateway_token()
    headers = {
        "Content-Type": "application/json",
        "x-openclaw-agent-id": "cyberdecision",
        "x-openclaw-model": (
            configured_model
            if "/" in configured_model
            else f"ollama/{configured_model}"
        ),
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    briefs = build_agent_briefs(
        run,
        request.scopes,
        audience=request.audience,
        deep=request.analysis_mode == "deep",
    )
    roles = [str(brief["agent_id"]) for brief in briefs]
    instructions = "\n\n".join(
        [
            execution_request.system_prompt,
            "Trabaja internamente con estos roles especializados: " + ", ".join(roles) + ".",
            (
                "Integra sus perspectivas en una sola respuesta. No describas la plataforma, su código, "
                "conectores ni mantenimiento. Responde sobre la organización, la evidencia de la corrida, "
                "las limitaciones y las posibilidades de decisión."
            ),
            "Devuelve únicamente JSON compatible con el esquema incluido en el contexto.",
        ]
    )
    body = {
        "model": "openclaw",
        "instructions": instructions,
        "input": execution_request.user_prompt,
        "max_output_tokens": min(
            request.output_token_budget,
            720 if request.analysis_mode == "deep" else 420,
        ),
        "temperature": 0.12,
        "metadata": {
            "run_id": run.id,
            "prompt_version": CHAT_PROMPT_VERSION,
            "execution_mode": (
                "deep_specialist_analysis"
                if request.analysis_mode == "deep"
                else "interactive_specialist_analysis"
            ),
            "analysis_roles": ",".join(roles),
            "audience": request.audience,
            "scopes": ",".join(request.scopes),
        },
    }
    try:
        timeout_seconds = 240.0 if request.analysis_mode == "deep" else 120.0
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds, connect=10.0)) as client:
            response = await client.post(
                f"{endpoint}/v1/responses",
                headers=headers,
                json=body,
            )
            response.raise_for_status()
        payload = response.json()
        raw_text = _response_output_text(payload)
        runtime_error = _detect_model_runtime_error(raw_text)
        if runtime_error:
            return AIExecutionResult(
                id=f"ai-chat-{uuid4().hex[:12]}",
                run_id=run.id,
                status="failed",
                provider="OpenClaw local",
                model=model,
                prompt_version=CHAT_PROMPT_VERSION,
                limitations=[runtime_error],
            )
        analysis, parse_limitation = _parse_analysis_json(raw_text)
        if parse_limitation or _is_thin_analysis(analysis):
            analysis = _chat_parse_fallback(run, request)
        evidence_validation = _validate_ai_evidence_refs(run, analysis)
        limitations: list[str] = []
        if parse_limitation:
            limitations.append(parse_limitation)
        if evidence_validation["unknown_refs"]:
            limitations.append(
                "OpenClaw incluyó referencias ajenas a la corrida; se conservaron como no validadas."
            )
        return AIExecutionResult(
            id=f"ai-chat-{uuid4().hex[:12]}",
            run_id=run.id,
            status="completed_with_limitations" if limitations else "completed",
            provider="OpenClaw local",
            model=model,
            prompt_version=CHAT_PROMPT_VERSION,
            analysis=analysis,
            raw_text=raw_text if parse_limitation else None,
            evidence_validation=evidence_validation,
            agent_trace=agent_trace_from_briefs(
                briefs,
                synthesis_status="completed",
                evidence_validation=evidence_validation,
            ),
            usage={
                **(payload.get("usage", {}) if isinstance(payload, dict) else {}),
                "analysis_roles": roles,
                "mode": (
                    "openclaw_deep_specialist_analysis"
                    if request.analysis_mode == "deep"
                    else "openclaw_interactive_analysis"
                ),
            },
            limitations=limitations,
        )
    except Exception as exc:
        return AIExecutionResult(
            id=f"ai-chat-{uuid4().hex[:12]}",
            run_id=run.id,
            status="failed",
            provider="OpenClaw local",
            model=model,
            prompt_version=CHAT_PROMPT_VERSION,
            agent_trace=agent_trace_from_briefs(
                briefs,
                synthesis_status="failed",
            ),
            limitations=[f"OpenClaw no completó la conversación: {type(exc).__name__}."],
        )


def _openclaw_roles_for_scopes(scopes: list[str]) -> list[str]:
    return [spec.agent_id for spec in plan_agent_specs(scopes)]


def _is_authoritative_fact_question(message: str) -> bool:
    normalized = message.casefold()
    exact_markers = (
        "cuánt",
        "cuant",
        "número",
        "numero",
        "cantidad",
        "how many",
        "kpi",
        "alcance",
        "qué se analizó",
        "que se analizo",
        "dominios analizados",
        "scope",
        "what was analyzed",
    )
    return any(marker in normalized for marker in exact_markers)


def _deterministic_chat_analysis(
    run: RunRecord,
    request: AIChatRequest,
) -> dict[str, Any] | None:
    question = request.message.casefold()
    quantitative_markers = (
        "cuánt",
        "cuant",
        "número",
        "numero",
        "cantidad",
        "how many",
        "kpi",
        "cifras de la corrida",
        "run figures",
    )
    action_markers = (
        "acción",
        "acciones",
        "actuar",
        "hacer",
        "frente a",
        "qué hago",
        "que hago",
        "siguiente paso",
        "siguientes pasos",
        "mitigar",
        "mitigación",
        "remediar",
        "responder",
        "tratamiento",
        "decisión",
        "decisiones",
        "prioridad",
        "prioridades",
        "recomienda",
        "qué se puede",
        "que se puede",
        "recommend",
        "action",
        "decision",
        "priority",
        "what should",
        "what can be done",
        "next step",
        "mitigate",
        "remediate",
    )
    strategy_markers = ("pestel", "porter")
    evidence_markers = (
        "evidencia",
        "evidencias",
        "hallazgo",
        "hallazgos",
        "evidence",
        "finding",
        "findings",
    )
    scope_markers = (
        "alcance",
        "qué se analizó",
        "que se analizo",
        "dominios analizados",
        "scope",
        "what was analyzed",
    )
    source_markers = (
        "fuente",
        "fuentes",
        "conector",
        "conectores",
        "source",
        "sources",
        "connector",
        "connectors",
    )
    intent = "quantitative" if any(marker in question for marker in quantitative_markers) else None
    if any(marker in question for marker in source_markers):
        intent = "sources"
    elif any(marker in question for marker in strategy_markers):
        intent = "strategy"
    elif any(marker in question for marker in action_markers):
        intent = "actions"
    elif any(marker in question for marker in evidence_markers):
        intent = "evidence"
    elif any(marker in question for marker in scope_markers):
        intent = "scope"
    if intent is None:
        intent = "overview"

    kpis = run.summary.kpis
    validated_findings = int(kpis.validated_findings or 0)
    unique_records = int(kpis.unique_records or 0)
    validated_evidence = int(kpis.validated_evidence or 0)
    confirmed_incidents = int(kpis.confirmed_incidents or 0)
    metrics = run.summary.metrics if isinstance(run.summary.metrics, dict) else {}
    snapshot = run.summary.decision_snapshot if isinstance(run.summary.decision_snapshot, dict) else {}
    supported_scenarios = list(snapshot.get("supported_scenarios") or [])
    scenario_counts = snapshot.get("scenario_counts") or snapshot.get("scenario_funnel") or {}
    supported_count = int(scenario_counts.get("supported") or len(supported_scenarios))

    if intent == "sources":
        return _deterministic_source_chat_analysis(run, request, metrics)

    if intent == "strategy":
        return _deterministic_strategy_chat_analysis(run, request, metrics)

    if intent == "actions":
        return _deterministic_action_chat_analysis(
            run,
            request,
            unique_records=unique_records,
            validated_findings=validated_findings,
            supported_count=supported_count,
            supported_scenarios=supported_scenarios,
            snapshot=snapshot,
        )

    if intent == "evidence":
        if request.language == "es":
            answer = (
                f"La corrida conserva {unique_records} registros únicos, {validated_evidence} evidencias "
                f"validadas, {validated_findings} hallazgos validados y {confirmed_incidents} incidentes "
                "confirmados. Un registro o una URL solo demuestra que una fuente fue recolectada; no demuestra "
                "afectación hasta que exista relación directa, método de validación y trazabilidad."
            )
            limitation = "El volumen recolectado no equivale a hallazgos, riesgo ni incidentes."
        else:
            answer = (
                f"The run contains {unique_records} unique records, {validated_evidence} validated evidence "
                f"items, {validated_findings} validated findings and {confirmed_incidents} confirmed incidents. "
                "A record or URL only proves collection from a source; it does not prove impact without a direct "
                "relationship, validation method and traceability."
            )
            limitation = "Collection volume is not equivalent to findings, risk or incidents."
        return _grounded_chat_payload(
            request,
            answer=answer,
            limitation=limitation,
            evidence_refs=[
                "kpi:unique_records",
                "kpi:validated_evidence",
                "kpi:validated_findings",
                "kpi:confirmed_incidents",
            ],
            dashboard_modules=["evidence", "overview"],
        )

    if intent == "scope":
        subject = run.request.subject_name or ", ".join(run.domains)
        domains = ", ".join(run.domains)
        countries = ", ".join(run.request.countries_of_operation or [])
        window = run.request.analysis_window
        if request.language == "es":
            answer = (
                f"La corrida analiza {subject} mediante {len(run.domains)} dominios ({domains}) durante la ventana "
                f"{window}, con contexto sectorial {run.request.sector or 'no declarado'}"
                + (f" y operaciones declaradas en {countries}" if countries else "")
                + f". Recolectó {unique_records} registros únicos, pero no permite concluir afectación, incidente "
                f"ni riesgo materializado porque contiene {validated_findings} hallazgos validados."
            )
            limitation = "El alcance describe qué se observó; no convierte cobertura de recolección en una conclusión."
        else:
            answer = (
                f"The run analyzes {subject} through {len(run.domains)} domains ({domains}) over the {window} window, "
                f"with sector context {run.request.sector or 'not declared'}"
                + (f" and declared operations in {countries}" if countries else "")
                + f". It collected {unique_records} unique records, but it cannot establish impact, an incident or "
                f"materialized risk because it has {validated_findings} validated findings."
            )
            limitation = "Scope describes what was observed; it does not turn collection coverage into a conclusion."
        return _grounded_chat_payload(
            request,
            answer=answer,
            limitation=limitation,
            evidence_refs=["kpi:unique_records", "kpi:validated_findings"],
            dashboard_modules=["overview", "evidence"],
        )

    if request.language == "es":
        answer = (
            f"La corrida contiene {unique_records} registros únicos, "
            f"{validated_findings} hallazgos validados y {confirmed_incidents} incidentes confirmados. "
            f"Hay {validated_evidence} evidencias validadas. "
        )
        if validated_findings == 0:
            answer += (
                "La limitación principal es que los registros recolectados no han superado el umbral de "
                "validación necesario para tratarlos como hallazgos; por tanto, no prueban por sí solos "
                "afectación, incidente ni riesgo materializado. Para esta corrida, la lectura prudente es "
                "priorizar la validación de los registros relacionados y contextuales antes de escalar decisiones."
            )
        else:
            answer += "Las decisiones deben apoyarse en los hallazgos y evidencias validados, no en el volumen bruto."
        limitation = (
            "El volumen recolectado mide cobertura de observación; no equivale a evidencia validada ni a incidente."
        )
        follow_up = "¿Quieres que explique los hallazgos validados o la cobertura de fuentes por dominio?"
    else:
        answer = (
            f"The run contains {unique_records} unique records, "
            f"{validated_findings} validated findings and {confirmed_incidents} confirmed incidents. "
            f"It has {validated_evidence} validated evidence items. "
        )
        if validated_findings == 0:
            answer += (
                "The main limitation is that collected records have not passed the validation threshold required "
                "to become findings; by themselves they do not prove impact, an incident or materialized risk. "
                "For this run, the prudent interpretation is to prioritize validation of related and contextual "
                "records before escalating decisions."
            )
        else:
            answer += "Decisions must rely on validated findings and evidence, not raw volume."
        limitation = "Collection volume measures observation coverage; it is not validated evidence or an incident."
        follow_up = "Should I explain the validated findings or source coverage by domain?"

    facts = [
        {
            "statement": f"unique_records={unique_records}",
            "evidence_refs": ["kpi:unique_records"],
            "source_type": "run_kpi",
        },
        {
            "statement": f"validated_findings={validated_findings}",
            "evidence_refs": ["kpi:validated_findings"],
            "source_type": "run_kpi",
        },
        {
            "statement": f"validated_evidence={validated_evidence}",
            "evidence_refs": ["kpi:validated_evidence"],
            "source_type": "run_kpi",
        },
    ]
    decision_options = []
    if validated_findings == 0:
        decision_options = [
            {
                "option": (
                    "Priorizar revisión y validación de los registros con mayor relación al alcance"
                    if request.language == "es"
                    else "Prioritize review and validation of records most related to the scope"
                ),
                "rationale": (
                    "Evita convertir volumen recolectado o señales contextuales en riesgo confirmado."
                    if request.language == "es"
                    else "This prevents collection volume or contextual signals from becoming confirmed risk."
                ),
                "priority": "P1",
                "evidence_refs": ["kpi:unique_records", "kpi:validated_findings"],
            }
        ]
    return {
        "answer": answer,
        "facts": facts,
        "inferences": [],
        "decision_options": decision_options,
        "technical_checks": [],
        "dashboard_targets": [
            {"module": "overview", "reason": "authoritative run KPIs"},
            {"module": "evidence", "reason": "record and evidence validation detail"},
        ],
        "report_guidance": {
            "executive": "Use validated findings and explicit limitations.",
            "technical": "Keep collected records, validation state and evidence references separated.",
        },
        "evidence_refs": [ref for fact in facts for ref in fact["evidence_refs"]],
        "limitations": [limitation],
        "follow_up_questions": [follow_up],
        "language": request.language,
        "prompt_version": CHAT_PROMPT_VERSION,
    }


def _deterministic_source_chat_analysis(
    run: RunRecord,
    request: AIChatRequest,
    metrics: dict[str, Any],
) -> dict[str, Any]:
    kpis = run.summary.kpis
    coverage = metrics.get("source_coverage")
    lifecycle = coverage.get("source_lifecycle") if isinstance(coverage, dict) else {}
    lifecycle = lifecycle if isinstance(lifecycle, dict) else {}

    def count(name: str, fallback: int | None) -> int:
        value = lifecycle.get(name)
        return int(value if value is not None else (fallback or 0))

    registered = count("registered", kpis.registered_sources)
    eligible = count("eligible", kpis.eligible_sources or kpis.total_sources)
    queried = count("attempted", kpis.queried_sources)
    successful = count("succeeded", kpis.successful_sources or kpis.healthy_sources)
    productive = count("productive", kpis.productive_sources)
    empty = count("empty", kpis.empty_sources)
    degraded = count("degraded", kpis.degraded_sources)
    failed = count("failed", kpis.failed_sources)
    skipped = count("skipped", kpis.skipped_sources)

    if request.language == "es":
        answer = (
            f"La corrida tiene {registered} fuentes registradas en el catálogo, "
            f"{eligible} elegibles para este alcance, {queried} consultadas, "
            f"{successful} exitosas a nivel técnico y {productive} productivas, es decir, "
            "con registros útiles devueltos. "
            f"Además, {empty} terminaron sin datos, {degraded} operaron de forma parcial, "
            f"{failed} fallaron y {skipped} fueron omitidas por configuración o alcance. "
            "El denominador correcto para evaluar cobertura es el número de fuentes "
            "elegibles, no todo el catálogo registrado."
        )
        limitation = (
            "Una fuente exitosa puede no producir registros; una fuente productiva no "
            "implica por sí sola evidencia validada ni un hallazgo."
        )
    else:
        answer = (
            f"The run has {registered} sources registered in the catalog, "
            f"{eligible} eligible for this scope, {queried} queried, "
            f"{successful} technically successful and {productive} productive, meaning "
            "they returned useful records. "
            f"In addition, {empty} completed without data, {degraded} operated partially, "
            f"{failed} failed and {skipped} were skipped by configuration or scope. "
            "Coverage must use eligible sources as its denominator, not the entire "
            "registered catalog."
        )
        limitation = (
            "A technically successful source may return no records; a productive source "
            "does not by itself establish validated evidence or a finding."
        )

    return _grounded_chat_payload(
        request,
        answer=answer,
        limitation=limitation,
        evidence_refs=[
            "kpi:registered_sources",
            "kpi:eligible_sources",
            "kpi:queried_sources",
            "kpi:successful_sources",
            "kpi:productive_sources",
            "kpi:empty_sources",
            "kpi:degraded_sources",
            "kpi:failed_sources",
            "kpi:skipped_sources",
        ],
        dashboard_modules=["overview", "settings"],
    )


def _deterministic_strategy_chat_analysis(
    run: RunRecord,
    request: AIChatRequest,
    metrics: dict[str, Any],
) -> dict[str, Any]:
    language = request.language
    model_summaries: list[str] = []
    evidence_refs = ["kpi:unique_records", "kpi:validated_findings"]
    dimension_labels = {
        "cyber_geopolitics": ("Geopolítica y política pública", "Geopolitics and public policy"),
        "cyber_economy": ("Economía digital y fraude", "Digital economy and fraud"),
        "cyber_human": ("Factores sociales y humanos", "Social and human factors"),
        "cyber_technology": ("Tecnología y exposición", "Technology and exposure"),
        "cyber_resilience": ("Resiliencia y continuidad", "Resilience and continuity"),
        "cyber_legal": ("Entorno legal y regulatorio", "Legal and regulatory environment"),
        "cyber_rivalry": ("Rivalidad digital", "Digital rivalry"),
        "cyber_new_entrants": ("Nuevos entrantes digitales", "Digital new entrants"),
        "cyber_suppliers": ("Dependencia de proveedores", "Supplier dependency"),
        "cyber_customers": ("Poder y confianza de clientes", "Customer power and trust"),
        "cyber_substitutes": ("Sustitutos y alternativas digitales", "Digital substitutes and alternatives"),
    }
    for model_key, model_label in (
        ("pestel", "PESTEL"),
        ("porter", "Porter"),
    ):
        model = metrics.get(model_key)
        if not isinstance(model, dict):
            continue
        dimensions = []
        for dimension in model.get("dimensions") or []:
            if not isinstance(dimension, dict) or dimension.get("signalScore") is None:
                continue
            dimension_id = str(dimension.get("dimensionId") or "dimension")
            translated_label = dimension_labels.get(
                dimension_id,
                (dimension_id.replace("_", " ").title(), dimension_id.replace("_", " ").title()),
            )[0 if language == "es" else 1]
            dimensions.append(
                (
                    float(dimension.get("signalScore") or 0),
                    translated_label,
                    str(dimension.get("status") or "candidate"),
                )
            )
        dimensions.sort(reverse=True)
        if not dimensions:
            model_summaries.append(
                (
                    f"{model_label}: sin dimensiones con señales suficientes"
                    if language == "es"
                    else f"{model_label}: no dimensions have sufficient signals"
                )
            )
            continue
        detail = ", ".join(
            f"{label} {score:.1f}/100 ({status})"
            for score, label, status in dimensions[:3]
        )
        aggregate = model.get("signalScore")
        model_summaries.append(
            f"{model_label}: índice contextual {float(aggregate):.1f}/100; {detail}"
            if aggregate is not None
            else f"{model_label}: {detail}"
        )
    if language == "es":
        if model_summaries:
            answer = (
                "La lectura estratégica disponible es: "
                + " | ".join(model_summaries)
                + ". Estos valores miden concentración de señales contextuales relacionadas con la organización, "
                "su sector y sus países de operación. No son probabilidad de ataque, riesgo residual ni cumplimiento. "
                "Las dimensiones marcadas como candidate orientan dónde profundizar; no sustentan por sí solas una acción."
            )
        else:
            answer = (
                "La corrida no contiene resultados publicables de PESTEL o Porter. La ausencia de datos no se "
                "convierte en cero ni en una conclusión favorable."
            )
        limitation = (
            "La presión validada permanece N/D mientras no exista corroboración directa suficiente en cada dimensión."
        )
    else:
        if model_summaries:
            answer = (
                "The available strategic reading is: "
                + " | ".join(model_summaries)
                + ". These values measure contextual signal concentration related to the organization, its sector "
                "and countries of operation. They are not attack probability, residual risk or compliance. Candidate "
                "dimensions guide further analysis but do not justify action by themselves."
            )
        else:
            answer = (
                "The run has no publishable PESTEL or Porter results. Missing data is not converted into zero or "
                "a favorable conclusion."
            )
        limitation = "Validated pressure remains N/A until each dimension has sufficient direct corroboration."
    return _grounded_chat_payload(
        request,
        answer=answer,
        limitation=limitation,
        evidence_refs=evidence_refs,
        dashboard_modules=["overview", "risk"],
    )


def _deterministic_action_chat_analysis(
    run: RunRecord,
    request: AIChatRequest,
    *,
    unique_records: int,
    validated_findings: int,
    supported_count: int,
    supported_scenarios: list[Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    language = request.language
    if validated_findings == 0 or supported_count == 0:
        answer = (
            "No se publica un plan de mitigación específico porque la corrida no contiene hallazgos validados ni "
            f"escenarios respaldados por evidencia. Sí hay {unique_records} registros que pueden convertirse en "
            "inteligencia después de revisión. El curso de acción sustentable es: 1) priorizar y validar los registros "
            "con relación directa a los dominios analizados; 2) comprobar contenido, fecha, entidad y URL; 3) confirmar "
            "o descartar la relación y marcar falsos positivos; y 4) escalar únicamente las señales que superen la "
            "validación y activen un escenario con controles NIST, ISO 27001, CIS o COBIT."
            if language == "es"
            else
            "A specific remediation should not be ordered yet because the run contains no validated findings or "
            f"evidence-supported scenarios. It does contain {unique_records} records that may become intelligence "
            "after review. The supportable course is to: 1) prioritize records directly related to the analyzed "
            "domains; 2) verify content, date, entity and URL; 3) confirm or reject the relationship and mark false "
            "positives; and 4) escalate only signals that pass validation and activate a scenario with NIST, "
            "ISO 27001, CIS or COBIT controls."
        )
        limitation = (
            "Sin hallazgos validados no se atribuye afectación ni se prescribe una remediación técnica específica."
            if language == "es"
            else "Without validated findings, impact is not attributed and no specific technical remediation is prescribed."
        )
        return _grounded_chat_payload(
            request,
            answer=answer,
            limitation=limitation,
            evidence_refs=["kpi:unique_records", "kpi:validated_findings"],
            dashboard_modules=["scenarios", "evidence", "frameworks"],
            decision_options=[
                {
                    "option": (
                        "Validar primero los registros con relación directa al alcance"
                        if language == "es"
                        else "Validate records directly related to scope first"
                    ),
                    "rationale": (
                        "Permite separar una coincidencia pública de una evidencia que realmente sustenta un hallazgo."
                        if language == "es"
                        else "This separates a public match from evidence that actually supports a finding."
                    ),
                    "priority": "P1",
                    "evidence_refs": ["kpi:unique_records", "kpi:validated_findings"],
                },
                {
                    "option": (
                        "Resolver falsos positivos y contradicciones antes de escalar"
                        if language == "es"
                        else "Resolve false positives and contradictions before escalation"
                    ),
                    "rationale": (
                        "Evita tratar volumen recolectado o contexto sectorial como afectación confirmada."
                        if language == "es"
                        else "This avoids treating collection volume or sector context as confirmed impact."
                    ),
                    "priority": "P1",
                    "evidence_refs": ["kpi:validated_findings"],
                },
                {
                    "option": (
                        "Mantener vigilancia y activar controles solo ante un escenario respaldado"
                        if language == "es"
                        else "Continue monitoring and activate controls only for a supported scenario"
                    ),
                    "rationale": (
                        "Conserva capacidad de anticipación sin inventar riesgo ni acciones no justificadas."
                        if language == "es"
                        else "This preserves anticipatory capability without inventing risk or unsupported actions."
                    ),
                    "priority": "P2",
                    "evidence_refs": ["kpi:validated_findings"],
                },
            ],
            technical_checks=[
                {
                    "check": (
                        "Confirmar que cada registro corresponde al dominio, entidad y periodo de la corrida"
                        if language == "es"
                        else "Confirm each record matches the run domain, entity and time window"
                    ),
                    "reason": (
                        "Una coincidencia de texto o una URL de tercero no demuestra relación directa."
                        if language == "es"
                        else "A text match or third-party URL does not prove a direct relationship."
                    ),
                }
            ],
            follow_up_questions=[
                (
                    "¿Quieres que priorice la revisión por dominio o por tipo de evidencia?"
                    if language == "es"
                    else "Should I prioritize the review by domain or evidence type?"
                )
            ],
        )

    action_plan = [
        item
        for item in (snapshot.get("action_plan") or snapshot.get("decision_items") or [])
        if isinstance(item, dict)
    ][:3]
    scenario_names = [
        str(item.get("title") or item.get("name") or item.get("scenario_id") or item.get("scenarioId"))
        for item in supported_scenarios[:3]
        if isinstance(item, dict)
    ]
    action_labels = [
        str(item.get("action") or item.get("title") or item.get("decision") or "").strip()
        for item in action_plan
    ]
    action_labels = [item for item in action_labels if item]
    if language == "es":
        answer = (
            f"La corrida contiene {supported_count} escenarios respaldados por evidencia. "
            + (f"Los principales son: {', '.join(scenario_names)}. " if scenario_names else "")
            + (
                f"Las opciones registradas son: {'; '.join(action_labels)}."
                if action_labels
                else "Revise el panel de escenarios para comparar evidencia, controles y criterio de cierre."
            )
        )
        limitation = "Las opciones son posibilidades de decisión; requieren aprobación y verificación de cierre."
    else:
        answer = (
            f"The run contains {supported_count} evidence-supported scenarios. "
            + (f"The leading scenarios are: {', '.join(scenario_names)}. " if scenario_names else "")
            + (
                f"The recorded options are: {'; '.join(action_labels)}."
                if action_labels
                else "Review the scenarios panel to compare evidence, controls and closure criteria."
            )
        )
        limitation = "Options are decision possibilities and require approval and closure verification."
    return _grounded_chat_payload(
        request,
        answer=answer,
        limitation=limitation,
        evidence_refs=["kpi:validated_findings"],
        dashboard_modules=["scenarios", "frameworks", "evidence"],
    )


def _grounded_chat_payload(
    request: AIChatRequest,
    *,
    answer: str,
    limitation: str,
    evidence_refs: list[str],
    dashboard_modules: list[str],
    decision_options: list[dict[str, Any]] | None = None,
    technical_checks: list[dict[str, Any]] | None = None,
    follow_up_questions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "answer": answer,
        "facts": [],
        "inferences": [],
        "decision_options": decision_options or [],
        "technical_checks": technical_checks or [],
        "dashboard_targets": [
            {"module": module, "reason": "authoritative run context"}
            for module in dashboard_modules
        ],
        "report_guidance": {},
        "evidence_refs": evidence_refs,
        "limitations": [limitation],
        "follow_up_questions": follow_up_questions or [],
        "language": request.language,
        "prompt_version": CHAT_PROMPT_VERSION,
    }


def _chat_parse_fallback(run: RunRecord, request: AIChatRequest) -> dict[str, Any]:
    kpis = run.summary.kpis
    unique_records = int(kpis.unique_records or 0)
    validated_findings = int(kpis.validated_findings or 0)
    validated_evidence = int(kpis.validated_evidence or 0)
    confirmed_incidents = int(kpis.confirmed_incidents or 0)
    question = request.message.casefold()
    action_intent = any(
        marker in question
        for marker in (
            "acción",
            "acciones",
            "actuar",
            "hacer",
            "frente a",
            "qué hago",
            "que hago",
            "siguiente paso",
            "mitigar",
            "remediar",
            "responder",
            "decisión",
            "decisiones",
            "recomienda",
            "recommend",
            "action",
            "decision",
            "what should",
            "what can be done",
            "next step",
        )
    )
    evidence_intent = any(
        marker in question
        for marker in ("evidencia", "hallazgo", "url", "evidence", "finding")
    )
    if request.language == "es":
        if action_intent and validated_findings == 0:
            answer = (
                "No se publica un plan de mitigación para esta corrida: no existen hallazgos validados "
                "ni escenarios respaldados por evidencia suficientes para sustentar acciones. "
                f"Los {unique_records} registros recolectados permanecen como contexto de análisis; "
                "deben superar validación y activar un escenario antes de convertirse en una decisión."
            )
        elif evidence_intent:
            answer = (
                f"La corrida conserva {unique_records} registros únicos, {validated_evidence} evidencias "
                f"validadas y {validated_findings} hallazgos validados. Estos estados deben revisarse "
                "por separado: un registro o una URL no demuestran por sí solos afectación."
            )
        else:
            answer = (
                f"La corrida conserva {unique_records} registros únicos, {validated_evidence} evidencias validadas, "
                f"{validated_findings} hallazgos validados y {confirmed_incidents} incidentes confirmados. "
                "La lectura actual debe partir de esos estados: revisar los registros relacionados con el alcance, "
                "resolver contradicciones y falsos positivos, y escalar únicamente lo que tenga evidencia validada."
            )
        limitation = "La respuesta se limita a datos y estados verificables de la corrida."
    else:
        if action_intent and validated_findings == 0:
            answer = (
                "No mitigation plan is published for this run: there are no validated findings or "
                "evidence-supported scenarios sufficient to justify actions. "
                f"The {unique_records} collected records remain analytical context and must pass "
                "validation and activate a scenario before becoming a decision."
            )
        elif evidence_intent:
            answer = (
                f"The run contains {unique_records} unique records, {validated_evidence} validated "
                f"evidence items and {validated_findings} validated findings. These states must remain "
                "separate: a record or URL does not prove impact by itself."
            )
        else:
            answer = (
                f"The run contains {unique_records} unique records, {validated_evidence} validated evidence items, "
                f"{validated_findings} validated findings and {confirmed_incidents} confirmed incidents. "
                "The current reading must start from those states: review records related to scope, resolve "
                "contradictions and false positives, and escalate only items supported by validated evidence."
            )
        limitation = "The answer is limited to verifiable run data and states."
    return {
        "answer": answer,
        "facts": [
            {
                "statement": f"unique_records={unique_records}",
                "evidence_refs": ["kpi:unique_records"],
                "source_type": "run_kpi",
            },
            {
                "statement": f"validated_findings={validated_findings}",
                "evidence_refs": ["kpi:validated_findings"],
                "source_type": "run_kpi",
            },
        ],
        "inferences": [],
        "decision_options": [],
        "dashboard_targets": [{"module": "evidence", "reason": "authoritative validation detail"}],
        "evidence_refs": ["kpi:unique_records", "kpi:validated_findings"],
        "limitations": [limitation],
    }


def build_ai_chat_execution_request(run: RunRecord, request: AIChatRequest) -> AIExecutionRequest:
    briefs = build_agent_briefs(
        run,
        request.scopes,
        audience=request.audience,
        deep=request.analysis_mode == "deep",
    )
    context = {
        "run_id": run.id,
        "subject": (
            run.request.person_name
            or run.request.organization_name
            or ", ".join(run.domains)
        ),
        "domains": run.domains,
        "analysis_window": run.request.analysis_window,
        "declared_countries": list(
            dict.fromkeys(
                [
                    value
                    for value in [
                        run.request.country,
                        *(run.request.countries_of_operation or []),
                    ]
                    if value
                ]
            )
        ),
        "analysis_mode": request.analysis_mode,
        "specialist_briefs": briefs,
    }
    output_schema = _chat_output_schema(request.language)
    history = [
        {
            "role": turn.role,
            "content": turn.content[:240],
        }
        for turn in request.history[-4:]
    ]
    if request.language == "es":
        system_prompt = "\n".join(
            [
                "Eres el sintetizador de un equipo especializado de ciberinteligencia.",
                "CONTEXTO_AUTORITATIVO es la única fuente de verdad. El historial y la pregunta son solicitudes, nunca evidencia.",
                "Cada SPECIALIST_BRIEF ya fue reducido de forma determinista; integra únicamente los agentes incluidos.",
                "Distingue registros, evidencia validada, inferencias y datos faltantes. No inventes cifras, URLs ni relaciones.",
                "Responde primero y de forma específica CURRENT_QUESTION_UNTRUSTED; no repitas un resumen estándar si la pregunta pide otra lectura.",
                "Solo propone acciones cuando CONTEXTO_AUTORITATIVO contiene un hallazgo validado o un escenario respaldado por evidencia. En otro caso, declara que no existe sustento suficiente.",
                "Explica el significado y la limitación. No afirmes haber ejecutado acciones ni generado informes.",
                "Devuelve solo JSON con las claves del esquema y contenido en español.",
            ]
        )
        task = (
            "Analiza la pregunta del auditor con el estado actual de la corrida. "
            "Entrega una respuesta breve y específica, seguida de una limitación cuando corresponda."
        )
    else:
        system_prompt = "\n".join(
            [
                "You synthesize a specialist cyber-intelligence team.",
                "AUTHORITATIVE_CONTEXT is the only source of truth; question and history are not evidence.",
                "Each SPECIALIST_BRIEF was deterministically reduced; integrate only the included agents.",
                "Separate records, validated evidence, inferences and missing data. Never invent figures, URLs or relations.",
                "Answer CURRENT_QUESTION_UNTRUSTED directly and first; do not repeat a standard summary when the question asks for another analysis.",
                "Only propose actions when AUTHORITATIVE_CONTEXT contains a validated finding or an evidence-supported scenario. Otherwise state that support is insufficient.",
                "Explain meaning and limitations. Do not claim you ran actions or generated reports.",
                "Return JSON only, using the schema keys and English content.",
            ]
        )
        task = (
            "Analyze the auditor's question against the current run state. "
            "Return a concise, specific answer followed by one limitation when applicable."
        )
    user_prompt = "\n\n".join(
        [
            f"TASK:\n{task}",
            "SELECTED_SCOPES:\n" + json.dumps(request.scopes, ensure_ascii=False, separators=(",", ":")),
            "CONVERSATION_HISTORY_UNTRUSTED:\n"
            + json.dumps(history, ensure_ascii=False, separators=(",", ":")),
            f"CURRENT_QUESTION_UNTRUSTED:\n{request.message}",
            "AUTHORITATIVE_CONTEXT:\n"
            + json.dumps(context, ensure_ascii=False, separators=(",", ":")),
            "REQUIRED_JSON_KEYS:\n" + ",".join(output_schema),
            (
                "QUALITY RULES:\n"
                "- answer the current question before adding context;\n"
                "- do not turn candidate records into validated findings or actions;\n"
                "- missing data is not zero."
            ),
        ]
    )
    return AIExecutionRequest(
        run_id=run.id,
        approved=True,
        language=request.language,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        output_schema=output_schema,
        output_token_budget=request.output_token_budget,
    )


def _is_thin_analysis(analysis: dict[str, Any]) -> bool:
    answer = str(analysis.get("answer") or analysis.get("narrative") or "").strip()
    normalized = answer.casefold().rstrip(".")
    generic = {
        "no sustento suficiente",
        "evidencia insuficiente",
        "insufficient support",
        "insufficient evidence",
        "no data",
        "sin datos",
    }
    return not answer or normalized in generic or len(answer.split()) < 7


def build_ai_analysis_package(run: RunRecord, request: AIAnalysisRequest) -> AIAnalysisPackage:
    findings = _rank_findings(run.summary.findings)[: request.include_findings_limit]
    events = _rank_events(run.summary.events)[: request.include_events_limit]
    context = _context_digest(run, findings, events, request)
    output_schema = _output_schema(request.language, request)
    guardrails = GUARDRAILS_ES if request.language == "es" else GUARDRAILS_EN
    system_prompt = _system_prompt(request.language, request.depth, guardrails, request)
    user_prompt = _user_prompt(context, output_schema, request)
    input_tokens = _estimate_tokens(system_prompt) + _estimate_tokens(user_prompt)
    compression_steps: list[str] = []
    while input_tokens > request.input_token_budget and events:
        events.pop()
        compression_steps.append("event_omitted")
        context = _context_digest(run, findings, events, request)
        user_prompt = _user_prompt(context, output_schema, request)
        input_tokens = _estimate_tokens(system_prompt) + _estimate_tokens(user_prompt)
    while input_tokens > request.input_token_budget and findings:
        findings.pop()
        compression_steps.append("finding_omitted")
        context = _context_digest(run, findings, events, request)
        user_prompt = _user_prompt(context, output_schema, request)
        input_tokens = _estimate_tokens(system_prompt) + _estimate_tokens(user_prompt)
    while input_tokens > request.input_token_budget and context["source_statuses"]:
        context["source_statuses"].pop()
        compression_steps.append("source_status_omitted")
        user_prompt = _user_prompt(context, output_schema, request)
        input_tokens = _estimate_tokens(system_prompt) + _estimate_tokens(user_prompt)
    for optional_metric in ("risk_heat_radar", "forecast", "source_freshness", "scenario_matches", "framework_mapping"):
        if input_tokens <= request.input_token_budget:
            break
        if optional_metric in context["risk_metrics"]:
            context["risk_metrics"].pop(optional_metric)
            compression_steps.append(f"metric_omitted:{optional_metric}")
            user_prompt = _user_prompt(context, output_schema, request)
            input_tokens = _estimate_tokens(system_prompt) + _estimate_tokens(user_prompt)
    if input_tokens > request.input_token_budget:
        context["risk_metrics"] = _minimal_strategic_metrics(context["risk_metrics"])
        context["report"] = None
        compression_steps.append("strategic_metrics_minimized")
        user_prompt = _user_prompt(context, output_schema, request)
        input_tokens = _estimate_tokens(system_prompt) + _estimate_tokens(user_prompt)
    provider_payloads = [_provider_payload(provider, system_prompt, user_prompt, output_schema, request) for provider in request.providers]
    return AIAnalysisPackage(
        id=f"ai-draft-{uuid4().hex[:12]}",
        prompt_version=PROMPT_VERSION,
        generated_at=utcnow_iso(),
        run_id=run.id,
        subject=context["scope"]["subject"],
        token_estimate={
            "system_prompt": _estimate_tokens(system_prompt),
            "user_prompt": _estimate_tokens(user_prompt),
            "input_total": input_tokens,
            "output_budget": request.output_token_budget,
            "budget_remaining": max(0, request.input_token_budget - input_tokens),
        },
        token_policy={
            "input_budget": request.input_token_budget,
            "output_budget": request.output_token_budget,
            "findings_included": len(findings),
            "events_included": len(events),
            "compression_applied": bool(compression_steps),
            "compression_steps": compression_steps,
            "truncation_rule": "drop lowest-risk/oldest evidence first; never summarize into unsupported facts",
        },
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        context_digest=context,
        evidence_manifest={
            "run_id": run.id,
            "run_status": run.status,
            "findings_available": len(run.summary.findings),
            "findings_included": len(findings),
            "events_available": len(run.summary.events),
            "events_included": len(events),
            "sources_included": sorted({str(event.get("source", "")) for event in events if event.get("source")}),
            "omitted_policy": "Evidence beyond configured limits is intentionally omitted to control tokens.",
        },
        guardrails=guardrails,
        output_schema=output_schema,
        provider_payloads=provider_payloads,
        approval_question=(
            "Edwin, ¿apruebas este prompt maestro para activar análisis IA y automatizaciones, "
            "o quieres ajustar tono, estructura, profundidad, proveedores o límites de tokens?"
            if request.language == "es"
            else "Edwin, do you approve this master prompt for AI analysis and automation, "
            "or should tone, structure, depth, providers or token limits be adjusted?"
        ),
    )


def _context_digest(run: RunRecord, findings: list[dict[str, Any]], events: list[dict[str, Any]], request: AIAnalysisRequest) -> dict[str, Any]:
    subject = run.request.subject_name or ", ".join(run.domains) or "CyberDecisionEngine scope"
    return {
        "run": {
            "run_id": run.id,
            "status": run.status,
            "stage": run.stage,
            "progress": run.progress,
            "created_at": run.created_at,
            "updated_at": run.updated_at,
            "report_available": run.report is not None,
        },
        "scope": {
            "subject": subject,
            "subject_type": run.request.subject_type,
            "domains": run.domains,
            "competitor_domains": run.request.competitor_domains,
            "sector": run.request.sector or "not_declared",
            "country": run.request.country or "not_declared",
            "analysis_window": run.request.analysis_window,
            "lookback_days": run.request.lookback_days,
            "language": request.language,
            "audience": request.audience,
            "objective": request.objective,
        },
        "kpis": run.summary.kpis.model_dump(mode="json"),
        "risk_metrics": _safe_metrics(run.summary.metrics),
        "findings": [_compact_finding(item) for item in findings],
        "events": [_compact_event(item) for item in events],
        "source_statuses": [_compact_source_status(item) for item in run.summary.source_statuses[:20]],
        "traceability": {
            "processing_summary": _bounded_json(run.summary.processing_summary, depth=2, list_limit=8),
            "claims": [_compact_claim(item) for item in run.summary.claims[:10]],
            "evidence_items": [_compact_evidence_item(item) for item in run.summary.evidence_items[:16]],
            "contradictions": [
                _bounded_json(item, depth=2, list_limit=5)
                for item in run.summary.contradicting_evidence[:8]
            ],
            "decisions": [
                _bounded_json(item, depth=2, list_limit=5)
                for item in run.summary.decisions[:8]
            ],
            "counts": {
                "claims": len(run.summary.claims),
                "evidence_items": len(run.summary.evidence_items),
                "claim_evidence_links": len(run.summary.claim_evidence_links),
                "contradictions": len(run.summary.contradicting_evidence),
                "interpretations": len(run.summary.interpretations),
                "decisions": len(run.summary.decisions),
            },
        },
        "report": run.report.model_dump(mode="json") if run.report else None,
        "analysis_roles": OPENCLAW_ANALYSIS_TASKS,
        "custom_instructions": request.custom_instructions or "",
    }


def _scope_chat_context(context: dict[str, Any], scopes: list[str]) -> dict[str, Any]:
    selected_metric_keys: set[str] = set()
    for scope in scopes:
        selected_metric_keys.update(CHAT_SCOPE_METRICS.get(scope, set()))
    metrics = context.get("risk_metrics", {})
    scoped_metrics = {
        key: _compact_chat_metric(key, value)
        for key, value in metrics.items()
        if key in selected_metric_keys
    }
    traceability = context.get("traceability", {})
    report = context.get("report")
    compact_report = None
    if isinstance(report, dict):
        compact_report = {
            "available": True,
            "generated_at": report.get("generated_at"),
            "validation_status": report.get("validation_status"),
            "final": report.get("final"),
            "executive_url": report.get("url"),
            "technical_url": report.get("technical_url"),
        }
    scope = context.get("scope") or {}
    scoped_context: dict[str, Any] = {
        "run": context.get("run"),
        "scope": {
            "subject": scope.get("subject"),
            "subject_type": scope.get("subject_type"),
            "domains": scope.get("domains"),
            "sector": scope.get("sector"),
            "country": scope.get("country"),
            "analysis_window": scope.get("analysis_window"),
        },
        "kpis": context.get("kpis"),
        "selected_scopes": scopes,
        "risk_metrics": scoped_metrics,
        "traceability_counts": traceability.get("counts") or {},
        "report": compact_report,
    }
    scope_set = set(scopes)
    if scope_set & {"overview", "evidence"}:
        scoped_context["processing_summary"] = _compact_processing_summary(
            traceability.get("processing_summary")
        )
    if "evidence" in scope_set:
        scoped_context["evidence_items"] = (traceability.get("evidence_items") or [])[:1]
    if scope_set & {
        "osint",
        "socmint",
        "darkweb",
        "attack_surface",
        "brand_fraud",
        "disinformation",
        "geography",
        "vulnerabilities",
    }:
        scoped_context["events"] = (context.get("events") or [])[:2]
        scoped_context["source_statuses"] = (context.get("source_statuses") or [])[:3]
    if scope_set & {"risk", "scenarios", "frameworks", "vulnerabilities"}:
        scoped_context["findings"] = (context.get("findings") or [])[:4]
        scoped_context["claims"] = (traceability.get("claims") or [])[:2]
        scoped_context["contradictions"] = (traceability.get("contradictions") or [])[:2]
        scoped_context["decisions"] = (traceability.get("decisions") or [])[:2]
    return _bounded_json(scoped_context, depth=4, list_limit=4)


def _compact_chat_metric(key: str, value: Any) -> Any:
    if not isinstance(value, dict):
        return _bounded_json(value, depth=1, list_limit=4)
    if key in {"pestel", "porter"}:
        return {
            "modelVersion": value.get("modelVersion"),
            "signalScore": value.get("signalScore"),
            "validatedPressure": value.get("validatedPressure"),
            "confidence": value.get("confidence"),
            "coverage": value.get("coverage"),
            "status": value.get("status"),
            "dimensions": [
                {
                    "dimensionId": dimension.get("dimensionId"),
                    "signalScore": dimension.get("signalScore"),
                    "validatedPressure": dimension.get("validatedPressure"),
                    "confidence": dimension.get("confidence"),
                    "coverage": dimension.get("coverage"),
                    "status": dimension.get("status"),
                    "summary": str(dimension.get("summary") or "")[:100],
                    "evidenceIds": (dimension.get("evidenceIds") or [])[:2],
                }
                for dimension in value.get("dimensions", [])
                if isinstance(dimension, dict)
            ],
        }
    if key == "source_coverage":
        channels = {}
        for channel in ("osint", "socmint", "darkweb"):
            section = value.get(channel)
            if not isinstance(section, dict):
                continue
            statuses = section.get("statuses") or []
            channels[channel] = {
                "records": section.get("records"),
                "unique_records": section.get("unique_records"),
                "records_queried": section.get("records_queried"),
                "records_retrieved": section.get("records_retrieved"),
                "direct_or_validated_records": section.get("direct_or_validated_records"),
                "source_status_counts": _status_counts(statuses),
            }
        return {
            "coverage_score": value.get("coverage_score"),
            "source_health_score": value.get("source_health_score"),
            "source_completeness_score": value.get("source_completeness_score"),
            "channels": channels,
            "web_layers": {
                layer: {
                    "records": payload.get("records"),
                    "status_records": payload.get("status_records"),
                }
                for layer, payload in (value.get("web_layers") or {}).items()
                if isinstance(payload, dict)
            },
        }
    return _bounded_json(value, depth=1, list_limit=4)


def _compact_processing_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "raw_records_collected": value.get("raw_records_collected"),
        "normalized_records": value.get("normalized_records"),
        "unique_records": value.get("unique_records"),
        "duplicates_removed": value.get("duplicates_removed"),
        "related_evidence": value.get("related_evidence"),
        "contextual_evidence": value.get("contextual_evidence"),
        "validated_evidence": value.get("validated_evidence"),
        "validated_findings": value.get("validated_findings"),
        "confirmed_incidents": value.get("confirmed_incidents"),
        "false_positives": value.get("false_positives"),
        "status_counts": value.get("status_counts"),
    }


def _status_counts(statuses: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not isinstance(statuses, list):
        return counts
    for status in statuses:
        if not isinstance(status, dict):
            continue
        label = str(status.get("status") or "unknown")
        counts[label] = counts.get(label, 0) + 1
    return counts


def _chat_output_schema(language: str) -> dict[str, Any]:
    return {
        "answer": "string",
        "limitations": ["string"],
        "language": language,
    }


def _ollama_chat_json_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "answer": {"type": "string"},
            "limitations": {"type": "array", "items": {"type": "string"}, "maxItems": 1},
        },
        "required": [
            "answer",
            "limitations",
        ],
        "additionalProperties": False,
    }


def _is_search_planning(request: AIAnalysisRequest) -> bool:
    objective = (request.objective or "").strip().lower()
    return objective in SEARCH_PLANNING_OBJECTIVES or "search" in objective or "busqueda" in objective or "búsqueda" in objective


def _system_prompt(language: str, depth: str, guardrails: list[str], request: AIAnalysisRequest) -> str:
    search_mode = _is_search_planning(request)
    if language == "es":
        lines = [
            "Eres el motor experto de análisis aumentado de CyberDecisionEngine, creado por Edwin Peñuela desde 2022.",
            "Tu rol es producir ciberinteligencia estratégica, defensiva, accionable y verificable para toma de decisiones.",
            f"Nivel de profundidad requerido: {depth}.",
        ]
        if search_mode:
            lines.extend(
                [
                    "Modo especial: planificador de búsqueda y evidencia para OpenClaw.",
                    "Debes mejorar la recolección proponiendo consultas, fuentes, reintentos y ajustes seguros.",
                    "No ejecutes navegación, scraping, comandos, cambios de archivos, acciones programadas ni bypass de bloqueos.",
                    "Si una fuente falla o limita, propone backoff, API oficial, credenciales, caché, reducción de alcance o programación segura.",
                    "Cada propuesta debe estar ligada a dominios, gaps de evidencia, fuente objetivo y razón verificable.",
                ]
            )
        lines.extend(
            [
                "Reglas obligatorias:",
                *[f"- {item}" for item in guardrails],
                "Responde únicamente con la estructura solicitada. No agregues narrativa fuera del esquema.",
            ]
        )
        return "\n".join(lines)
    lines = [
        "You are CyberDecisionEngine's augmented analysis expert engine, created by Edwin Penuela since 2022.",
        "Your role is to produce strategic, defensive, actionable and verifiable cyber intelligence for decision-making.",
        f"Required depth: {depth}.",
    ]
    if search_mode:
        lines.extend(
            [
                "Special mode: search and evidence planning for OpenClaw.",
                "Improve collection by proposing queries, sources, retries and safe adjustments.",
                "Do not execute browsing, scraping, commands, file changes, scheduled actions or block bypass.",
                "If a source fails or rate-limits, propose backoff, official APIs, credentials, caching, scope reduction or safe scheduling.",
                "Each proposal must be tied to domains, evidence gaps, target source and verifiable rationale.",
            ]
        )
    lines.extend(
        [
            "Mandatory rules:",
            *[f"- {item}" for item in guardrails],
            "Respond only with the requested structure. Do not add narrative outside the schema.",
        ]
    )
    return "\n".join(lines)


def _user_prompt(context: dict[str, Any], output_schema: dict[str, Any], request: AIAnalysisRequest) -> str:
    search_mode = _is_search_planning(request)
    if request.language == "es" and search_mode:
        task = (
            "Analiza la corrida y crea un plan de búsqueda aumentada para obtener más evidencia pública y útil. "
            "Prioriza dominios con pocas señales, fuentes en timeout/skipped/partial, infraestructura, subdominios, tecnologías, documentos expuestos, SOCMINT/marca/fraude, perfiles de personas con consentimiento/alcance autorizado, superficie externa y dark web autorizada. "
            "Entrega consultas concretas, fuentes permitidas, reintentos seguros, señales esperadas, criterios anti-falso positivo y qué debe aprobar el admin. "
            "No propongas evasión de bloqueos, scraping agresivo, bypass de captchas, rotación opaca de proxies ni acceso no autorizado."
        )
    elif request.language != "es" and search_mode:
        task = (
            "Analyze the run and create an augmented search plan to obtain more useful public evidence. "
            "Prioritize domains with few signals, timeout/skipped/partial sources, infrastructure, subdomains, technologies, exposed documents, SOCMINT/brand/fraud, people profiles with consent/authorized scope, external surface and authorized dark-web checks. "
            "Return concrete queries, allowed sources, safe retries, expected signals, false-positive controls and what requires admin approval. "
            "Do not propose block evasion, aggressive scraping, captcha bypass, opaque proxy rotation or unauthorized access."
        )
    elif request.language == "es":
        task = (
            "Analiza el contexto JSON controlado. Genera recomendaciones directivas y técnicas con trazabilidad, "
            "escenarios soportados por evidencia, riesgo de fraude/marca, exposición, mapeo de gobierno y próximos pasos. "
            "No uses conocimiento externo salvo que lo marques como hipótesis no verificada."
        )
    else:
        task = (
            "Analyze the controlled JSON context. Produce executive and technical recommendations with traceability, "
            "likely scenarios, fraud/brand risk, exposure, compliance and next steps. "
            "Do not use external knowledge unless it is labeled as an unverified hypothesis."
        )
    return "\n\n".join(
        [
            f"TAREA / TASK:\n{task}",
            "CONTEXTO CONTROLADO JSON:\n" + json.dumps(context, ensure_ascii=False, indent=2),
            "ESQUEMA OBLIGATORIO DE SALIDA JSON:\n" + json.dumps(output_schema, ensure_ascii=False, indent=2),
            "CRITERIO DE CALIDAD:\n- evidence_refs debe apuntar a IDs, fuentes o títulos presentes en el contexto.\n- confidence debe bajar cuando falten datos.\n- decisions deben estar formuladas como posibilidades para decisión, no como certezas.",
        ]
    )


def _output_schema(language: str, request: AIAnalysisRequest | None = None) -> dict[str, Any]:
    if request is not None and _is_search_planning(request):
        return _search_planning_schema(language)
    labels = {
        "executive_summary": "resumen_ejecutivo" if language == "es" else "executive_summary",
        "strategic_decisions": "posibilidades_de_decision" if language == "es" else "decision_options",
        "technical_actions": "acciones_tecnicas" if language == "es" else "technical_actions",
    }
    return {
        "factsUsed": [{"fact": "string", "evidenceIds": ["string"]}],
        "inferences": [{"inference": "string", "evidenceIds": ["string"], "confidence": 0}],
        "pestelAnalysis": [{"dimensionId": "string", "causalChain": "string", "evidenceIds": ["string"], "limitations": ["string"]}],
        "porterAnalysis": [{"dimensionId": "string", "marketLimitation": "string", "evidenceIds": ["string"], "limitations": ["string"]}],
        "narrativeClaims": [{"claimText": "string", "contentType": "string", "truthStatus": "string", "coordinationStatus": "string", "evidenceIds": ["string"]}],
        "contradictions": [{"statement": "string", "supportingEvidenceIds": ["string"], "contradictingEvidenceIds": ["string"]}],
        "scenarioProposals": [{"scenario": "string", "evidenceIds": ["string"], "status": "candidate"}],
        "executiveImplications": [{"implication": "string", "evidenceIds": ["string"]}],
        "informationGaps": ["string"],
        "confidence": 0,
        "evidenceIds": ["string"],
        "limitations": ["string"],
        "model": "string",
        "promptVersion": PROMPT_VERSION,
        "timestamp": "datetime",
        labels["executive_summary"]: [{"finding": "string", "evidence_refs": ["string"], "confidence": "low|medium|high"}],
        labels["strategic_decisions"]: [{"decision": "string", "why_now": "string", "owner": "string", "tradeoff": "string"}],
        labels["technical_actions"]: [{"action": "string", "priority": "P1|P2|P3", "validation_evidence": "string"}],
    }


def _search_planning_schema(language: str) -> dict[str, Any]:
    if language == "es":
        return {
            "resumen_de_gaps": [{"gap": "string", "dominios": ["string"], "fuentes_afectadas": ["string"], "impacto_en_analisis": "string"}],
            "consultas_recomendadas": [
                {
                    "id": "string",
                    "dominio_o_marca": "string",
                    "consulta": "string",
                    "tipo": "osint|socmint|marca_fraude|superficie|infraestructura|personas_autorizadas|darkweb_autorizada|cti",
                    "fuente_permitida": "string",
                    "senal_esperada": "string",
                    "prioridad": "P1|P2|P3",
                    "razon": "string",
                }
            ],
            "plan_de_reintento": [
                {
                    "fuente": "string",
                    "estado_observado": "string",
                    "accion_segura": "backoff|api_oficial|credencial|cache|reducir_alcance|programar|omitir",
                    "parametros_sugeridos": {"clave": "valor"},
                    "requiere_aprobacion_admin": True,
                }
            ],
            "controles_anti_falso_positivo": [{"control": "string", "aplica_a": "string", "evidencia_requerida": "string"}],
            "limites_de_seguridad": ["string"],
            "criterios_para_ejecutar_en_cyberdecisionengine": ["string"],
        }
    return {
        "evidence_gaps": [{"gap": "string", "domains": ["string"], "affected_sources": ["string"], "analysis_impact": "string"}],
        "recommended_queries": [
            {
                "id": "string",
                "domain_or_brand": "string",
                "query": "string",
                "type": "osint|socmint|brand_fraud|surface|infrastructure|authorized_people|authorized_darkweb|cti",
                "allowed_source": "string",
                "expected_signal": "string",
                "priority": "P1|P2|P3",
                "rationale": "string",
            }
        ],
        "retry_plan": [
            {
                "source": "string",
                "observed_status": "string",
                "safe_action": "backoff|official_api|credential|cache|reduce_scope|schedule|omit",
                "suggested_parameters": {"key": "value"},
                "requires_admin_approval": True,
            }
        ],
        "false_positive_controls": [{"control": "string", "applies_to": "string", "required_evidence": "string"}],
        "security_limits": ["string"],
        "criteria_to_execute_in_cyberdecisionengine": ["string"],
    }


def _provider_payload(provider: str, system_prompt: str, user_prompt: str, output_schema: dict[str, Any], request: AIAnalysisRequest) -> AIProviderPayload:
    catalog = next(item for item in _provider_catalog() if item["key"] == provider)
    if provider in {"openai", "azure_openai"}:
        body = {
            "model": catalog["model_hint"],
            "instructions": system_prompt,
            "input": user_prompt,
            "max_output_tokens": request.output_token_budget,
            "temperature": 0.2,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "cyberdecision_analysis",
                    "schema": output_schema,
                    "strict": False,
                }
            },
        }
    elif provider == "anthropic":
        body = {
            "model": catalog["model_hint"],
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": request.output_token_budget,
        }
    elif provider == "gemini":
        body = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"maxOutputTokens": request.output_token_budget, "temperature": 0.2, "responseMimeType": "application/json"},
        }
    elif provider == "openclaw_gateway":
        allowed_outputs = ["executive_analysis", "technical_validation", "scheduled_scan_plan", "action_recommendations"]
        automation_mode = "proposal_only"
        if _is_search_planning(request):
            allowed_outputs = [
                "search_query_plan",
                "source_retry_plan",
                "evidence_gap_map",
                "false_positive_controls",
                "admin_approval_checklist",
            ]
            automation_mode = "search_planning_proposal_only"
        body = {
            "model": catalog["model_hint"],
            "instructions": "\n".join(
                [
                    system_prompt,
                    "OpenClaw integration policy: proposal-only mode. Do not execute tools, shell commands, browsers, channels, cron jobs, file writes, scraping, proxy rotation, captcha bypass or source block evasion. Return plans that CyberDecisionEngine can validate and execute only through allowlisted collectors after explicit admin approval.",
                ]
            ),
            "input": user_prompt,
            "max_output_tokens": request.output_token_budget,
            "temperature": 0.2,
            "metadata": {
                "source": "CyberDecisionEngine",
                "run_id": request.run_id,
                "automation_mode": automation_mode,
                "requires_admin_approval": True,
                "allowed_outputs": allowed_outputs,
                "execution_boundary": "OpenClaw plans; CyberDecisionEngine validates and executes only allowlisted collectors.",
            },
        }
    else:
        body = {
            "model": catalog["model_hint"],
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": request.output_token_budget,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
    return AIProviderPayload(
        provider=provider,  # type: ignore[arg-type]
        endpoint_hint=catalog["endpoint_hint"],
        model_hint=catalog["model_hint"],
        headers_required=catalog["headers_required"],
        body=body,
    )


def _provider_catalog() -> list[dict[str, Any]]:
    catalog = [dict(item) for item in PROVIDER_CATALOG]
    endpoint = _openclaw_gateway_endpoint()
    enabled = _openclaw_gateway_enabled()
    for item in catalog:
        if item["key"] != "openclaw_gateway":
            continue
        item["endpoint_hint"] = f"{endpoint}/v1/responses"
        item["enabled"] = enabled
        item["execution_policy"] = "draft payload only; external execution requires admin approval and OPENCLAW_ENABLED=true"
    return catalog


def _openclaw_gateway_endpoint() -> str:
    return os.getenv("OPENCLAW_GATEWAY_URL", "http://openclaw-gateway:18789").rstrip("/")


def _openclaw_gateway_enabled() -> bool:
    return os.getenv("OPENCLAW_ENABLED", "false").strip().lower() == "true"


def _ollama_base_url() -> str:
    return os.getenv("OLLAMA_BASE_URL", "http://ollama:11434").rstrip("/")


def _openclaw_gateway_token() -> str:
    direct = os.getenv("OPENCLAW_GATEWAY_TOKEN", "").strip()
    if direct:
        return direct
    token_path = os.getenv("OPENCLAW_GATEWAY_TOKEN_FILE", "").strip()
    if not token_path:
        return ""
    try:
        return Path(token_path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _model_count(response: httpx.Response) -> int:
    try:
        payload = response.json()
    except ValueError:
        return 0
    rows = payload.get("data") if isinstance(payload, dict) else None
    return len(rows) if isinstance(rows, list) else 0


def _ollama_model_names(response: httpx.Response) -> set[str]:
    try:
        payload = response.json()
    except ValueError:
        return set()
    rows = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return set()
    output = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or row.get("model") or "").strip()
        if name:
            output.add(name.removesuffix(":latest"))
    return output


def _response_output_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"].strip()
    chunks: list[str] = []
    for item in payload.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if not isinstance(content, dict):
                continue
            text = content.get("text") or content.get("output_text")
            if isinstance(text, str):
                chunks.append(text)
    return "\n".join(chunks).strip()


def _parse_analysis_json(raw_text: str) -> tuple[dict[str, Any], str | None]:
    candidate = _extract_json_object(raw_text)
    if candidate is None:
        return {"narrative": raw_text}, "El modelo devolvió texto no estructurado; requiere revisión humana."
    try:
        parsed = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return {"narrative": raw_text}, "El modelo devolvió JSON inválido; requiere revisión humana."
    if not isinstance(parsed, dict):
        return {"result": parsed}, "La salida JSON no fue un objeto; requiere revisión humana."
    return parsed, None


def _extract_json_object(raw_text: str) -> str | None:
    candidate = raw_text.strip()
    if candidate.startswith("```"):
        candidate = candidate.removeprefix("```json").removeprefix("```").strip()
        candidate = candidate.removesuffix("```").strip()
    try:
        json.loads(candidate)
        return candidate
    except (json.JSONDecodeError, TypeError):
        pass

    decoder = json.JSONDecoder()
    for index, character in enumerate(candidate):
        if character not in "[{":
            continue
        try:
            _, end = decoder.raw_decode(candidate[index:])
        except json.JSONDecodeError:
            continue
        return candidate[index : index + end]
    return None


def _detect_model_runtime_error(raw_text: str) -> str | None:
    normalized = raw_text.casefold()
    if "no response from openclaw" in normalized or normalized.strip() == "no_reply":
        return (
            "OpenClaw no produjo un análisis utilizable; la ejecución se marcó "
            "como fallida para evitar publicar una salida vacía."
        )
    if "context overflow" in normalized or "prompt too large" in normalized:
        return (
            "El análisis local excedió la ventana de contexto configurada; "
            "reduzca el alcance del paquete o utilice un modelo local con mayor contexto."
        )
    return None


def _validate_ai_evidence_refs(run: RunRecord, analysis: dict[str, Any]) -> dict[str, Any]:
    valid_refs: set[str] = {
        f"kpi:{key}"
        for key in run.summary.kpis.model_dump(mode="json")
    }
    for event in [*run.summary.events, *run.summary.records]:
        for key in ("id", "canonical_id", "evidence_url"):
            value = event.get(key)
            if value:
                valid_refs.add(str(value))
    for finding in run.summary.findings:
        for value in finding.get("evidence", []) or []:
            if value:
                valid_refs.add(str(value))
    for evidence in run.summary.evidence_items:
        for key in ("evidence_id", "evidenceId", "id", "canonical_url", "canonicalUrl", "url", "source_id", "sourceId"):
            value = evidence.get(key)
            if value:
                valid_refs.add(str(value))
    for claim in run.summary.claims:
        for key in ("claim_id", "claimId", "id"):
            value = claim.get(key)
            if value:
                valid_refs.add(str(value))
    requested_refs = _collect_evidence_refs(analysis)
    known = sorted(ref for ref in requested_refs if ref in valid_refs)
    unknown = sorted(ref for ref in requested_refs if ref not in valid_refs)
    return {
        "requested_count": len(requested_refs),
        "validated_count": len(known),
        "validated_refs": known,
        "unknown_refs": unknown,
        "all_refs_valid": not unknown,
    }


def _collect_evidence_refs(value: Any, parent_key: str = "") -> set[str]:
    output: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).replace("_", "").casefold()
            if "evidence" in normalized and isinstance(item, list):
                output.update(str(ref) for ref in item if isinstance(ref, (str, int)))
            else:
                output.update(_collect_evidence_refs(item, str(key)))
    elif isinstance(value, list):
        for item in value:
            output.update(_collect_evidence_refs(item, parent_key))
    return output


def _openclaw_gateway_config() -> dict[str, Any]:
    return {
        "enabled": _openclaw_gateway_enabled(),
        "endpoint": _openclaw_gateway_endpoint(),
        "mode": os.getenv("OPENCLAW_AUTOMATION_MODE", "analysis_only"),
        "recommended_use": [
            "assistant_explains_run_results",
            "evidence_search_planning",
            "collector_retry_and_source_health_recommendations",
            "admin_help_and_platform_guidance",
            "approved_scan_scheduling_plan",
            "draft_actions_for_decision_boards",
            "report_quality_review_before_delivery",
        ],
        "analysis_tasks": OPENCLAW_ANALYSIS_TASKS,
        "security_controls": [
            "isolated_internal_gateway",
            "no_tool_execution_from_generated_payload",
            "search_plans_must_use_allowlisted_collectors",
            "no_shell_browser_channel_or_cron_without_admin_approval",
            "single_gateway_per_trust_boundary",
            "token_required_when_enabled",
        ],
    }


def _rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda item: float(item.get("residual_risk") or 0), reverse=True)


def _rank_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=lambda item: str(item.get("observed_at") or ""), reverse=True)


def _compact_finding(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": item.get("title"),
        "category": item.get("category"),
        "residual_risk": item.get("residual_risk"),
        "owner": item.get("owner"),
        "evidence": (item.get("evidence") or [])[:4],
        "recommendations": (item.get("recommendations") or [])[:4],
    }


def _compact_event(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "category": item.get("category"),
        "source": item.get("source"),
        "observed_at": item.get("observed_at"),
        "actor": item.get("actor"),
        "technique": item.get("technique"),
        "tags": (item.get("tags") or [])[:8],
        "evidence_url": item.get("evidence_url"),
    }


def _compact_source_status(item: dict[str, Any]) -> dict[str, Any]:
    warning = str(item.get("warning") or "")
    return {
        "name": item.get("name"),
        "status": item.get("status"),
        "records": item.get("records", 0),
        "mode": item.get("mode"),
        "warning": warning[:240] if warning else None,
    }


def _compact_claim(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": item.get("claim_id") or item.get("claimId") or item.get("id"),
        "statement": item.get("statement") or item.get("claimText") or item.get("title"),
        "claim_type": item.get("claim_type") or item.get("claimType"),
        "claim_status": item.get("claim_status") or item.get("status"),
        "confidence": item.get("confidence"),
        "evidence_ids": (item.get("evidence_ids") or item.get("evidenceIds") or [])[:8],
        "limitations": (item.get("limitations") or [])[:3],
    }


def _compact_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": item.get("evidence_id") or item.get("evidenceId") or item.get("id"),
        "source_id": item.get("source_id") or item.get("sourceId") or item.get("source"),
        "evidence_type": item.get("evidence_type") or item.get("evidenceType") or item.get("category"),
        "canonical_url": item.get("canonical_url") or item.get("canonicalUrl") or item.get("url"),
        "collected_at": item.get("collected_at") or item.get("collectedAt"),
        "observed_at": item.get("observed_at") or item.get("observedAt"),
        "evidence_status": item.get("evidence_status") or item.get("status"),
        "confidence": item.get("confidence"),
        "validation_method": item.get("validation_method") or item.get("validationMethod"),
    }


def _bounded_json(value: Any, *, depth: int = 3, list_limit: int = 8) -> Any:
    if depth < 0:
        return "[omitted]"
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in list(value.items())[:24]:
            normalized = str(key).casefold()
            if normalized in {"raw", "raw_text", "raw_response", "body", "content", "html"}:
                continue
            output[str(key)] = _bounded_json(item, depth=depth - 1, list_limit=list_limit)
        return output
    if isinstance(value, list):
        return [
            _bounded_json(item, depth=depth - 1, list_limit=list_limit)
            for item in value[:list_limit]
        ]
    if isinstance(value, str):
        return value[:600]
    return value


def _compact_strategic_model(model: dict[str, Any]) -> dict[str, Any]:
    dimensions = []
    for dimension in model.get("dimensions", []):
        dimensions.append(
            {
                "dimensionId": dimension.get("dimensionId") or dimension.get("key"),
                "displayName": dimension.get("displayName") or dimension.get("name"),
                "signalScore": dimension.get("signalScore"),
                "validatedPressure": dimension.get("validatedPressure"),
                "confidence": dimension.get("confidence"),
                "coverage": dimension.get("coverage", dimension.get("evidence_coverage_percent")),
                "status": dimension.get("status"),
                "summary": dimension.get("summary") or dimension.get("why"),
                "cyberMechanism": dimension.get("cyberMechanism"),
                "evidenceIds": (dimension.get("evidence_ids") or [])[:8],
                "limitations": (dimension.get("limitations") or [])[:3],
                "decisionImplications": (dimension.get("decisionImplications") or [])[:3],
            }
        )
    return {
        "modelVersion": model.get("modelVersion") or model.get("version"),
        "signalScore": model.get("signalScore", model.get("signal_score")),
        "validatedPressure": model.get("validatedPressure", model.get("index")),
        "confidence": model.get("overall_confidence"),
        "coverage": model.get("evidence_coverage_ratio"),
        "status": model.get("overall_status") or model.get("assessment_status"),
        "dimensions": dimensions,
        "marketScope": model.get("marketScope"),
    }


def _compact_narrative_intelligence(model: dict[str, Any]) -> dict[str, Any]:
    claims = model.get("claims", [])
    return {
        "modelVersion": model.get("modelVersion"),
        "claimCount": model.get("claimCount", len(claims)),
        "contentTypeCounts": model.get("contentTypeCounts", {}),
        "truthStatusCounts": model.get("truthStatusCounts", {}),
        "coordinationStatusCounts": model.get("coordinationStatusCounts", {}),
        "claims": [
            {
                "claimId": claim.get("claimId"),
                "claimText": claim.get("claimText"),
                "contentType": claim.get("contentType"),
                "truthStatus": claim.get("truthStatus"),
                "coordinationStatus": claim.get("coordinationStatus"),
                "status": claim.get("status"),
                "confidence": claim.get("confidence"),
                "evidenceIds": (claim.get("sourceEvidenceIds") or [])[:6],
                "url": claim.get("url"),
            }
            for claim in claims[:12]
        ],
        "limitations": (model.get("limitations") or [])[:4],
    }


def _safe_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    allowed = [
        "actors",
        "atlas",
        "control_assessment",
        "control_priorities",
        "forecast",
        "risk_heat_radar",
        "control_scores",
        "d3fend",
        "evidence_capture",
        "evidence_summary",
        "fraud_pressure",
        "fraud_notes",
        "framework_mapping",
        "f3",
        "game_theory",
        "geographic_intelligence",
        "layered_scenario_risk",
        "mitre",
        "monte_carlo",
        "patterns",
        "public_entity_intelligence",
        "scenario_matches",
        "source_coverage",
        "source_freshness",
        "pestel",
        "porter",
        "strategy",
        "strategic_news",
        "threat_news",
        "trends",
        "narrative_intelligence",
        "vulnerability_intelligence",
    ]
    output = {
        key: _bounded_json(metrics.get(key), depth=3, list_limit=8)
        for key in allowed
        if key in metrics
    }
    for key in ("pestel", "porter"):
        if isinstance(output.get(key), dict):
            output[key] = _compact_strategic_model(output[key])
    if isinstance(output.get("strategic_news"), dict):
        strategic = output["strategic_news"]
        output["strategic_news"] = {
            "version": strategic.get("version"),
            "articleCount": len(strategic.get("articles", [])),
            "clusterCount": len(strategic.get("clusters", [])),
            "contradictionCount": len(strategic.get("contradictions", [])),
            "rejectedCount": len(strategic.get("rejected_articles", [])),
        }
    if isinstance(output.get("narrative_intelligence"), dict):
        output["narrative_intelligence"] = _compact_narrative_intelligence(output["narrative_intelligence"])
    return output


def _minimal_strategic_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in ("pestel", "porter"):
        model = metrics.get(key)
        if not isinstance(model, dict):
            continue
        output[key] = {
            "modelVersion": model.get("modelVersion"),
            "signalScore": model.get("signalScore"),
            "validatedPressure": model.get("validatedPressure"),
            "confidence": model.get("confidence"),
            "coverage": model.get("coverage"),
            "status": model.get("status"),
            "dimensions": [
                {
                    "dimensionId": dimension.get("dimensionId"),
                    "signalScore": dimension.get("signalScore"),
                    "validatedPressure": dimension.get("validatedPressure"),
                    "confidence": dimension.get("confidence"),
                    "coverage": dimension.get("coverage"),
                    "status": dimension.get("status"),
                    "evidenceIds": dimension.get("evidenceIds", []),
                }
                for dimension in model.get("dimensions", [])
            ],
        }
    narrative = metrics.get("narrative_intelligence")
    if isinstance(narrative, dict):
        output["narrative_intelligence"] = narrative
    return output


def _estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 4))
