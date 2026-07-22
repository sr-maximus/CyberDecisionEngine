from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from cyberdeck_api.models import AIAnalysisPackage, AIAnalysisRequest, AIProviderPayload, RunRecord, utcnow_iso


PROMPT_VERSION = "CDE-AI-STRATEGIC-2026.07-V2"

OPENCLAW_ANALYSIS_TASKS = [
    "StrategicEvidenceAgent",
    "CyberCausalAnalysisAgent",
    "NarrativeIntelligenceAgent",
    "FactCheckContradictionAgent",
    "CoordinationAssessmentAgent",
    "ScenarioBuilderAgent",
    "ExecutiveBriefAgent",
    "ReportReviewAgent",
]
SEARCH_PLANNING_OBJECTIVES = {
    "evidence_search_planning",
    "search_augmentation",
    "collector_remediation",
    "openclaw_search_planning",
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
        "model_hint": "openclaw-configured-model",
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
        "provider_catalog": _provider_catalog(),
        "token_policy": {
            "context_budget_strategy": "compress-first",
            "default_input_budget": 12000,
            "default_output_budget": 4000,
            "hard_input_budget": 64000,
            "hard_output_budget": 32000,
            "evidence_selection": "highest residual risk, newest events, source diversity",
        },
        "approval_required": True,
        "automation_default": "disabled_until_prompt_approved",
        "openclaw_gateway": _openclaw_gateway_config(),
        "analysis_tasks": OPENCLAW_ANALYSIS_TASKS,
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
        model_status = (
            "configured_unverified"
            if models_response.is_success and _model_count(models_response)
            else "not_configured"
        )
        return {
            "runtime_status": "ready",
            "ready": True,
            "model_status": model_status,
            "health_endpoint": f"{endpoint}/readyz",
        }
    except Exception as exc:
        return {
            "runtime_status": "unavailable",
            "ready": False,
            "model_status": "not_checked",
            "error": type(exc).__name__,
        }


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
        "report": run.report.model_dump(mode="json") if run.report else None,
        "analysis_roles": OPENCLAW_ANALYSIS_TASKS,
        "custom_instructions": request.custom_instructions or "",
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
        "forecast",
        "risk_heat_radar",
        "control_scores",
        "fraud_pressure",
        "framework_mapping",
        "scenario_matches",
        "source_freshness",
        "pestel",
        "porter",
        "strategic_news",
        "narrative_intelligence",
    ]
    output = {key: metrics.get(key) for key in allowed if key in metrics}
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
