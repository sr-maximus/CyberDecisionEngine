from cyberdeck_api.ai_orchestration import ai_orchestration_config, build_ai_analysis_package
from cyberdeck_api.models import AIAnalysisRequest, AnalysisSummary, DomainAnalysisRequest, KpiSummary, RunRecord


def test_openclaw_gateway_payload_is_proposal_only():
    run = RunRecord(
        id="run-openclaw",
        status="completed",
        stage="Informe generado",
        request=DomainAnalysisRequest(
            domains=["example.com"],
            organization_name="Example Group",
            sector="Energy",
            country="Colombia",
            authorized_scope=True,
        ),
        domains=["example.com"],
        summary=AnalysisSummary(
            kpis=KpiSummary(active_domains=1, new_events=1, max_residual_risk=0.58),
            findings=[
                {
                    "title": "Exposicion publica observada",
                    "category": "attack_surface",
                    "residual_risk": 0.58,
                    "evidence": ["https://example.com/security.txt"],
                    "recommendations": ["Validar gobierno de activos expuestos"],
                }
            ],
            events=[
                {
                    "id": "evt-1",
                    "title": "Senal publica",
                    "category": "attack_surface",
                    "source": "public",
                    "observed_at": "2026-07-17T00:00:00Z",
                    "evidence_url": "https://example.com/security.txt",
                }
            ],
        ),
    )

    package = build_ai_analysis_package(
        run,
        AIAnalysisRequest(
            run_id=run.id,
            providers=["openclaw_gateway"],
            language="es",
            include_findings_limit=5,
            include_events_limit=5,
        ),
    )

    payload = package.provider_payloads[0]
    assert payload.provider == "openclaw_gateway"
    assert payload.endpoint_hint.endswith("/v1/responses")
    assert payload.body["metadata"]["automation_mode"] == "proposal_only"
    assert payload.body["metadata"]["requires_admin_approval"] is True
    assert "Do not execute tools" in payload.body["instructions"]


def test_openclaw_search_planning_payload_is_safe_and_structured():
    run = RunRecord(
        id="run-openclaw-search",
        status="completed",
        stage="Informe generado",
        request=DomainAnalysisRequest(
            domains=["puertobahia.com.co", "odl.com.co"],
            organization_name="Energia Colombia",
            sector="Energy",
            country="Colombia",
            authorized_scope=True,
        ),
        domains=["puertobahia.com.co", "odl.com.co"],
        summary=AnalysisSummary(
            kpis=KpiSummary(active_domains=2, new_events=3, max_residual_risk=0.64),
            source_statuses=[
                {"name": "Busqueda publica", "status": "partial", "records": 28},
                {"name": "SOCMINT", "status": "skipped", "records": 0},
                {"name": "Inventario pasivo", "status": "timeout", "records": 0},
            ],
            findings=[
                {
                    "title": "Evidencia incompleta para correlacion social",
                    "category": "socmint",
                    "residual_risk": 0.64,
                    "evidence": ["https://example.test/resultado"],
                    "recommendations": ["Reintentar con fuentes permitidas y validar falsos positivos"],
                }
            ],
            events=[
                {
                    "id": "evt-search-1",
                    "title": "Resultado publico parcial",
                    "category": "osint",
                    "source": "Busqueda publica",
                    "observed_at": "2026-07-17T00:00:00Z",
                    "evidence_url": "https://example.test/resultado",
                }
            ],
        ),
    )

    package = build_ai_analysis_package(
        run,
        AIAnalysisRequest(
            run_id=run.id,
            providers=["openclaw_gateway"],
            language="es",
            objective="evidence_search_planning",
            include_findings_limit=5,
            include_events_limit=5,
        ),
    )

    payload = package.provider_payloads[0]
    assert payload.body["metadata"]["automation_mode"] == "search_planning_proposal_only"
    assert "search_query_plan" in payload.body["metadata"]["allowed_outputs"]
    assert "consultas_recomendadas" in package.output_schema
    assert "plan_de_reintento" in package.output_schema
    assert "timeout/skipped/partial" in package.user_prompt
    assert "No ejecutes nada" in package.context_digest["custom_instructions"] or "No ejecutes" in package.system_prompt
    assert "proxy rotation" in payload.body["instructions"]
    assert "captcha bypass" in payload.body["instructions"]
    assert "allowlisted collectors" in payload.body["instructions"]


def test_ai_config_exposes_openclaw_gateway_policy():
    config = ai_orchestration_config()
    providers = {provider["key"]: provider for provider in config["provider_catalog"]}

    assert "openclaw_gateway" in providers
    assert config["openclaw_gateway"]["mode"] == "analysis_only"
    assert "no_tool_execution_from_generated_payload" in config["openclaw_gateway"]["security_controls"]


def test_ai_package_compacts_repeated_source_warnings_and_strategic_payloads():
    run = RunRecord(
        id="run-token-budget",
        status="completed",
        stage="Analysis ready",
        request=DomainAnalysisRequest(domains=["example.com"], organization_name="Example", authorized_scope=True),
        domains=["example.com"],
        summary=AnalysisSummary(
            kpis=KpiSummary(active_domains=1, new_events=1),
            source_statuses=[{"name": "SOCMINT", "status": "partial", "records": 1, "warning": "rate limit; " * 2000}],
            metrics={
                "pestel": {
                    "signalScore": 72,
                    "dimensions": [
                        {
                            "key": "cyber_human",
                            "signalScore": 72,
                            "evidence_ids": ["evd-1"],
                            "drivers": [{"large": "payload" * 5000}],
                        }
                    ],
                }
            },
            events=[{"id": "evd-1", "title": "Related signal", "source": "public"}],
        ),
    )

    package = build_ai_analysis_package(
        run,
        AIAnalysisRequest(run_id=run.id, providers=["openclaw_gateway"], input_token_budget=12000),
    )

    assert package.token_estimate["input_total"] <= 12000
    assert len(package.context_digest["source_statuses"][0]["warning"]) <= 240
    assert "drivers" not in package.context_digest["risk_metrics"]["pestel"]["dimensions"][0]


def test_ai_package_enforces_budget_with_many_verbose_events():
    events = [
        {
            "id": f"evd-{index}",
            "title": "Related public evidence " + ("detail " * 80),
            "source": "Public source",
            "observed_at": f"2026-07-{(index % 20) + 1:02d}T00:00:00Z",
            "evidence_url": "https://example.org/evidence/" + ("path/" * 80) + str(index),
        }
        for index in range(80)
    ]
    run = RunRecord(
        id="run-large-ai-context",
        status="completed",
        stage="Analysis ready",
        request=DomainAnalysisRequest(domains=["example.com"], organization_name="Example", authorized_scope=True),
        domains=["example.com"],
        summary=AnalysisSummary(kpis=KpiSummary(active_domains=1, new_events=80), events=events),
    )

    package = build_ai_analysis_package(
        run,
        AIAnalysisRequest(
            run_id=run.id,
            providers=["openclaw_gateway"],
            input_token_budget=12000,
            include_events_limit=80,
        ),
    )

    assert package.token_estimate["input_total"] <= 12000
    assert package.token_policy["compression_applied"] is True
    assert package.evidence_manifest["events_included"] < 80
    assert "StrategicEvidenceAgent" in package.context_digest["analysis_roles"]
