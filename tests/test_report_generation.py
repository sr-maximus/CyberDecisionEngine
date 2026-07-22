from pathlib import Path

from cyberdeck.decision_intelligence import build_decision_snapshot
from cyberdeck.reporting.html_report import (
    _format_strategic_percent,
    _radar_svg,
    _risk_digest,
    prepare_context_for_report,
    render_report,
)
from cyberdeck.schemas import OrganizationProfile, RiskFinding, RunContext, SourceStatus


def test_report_generation(tmp_path):
    org = OrganizationProfile(
        name="Demo Bank",
        sector="Financial and insurance activities",
        country="CO",
        author="Edwin Penuela",
        authorized_scope=True,
        primary_domains=["demo-bank.com"],
        comparison_domains=["benchmark-bank.com"],
        control_maturity={
            "iso27001_score": 0.6,
            "nist_csf_score": 0.65,
            "soc2_score": 0.55,
            "d3fend_coverage": 0.5,
            "attack_detection_coverage": 0.52,
            "incident_response_maturity": 0.7,
        },
        fraud_maturity={"identity_proofing": 0.58},
    )
    finding = RiskFinding(
        title="Fraud demo risk",
        category="fraud",
        likelihood=0.7,
        impact=0.8,
        inherent_risk=56,
        residual_risk=24,
        matrix_score=12,
        matrix_label="Critico",
        evidence=["demo"],
        recommendations=["Actuar"],
        owner="Fraude",
        demo=True,
    )
    context = RunContext(
        organization=org,
        mode="snapshot",
        lookback_days=30,
        report_display_at="2026-02-03T14:45",
        source_statuses=[SourceStatus(name="demo", status="ok", records=1, mode="demo")],
        risk_findings=[finding],
        metrics={
            "posture_index": 62.0,
            "fraud_pressure": 0.5,
            "fraud_notes": ["Fraud note"],
            "control_scores": {"NIST CSF 2.0": 0.65},
            "trends": {"by_category": {"fraud": 1}, "by_source": {"demo": 1}, "by_actor": {}, "by_technique": {}},
            "actors": {"purpose": "actors", "rows": [{"actor": "unattributed", "count": 1, "confidence": "test", "sources": ["demo"], "patterns": ["fraud"]}]},
            "patterns": {"purpose": "patterns", "patterns": [{"name": "Fraud", "count": 1, "meaning": "test"}], "top_sources": [], "top_techniques": []},
            "mitre": {"purpose": "mitre", "coverage_count": 1, "tactics": [{"name": "Initial Access", "count": 1, "techniques": [{"id": "T1566", "name": "Phishing", "count": 1, "sources": ["demo"], "d3fend": [{"id": "D3-PH", "name": "Phishing Detection"}], "examples": [{"title": "demo", "url": ""}]}]}]},
            "d3fend": {"purpose": "d3fend", "rows": [{"id": "D3-PH", "name": "Phishing Detection", "count": 1, "action": "Detect", "tools": "SEG", "samples": ["demo"]}]},
            "atlas": {"purpose": "atlas", "ai_signal_observed": False, "sections": [{"id": "AML.TA0003", "name": "Initial Access", "risk": "risk", "controls": "controls"}]},
            "source_coverage": {
                "osint": {"purpose": "osint", "records": 1, "statuses": [{"name": "demo", "status": "ok", "records": 1, "warning": ""}]},
                "socmint": {"purpose": "socmint", "records": 0, "related_public_records": 0, "statuses": []},
                "darkweb": {"purpose": "darkweb", "records": 0, "statuses": []},
            },
            "risk_heat_radar": {
                "purpose": "risk heat",
                "how_to_read": "read",
                "rows": [{"index": 1, "name": "Fraude e ingenieria social", "score": 0.6, "heat": "high", "evidence_count": 1, "decision": "decide", "signals": ["demo: 1"]}],
            },
            "strategy": {
                "purpose": "strategy",
                "roles": [{"role": "CISO", "strategic_decision": "decide", "preventive": "prevent", "corrective": "correct", "predictive": "predict", "technical_detail": "detail"}],
                "early_warnings": [{"indicator": "KEV", "current_signal": 1, "trigger": "trigger", "anticipation": "anticipate"}],
            },
            "risk_methodology": {"purpose": "risk", "likelihood": "L", "impact": "I", "control_effectiveness": "CE", "matrix": "4x4", "monte_carlo": "P10/P50/P90"},
            "vulnerability_intelligence": {
                "confirmed_cves": 1,
                "kev_matches": 0,
                "observed_technologies": 1,
                "surface_assets": 2,
                "patch_focus": "Validar CVE y versiones observadas.",
                "method": "No se marca una vulnerabilidad como aplicable sin evidencia suficiente.",
                "rows": [
                    {
                        "type": "confirmed",
                        "label": "CVE-2026-1234",
                        "asset": "demo-bank.com",
                        "status": "CVE observada",
                        "decision": "Validar aplicabilidad.",
                        "evidence_url": "https://urlscan.io/api/v1/result/019ed40b-2269-7628-9d53-4f8400647c66/",
                    }
                ],
            },
            "pestel": {
                "index": 70.0,
                "interpretation": "demo",
                "political": 0.5,
                "overall_confidence": 62.0,
                "evidence_coverage_ratio": 0.0322,
                "coverage_ratio": 0.5,
                "dimensions": [{"name": "Politico", "key": "political", "score": 0.5, "confidence": 62.0, "evidence_coverage_percent": 3.22, "cluster_count": 1, "independent_source_count": 1, "why": "why", "decision": "decision"}],
            },
            "porter": {
                "index": 68.0,
                "interpretation": "demo",
                "rivalry": 0.7,
                "overall_confidence": 58.0,
                "evidence_coverage_ratio": 0.0033,
                "coverage_ratio": 0.2,
                "dimensions": [{"name": "Rivalidad", "key": "rivalry", "score": 0.7, "confidence": 58.0, "evidence_coverage_percent": 0.33, "cluster_count": 1, "independent_source_count": 1, "why": "why", "decision": "decision"}],
            },
            "forecast": {"7": {"p10": 0.1, "p50": 0.2, "p90": 0.3, "language": "demo"}},
            "system_model": {"control_loops": ["loop"], "dependencies": [{"asset": "payments", "depends_on": ["api"], "feedback_loop": "detect -> respond"}]},
            "game_theory": {"ranked_controls": [{"control": "identity", "minimax_score": 10}]},
            "control_priorities": {"patching": 0.62, "monitoring": 0.48},
        },
    )
    context.source_statuses.append(SourceStatus(name="OpenCTI", status="unavailable", records=0, mode="legacy"))
    context.decision_snapshot = build_decision_snapshot(context, "stale-run").model_dump(mode="json")
    assert context.decision_snapshot["metrics"]["total_sources"]["value"] == 2
    prepared = prepare_context_for_report(context, "stale-run")
    assert prepared.decision_snapshot["metrics"]["total_sources"]["value"] == 1
    assert len(prepared.connector_coverage["connectors"]) == 1
    out = render_report(context, str(tmp_path / "report.html"))
    html = Path(out).read_text(encoding="utf-8")
    assert "Fraud demo risk" in html
    assert "CyberDecisionEngine" in html
    assert '<html lang="es">' in html
    assert "Arquitectura de decisión" in html
    assert "Alcance y base de comparación" in html
    assert "demo-bank.com" in html
    assert "benchmark-bank.com" in html
    assert "Catálogo accionable de recomendaciones" in html
    assert "Plan de trabajo de mitigación y revisión de escenarios" in html
    assert "Cobertura de módulos de inteligencia" in html
    assert "Metodología y lectura de porcentajes" in html
    assert "Inteligencia de vulnerabilidades" in html
    assert "Escenarios multi-framework activados" in html
    assert "Fecha del informe" in html
    assert "2026-02-03" in html
    assert "2026-02-03 14:45" not in html
    assert "Riesgo virtual" not in html
    assert " · []" not in html
    assert "Actividades financieras y de seguros" in html
    assert "Colombia" in html

    context.organization.language = "en"
    context.metrics["risk_methodology"]["purpose"] = "La estructura de riesgo convierte senales tecnicas y de fraude en probabilidad contextual, impacto de negocio, efectividad de controles, riesgo inherente, riesgo residual y matriz 4x4."
    context.metrics["forecast"]["7"]["language"] = "Probabilidad relativa estimada; no implica certeza de ataque."
    english_out = render_report(context, str(tmp_path / "report-en.html"))
    english_html = Path(english_out).read_text(encoding="utf-8")
    technical_html = Path(tmp_path / "report-en-technical.html").read_text(encoding="utf-8")
    assert '<html lang="en">' in english_html
    assert "Strategic cyber intelligence report — Demo Bank" in english_html
    assert "Executive Summary" in english_html
    assert "Decision Architecture" in english_html
    assert "Scope and Comparison Basis" in english_html
    assert "Actionable Recommendation Catalog" in english_html
    assert "Mitigation and Scenario Review Work Plan" in english_html
    assert "Intelligence Module Coverage" in english_html
    assert "Methodology and Reading of Percentages" in english_html
    assert "Vulnerability intelligence" in english_html
    assert "The model separates evidence" in english_html
    assert "Signal pressure" in english_html
    assert "attack probability" in english_html
    assert "Estimated relative probability" not in english_html
    assert "Technical cyber intelligence report" in technical_html
    assert "Report date" in english_html
    assert "Report date/time" not in english_html
    assert "2026-02-03" in english_html
    assert "2026-02-03" in technical_html
    assert "2026-02-03 14:45" not in english_html
    assert "2026-02-03 14:45" not in technical_html
    assert "Financial and insurance activities" in english_html
    assert "Scope, Data and Definitions" in technical_html
    assert "Methodology and Assumptions" in technical_html
    assert "Vulnerability Intelligence and Patch Focus" in technical_html
    assert "https://urlscan.io/result/019ed40b-2269-7628-9d53-4f8400647c66/" not in technical_html
    assert "https://urlscan.io/screenshots/019ed40b-2269-7628-9d53-4f8400647c66.png" not in technical_html
    assert "Narrative intelligence, disinformation and reputational risk" in technical_html
    assert "Evidence-Activated Multi-Framework Scenarios" in technical_html
    assert "Resumen Ejecutivo" not in english_html
    assert "Employee Virtual Risk" not in english_html


def test_strategic_coverage_percent_preserves_small_nonzero_values():
    assert _format_strategic_percent(0.33, "es") == "0,33%"
    assert _format_strategic_percent(0.33, "en") == "0.33%"
    assert _format_strategic_percent(0, "es") == "0,00%"


def test_radar_preserves_all_dimensions_and_marks_missing_values() -> None:
    dimensions = [
        {"shortName": f"Dimension {index + 1}", "signalScore": score}
        for index, score in enumerate((71.0, None, 43.0, None, 84.0, None))
    ]

    rendered = _radar_svg("Cyber-PESTEL · SignalScore", dimensions)

    assert rendered.count("<li>") == 6
    assert rendered.count("<strong>N/D</strong>") == 3
    assert "stroke-dasharray=\"3 3\"" in rendered
    assert "rgba(8,127,140,.28)" not in rendered
    assert rendered.count("r=\"4\" fill=\"#087f8c\"") == 3


def test_risk_digest_does_not_turn_missing_heat_data_into_zero() -> None:
    digest = _risk_digest({"metrics": {}, "source_statuses": []}, "es")

    assert digest["top_heat"] == "sin datos"
    assert digest["top_heat_score"] is None


def test_report_templates_guard_optional_context():
    template_dir = Path("cyberdeck/reporting/templates")
    for name in ("executive_report.html.j2", "technical_report.html.j2"):
        source = (template_dir / name).read_text(encoding="utf-8")
        assert "scenario_library = scenario_library | default" in source
        assert "model_summary = model_summary | default" in source
        assert "disinformation_summary = disinformation_summary | default" in source
        assert "work_plan = work_plan | default" in source
        assert "methodology_summary = methodology_summary | default" in source
        assert "vuln_intel = metrics.vulnerability_intelligence | default" in source
