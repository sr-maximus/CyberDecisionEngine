import csv
import json

from cyberdeck.decision_intelligence import build_decision_snapshot
from cyberdeck.reporting.html_report import prepare_context_for_report, render_report
from cyberdeck.schemas import OrganizationProfile, RunContext, SourceStatus
from cyberdeck.semantics import CLAIM_EVIDENCE_MODEL_VERSION
from cyberdeck_api.jobs import summarize_context


RUN_ID = "syntheticregression"


def test_regression_snapshot_is_the_shared_decision_record(tmp_path, regression_context):
    context = regression_context.model_copy(deep=True)
    prepared = prepare_context_for_report(context, run_id=RUN_ID)
    snapshot = prepared.decision_snapshot
    assert prepared.claim_evidence_model_version == CLAIM_EVIDENCE_MODEL_VERSION

    assert snapshot["report_context"]["primary_domains"] == ["example.com"]
    assert snapshot["metrics"]["unique_records"]["value"] == 2
    assert snapshot["metrics"]["healthy_sources"]["value"] == 3
    assert snapshot["metrics"]["queried_sources"]["value"] == 3
    assert snapshot["metrics"]["productive_sources"]["value"] == 1
    assert snapshot["metrics"]["total_sources"]["value"] == 3
    assert snapshot["metrics"]["registered_sources"]["value"] == 3
    assert all(status.name.lower() != "opencti" for status in prepared.source_statuses)
    assert len(prepared.connector_coverage["connectors"]) == 3
    assert snapshot["metrics"]["validated_findings"]["value"] == 2
    assert snapshot["scenario_funnel"]["reference_templates"] == 1500
    assert snapshot["scenario_funnel"]["executable"] == 0
    assert snapshot["scenario_funnel"]["supported"] == 2
    assert snapshot["metrics"]["pending_decisions"]["value"] == 2
    assert snapshot["metrics"]["pending_decisions"]["evidence_ids"]
    assert snapshot["metrics"]["max_residual_risk"]["evidence_ids"]
    assert len(snapshot["supported_scenarios"]) == 2
    assert all(row["status"] == "supported" and row["evidence_ids"] for row in snapshot["supported_scenarios"])
    assert snapshot["scenario_funnel"]["confirmed"] == 0
    assert snapshot["strategic_models"]["pestel"]["value_status"] == "insufficient_evidence"
    assert snapshot["strategic_models"]["porter"]["value_status"] == "insufficient_evidence"
    assert snapshot["formula_versions"]["strategic_news"] == prepared.metrics["strategic_news"]["version"]
    assert "regulatorios" in snapshot["chart_eligibility"]["pestel"]["metric_definition"]
    assert "strategic_evidence_clusters" in snapshot["chart_eligibility"]["porter"]["sources"]
    assert snapshot["chart_eligibility"]["executive_risk_radar"]["eligible"] is False
    assert snapshot["chart_eligibility"]["risk_heatmap"]["eligible"] is False
    assert snapshot["reference_integrity"]["orphan_reference_ids"] == []

    summary = summarize_context(prepared.organization.primary_domains, prepared)
    assert summary.decision_snapshot["snapshot_hash"] == snapshot["snapshot_hash"]
    assert summary.kpis.unique_records == snapshot["metrics"]["unique_records"]["value"]
    assert summary.kpis.healthy_sources == snapshot["metrics"]["healthy_sources"]["value"]
    assert next(row for row in summary.domain_signals if row.domain == "example.com").max_residual_risk == 0.12

    report = render_report(prepared, str(tmp_path / f"{RUN_ID}-scope.html"))
    technical = report.with_name(f"{report.stem}-technical.html")
    snapshot_json = report.with_name(f"{report.stem}_decision_snapshot.json")
    snapshot_csv = report.with_name(f"{report.stem}_decision_snapshot.csv")
    exported = json.loads(snapshot_json.read_text(encoding="utf-8"))
    csv_rows = list(csv.DictReader(snapshot_csv.open(encoding="utf-8")))
    metric_rows = {row["record_id"]: row for row in csv_rows if row["record_type"] == "metric"}

    assert exported["snapshot_hash"] == snapshot["snapshot_hash"]
    assert float(metric_rows["unique_records"]["value"]) == snapshot["metrics"]["unique_records"]["value"]
    assert float(metric_rows["healthy_sources"]["value"]) == snapshot["metrics"]["healthy_sources"]["value"]
    executive_html = report.read_text(encoding="utf-8")
    technical_html = technical.read_text(encoding="utf-8")
    assert snapshot["snapshot_hash"][:12] in executive_html
    assert snapshot["snapshot_hash"][:12] in technical_html
    assert all(domain in executive_html for domain in snapshot["report_context"]["primary_domains"])
    assert "1/3" in executive_html
    assert "Registros asociados" in executive_html
    assert "Registros asociados" in technical_html
    assert "Referencias completas de evidencia" in technical_html
    assert "https://example.com/evidence/phishing" in technical_html


def test_zero_and_missing_values_are_not_conflated(tmp_path):
    context = RunContext(
        organization=OrganizationProfile(
            name="Scope without evidence",
            sector="",
            country="",
            author="test",
            authorized_scope=True,
            primary_domains=["empty.example"],
        ),
        mode="snapshot",
        lookback_days=30,
        source_statuses=[SourceStatus(name="empty", status="empty", records=0)],
    )
    snapshot = build_decision_snapshot(context, run_id="empty-run")

    assert snapshot.metrics["confirmed_incidents"].value == 0
    assert snapshot.metrics["confirmed_incidents"].value_status == "observed_zero"
    assert snapshot.metrics["max_residual_risk"].value is None
    assert snapshot.metrics["max_residual_risk"].value_status == "no_data"
    assert snapshot.domains[0].max_residual_risk is None
    assert snapshot.domains[0].risk_value_status == "no_data"
    assert snapshot.strategic_models["pestel"]["value"] is None
    assert snapshot.strategic_models["pestel"]["value_status"] == "insufficient_evidence"
    summary = summarize_context(["empty.example"], context)
    assert summary.kpis.max_residual_risk is None
    assert summary.domain_signals[0].max_residual_risk is None
    report = render_report(context, str(tmp_path / "empty-run.html"))
    technical_html = report.with_name("empty-run-technical.html").read_text(encoding="utf-8")
    executive_html = report.read_text(encoding="utf-8")
    assert "Riesgo residual máx.</span><strong>N/D</strong>" in executive_html
    assert "Riesgo residual máx.</span><strong>N/D</strong>" in technical_html
    assert "Riesgo residual máximo 0.0" not in technical_html
    assert "Presión de fraude</span><strong>Sin señales validadas</strong>" in technical_html


def test_strategic_charts_use_dimension_signal_score_without_validated_aggregate():
    context = RunContext(
        organization=OrganizationProfile(
            name="Evidence scope",
            sector="Finance",
            country="CO",
            author="test",
            authorized_scope=True,
            primary_domains=["evidence.example"],
        ),
        mode="snapshot",
        lookback_days=30,
        metrics={
            "pestel": {
                "index": None,
                "signalScore": 64.0,
                "overall_confidence": 55.0,
                "dimensions": [{"key": "cyber_economy", "signalScore": 64.0, "evidence_ids": ["evd-1"]}],
            },
            "porter": {
                "index": None,
                "signalScore": 58.0,
                "overall_confidence": 50.0,
                "dimensions": [{"key": "cyber_rivalry", "signalScore": 58.0, "evidence_ids": ["evd-2"]}],
            },
        },
    )

    snapshot = build_decision_snapshot(context, run_id="strategic-signals")

    assert snapshot.strategic_models["pestel"]["signalScore"] == 64.0
    assert snapshot.strategic_models["pestel"]["validatedPressure"] is None
    assert snapshot.chart_eligibility["pestel"]["eligible"] is True
    assert snapshot.chart_eligibility["porter"]["eligible"] is True
    assert snapshot.chart_eligibility["pestel"]["evidence_count"] == 1


def test_person_snapshot_is_rendered_as_an_authorized_target_without_fake_domain(tmp_path):
    context = RunContext(
        organization=OrganizationProfile(
            name="Ada Example",
            entity_type="person",
            subject_aliases=["ada_example"],
            sector="",
            country="CO",
            author="test",
            language="es",
            authorized_scope=True,
            primary_domains=[],
        ),
        mode="snapshot",
        lookback_days=7,
        lookback_hours=168,
        analysis_window="7d",
        source_statuses=[SourceStatus(name="public-search", status="empty", records=0)],
    )

    prepared = prepare_context_for_report(context, run_id="person-run")
    snapshot = prepared.decision_snapshot
    output = render_report(prepared, str(tmp_path / "person-run.html"))
    html = output.read_text(encoding="utf-8")
    csv_rows = list(csv.DictReader(output.with_name("person-run_decision_snapshot.csv").open(encoding="utf-8")))

    assert snapshot["report_context"]["subject_type"] == "person"
    assert snapshot["report_context"]["subject_name"] == "Ada Example"
    assert snapshot["report_context"]["primary_domains"] == []
    assert snapshot["metrics"]["active_targets"]["value"] == 1
    assert snapshot["metrics"]["active_domains"]["value"] == 0
    assert snapshot["analyzed_entities"][0]["entity_type"] == "person"
    assert snapshot["strategic_models"]["pestel"]["value_status"] == "not_applicable"
    assert snapshot["strategic_models"]["porter"]["value_status"] == "not_applicable"
    assert "Informe autorizado de inteligencia digital" in html
    assert "Objetivos analizados" in html
    assert "Ada Example" in html
    assert any(row["record_type"] == "entity" and row["name"] == "Ada Example" for row in csv_rows)


def test_organization_without_domains_keeps_an_organization_scope_subtitle():
    context = RunContext(
        organization=OrganizationProfile(
            name="Example Holdings",
            entity_type="organization",
            sector="Servicios",
            country="CO",
            author="test",
            language="es",
            authorized_scope=True,
            primary_domains=[],
        ),
        mode="snapshot",
        lookback_days=7,
        lookback_hours=168,
        analysis_window="7d",
    )

    snapshot = build_decision_snapshot(context, run_id="organization-run")

    assert snapshot.report_context.subject_type == "organization"
    assert snapshot.report_context.subject_name == "Example Holdings"
    assert snapshot.report_context.report_subtitle.startswith("Alcance de organización declarado")
    assert "0 dominios" not in snapshot.report_context.report_subtitle
