from cyberdeck.reporting.html_report import (
    _build_report_scenario_matches,
    _local_scenario_library,
    prepare_context_for_report,
    render_report,
)
from cyberdeck.analysis.cyber_radar import build_cyber_risk_radar
from cyberdeck.schemas import EvidenceStatus


def test_fixture_run_is_reclassified_without_inflated_claims(tmp_path, regression_context):
    context = regression_context.model_copy(deep=True)
    prepared = prepare_context_for_report(context)

    assert prepared.processing_summary["raw_records_collected"] == 2
    assert prepared.processing_summary["unique_records"] == 2
    assert prepared.processing_summary["validated_findings"] == 2
    assert prepared.processing_summary["confirmed_findings"] == 0
    assert prepared.processing_summary["duplicates_removed"] == 0

    regenerated = prepare_context_for_report(prepared)
    assert regenerated.processing_summary == prepared.processing_summary

    radar = build_cyber_risk_radar(prepared.raw_events, prepared.risk_findings)
    scores = {row["key"]: row["score"] for row in radar["rows"]}
    assert scores["fraud"] > 0
    assert scores["identity"] > 0
    assert prepared.processing_summary["confirmed_incidents"] == 0
    assert len(prepared.risk_findings) == 2
    assert all(finding.evidence_status == EvidenceStatus.VALIDATED for finding in prepared.risk_findings)
    assert all(finding.matrix_label == "Bajo" for finding in prepared.risk_findings)
    assert prepared.metrics["control_scores"] == {}
    assert prepared.metrics["control_assessment"]["status"] == "unassessed"
    assert prepared.metrics["vulnerability_intelligence"]["confirmed_cves"] == 0
    assert prepared.metrics["vulnerability_intelligence"]["kev_matches"] == 0
    assert prepared.connector_coverage["darkweb"]["direct_or_validated_records"] == 0
    assert prepared.connector_coverage["socmint"]["direct_or_validated_records"] == 0
    assert prepared.metrics["forecast"]["30"]["prediction_is_calibrated"] is False
    assert prepared.metrics["forecast"]["30"]["signal_pressure_index"] < 0.2
    scenario_matches = _build_report_scenario_matches(
        _local_scenario_library()["scenarios"],
        prepared.model_dump(),
        "es",
    )
    assert scenario_matches == []

    report = render_report(context, str(tmp_path / "historical.html"))
    executive = report.read_text(encoding="utf-8").lower()
    technical = report.with_name("historical-technical.html").read_text(encoding="utf-8").lower()
    assert "98%" not in executive
    assert "probabilidad de ataque" in executive
    assert "no es una probabilidad" in executive
    assert "2 hallazgos" in executive or "2 riesgos calculados" in executive
    assert "cve aplicable" not in technical
