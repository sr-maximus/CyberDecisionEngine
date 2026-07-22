from pathlib import Path

from cyberdeck.reporting.data_export import export_evidence
from cyberdeck.reporting.validator import ValidationIssue, _validate_strategic_exports, validate_report_bundle
from cyberdeck.schemas import OrganizationProfile, RunContext, ThreatEvent


def _context() -> RunContext:
    event = ThreatEvent(
        id="EV-1",
        title="Public record",
        category="osint",
        source="Public source",
        evidence_url="https://example.org/evidence/1",
    )
    return RunContext(
        organization=OrganizationProfile(
            name="Example Org",
            sector="Technology",
            country="US",
            author="Test",
            primary_domains=["example.org"],
            authorized_scope=True,
        ),
        mode="snapshot",
        lookback_days=30,
        raw_events=[event],
        decision_snapshot={
            "run_id": "run-validator",
            "engine_version": "test",
            "snapshot_hash": "snapshot-validator",
            "report_context": {
                "run_id": "run-validator",
                "snapshot_version": "test",
                "engine_version": "test",
                "organization_name": "Example Org",
            },
            "reference_integrity": {"status": "pass", "invalid_reference_ids": 0},
            "metrics": {
                "records": {
                    "label": "Records",
                    "value": 1,
                    "unit": "records",
                    "value_status": "valid_value",
                    "confidence": 1.0,
                    "definition": "Number of normalized records in the fixture.",
                    "evidence_ids": [],
                }
            },
        },
    )


def test_report_validator_accepts_consistent_html_json_and_csv(tmp_path: Path) -> None:
    context = _context()
    executive = tmp_path / "run-validator-example.html"
    technical = tmp_path / "run-validator-example-technical.html"
    executive.write_text(
        '<html><meta name="cde:snapshot-hash" content="snapshot-validator"><body>'
        + "Executive report " * 40
        + "</body></html>",
        encoding="utf-8",
    )
    technical.write_text(
        '<html><meta name="cde:snapshot-hash" content="snapshot-validator"><body>'
        + "Technical report " * 40
        + "</body></html>",
        encoding="utf-8",
    )
    export_evidence(context, executive)

    result = validate_report_bundle(context, executive, technical)

    assert result.status == "approved"
    assert result.counts["context_records"] == 1
    assert result.counts["json_records"] == 1
    assert result.counts["csv_records"] == 1


def test_report_validator_rejects_export_count_mismatch(tmp_path: Path) -> None:
    context = _context()
    executive = tmp_path / "run-validator-example.html"
    technical = tmp_path / "run-validator-example-technical.html"
    executive.write_text(
        '<html><meta name="cde:snapshot-hash" content="snapshot-validator"><body>'
        + "Executive report " * 40
        + "</body></html>",
        encoding="utf-8",
    )
    technical.write_text(
        '<html><meta name="cde:snapshot-hash" content="snapshot-validator"><body>'
        + "Technical report " * 40
        + "</body></html>",
        encoding="utf-8",
    )
    export_evidence(context, executive)
    executive.with_name(f"{executive.stem}_evidence.csv").write_text("id,title\n", encoding="utf-8")

    result = validate_report_bundle(context, executive, technical)

    assert result.status == "rejected"
    assert any(issue.code == "EXPORT_COUNT_MISMATCH" for issue in result.issues)


def test_report_validator_rejects_html_from_another_snapshot(tmp_path: Path) -> None:
    context = _context()
    executive = tmp_path / "run-validator-example.html"
    technical = tmp_path / "run-validator-example-technical.html"
    executive.write_text("<html><body>" + "Executive report " * 40 + "</body></html>", encoding="utf-8")
    technical.write_text("<html><body>" + "Technical report " * 40 + "</body></html>", encoding="utf-8")
    export_evidence(context, executive)

    result = validate_report_bundle(context, executive, technical)

    assert result.status == "rejected"
    assert any(issue.code == "REPORT_SNAPSHOT_MISMATCH" for issue in result.issues)


def test_report_validator_rejects_strategic_score_without_evidence_and_missing_visuals(tmp_path: Path) -> None:
    context = _context()
    pestel_ids = ["cyber_geopolitics", "cyber_economy", "cyber_human", "cyber_technology", "cyber_resilience", "cyber_legal"]
    porter_ids = ["cyber_rivalry", "cyber_new_entrants", "cyber_suppliers", "cyber_customers", "cyber_substitutes"]
    context.metrics = {
        "pestel": {
            "dimensions": [
                {"key": key, "dimensionId": key, "signalScore": 42 if index == 0 else None, "status": "candidate" if index == 0 else "no_data", "evidence_ids": []}
                for index, key in enumerate(pestel_ids)
            ]
        },
        "porter": {"dimensions": [{"key": key, "dimensionId": key, "signalScore": None, "status": "no_data", "evidence_ids": []} for key in porter_ids]},
    }
    executive = tmp_path / "run-validator-example.html"
    technical = tmp_path / "run-validator-example-technical.html"
    body = '<html><meta name="cde:snapshot-hash" content="snapshot-validator"><body>' + "Report " * 100 + "</body></html>"
    executive.write_text(body, encoding="utf-8")
    technical.write_text(body, encoding="utf-8")
    export_evidence(context, executive)

    result = validate_report_bundle(context, executive, technical)

    assert result.status == "rejected"
    assert any(issue.code == "STRATEGIC_SCORE_WITHOUT_EVIDENCE" for issue in result.issues)
    assert any(issue.code == "STRATEGIC_VISUAL_MISSING" for issue in result.issues)


def test_strategic_export_validation_rejects_json_csv_signal_mismatch(tmp_path: Path) -> None:
    context = _context()
    context.metrics = {
        "pestel": {
            "dimensions": [
                {
                    "dimensionId": "cyber_economy",
                    "signalScore": 42.0,
                    "validatedPressure": None,
                }
            ]
        }
    }
    executive = tmp_path / "run-validator-example.html"
    executive.with_name(f"{executive.stem}_strategic_scores.json").write_text(
        '{"pestel":{"dimensions":[{"dimensionId":"cyber_economy","signalScore":42.0,"validatedPressure":null}]}}',
        encoding="utf-8",
    )
    executive.with_name(f"{executive.stem}_strategic_scores.csv").write_text(
        "model,dimension,signal_score,validated_pressure\npestel,cyber_economy,41.0,\n",
        encoding="utf-8",
    )
    issues: list[ValidationIssue] = []

    count = _validate_strategic_exports(context, executive, issues)

    assert count == 1
    assert any(issue.code == "STRATEGIC_SIGNAL_EXPORT_MISMATCH" for issue in issues)
