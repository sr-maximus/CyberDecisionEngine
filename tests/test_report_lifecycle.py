from __future__ import annotations

import asyncio
import json

from cyberdeck.reporting.html_report import REPORT_GENERATOR_VERSION, _current_report_references
from cyberdeck_api.jobs import RunStore, _compact_run, _dashboard_run, _hydrate_report_lifecycle
from cyberdeck_api.models import AnalysisSummary, DomainAnalysisRequest, ReportSummary, RunRecord, utcnow_iso
from cyberdeck.snapshot_integrity import seal_snapshot


def _completed_run(run_id: str = "report-run") -> RunRecord:
    event = {
        "id": "event-1",
        "title": "Collected public record",
        "category": "open_web",
        "source": "fixture",
        "observed_at": utcnow_iso(),
        "technical_validation": {
            "unstructured_artifacts": [{"type": "domain", "value": "example.com"}]
        },
    }
    summary = AnalysisSummary(
        events=[event],
        records=[event],
        metrics={
            "strategic_news": {
                "articles": [{"title": "Accepted"}],
                "rejected_articles": [{"title": "Rejected"}],
                "pestel": {"duplicate": True},
                "porter": {"duplicate": True},
            },
            "framework_mapping": {
                "mappings": [
                    {
                        "framework": "NIST CSF",
                        "axis": "protect",
                        "record_count": 2,
                        "evidence_ids": ["ev-1", "ev-2"],
                        "evidence": [
                            {"evidence_id": "ev-1", "title": "One"},
                            {"evidence_id": "ev-2", "title": "Two"},
                        ],
                    }
                ]
            },
            "geographic_intelligence": {
                "country_inventory": [{"country": "Colombia", "records": 1, "evidence_ids": ["ev-1"]}]
            },
            "source_coverage": {
                "source_lifecycle": {"registered": 1, "attempted": 1, "productive": 1},
                "connectors": [{"name": "fixture"}],
            },
        },
        decision_snapshot=seal_snapshot({
            "report_context": {"snapshot_version": "1.0", "analysis_window": "30d"},
            "metrics": {},
            "domains": [],
            "analyzed_entities": [],
            "decisions": [],
            "scenario_funnel": {},
            "coverage": {"duplicate": True},
            "strategic_news": {"duplicate": True},
        }),
        claims=[{"claim_id": "claim-1", "evidence_ids": ["ev-1"]}],
        evidence_items=[
            {"evidence_id": "ev-1", "source_id": "fixture", "evidence_status": "validated"},
            {"evidence_id": "unused", "source_id": "fixture", "evidence_status": "raw"},
        ],
        claim_evidence_links=[{"claim_id": "claim-1", "evidence_id": "ev-1", "relation": "supports"}],
    )
    return RunRecord(
        id=run_id,
        status="completed",
        stage="Analysis ready - report pending user request",
        progress=100,
        request=DomainAnalysisRequest(
            domains=["example.com"],
            organization_name="Example",
            authorized_scope=True,
            language="es",
        ),
        domains=["example.com"],
        summary=summary,
    )


def _local_store(tmp_path, monkeypatch) -> RunStore:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = RunStore(tmp_path / "runs.json")
    store.database_url = None
    store.run_dir = tmp_path / "contexts"
    store.report_dir = tmp_path / "reports"
    return store


def test_dashboard_projection_is_small_and_does_not_mutate_source() -> None:
    source = _completed_run()

    projected = _dashboard_run(source)

    assert source.summary.records
    assert source.summary.metrics["strategic_news"]["rejected_articles"]
    assert len(source.summary.evidence_items) == 2
    assert projected.summary.records == []
    assert "rejected_articles" not in projected.summary.metrics["strategic_news"]
    assert "connectors" not in projected.summary.metrics["source_coverage"]
    assert "coverage" not in projected.summary.decision_snapshot
    assert [item["evidence_id"] for item in projected.summary.evidence_items] == ["ev-1"]
    mapping = projected.summary.metrics["framework_mapping"]["mappings"][0]
    assert "evidence_ids" not in mapping
    assert mapping["record_count"] == 2


def test_status_projection_does_not_deep_copy_the_evidence_corpus(monkeypatch) -> None:
    source = _completed_run()
    copy_options: list[dict] = []
    original_model_copy = RunRecord.model_copy

    def tracked_model_copy(self, *args, **kwargs):
        copy_options.append(kwargs)
        return original_model_copy(self, *args, **kwargs)

    monkeypatch.setattr(RunRecord, "model_copy", tracked_model_copy)

    projected = _compact_run(source)

    assert source.summary.events
    assert projected.summary.events == []
    assert projected.summary.kpis == source.summary.kpis
    assert copy_options[-1].get("deep") is not True


def test_report_request_is_idempotent_and_keeps_requested_language(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        store = _local_store(tmp_path, monkeypatch)
        run = _completed_run()
        store._runs[run.id] = run
        started = 0
        release = asyncio.Event()

        async def fake_report_task(
            run_id: str,
            language: str,
            technology_domains: list[str],
            analysis_domains: list[str],
            review_mode: str,
        ) -> None:
            nonlocal started
            assert run_id == run.id
            assert language == "en"
            assert technology_domains == []
            assert analysis_domains == []
            assert review_mode == "manual"
            started += 1
            await release.wait()

        monkeypatch.setattr(store, "_run_report_task", fake_report_task)
        first = await store.request_report(run.id, "en")
        second = await store.request_report(run.id, "en")
        await asyncio.sleep(0)

        assert first is not None and second is not None
        assert first.report_status == second.report_status == "queued"
        assert store._runs[run.id].request.language == "en"
        assert started == 1

        release.set()
        await asyncio.gather(*store._report_tasks.values())
        await store.stop()

    asyncio.run(scenario())


def test_auto_report_schedule_requests_report_when_due(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        store = _local_store(tmp_path, monkeypatch)
        run = _completed_run()
        run.report_auto_due_at = utcnow_iso()
        store._runs[run.id] = run
        requested = asyncio.Event()

        async def fake_request_report(run_id: str, language: str = "es") -> RunRecord:
            assert run_id == run.id
            assert language == "es"
            requested.set()
            return run

        monkeypatch.setattr(store, "request_report", fake_request_report)
        store._schedule_auto_report(run.id, run.report_auto_due_at)
        await asyncio.wait_for(requested.wait(), timeout=1)
        await store.stop()

    asyncio.run(scenario())


def test_explicit_report_refresh_bypasses_cached_report_once(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        store = _local_store(tmp_path, monkeypatch)
        run = _completed_run()
        run.report = ReportSummary(path="cached.html", url="/reports/cached.html")
        run.report_status = "ready"
        store._runs[run.id] = run
        started = 0
        release = asyncio.Event()

        async def fake_report_task(*args) -> None:
            nonlocal started
            started += 1
            await release.wait()

        monkeypatch.setattr(store, "_run_report_task", fake_report_task)
        monkeypatch.setattr("cyberdeck_api.jobs._report_matches_snapshot", lambda _: True)
        first = await store.request_report(run.id, force=True)
        second = await store.request_report(run.id, force=True)
        await asyncio.sleep(0)
        assert first.report_status == second.report_status == "queued"
        assert store._runs[run.id].report is None
        assert started == 1
        release.set()
        await asyncio.gather(*store._report_tasks.values())
        await store.stop()

    asyncio.run(scenario())


def test_hydration_only_reschedules_interrupted_or_requested_reports(monkeypatch) -> None:
    monkeypatch.setenv("CDE_AUTO_REPORT_DELAY_SECONDS", "600")
    historical = _completed_run("historical")
    _hydrate_report_lifecycle(historical)
    assert historical.report_auto_due_at is None

    interrupted = _completed_run("interrupted")
    interrupted.report_status = "generating"
    interrupted.report_requested_at = utcnow_iso()
    _hydrate_report_lifecycle(interrupted)
    assert interrupted.report_status == "not_requested"
    assert interrupted.report_auto_due_at is not None
    assert interrupted.report_error


def test_hydration_refreshes_persisted_report_validation(tmp_path) -> None:
    validation_path = tmp_path / "report_validation.json"
    validation_path.write_text('{"status":"approved","issues":[]}', encoding="utf-8")
    run = _completed_run("validated")
    report_path = tmp_path / "report.html"
    report_snapshot = run.summary.decision_snapshot
    report_path.with_name("report_decision_snapshot.json").write_text(
        json.dumps(report_snapshot), encoding="utf-8"
    )
    run.report = ReportSummary(
        path=str(report_path),
        url="/reports/report.html",
        validation_path=str(validation_path),
        validation_status="approved_with_observations",
        final=True,
        source_snapshot_hash=report_snapshot["snapshot_hash"],
        report_snapshot_hash=report_snapshot["snapshot_hash"],
        generator_version=REPORT_GENERATOR_VERSION,
    )

    changed = _hydrate_report_lifecycle(run)

    assert changed is True
    assert run.report.validation_status == "approved"
    assert run.report.final is True


def test_hydration_marks_a_report_with_a_different_snapshot_as_stale(tmp_path) -> None:
    run = _completed_run("stale")
    report_path = tmp_path / "stale.html"
    stale_snapshot = seal_snapshot({**run.summary.decision_snapshot, "run_id": "older"})
    report_path.with_name("stale_decision_snapshot.json").write_text(
        json.dumps(stale_snapshot), encoding="utf-8"
    )
    run.report = ReportSummary(
        path=str(report_path),
        url="/reports/stale.html",
        source_snapshot_hash=stale_snapshot["snapshot_hash"],
        report_snapshot_hash=stale_snapshot["snapshot_hash"],
        generator_version=REPORT_GENERATOR_VERSION,
    )

    assert _hydrate_report_lifecycle(run) is True
    assert run.report_status == "not_requested"
    assert run.report.final is False
    assert run.report.validation_status == "rejected"


def test_hydration_marks_an_old_report_generator_as_stale(tmp_path) -> None:
    run = _completed_run("old-generator")
    report_path = tmp_path / "old-generator.html"
    snapshot = run.summary.decision_snapshot
    report_path.with_name("old-generator_decision_snapshot.json").write_text(
        json.dumps(snapshot), encoding="utf-8"
    )
    run.report = ReportSummary(
        path=str(report_path),
        url="/reports/old-generator.html",
        source_snapshot_hash=snapshot["snapshot_hash"],
        report_snapshot_hash=snapshot["snapshot_hash"],
        generator_version="cde-html-report-v1.4.0",
    )

    assert REPORT_GENERATOR_VERSION == "cde-html-report-v1.10.3"
    assert _hydrate_report_lifecycle(run) is True
    assert run.report_status == "not_requested"
    assert run.report.final is False
    assert run.report.validation_status == "rejected"


def test_current_report_references_replace_stale_mitre_versions() -> None:
    references = _current_report_references(
        [
            {"name": "MITRE ATT&CK v19.1", "url": "https://attack.example/old"},
            {"name": "MITRE D3FEND v1.4.0", "url": "https://d3fend.example/old"},
            {"name": "Run-specific public source", "url": "https://example.com/feed"},
        ]
    )
    names = {reference["name"] for reference in references}

    assert "MITRE ATT&CK v19.1" not in names
    assert "MITRE D3FEND v1.4.0" not in names
    assert "MITRE ATT&CK Enterprise v19.2" in names
    assert "MITRE ATT&CK for ICS v19.2" in names
    assert "MITRE ATT&CK Mobile v19.2" in names
    assert "MITRE Fight Fraud Framework (F3)" in names
    assert "Run-specific public source" in names
