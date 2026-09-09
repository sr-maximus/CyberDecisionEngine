import importlib.util
import io
import json
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location("historical_workflow", Path(__file__).parents[1] / "scripts/complete_historical_run.py")
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


def test_historical_request_preserves_scope_and_does_not_mutate_original():
    source = {"request": {"domains": ["example.com"], "organization_name": "Example",
                          "authorized_scope": True, "mode": "deep", "allow_tor": True,
                          "analysis_window": "180d"}}
    request = workflow.historical_request(source, "2026-01-01", "2026-06-30")
    assert source["request"]["analysis_window"] == "180d"
    assert request["analysis_window"] == "custom"
    assert request["lookback_days"] == 181
    assert request["scan_time_budget_minutes"] == 0
    assert request["domains"] == ["example.com"]
    assert request["allow_tor"] is True
    with pytest.raises(ValueError):
        workflow.historical_request({"request": {"authorized_scope": False}}, "2026-01-01", "2026-06-30")


def test_drain_includes_active_collection_and_reports():
    rows = [{"id": "one", "status": "running"}, {"id": "two", "status": "completed", "report_status": "generating"},
            {"id": "three", "status": "completed", "report_status": "ready"}]
    assert [row["id"] for row in workflow.busy_runs(rows)] == ["one", "two"]


def test_recovery_matching_requires_same_scope_period_and_time():
    request = {"domains": ["example.com"], "organization_name": "Example",
               "analysis_start_date": "2026-01-01", "analysis_end_date": "2026-06-30"}
    rows = [{"id": "same", "request": request, "created_at": "2026-09-08T16:00:00+00:00"},
            {"id": "old", "request": request, "created_at": "2026-09-01T16:00:00+00:00"},
            {"id": "other", "request": {**request, "domains": ["other.example"]}, "created_at": "2026-09-08T16:00:00+00:00"}]
    assert [row["id"] for row in workflow.matching_runs(rows, request, "2026-09-08")] == ["same"]


def test_workflow_wait_has_finite_deadline_and_does_not_cancel(monkeypatch):
    ticks = iter([0, 0, 100])
    monkeypatch.setattr(workflow.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(workflow.time, "sleep", lambda _: None)
    with pytest.raises(TimeoutError, match="no active run was cancelled"):
        workflow.wait_for(lambda: [{"status": "running"}], lambda value: False, 60, "Fixture")


def test_complete_workflow_deploys_once_preserves_original_and_checks_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(workflow, "ROOT", tmp_path)
    source = {"id": "original", "request": {"domains": ["example.com"], "organization_name": "Example",
                                             "authorized_scope": True, "analysis_window": "180d"}, "status": "completed"}
    current = {}
    calls = []
    def api(path, payload=None):
        calls.append(path)
        if path == "/api/runs/original":
            return source
        if path == "/api/runs/status":
            return [current] if current else []
        if path == "/api/health":
            return {"status": "ok"}
        if path == "/openapi.json":
            return {"components": {"schemas": {"DomainAnalysisRequest": {"properties": {"analysis_start_date": {}, "analysis_end_date": {}}}}}}
        if path == "/api/analysis":
            current.update(id="historical", request=payload, status="completed", report_status="not_requested")
            context_dir = tmp_path / "data/web_runs/historical"
            context_dir.mkdir(parents=True)
            (context_dir / "context.json").write_text(json.dumps({"raw_events": [], "metrics": {"analysis_period": {
                "start_date": "2026-01-01", "end_date": "2026-06-30", "included_records": 0}}}))
            return current
        if path == "/api/runs/historical/report":
            current.update(report_status="ready", report={"url": "/reports/executive.html", "technical_url": "/reports/technical.html", "validation_status": "approved"})
            return current
        if path == "/api/runs/historical":
            return current
        raise AssertionError(path)
    deployments = []
    monkeypatch.setattr(workflow, "api", api)
    monkeypatch.setattr(workflow, "compose", lambda *args: deployments.append(args))
    monkeypatch.setattr(workflow, "urlopen", lambda *args, **kwargs: io.BytesIO(b"2026-01-01 to 2026-06-30"))
    workflow.complete("original", "2026-01-01", "2026-06-30")
    workflow.complete("original", "2026-01-01", "2026-06-30")
    assert calls.count("/api/analysis") == 1
    assert len(deployments) == 2
    assert deployments[0][0] == "build" and deployments[1][0] == "up"
    assert source["request"]["analysis_window"] == "180d"
    state = json.loads((tmp_path / "data/recovery/original/2026-01-01_2026-06-30/workflow.json").read_text())
    assert state["phase"] == "completed"
    assert state["result"]["undated_included"] is True
