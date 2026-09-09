import asyncio
import importlib.util
import sys
from pathlib import Path

from cyberdeck.cli import _collect_safely
from cyberdeck.collectors.base import CollectionResult
from cyberdeck.collectors.spiderfoot import SpiderFootCollector
from cyberdeck.schemas import SourceStatus, ThreatEvent
from cyberdeck_api.jobs import RunStore, _estimated_collection_seconds
from cyberdeck_api.models import RunRecord, DomainAnalysisRequest


class WaitingCollector:
    name = "waiting-source"

    def __init__(self, partial_events=()):
        self.partial_events = list(partial_events)
        self.cancelled = False

    async def collect(self):
        try:
            await asyncio.Event().wait()
        finally:
            self.cancelled = True


def test_deadline_preserves_partial_records_and_releases_other_sources():
    event = ThreatEvent(id="partial", title="Observed asset", category="attack_surface", source="fixture")
    waiting = WaitingCollector([event])

    class ReadyCollector:
        name = "ready-source"

        async def collect(self):
            return CollectionResult(SourceStatus(name=self.name, status="ok", records=1), [event])

    async def run():
        return await asyncio.gather(_collect_safely(waiting, 0.01), _collect_safely(ReadyCollector(), 0.1))

    partial, ready = asyncio.run(run())
    assert waiting.cancelled
    assert partial.status.status == "partial"
    assert partial.status.records == 1
    assert partial.events == [event]
    assert "incomplete" in partial.status.warning
    assert ready.status.status == "ok"


def test_empty_timeout_is_not_success_and_cancellation_propagates():
    collector = WaitingCollector()
    result = asyncio.run(_collect_safely(collector, 0.01))
    assert result.status.status == "error"
    assert result.events == []

    async def cancel():
        task = asyncio.create_task(_collect_safely(WaitingCollector(), 60))
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return
        raise AssertionError("Caller cancellation was swallowed")

    asyncio.run(cancel())


def test_passive_collector_zero_never_means_infinite_wait():
    assert SpiderFootCollector(["example.com"], timeout_seconds=0).timeout_seconds == 86400
    assert SpiderFootCollector(["example.com"], timeout_seconds=172800).timeout_seconds == 86400


def test_actual_progress_updates_source_status_without_inflating_percent(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = RunStore(state_path=tmp_path / "runs.json")
    run = RunRecord(id="fixture", request=DomainAnalysisRequest(domains=["example.com"]), status="running", progress=64)
    run.summary.source_statuses = [{"name": "source", "status": "pending"}]
    store._runs[run.id] = run

    async def check():
        await store._collection_progress(run.id, "Source completed", 36, SourceStatus(name="source", status="partial", records=4))
        assert run.progress == 64
        assert run.summary.source_statuses[0]["records"] == 4
        assert run.summary.source_statuses[0]["status"] == "partial"
        await store.stop()

    asyncio.run(check())


def test_large_query_plan_estimate_uses_hours():
    config = {"web_search": {"queries": ["query"] * 303, "max_queries": 0, "timeout_seconds": 9, "providers": ["duckduckgo_lite", "google_news_rss", "gdelt", "hacker_news"]}}
    assert _estimated_collection_seconds(config) > 3 * 3600


def test_long_estimate_survives_persistence_and_server_startup(tmp_path, monkeypatch):
    import json
    monkeypatch.delenv("DATABASE_URL", raising=False)
    run = RunRecord(id="long-run", request=DomainAnalysisRequest(domains=["example.com"]),
                    status="completed", estimated_seconds=20643)
    path = tmp_path / "runs.json"
    path.write_text(json.dumps({"runs": [run.model_dump(mode="json")]}))
    store = RunStore(state_path=path)
    monkeypatch.setattr(store, "_resume_report_schedules", lambda: None)

    async def check():
        await store.load()
        assert store._runs[run.id].estimated_seconds == 20643
        await store.stop()

    asyncio.run(check())


def test_sidecar_terminates_overdue_process_and_recovers_output(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / "infra/spiderfoot/app/main.py"
    spec = importlib.util.spec_from_file_location("deadline_sidecar", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SPIDERFOOT_DIR", tmp_path)
    monkeypatch.setattr(module, "DEFAULT_SCAN_TIMEOUT_SECONDS", 0.05)
    result = module._run_command_sync(
        [sys.executable, "-u", "-c", 'import time; print(\'{"type":"asset","data":"example.com"},\', flush=True); time.sleep(60)'], 0,
    )
    assert result["timeout"] is True
    assert result["returncode"] != 0
    records, warning = module._parse_records(result["stdout"])
    assert records == [{"type": "asset", "data": "example.com"}]
    assert warning


def test_sidecar_allows_productive_output_but_stops_idle_process(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / "infra/spiderfoot/app/main.py"
    spec = importlib.util.spec_from_file_location("idle_sidecar", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SPIDERFOOT_DIR", tmp_path)
    monkeypatch.setattr(module, "SCAN_IDLE_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(module, "SCAN_POLL_SECONDS", 0.02)
    productive = module._run_command_sync(
        [sys.executable, "-u", "-c", 'import time; [(print(i, flush=True), time.sleep(.1)) for i in range(8)]'], 5,
    )
    assert productive["timeout"] is False
    assert productive["returncode"] == 0
    idle = module._run_command_sync(
        [sys.executable, "-u", "-c", 'import time; print("retained", flush=True); time.sleep(60)'], 5,
    )
    assert idle["timeout"] is True
    assert "retained" in idle["stdout"]
