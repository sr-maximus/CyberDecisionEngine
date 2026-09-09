import asyncio
import threading
import time

import pytest

from cyberdeck.analysis.multidomain import sanitize_public_payload
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RunContext, ThreatEvent
from cyberdeck.reporting.html_report import prepare_context_for_report
from cyberdeck_api.jobs import RunStore
from cyberdeck_api.models import AnalysisSummary, DomainAnalysisRequest, EvidenceReviewBatchRequest, RunRecord


def test_review_buttons_persist_and_allow_reversing_false_positive(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = RunStore(state_path=tmp_path / "runs.json")
    store.run_dir = tmp_path / "contexts"
    monkeypatch.setattr(store, "_schedule_auto_report", lambda *args: None)
    run = RunRecord(id="review-fixture", status="completed", request=DomainAnalysisRequest(domains=["example.com"], authorized_scope=True))
    store._runs[run.id] = run
    event = ThreatEvent(id="evidence-one", title="Public evidence", category="brand_fraud", source="fixture", evidence_url="https://example.com/evidence", evidence_status=EvidenceStatus.RELATED)
    context = RunContext(organization=OrganizationProfile(name="Example", primary_domains=["example.com"], sector="energy", country="CO", author="test"), mode="deep", lookback_days=30, raw_events=[event])
    context = prepare_context_for_report(context, run.id)
    store._write_context(store._context_path(run.id), context)
    public_id = sanitize_public_payload(context.raw_events[0].model_dump(mode="json"))["id"]

    async def check():
        for status in ("validated", "false_positive", "validated", "pending"):
            updated = await store.review_evidence(run.id, public_id, status, "test-reviewer")
            persisted = store._read_context(store._context_path(run.id))
            record = persisted.raw_events[0]
            assert record.technical_validation["human_review"]["status"] == status
            assert ("false_positive" in record.tags) == (status == "false_positive")
            if status != "pending":
                assert record.evidence_status.value == status
            assert persisted.processing_summary["validated_evidence"] == int(status == "validated")
            assert persisted.processing_summary["false_positives"] == int(status == "false_positive")
            assert updated.report is None
            assert updated.report_status == "not_requested"
        await store.stop()
    asyncio.run(check())


def test_batch_reviews_are_atomic_serialized_and_recompute_once(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = RunStore(state_path=tmp_path / "runs.json")
    store.run_dir = tmp_path / "contexts"
    monkeypatch.setattr(store, "_schedule_auto_report", lambda *args: None)
    run = RunRecord(id="batch-review", status="completed", request=DomainAnalysisRequest(domains=["example.com"], authorized_scope=True))
    store._runs[run.id] = run
    context = RunContext(organization=OrganizationProfile(name="Example", primary_domains=["example.com"], sector="energy", country="CO", author="test"), mode="deep", lookback_days=30, raw_events=[
        ThreatEvent(id=f"ev-{i}", title=f"Evidence {i}", category="brand_fraud", source="fixture", evidence_url=f"https://example.com/{i}", evidence_status=EvidenceStatus.RELATED)
        for i in range(3)
    ])
    path = store._context_path(run.id)
    store._write_context(path, context)
    calls = []
    main_thread = threading.get_ident()

    def prepare(context, run_id):
        assert threading.get_ident() != main_thread
        calls.append(run_id)
        time.sleep(0.03)
        return context

    def summarize(*args):
        assert threading.get_ident() != main_thread
        return AnalysisSummary()

    monkeypatch.setattr("cyberdeck_api.jobs.prepare_context_for_report", prepare)
    monkeypatch.setattr("cyberdeck_api.jobs.summarize_context", summarize)

    async def check():
        change = lambda i, status: {"evidence_id": f"ev-{i}", "status": status}
        await store.review_evidence_batch(run.id, [change(0, "validated"), change(1, "validated"), change(0, "false_positive")])
        assert len(calls) == 1
        persisted = store._read_context(path)
        assert [e.technical_validation.get("human_review", {}).get("status") for e in persisted.raw_events] == ["false_positive", "validated", None]
        before = path.read_bytes()
        with pytest.raises(ValueError, match="not found"):
            await store.review_evidence_batch(run.id, [change(0, "pending"), change(999, "validated")])
        assert path.read_bytes() == before
        assert len(calls) == 1
        await asyncio.gather(
            store.review_evidence_batch(run.id, [change(0, "validated")]),
            store.review_evidence_batch(run.id, [change(2, "validated")]),
        )
        assert len(calls) == 3
        assert all(e.technical_validation["human_review"]["status"] == "validated" for e in store._read_context(path).raw_events)
        # Report generation and review share the same lock.
        async with store._active_report_lock(run.id):
            task = asyncio.create_task(store.review_evidence_batch(run.id, [change(1, "pending")]))
            await asyncio.sleep(0.02)
            assert not task.done()
        await task
        await store.stop()

    asyncio.run(check())


def test_review_batch_request_bounds_and_statuses():
    with pytest.raises(ValueError):
        EvidenceReviewBatchRequest(reviews=[])
    with pytest.raises(ValueError):
        EvidenceReviewBatchRequest(reviews=[{"evidence_id": "ev", "status": "invalid"}])
    with pytest.raises(ValueError):
        EvidenceReviewBatchRequest(reviews=[{"evidence_id": "ev", "status": "validated"}] * 501)


def test_review_rebuilds_only_applicable_risk_findings():
    event = ThreatEvent(id="risk-review", title="example.com phishing", category="phishing", source="fixture", evidence_url="https://example.com/phishing", evidence_status=EvidenceStatus.RELATED)
    context = RunContext(organization=OrganizationProfile(name="Example", primary_domains=["example.com"], sector="energy", country="CO", author="test"), mode="deep", lookback_days=30, raw_events=[event])
    for status, has_risks in [("validated", True), ("false_positive", False), ("validated", True)]:
        RunStore._apply_evidence_review(context.raw_events[0], status, "test-reviewer", "")
        context.processing_summary.pop("unique_records", None)
        context = prepare_context_for_report(context, "risk-review")
        assert bool(context.risk_findings) is has_risks
    context.raw_events[0].category = "web_search"
    context.raw_events[0].tags = []
    context = prepare_context_for_report(context, "risk-review")
    assert context.risk_findings == []


def test_evidence_register_is_not_limited_to_dashboard_sample(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = RunStore(state_path=tmp_path / "runs.json")
    store.run_dir = tmp_path / "contexts"
    run = RunRecord(id="full-evidence", status="completed", request=DomainAnalysisRequest(domains=["example.com"], authorized_scope=True))
    store._runs[run.id] = run
    context = RunContext(organization=OrganizationProfile(name="Example", primary_domains=["example.com"], sector="energy", country="CO", author="test"), mode="deep", lookback_days=30, raw_events=[
        ThreatEvent(id=f"ev-{i}", title=f"Evidence {i}", category="web_search", source="fixture", evidence_url=f"https://example.com/{i}") for i in range(805)
    ])
    store._write_context(store._context_path(run.id), context)
    async def check():
        assert len(await store.get_evidence(run.id)) == 805
        assert await store.get_evidence("not-a-run") is None
        await store.stop()
    asyncio.run(check())
