import asyncio
import json

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RecordKind, RunContext, ThreatEvent
from cyberdeck.storage.db import connect, store_events
from cyberdeck_api.jobs import RunStore


def _context() -> RunContext:
    return RunContext(
        organization=OrganizationProfile(
            name="Example",
            sector="",
            country="",
            author="test",
            authorized_scope=True,
            primary_domains=["example.com"],
        ),
        mode="snapshot",
        lookback_days=30,
        processing_summary={"raw_records_collected": 1, "unique_records": 1},
    )


def _run_store(state_path):
    # The host test runtime is Python 3.9 while the application requires 3.13;
    # create the legacy asyncio primitive inside an explicit loop.
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return RunStore(state_path=state_path)
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def test_sqlite_persists_canonical_evidence_fields(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    database = tmp_path / "evidence.sqlite"
    event = ThreatEvent(
        id="collector-id",
        canonical_id="canonical-id",
        content_hash="sha256-value",
        title="Validated DNS evidence",
        category="attack_surface",
        source="public_dns",
        evidence_url="https://example.com/evidence",
        record_kind=RecordKind.VALIDATED_TECHNICAL_EVIDENCE,
        evidence_status=EvidenceStatus.VALIDATED,
        confidence_score=0.91,
        relationship_to_scope="direct_domain_match",
        validation_result="validated",
        asset="example.com",
        host="example.com",
        indicator="v=DMARC1",
        external_id="dns:example.com:dmarc",
        vulnerability_status="not_applicable",
        attack_mapping_status="preventive_reference",
    )

    assert store_events([event], str(database)) == 1

    conn = connect(str(database))
    row = conn.execute(
        "SELECT id, original_id, canonical_id, record_kind, evidence_status, confidence_score, payload_json FROM events"
    ).fetchone()
    conn.close()

    assert row[:5] == (
        "canonical-id",
        "collector-id",
        "canonical-id",
        "validated_technical_evidence",
        "validated",
    )
    assert row[5] == 0.91
    assert json.loads(row[6])["technical_validation"] == {}


def test_run_context_uses_atomic_local_round_trip(tmp_path):
    store = _run_store(tmp_path / "runs.json")
    store.database_url = None
    store.run_dir = tmp_path / "contexts"
    path = store._context_path("run-1")

    store._write_context(path, _context())
    restored = store._read_context(path)

    assert restored.organization.primary_domains == ["example.com"]
    assert restored.processing_summary["unique_records"] == 1
    assert not path.with_suffix(".tmp").exists()


def test_run_context_falls_back_to_postgres_payload(tmp_path, monkeypatch):
    store = _run_store(tmp_path / "runs.json")
    store.database_url = "postgresql://configured"
    store.run_dir = tmp_path / "contexts"
    expected = _context().model_dump(mode="json")
    monkeypatch.setattr(store, "_load_context_postgres", lambda run_id: expected if run_id == "run-2" else None)

    restored = store._read_context(store._context_path("run-2"))

    assert restored.organization.name == "Example"
    assert restored.processing_summary["raw_records_collected"] == 1
