import asyncio

import pytest
from pydantic import ValidationError

from cyberdeck.knowledge import (
    DualWriteKnowledgeBackend,
    InternalKnowledgeBackend,
    KnowledgeRecord,
    OpenCTIKnowledgeBackend,
    assess_opencti_value,
    create_knowledge_backend,
)


def _validated_record() -> KnowledgeRecord:
    return KnowledgeRecord(
        record_id="claim-1",
        kind="validated_relationship",
        payload={"subject": "example.com", "statement": "Validated relationship"},
        validation_status="validated",
        confidence=0.8,
        evidence_references=["evidence-1"],
    )


def test_opencti_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("OPENCTI_MODE", raising=False)
    backend = create_knowledge_backend()
    assert isinstance(backend, InternalKnowledgeBackend)
    assert backend.status()["available"] is True


def test_invalid_mode_falls_back_to_internal(monkeypatch):
    monkeypatch.setenv("OPENCTI_MODE", "unexpected")
    assert isinstance(create_knowledge_backend(), InternalKnowledgeBackend)


def test_opencti_missing_or_down_is_fail_open(tmp_path):
    internal = InternalKnowledgeBackend(tmp_path / "knowledge.sqlite")
    external = OpenCTIKnowledgeBackend(mode="sync_validated", url="http://127.0.0.1:1", token="test", sync_url="http://127.0.0.1:1/sync", timeout_seconds=0.05)
    backend = DualWriteKnowledgeBackend(internal, external)
    result = asyncio.run(backend.write_validated([_validated_record()]))
    assert result.accepted == 1
    assert result.synchronized == 0
    assert result.available is True
    context = asyncio.run(internal.read_context(["example.com"]))
    assert len(context.records) == 1


def test_raw_or_unvalidated_records_cannot_be_created_or_sent():
    with pytest.raises(ValidationError):
        KnowledgeRecord(
            record_id="raw-1",
            kind="raw_data",
            validation_status="raw",
            evidence_references=[],
        )
    invalid = KnowledgeRecord.model_construct(
        record_id="raw-2",
        kind="raw_data",
        payload={"raw": True},
        validation_status="validated",
        confidence=1.0,
        tlp="TLP:CLEAR",
        pap="PAP:GREEN",
        evidence_references=["E-1"],
    )
    backend = OpenCTIKnowledgeBackend(mode="sync_validated", url="https://unused.invalid", token="token")
    result = asyncio.run(backend.write_validated([invalid]))
    assert result.accepted == 0
    assert result.rejected == 1
    assert result.synchronized == 0


def test_default_value_assessment_leaves_opencti_optional():
    assessment = assess_opencti_value()
    assert assessment.conclusion == "dejar opcional"
    assert assessment.value_score == -0.3
