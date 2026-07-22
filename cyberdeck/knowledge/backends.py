from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional

import httpx
from pydantic import BaseModel, Field, model_validator

from cyberdeck.semantics.claim_evidence import ClaimEvidenceBundle
from cyberdeck.settings import PROJECT_ROOT


OpenCTIMode = Literal["disabled", "read_context", "sync_validated", "system_of_record"]
OPENCTI_MODES = {"disabled", "read_context", "sync_validated", "system_of_record"}
ALLOWED_OPENCTI_KINDS = {
    "normalized_entity",
    "validated_relationship",
    "indicator",
    "applicable_vulnerability",
    "actor",
    "campaign",
    "malware",
    "technique",
    "sighting",
    "report",
}
PROHIBITED_OPENCTI_KINDS = {
    "raw_data",
    "raw_record",
    "duplicate_url",
    "unvalidated_news",
    "candidate_scenario",
    "ai_proposed_relationship",
    "unlinked_record",
    "cache",
    "false_positive",
}


class KnowledgeRecord(BaseModel):
    record_id: str
    kind: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    validation_status: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    tlp: str = "TLP:CLEAR"
    pap: str = "PAP:GREEN"
    evidence_references: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validated_knowledge_only(self) -> "KnowledgeRecord":
        if self.validation_status not in {"validated", "confirmed"}:
            raise ValueError("Knowledge records must be validated or confirmed.")
        if self.kind in PROHIBITED_OPENCTI_KINDS:
            raise ValueError(f"Knowledge record kind '{self.kind}' is prohibited.")
        if not self.evidence_references:
            raise ValueError("Validated knowledge requires evidence references.")
        return self


class KnowledgeContext(BaseModel):
    backend: str
    mode: OpenCTIMode = "disabled"
    records: List[Dict[str, Any]] = Field(default_factory=list)
    available: bool = True
    warning: Optional[str] = None


class KnowledgeSyncResult(BaseModel):
    backend: str
    mode: OpenCTIMode = "disabled"
    accepted: int = 0
    rejected: int = 0
    synchronized: int = 0
    available: bool = True
    warning: Optional[str] = None


class OpenCTIValueAssessment(BaseModel):
    graph_requirement: float = Field(ge=0.0, le=1.0)
    stix_interoperability_requirement: float = Field(ge=0.0, le=1.0)
    collaboration_requirement: float = Field(ge=0.0, le=1.0)
    stream_integration_requirement: float = Field(ge=0.0, le=1.0)
    historical_knowledge_requirement: float = Field(ge=0.0, le=1.0)
    duplication_reduction_requirement: float = Field(ge=0.0, le=1.0)
    deployment_cost: float = Field(ge=0.0, le=1.0)
    operational_complexity: float = Field(ge=0.0, le=1.0)
    data_duplication_risk: float = Field(ge=0.0, le=1.0)
    value_score: float = Field(ge=-1.0, le=1.0)
    conclusion: Literal["configurar", "ejecutar prueba", "dejar opcional", "no utilizar"]
    rationale: str


class KnowledgeBackendPort(ABC):
    name = "knowledge-backend"
    mode: OpenCTIMode = "disabled"

    @abstractmethod
    async def read_context(self, subjects: List[str]) -> KnowledgeContext:
        raise NotImplementedError

    @abstractmethod
    async def write_validated(self, records: Iterable[KnowledgeRecord]) -> KnowledgeSyncResult:
        raise NotImplementedError

    @abstractmethod
    def status(self) -> Dict[str, Any]:
        raise NotImplementedError


class InternalKnowledgeBackend(KnowledgeBackendPort):
    name = "internal"
    mode: OpenCTIMode = "disabled"

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or PROJECT_ROOT / "data" / "knowledge_backend.sqlite"

    async def read_context(self, subjects: List[str]) -> KnowledgeContext:
        return await asyncio.to_thread(self._read, subjects)

    async def write_validated(self, records: Iterable[KnowledgeRecord]) -> KnowledgeSyncResult:
        rows = list(records)
        return await asyncio.to_thread(self._write, rows)

    def status(self) -> Dict[str, Any]:
        return {"backend": self.name, "mode": self.mode, "available": True, "path": str(self.path)}

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS validated_knowledge (
                record_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                validation_status TEXT NOT NULL,
                confidence REAL NOT NULL,
                tlp TEXT NOT NULL,
                pap TEXT NOT NULL,
                evidence_references TEXT NOT NULL,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        return connection

    def _read(self, subjects: List[str]) -> KnowledgeContext:
        if not subjects:
            return KnowledgeContext(backend=self.name, records=[])
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT record_id, kind, validation_status, confidence, tlp, pap, evidence_references, payload "
                "FROM validated_knowledge ORDER BY updated_at DESC LIMIT 500"
            ).fetchall()
        finally:
            connection.close()
        needles = {item.strip().lower() for item in subjects if item.strip()}
        records: List[Dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row[7])
            blob = json.dumps(payload, ensure_ascii=False).lower()
            if needles and not any(item in blob for item in needles):
                continue
            records.append(
                {
                    "record_id": row[0],
                    "kind": row[1],
                    "validation_status": row[2],
                    "confidence": row[3],
                    "tlp": row[4],
                    "pap": row[5],
                    "evidence_references": json.loads(row[6]),
                    "payload": payload,
                }
            )
        return KnowledgeContext(backend=self.name, records=records)

    def _write(self, records: List[KnowledgeRecord]) -> KnowledgeSyncResult:
        connection = self._connect()
        accepted = 0
        try:
            for record in records:
                connection.execute(
                    """
                    INSERT INTO validated_knowledge
                        (record_id, kind, validation_status, confidence, tlp, pap, evidence_references, payload, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(record_id) DO UPDATE SET
                        kind=excluded.kind,
                        validation_status=excluded.validation_status,
                        confidence=excluded.confidence,
                        tlp=excluded.tlp,
                        pap=excluded.pap,
                        evidence_references=excluded.evidence_references,
                        payload=excluded.payload,
                        updated_at=CURRENT_TIMESTAMP
                    """,
                    (
                        record.record_id,
                        record.kind,
                        record.validation_status,
                        record.confidence,
                        record.tlp,
                        record.pap,
                        json.dumps(record.evidence_references, ensure_ascii=False),
                        json.dumps(record.payload, ensure_ascii=False, default=str),
                    ),
                )
                accepted += 1
            connection.commit()
        finally:
            connection.close()
        return KnowledgeSyncResult(backend=self.name, accepted=accepted, synchronized=accepted)


class OpenCTIKnowledgeBackend(KnowledgeBackendPort):
    name = "opencti"

    def __init__(
        self,
        mode: OpenCTIMode = "disabled",
        url: Optional[str] = None,
        token: Optional[str] = None,
        sync_url: Optional[str] = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.mode = _normalize_mode(mode)
        self.url = (url or os.getenv("OPENCTI_URL") or "").rstrip("/")
        self.token = token or os.getenv("OPENCTI_TOKEN") or os.getenv("OPENCTI_API_TOKEN") or ""
        self.sync_url = (sync_url or os.getenv("OPENCTI_SYNC_URL") or "").strip()
        self.timeout_seconds = timeout_seconds

    async def read_context(self, subjects: List[str]) -> KnowledgeContext:
        if self.mode not in {"read_context", "system_of_record"}:
            return KnowledgeContext(backend=self.name, mode=self.mode, available=False, warning="Lectura OpenCTI deshabilitada por modo.")
        unavailable = self._configuration_warning()
        if unavailable:
            return KnowledgeContext(backend=self.name, mode=self.mode, available=False, warning=unavailable)
        try:
            records: List[Dict[str, Any]] = []
            for subject in subjects[:20]:
                payload = await self._graphql(
                    "query KnowledgeContext($search: String!) { stixCoreObjects(search: $search, first: 50) "
                    "{ edges { node { id entity_type standard_id created_at updated_at } } } }",
                    {"search": subject},
                )
                records.extend(((payload.get("data") or {}).get("stixCoreObjects") or {}).get("edges") or [])
            return KnowledgeContext(backend=self.name, mode=self.mode, records=records)
        except Exception as exc:
            return KnowledgeContext(backend=self.name, mode=self.mode, available=False, warning=f"OpenCTI no disponible: {type(exc).__name__}")

    async def write_validated(self, records: Iterable[KnowledgeRecord]) -> KnowledgeSyncResult:
        rows = list(records)
        allowed = [item for item in rows if item.kind in ALLOWED_OPENCTI_KINDS and item.validation_status in {"validated", "confirmed"}]
        rejected = len(rows) - len(allowed)
        if self.mode not in {"sync_validated", "system_of_record"}:
            return KnowledgeSyncResult(backend=self.name, mode=self.mode, rejected=rejected, available=False, warning="Sincronización OpenCTI deshabilitada por modo.")
        unavailable = self._configuration_warning()
        if unavailable:
            return KnowledgeSyncResult(backend=self.name, mode=self.mode, accepted=len(allowed), rejected=rejected, available=False, warning=unavailable)
        if not self.sync_url:
            return KnowledgeSyncResult(
                backend=self.name,
                mode=self.mode,
                accepted=len(allowed),
                rejected=rejected,
                available=False,
                warning="OPENCTI_SYNC_URL no configurada; no se enviaron registros.",
            )
        try:
            body = {"records": [item.model_dump() for item in allowed], "contract": "validated-knowledge-v1"}
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(self.sync_url, headers=self._headers(), json=body)
                response.raise_for_status()
            return KnowledgeSyncResult(backend=self.name, mode=self.mode, accepted=len(allowed), rejected=rejected, synchronized=len(allowed))
        except Exception as exc:
            return KnowledgeSyncResult(
                backend=self.name,
                mode=self.mode,
                accepted=len(allowed),
                rejected=rejected,
                available=False,
                warning=f"Sincronización OpenCTI omitida: {type(exc).__name__}",
            )

    def status(self) -> Dict[str, Any]:
        warning = self._configuration_warning()
        return {
            "backend": self.name,
            "mode": self.mode,
            "available": not bool(warning),
            "configured": not bool(warning),
            "warning": warning,
        }

    async def _graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(f"{self.url}/graphql", headers=self._headers(), json={"query": query, "variables": variables})
            response.raise_for_status()
            payload = response.json()
            if payload.get("errors"):
                raise RuntimeError("OpenCTI GraphQL returned errors.")
            return payload

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _configuration_warning(self) -> Optional[str]:
        if self.mode == "disabled":
            return "OpenCTI deshabilitado."
        if not self.url or not self.token:
            return "OpenCTI no configurado; se mantiene el backend interno."
        return None


class DualWriteKnowledgeBackend(KnowledgeBackendPort):
    name = "dual-write"

    def __init__(self, internal: InternalKnowledgeBackend, external: OpenCTIKnowledgeBackend) -> None:
        self.internal = internal
        self.external = external
        self.mode = external.mode

    async def read_context(self, subjects: List[str]) -> KnowledgeContext:
        internal_context, external_context = await asyncio.gather(
            self.internal.read_context(subjects),
            self.external.read_context(subjects),
        )
        return KnowledgeContext(
            backend=self.name,
            mode=self.mode,
            records=[*internal_context.records, *external_context.records],
            available=True,
            warning=external_context.warning,
        )

    async def write_validated(self, records: Iterable[KnowledgeRecord]) -> KnowledgeSyncResult:
        rows = list(records)
        internal_result, external_result = await asyncio.gather(
            self.internal.write_validated(rows),
            self.external.write_validated(rows),
        )
        return KnowledgeSyncResult(
            backend=self.name,
            mode=self.mode,
            accepted=internal_result.accepted,
            rejected=external_result.rejected,
            synchronized=external_result.synchronized,
            available=True,
            warning=external_result.warning,
        )

    def status(self) -> Dict[str, Any]:
        return {"backend": self.name, "mode": self.mode, "available": True, "internal": self.internal.status(), "external": self.external.status()}


def create_knowledge_backend(mode: Optional[str] = None) -> KnowledgeBackendPort:
    selected = _normalize_mode(mode or os.getenv("OPENCTI_MODE", "disabled"))
    internal = InternalKnowledgeBackend()
    if selected == "disabled":
        return internal
    return DualWriteKnowledgeBackend(internal, OpenCTIKnowledgeBackend(mode=selected))


def knowledge_records_from_bundle(bundle: ClaimEvidenceBundle) -> List[KnowledgeRecord]:
    evidence_by_id = {item.evidence_id: item for item in bundle.evidence}
    records: List[KnowledgeRecord] = []
    for claim in bundle.claims:
        if claim.claim_status not in {"validated", "confirmed"} or not claim.evidence_ids:
            continue
        supporting = [evidence_by_id[item] for item in claim.evidence_ids if item in evidence_by_id]
        if not supporting:
            continue
        records.append(
            KnowledgeRecord(
                record_id=claim.claim_id,
                kind="validated_relationship",
                validation_status=claim.claim_status,
                confidence=claim.confidence,
                evidence_references=claim.evidence_ids,
                tlp=supporting[0].TLP,
                pap=supporting[0].PAP,
                payload={
                    "statement": claim.statement,
                    "subject_entity_ids": claim.subject_entity_ids,
                    "scope": claim.scope,
                    "claim_type": claim.claim_type,
                    "limitations": claim.limitations,
                    "last_validated_at": claim.last_validated_at,
                },
            )
        )
    return records


def assess_opencti_value(**overrides: float) -> OpenCTIValueAssessment:
    values = {
        "graph_requirement": 0.45,
        "stix_interoperability_requirement": 0.55,
        "collaboration_requirement": 0.35,
        "stream_integration_requirement": 0.30,
        "historical_knowledge_requirement": 0.65,
        "duplication_reduction_requirement": 0.40,
        "deployment_cost": 0.75,
        "operational_complexity": 0.80,
        "data_duplication_risk": 0.70,
    }
    values.update(overrides)
    benefit = sum(values[key] for key in list(values)[:6]) / 6
    cost = sum(values[key] for key in ("deployment_cost", "operational_complexity", "data_duplication_risk")) / 3
    score = round(benefit - cost, 4)
    if score >= 0.35:
        conclusion = "configurar"
    elif score >= 0.10:
        conclusion = "ejecutar prueba"
    elif score >= -0.35:
        conclusion = "dejar opcional"
    else:
        conclusion = "no utilizar"
    return OpenCTIValueAssessment(
        **values,
        value_score=score,
        conclusion=conclusion,
        rationale="El valor se decide por necesidades verificables de grafo, interoperabilidad y colaboración, descontando costo, complejidad y duplicación; pertenecer al ecosistema CTI no es criterio suficiente.",
    )


def _normalize_mode(mode: str) -> OpenCTIMode:
    candidate = (mode or "disabled").strip().lower()
    if candidate not in OPENCTI_MODES:
        return "disabled"
    return candidate  # type: ignore[return-value]
