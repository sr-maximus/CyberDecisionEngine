from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from cyberdeck.schemas import EvidenceCapture, RiskFinding, ThreatEvent, utcnow_iso
from cyberdeck.semantics.registry import get_term_registry


CLAIM_EVIDENCE_MODEL_VERSION = "1.1.3"


class Evidence(BaseModel):
    evidence_id: str
    source_id: str
    evidence_type: str
    collected_at: str
    observed_at: Optional[str] = None
    canonical_url: Optional[str] = None
    content_hash: Optional[str] = None
    raw_reference: Optional[str] = None
    query: Optional[str] = None
    original_response: Optional[str] = None
    entity: Optional[str] = None
    relation_to_claim: str = "unlinked"
    evidence_status: str = "raw"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    validation_method: Optional[str] = None
    validator: Optional[str] = None
    TLP: str = "TLP:CLEAR"
    PAP: str = "PAP:GREEN"
    captures: List[EvidenceCapture] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_evidence_semantics(self) -> "Evidence":
        if self.evidence_status in {"validated", "confirmed"}:
            if not self.validation_method or self.validation_method == "not_validated":
                raise ValueError("Validated evidence requires validation_method.")
            if not self.validator:
                raise ValueError("Validated evidence requires validator.")
        return self


class Claim(BaseModel):
    claim_id: str
    statement: str
    subject_entity_ids: List[str]
    scope: str
    claim_type: str
    claim_status: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utcnow_iso)
    last_validated_at: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)
    validation_method: Optional[str] = None
    validator: Optional[str] = None
    confirmation_threshold_passed: bool = False
    unresolved_critical_contradiction: bool = False

    @model_validator(mode="after")
    def enforce_claim_semantics(self) -> "Claim":
        registry = get_term_registry()
        if self.claim_status in {"validated", "confirmed"}:
            registry.validate(
                "validated_finding",
                {
                    "validation_status": self.claim_status,
                    "validation_method": self.validation_method,
                    "validated_at": self.last_validated_at,
                    "validator": self.validator,
                    "evidence_ids": self.evidence_ids,
                },
            )
        if self.claim_status == "confirmed":
            registry.validate(
                "confirmed",
                {
                    "confirmation_threshold_passed": self.confirmation_threshold_passed,
                    "unresolved_critical_contradiction": self.unresolved_critical_contradiction,
                    "evidence_ids": self.evidence_ids,
                },
            )
        return self


class ClaimEvidenceLink(BaseModel):
    claim_id: str
    evidence_id: str
    relation: str
    strength: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: str = Field(default_factory=utcnow_iso)


class ContradictingEvidence(BaseModel):
    contradiction_id: str
    claim_id: str
    evidence_id: str
    statement: str
    severity: str = "material"
    resolved: bool = False
    resolution: Optional[str] = None


class Interpretation(BaseModel):
    interpretation_id: str
    claim_id: str
    what_found: str
    what_demonstrates: str
    what_not_demonstrates: str
    validation_summary: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    limitations: List[str] = Field(default_factory=list)


class Decision(BaseModel):
    decision_id: str
    claim_id: str
    decision: str
    owner: str
    recommended_action: str
    closure_criteria: str
    status: str = "proposed"


class ClaimEvidenceBundle(BaseModel):
    claims: List[Claim] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    links: List[ClaimEvidenceLink] = Field(default_factory=list)
    contradictions: List[ContradictingEvidence] = Field(default_factory=list)
    interpretations: List[Interpretation] = Field(default_factory=list)
    decisions: List[Decision] = Field(default_factory=list)

    def presentations(self) -> List[Dict[str, Any]]:
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        interpretation_by_claim = {item.claim_id: item for item in self.interpretations}
        decision_by_claim = {item.claim_id: item for item in self.decisions}
        rows: List[Dict[str, Any]] = []
        for claim in self.claims:
            interpretation = interpretation_by_claim.get(claim.claim_id)
            decision = decision_by_claim.get(claim.claim_id)
            evidence = [evidence_by_id[item] for item in claim.evidence_ids if item in evidence_by_id]
            rows.append(
                {
                    "claim_id": claim.claim_id,
                    "claim_status": claim.claim_status,
                    "what_found": interpretation.what_found if interpretation else claim.statement,
                    "what_demonstrates": interpretation.what_demonstrates if interpretation else "Relación pendiente de interpretación.",
                    "what_not_demonstrates": interpretation.what_not_demonstrates if interpretation else "No demuestra por sí solo compromiso o incidente.",
                    "how_validated": interpretation.validation_summary if interpretation else claim.validation_method or "No validado",
                    "evidence": [item.model_dump() for item in evidence],
                    "confidence": claim.confidence,
                    "limitations": claim.limitations,
                    "decision": decision.decision if decision else "Revisión analítica",
                    "owner": decision.owner if decision else "Analista de ciberinteligencia",
                    "closure_criteria": decision.closure_criteria if decision else "Validar o descartar la afirmación con evidencia reproducible.",
                }
            )
        return rows


def build_claim_evidence_bundle(
    events: List[ThreatEvent],
    findings: List[RiskFinding],
    subject_entity_ids: List[str],
    scope: str,
) -> ClaimEvidenceBundle:
    evidence_rows: List[Evidence] = []
    event_by_id: Dict[str, ThreatEvent] = {}
    event_aliases: Dict[str, List[str]] = {}
    for event in events:
        evidence_id = event.canonical_id or event.id
        event_by_id[evidence_id] = event
        for alias in (evidence_id, event.id, event.canonical_id, event.external_id, event.evidence_url):
            normalized_alias = str(alias or "").strip()
            if normalized_alias:
                event_aliases.setdefault(normalized_alias, []).append(evidence_id)
        validation_method = _validation_method(event)
        evidence_status = str(getattr(event.evidence_status, "value", event.evidence_status))
        if evidence_status in {"validated", "confirmed"} and not validation_method:
            evidence_status = "related"
        tlp = _tag_value(event.tags, "tlp") or "CLEAR"
        pap = _tag_value(event.tags, "pap") or "GREEN"
        evidence_rows.append(
            Evidence(
                evidence_id=evidence_id,
                source_id=event.source,
                evidence_type=str(getattr(event.record_kind, "value", event.record_kind)),
                collected_at=event.observed_at,
                observed_at=event.observed_at,
                canonical_url=event.evidence_url,
                content_hash=event.content_hash,
                raw_reference=event.evidence_url or event.external_id,
                query=str((event.technical_validation or {}).get("query") or "") or None,
                original_response=str(
                    (event.technical_validation or {}).get("original_response")
                    or (event.technical_validation or {}).get("response_excerpt")
                    or ""
                ) or None,
                entity=event.asset or event.host or event.indicator,
                relation_to_claim=event.relationship_to_scope,
                evidence_status=evidence_status,
                confidence=event.confidence_score,
                validation_method=validation_method,
                validator=event.source if validation_method else None,
                TLP=tlp if tlp.startswith("TLP:") else f"TLP:{tlp}",
                PAP=pap if pap.startswith("PAP:") else f"PAP:{pap}",
                captures=event.captures,
            )
        )

    claims: List[Claim] = []
    links: List[ClaimEvidenceLink] = []
    interpretations: List[Interpretation] = []
    decisions: List[Decision] = []
    for index, finding in enumerate(findings, start=1):
        claim_id = finding.finding_id or f"claim-{index:04d}"
        status = str(getattr(finding.evidence_status, "value", finding.evidence_status))
        claim_status = "confirmed" if status == "confirmed" else "validated" if status == "validated" else "supported"
        evidence_ids: List[str] = []
        for reference in [*finding.linked_evidence_ids, *finding.evidence]:
            for evidence_id in event_aliases.get(str(reference or "").strip(), []):
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
        event = event_by_id.get(evidence_ids[0]) if evidence_ids else None
        validation_method = finding.validation_method if finding.validation_method not in {"", "not_validated"} else _validation_method(event)
        validated_at = event.observed_at if event and claim_status in {"validated", "confirmed"} else None
        validator = event.source if event and claim_status in {"validated", "confirmed"} else None
        if not evidence_ids:
            claim_status = "candidate"
            validated_at = None
            validator = None
        elif claim_status in {"validated", "confirmed"} and not validation_method:
            claim_status = "supported"
            validated_at = None
            validator = None
        claim = Claim(
            claim_id=claim_id,
            statement=finding.title,
            subject_entity_ids=subject_entity_ids,
            scope=scope,
            claim_type="risk_finding",
            claim_status=claim_status,
            confidence=finding.confidence_score,
            evidence_ids=evidence_ids,
            contradicting_evidence_ids=[],
            last_validated_at=validated_at,
            limitations=finding.assumptions,
            validation_method=validation_method,
            validator=validator,
            confirmation_threshold_passed=claim_status == "confirmed" and bool(evidence_ids),
            unresolved_critical_contradiction=False,
        )
        claims.append(claim)
        for evidence_id in evidence_ids:
            links.append(ClaimEvidenceLink(claim_id=claim_id, evidence_id=evidence_id, relation="supports", strength=finding.confidence_score))
        interpretations.append(
            Interpretation(
                interpretation_id=f"interpretation-{claim_id}",
                claim_id=claim_id,
                what_found=finding.title,
                what_demonstrates=_demonstrates(finding, event),
                what_not_demonstrates=_does_not_demonstrate(finding),
                validation_summary=validation_method or "Pendiente de validación reproducible",
                confidence=finding.confidence_score,
                limitations=finding.assumptions,
            )
        )
        recommendation = finding.recommendations[0] if finding.recommendations else "Validar la condición y priorizar tratamiento según impacto."
        decisions.append(
            Decision(
                decision_id=f"decision-{claim_id}",
                claim_id=claim_id,
                decision="Evaluar tratamiento con el responsable del riesgo.",
                owner=finding.owner,
                recommended_action=recommendation,
                closure_criteria=finding.closure_evidence[0] if finding.closure_evidence else "Evidencia de corrección y revalidación técnica sin recurrencia.",
            )
        )
    return ClaimEvidenceBundle(claims=claims, evidence=evidence_rows, links=links, interpretations=interpretations, decisions=decisions)


def _validation_method(event: Optional[ThreatEvent]) -> Optional[str]:
    if event is None:
        return None
    validation = event.technical_validation or {}
    method = str(validation.get("validation_method") or validation.get("method") or event.validation_result or "").strip()
    return None if method in {"", "not_validated", "requires_owner_validation"} else method


def _demonstrates(finding: RiskFinding, event: Optional[ThreatEvent]) -> str:
    finding_method = finding.validation_method if finding.validation_method not in {"", "not_validated"} else None
    validation_method = _validation_method(event) or finding_method
    if event and event.relationship_to_scope == "direct" and validation_method:
        return "Demuestra una condición reproducible vinculada directamente con el alcance analizado."
    finding_status = str(getattr(finding.evidence_status, "value", finding.evidence_status))
    if event and finding_status in {"validated", "confirmed"} and validation_method:
        return "Demuestra que existe un registro validado enlazado exactamente con el hallazgo; la relación directa y su impacto conservan las limitaciones indicadas."
    return "Respalda una posibilidad de riesgo que requiere validación adicional antes de tratarse como hallazgo validado."


def _does_not_demonstrate(finding: RiskFinding) -> str:
    if finding.incident_confirmed:
        return "No atribuye automáticamente actor, intención ni alcance total del impacto."
    return "No demuestra por sí solo explotación, compromiso, atribución ni incidente confirmado."


def _tag_value(tags: List[str], prefix: str) -> Optional[str]:
    needle = f"{prefix.lower()}:"
    for tag in tags:
        if tag.lower().startswith(needle):
            return tag.split(":", 1)[1].strip()
    return None
