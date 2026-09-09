from __future__ import annotations

import re
from collections import Counter
from typing import Any, Sequence

from cyberdeck.schemas import EvidenceStatus, ThreatEvent


EVIDENCE_REVIEW_MODEL_VERSION = "cde-grounded-evidence-review-v1.0.0"
_ASSURED = {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
_EXCLUDED = {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}
_ACTIONABLE_TERMS = re.compile(
    r"\b(?:breach|filtraci[oó]n|ransomware|malware|phishing|fraude|fraud|scam|"
    r"vulnerab|cve-\d{4}-\d+|credential|credencial|leak|compromise|ataque|attack|"
    r"suplantaci[oó]n|typosquat|cybersquat|ciberocupaci[oó]n)\b",
    re.IGNORECASE,
)


def build_evidence_review_summary(
    events: Sequence[ThreatEvent], mode: str = "manual"
) -> dict[str, Any]:
    selected_mode = "ai_assisted" if mode == "ai_assisted" else "manual"
    reviewable = [event for event in events if event.evidence_status not in _EXCLUDED]
    proposals = [_proposal(event, selected_mode) for event in reviewable]
    status_counts = Counter(proposal["recommendation"] for proposal in proposals)
    return {
        "model_version": EVIDENCE_REVIEW_MODEL_VERSION,
        "mode": selected_mode,
        "provider": "deterministic_grounded_triage",
        "automatic_validation": False,
        "reviewable_count": len(reviewable),
        "human_reviewed_count": sum(bool(event.human_reviewed) for event in reviewable),
        "assured_count": sum(event.evidence_status in _ASSURED for event in reviewable),
        "pending_human_decision_count": sum(
            proposal["recommendation"]
            in {
                "manual_review_required",
                "retain_for_human_validation",
                "possible_false_positive",
            }
            for proposal in proposals
        ),
        "recommendation_counts": dict(status_counts),
        "proposals": proposals,
        "policy": (
            "La revisión asistida prioriza registros y explica sus criterios; nunca cambia por sí sola "
            "el estado de evidencia, un hallazgo, un riesgo ni un incidente."
        ),
    }


def _proposal(event: ThreatEvent, mode: str) -> dict[str, Any]:
    text = " ".join(
        filter(
            None,
            (
                event.title,
                event.category,
                event.actor or "",
                event.host or "",
                event.indicator or "",
                " ".join(event.tags),
            ),
        )
    )
    evidence_id = str(event.public_evidence_id or event.canonical_id or event.id)
    relationship = str(event.relationship_to_scope or "").casefold()
    contradictions = max(0, int(event.contradiction_count or 0))
    has_url = bool(event.original_artifact_url or event.evidence_url)
    actionable = bool(_ACTIONABLE_TERMS.search(text))
    direct_relationship = relationship in {
        "direct",
        "direct_scope",
        "scope_asset",
        "owned_asset",
        "explicit_mention",
    }

    if event.human_reviewed or event.evidence_status in _ASSURED:
        recommendation = "already_reviewed"
        rationale = "El registro ya cuenta con revisión humana o evidencia asegurada."
    elif contradictions:
        recommendation = "retain_for_human_validation"
        rationale = "Existen contradicciones pendientes que requieren resolución humana."
    elif not has_url or not relationship or relationship in {"unknown", "unrelated"}:
        recommendation = "possible_false_positive"
        rationale = "Falta una URL verificable o una relación explícita con el alcance."
    elif actionable and direct_relationship:
        recommendation = "retain_for_human_validation"
        rationale = "La señal contiene un término accionable y una relación directa declarada."
    else:
        recommendation = "context_only"
        rationale = "El registro aporta contexto, pero no sustenta por sí solo un hallazgo o riesgo."

    if mode == "manual" and recommendation not in {"already_reviewed"}:
        recommendation = "manual_review_required"
        rationale = "El usuario seleccionó revisión manual; el registro conserva su estado actual."

    return {
        "evidence_id": evidence_id,
        "recommendation": recommendation,
        "rationale": rationale,
        "current_status": str(getattr(event.evidence_status, "value", event.evidence_status)),
        "confidence": round(max(0.0, min(1.0, float(event.confidence_score or 0.0))), 3),
        "has_verifiable_url": has_url,
        "direct_scope_relationship": direct_relationship,
        "actionable_terms_present": actionable,
        "contradiction_count": contradictions,
        "requires_human_decision": recommendation not in {"already_reviewed", "context_only"},
    }
