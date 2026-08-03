from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from cyberdeck.schemas import EvidenceStatus, ThreatEvent


MODEL_VERSION = "cde-bounded-pivot-v1.0.0"
ASSURED = {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
SEARCHABLE_TYPES = {"domain", "email", "phone", "ip", "cve"}


def build_pivot_intelligence(
    events: Iterable[ThreatEvent],
    *,
    max_entities: int = 500,
) -> dict[str, Any]:
    event_list = list(events)
    grouped: dict[tuple[str, str], list[tuple[ThreatEvent, dict[str, Any]]]] = defaultdict(list)
    for event in event_list:
        artifacts = (event.technical_validation or {}).get("unstructured_artifacts") or []
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            artifact_type = str(artifact.get("type") or "").strip().lower()
            value = str(artifact.get("value") or "").strip()
            if not artifact_type or not value or artifact_type == "secret_indicator":
                continue
            grouped[(artifact_type, value.casefold())].append((event, artifact))

    rows = []
    type_counts: Counter[str] = Counter()
    for (artifact_type, _), observations in grouped.items():
        representative = str(observations[0][1].get("value") or "")
        sources = sorted({event.source for event, _ in observations})
        evidence_ids = list(dict.fromkeys(event.canonical_id or event.id for event, _ in observations))
        evidence_urls = list(dict.fromkeys(event.evidence_url for event, _ in observations if event.evidence_url))
        assured = [event for event, _ in observations if event.evidence_status in ASSURED]
        scope_related = [
            event
            for event, _ in observations
            if event.relationship_to_scope in {"direct", "related", "validated", "confirmed"}
            or event.evidence_status in ASSURED
        ]
        corroborated = len(sources) >= 2 or any(event.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED} for event in assured)
        decision_relevant = bool(scope_related) and corroborated
        confidence = min(
            0.98,
            0.35
            + 0.18 * min(3, len(sources))
            + 0.12 * min(2, len(assured))
            + 0.08 * min(2, len(evidence_urls)),
        )
        rows.append(
            {
                "entity_type": artifact_type,
                "value": representative,
                "observation_count": len(observations),
                "source_count": len(sources),
                "sources": sources[:12],
                "evidence_ids": evidence_ids[:30],
                "evidence_urls": evidence_urls[:12],
                "corroborated": corroborated,
                "decision_relevant": decision_relevant,
                "confidence": round(confidence, 3),
                "risk_contribution": "supports_confidence" if decision_relevant else "context_only",
                "searchable": artifact_type in SEARCHABLE_TYPES,
            }
        )
        type_counts[artifact_type] += 1

    rows.sort(
        key=lambda row: (
            bool(row["decision_relevant"]),
            bool(row["corroborated"]),
            int(row["source_count"]),
            int(row["observation_count"]),
        ),
        reverse=True,
    )
    selected = rows[: max(1, max_entities)]
    return {
        "model_version": MODEL_VERSION,
        "total_entities": len(rows),
        "visible_entities": len(selected),
        "corroborated_entities": sum(1 for row in rows if row["corroborated"]),
        "decision_relevant_entities": sum(1 for row in rows if row["decision_relevant"]),
        "entity_types": dict(sorted(type_counts.items())),
        "entities": selected,
        "collection_policy": {
            "result_cap": None,
            "execution": "finite_source_plans_with_persistent_deduplicated_monitoring_cycles",
            "deduplication": "canonical_entity_and_evidence_id",
            "risk_rule": "volume_never_increases_risk_without_scope_relationship_and_validation",
        },
        "limitations": [
            "Una coincidencia textual crea un candidato, no una relación directa.",
            "Hashes y posibles secretos no se convierten en consultas ni se muestran como credenciales.",
            "La correlación mejora cobertura y confianza; no eleva severidad por volumen.",
        ],
    }
