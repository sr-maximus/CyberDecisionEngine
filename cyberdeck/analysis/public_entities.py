from __future__ import annotations

from collections import Counter
from typing import Any

from cyberdeck.schemas import OrganizationProfile, ThreatEvent


_ENTITY_PREFIXES = {
    "email": "email",
    "phone": "phone",
    "person_candidate": "person",
}


def build_public_entity_intelligence(
    events: list[ThreatEvent],
    organization: OrganizationProfile,
) -> dict[str, Any]:
    """Build a traceable inventory of public contact and profile candidates."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        candidates = _event_candidates(event)
        for entity_type, value, candidate_status in candidates:
            key = (entity_type, value.lower())
            row = rows.setdefault(
                key,
                {
                    "type": entity_type,
                    "value": value,
                    "status": candidate_status,
                    "relationship_to_scope": event.relationship_to_scope or "unassessed",
                    "records": 0,
                    "sources": [],
                    "evidence_ids": [],
                    "evidence_urls": [],
                    "what_it_demonstrates": _demonstrates(entity_type, organization.language),
                    "what_it_does_not_demonstrate": _limitation(entity_type, organization.language),
                },
            )
            row["records"] += 1
            row["relationship_to_scope"] = _stronger_relationship(
                row["relationship_to_scope"],
                event.relationship_to_scope or "unassessed",
            )
            _append_unique(row["sources"], event.source)
            _append_unique(row["evidence_ids"], event.canonical_id or event.id)
            _append_unique(row["evidence_urls"], event.evidence_url or "")

    ordered = sorted(
        rows.values(),
        key=lambda item: (
            item["relationship_to_scope"] in {"direct", "related"},
            item["records"],
            item["type"],
            item["value"],
        ),
        reverse=True,
    )
    counts = Counter(item["type"] for item in ordered)
    return {
        "total_candidates": len(ordered),
        "emails": counts["email"],
        "phones": counts["phone"],
        "people_profiles": counts["person"],
        "rows": ordered,
        "method": (
            "Public contacts and profiles are extracted from collected content and retain their source URLs. "
            "They remain candidates until corroborated by an official source."
            if organization.language == "en"
            else "Los contactos y perfiles públicos se extraen del contenido recolectado y conservan sus URL de origen. "
            "Se mantienen como candidatos hasta ser corroborados por una fuente oficial."
        ),
    }


def _event_candidates(event: ThreatEvent) -> list[tuple[str, str, str]]:
    values: list[tuple[str, str, str]] = []
    for tag in event.tags or []:
        lowered = tag.lower()
        for prefix, entity_type in _ENTITY_PREFIXES.items():
            marker = f"{prefix}:"
            if lowered.startswith(marker):
                value = tag[len(marker) :].strip()
                if value:
                    status = "public_profile_candidate" if entity_type == "person" else "public_contact_candidate"
                    values.append((entity_type, value, status))
    structured = (event.technical_validation or {}).get("public_entity_candidates")
    if isinstance(structured, list):
        for item in structured:
            if not isinstance(item, dict):
                continue
            entity_type = str(item.get("type") or "").strip().lower()
            value = str(item.get("value") or "").strip()
            status = str(item.get("status") or "public_candidate").strip()
            if entity_type in {"email", "phone", "person"} and value:
                values.append((entity_type, value, status))
    return list(dict.fromkeys(values))


def _demonstrates(entity_type: str, language: str) -> str:
    if language == "en":
        return {
            "email": "The email address appears in public collected material.",
            "phone": "The phone number appears in public collected material.",
            "person": "A public profile with this displayed name was indexed.",
        }.get(entity_type, "The entity appears in public collected material.")
    return {
        "email": "La dirección de correo aparece en material público recolectado.",
        "phone": "El número telefónico aparece en material público recolectado.",
        "person": "Se indexó un perfil público con este nombre visible.",
    }.get(entity_type, "La entidad aparece en material público recolectado.")


def _limitation(entity_type: str, language: str) -> str:
    if language == "en":
        if entity_type == "person":
            return "It does not prove identity or current employment without official-source corroboration."
        return "It does not prove ownership, active use or authorization by the organization."
    if entity_type == "person":
        return "No demuestra identidad ni empleo vigente sin corroboración de una fuente oficial."
    return "No demuestra titularidad, uso vigente ni autorización por parte de la organización."


def _stronger_relationship(current: str, incoming: str) -> str:
    order = {"unassessed": 0, "contextual": 1, "related": 2, "direct": 3}
    return incoming if order.get(incoming, 0) > order.get(current, 0) else current


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)
