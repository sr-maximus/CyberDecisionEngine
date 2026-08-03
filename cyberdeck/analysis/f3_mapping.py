from __future__ import annotations

import re
import unicodedata
from collections import Counter, defaultdict
from typing import Any, Iterable

from cyberdeck.frameworks.f3 import F3_TACTIC_LABELS_ES, load_f3_catalog
from cyberdeck.schemas import EvidenceStatus, ThreatEvent


MODEL_VERSION = "mitre-f3-evidence-mapping-v1.0.0"
ASSURED_STATUSES = {
    EvidenceStatus.DIRECT,
    EvidenceStatus.VALIDATED,
    EvidenceStatus.CONFIRMED,
}

# Rules map already-classified evidence to an exact official F3 technique. They
# never promote a mapping to a confirmed fraud incident.
F3_EVENT_RULES: tuple[dict[str, Any], ...] = (
    {"id": "T1660", "categories": {"phishing"}, "tags": {"phishing"}},
    {
        "id": "T1598",
        "patterns": (r"\bphishing for information\b", r"\brecoleccion de informacion por phishing\b"),
    },
    {"id": "F1006", "categories": {"account_takeover"}, "tags": {"account_takeover"}},
    {
        "id": "F1006.002",
        "patterns": (
            r"\bexposed login credential(?:s)?\b",
            r"\bcredencial(?:es)? de acceso expuesta(?:s)?\b",
        ),
    },
    {
        "id": "F1004",
        "patterns": (
            r"\bstolen session cookie\b",
            r"\bcookie de sesion robad[oa]\b",
        ),
    },
    {
        "id": "T1185",
        "patterns": (r"\bbrowser session hijacking\b", r"\bsecuestro de sesion del navegador\b"),
    },
    {
        "id": "T1110.004",
        "patterns": (r"\bcredential stuffing\b", r"\brelleno de credenciales\b"),
    },
    {"id": "F1020.002", "categories": {"fake_domain"}, "tags": {"fake_domain"}},
    {
        "id": "F1032",
        "categories": {"brand_impersonation", "fake_recruitment"},
        "tags": {"brand_impersonation", "fake_recruitment"},
    },
    {
        "id": "F1040",
        "patterns": (r"\bphone number spoofing\b", r"\bsuplantacion de numero telefonico\b"),
    },
    {
        "id": "F1036",
        "patterns": (r"\bnew vendor setup\b", r"\bnuevo proveedor\b"),
    },
    {
        "id": "F1013",
        "patterns": (r"\bchange payroll details\b", r"\bcambio de datos de nomina\b"),
    },
    {
        "id": "F1025.003",
        "patterns": (r"\bwire transfer\b", r"\btransferencia bancaria\b"),
    },
    {
        "id": "F1047",
        "patterns": (r"\btransfer of funds\b", r"\btransferencia de fondos\b"),
    },
    {
        "id": "F1018",
        "patterns": (r"\bconvert to cryptocurrency\b", r"\bconversion a criptomoneda\b"),
    },
)


def enrich_f3_mappings(events: Iterable[ThreatEvent]) -> dict[str, Any]:
    catalog = load_f3_catalog()
    technique_by_id = {item["id"]: item for item in catalog["techniques"]}
    mapped_events = 0
    mapped_ids: set[str] = set()
    for event in events:
        if event.evidence_status not in ASSURED_STATUSES:
            continue
        mappings = _event_mappings(event, technique_by_id)
        if not mappings:
            continue
        validation = dict(event.technical_validation or {})
        validation["f3_mappings"] = mappings
        validation["f3_model_version"] = MODEL_VERSION
        event.technical_validation = validation
        tags = list(event.tags)
        for mapping in mappings:
            marker = f"f3:{mapping['id']}"
            if marker not in tags:
                tags.append(marker)
            mapped_ids.add(mapping["id"])
        if "f3_candidate" not in tags:
            tags.append("f3_candidate")
        event.tags = tags
        mapped_events += 1
    return {
        "model_version": MODEL_VERSION,
        "framework_version": catalog["version"],
        "mapped_event_count": mapped_events,
        "mapped_technique_count": len(mapped_ids),
        "mapped_technique_ids": sorted(mapped_ids),
    }


def build_f3_profile(events: Iterable[ThreatEvent], language: str = "es") -> dict[str, Any]:
    catalog = load_f3_catalog()
    tactic_by_id = {item["id"]: item for item in catalog["tactics"]}
    technique_by_id = {item["id"]: item for item in catalog["techniques"]}
    technique_events: dict[str, list[ThreatEvent]] = defaultdict(list)
    for event in events:
        if event.evidence_status not in ASSURED_STATUSES:
            continue
        for mapping in (event.technical_validation or {}).get("f3_mappings", []):
            identifier = str(mapping.get("id") or "")
            if identifier in technique_by_id:
                technique_events[identifier].append(event)

    tactic_counts: Counter[str] = Counter()
    techniques = []
    for identifier, related in sorted(
        technique_events.items(),
        key=lambda item: (-len(item[1]), item[0]),
    ):
        technique = technique_by_id[identifier]
        tactic_ids = list(technique.get("tactics") or [])
        for tactic_id in tactic_ids:
            tactic_counts[tactic_id] += len(related)
        techniques.append(
            {
                "id": identifier,
                "official_name": technique["name"],
                "tactic_ids": tactic_ids,
                "tactics": [
                    _tactic_label(tactic_id, tactic_by_id, language)
                    for tactic_id in tactic_ids
                ],
                "record_count": len(related),
                "validated_count": sum(
                    event.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
                    for event in related
                ),
                "evidence": [
                    {
                        "evidence_id": event.canonical_id or event.id,
                        "title": event.title,
                        "url": event.evidence_url,
                        "status": event.evidence_status.value,
                    }
                    for event in related[:12]
                ],
                "mapping_status": "evidence_supported_candidate",
            }
        )
    tactics = [
        {
            "id": tactic["id"],
            "official_name": tactic["name"],
            "display_name": _tactic_label(tactic["id"], tactic_by_id, language),
            "record_count": tactic_counts.get(tactic["id"], 0),
        }
        for tactic in catalog["tactics"]
    ]
    return {
        "model_version": MODEL_VERSION,
        "framework": catalog["framework"],
        "framework_version": catalog["version"],
        "source_url": catalog["reference_url"],
        "catalog_sha256": catalog["sha256"],
        "status": "evidence_backed" if techniques else "no_data",
        "mapped_record_count": sum(item["record_count"] for item in techniques),
        "mapped_technique_count": len(techniques),
        "tactics": tactics,
        "techniques": techniques,
        "limitations": [
            "Un mapeo F3 describe compatibilidad conductual con evidencia de la corrida; no confirma fraude ni incidente.",
            "Las técnicas F3 solo se publican cuando una regla explícita enlaza un registro asegurado con un identificador oficial.",
            "Los porcentajes de fraude, pérdidas o probabilidad no se derivan del catálogo F3.",
        ],
    }


def _event_mappings(
    event: ThreatEvent,
    technique_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    category = _normalize(event.category)
    tags = {_normalize(tag) for tag in event.tags}
    text = _normalize(
        " ".join(
            [
                event.title,
                event.category,
                event.actor or "",
                event.technique or "",
                event.indicator or "",
                " ".join(event.tags),
            ]
        )
    )
    output = []
    seen: set[str] = set()
    for rule in F3_EVENT_RULES:
        identifier = rule["id"]
        technique = technique_by_id.get(identifier)
        if technique is None or identifier in seen:
            continue
        category_match = category in {_normalize(value) for value in rule.get("categories", set())}
        tag_match = bool(tags.intersection({_normalize(value) for value in rule.get("tags", set())}))
        pattern_match = any(re.search(pattern, text, re.IGNORECASE) for pattern in rule.get("patterns", ()))
        if not (category_match or tag_match or pattern_match):
            continue
        seen.add(identifier)
        output.append(
            {
                "id": identifier,
                "official_name": technique["name"],
                "tactics": list(technique.get("tactics") or []),
                "is_attack_reference": bool(technique.get("isAttack")),
                "mapping_status": "evidence_supported_candidate",
                "match_basis": (
                    "normalized_category"
                    if category_match
                    else "normalized_tag"
                    if tag_match
                    else "explicit_phrase"
                ),
            }
        )
    return output


def _tactic_label(
    tactic_id: str,
    tactic_by_id: dict[str, dict[str, Any]],
    language: str,
) -> str:
    official = str(tactic_by_id.get(tactic_id, {}).get("name") or tactic_id)
    if language == "es":
        return F3_TACTIC_LABELS_ES.get(tactic_id, official)
    return official


def _normalize(value: str) -> str:
    return (
        unicodedata.normalize("NFKD", str(value))
        .encode("ascii", "ignore")
        .decode("ascii")
        .casefold()
        .strip()
    )
