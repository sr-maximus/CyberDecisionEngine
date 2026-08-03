from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent
from cyberdeck.settings import PROJECT_ROOT


_OFFICIAL_HINTS = {
    "annual_report",
    "official_record",
    "regulatory",
    "corporate",
    "official_source",
}
_ASSURED_STATUSES = {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}


def build_geographic_intelligence(
    events: list[ThreatEvent],
    organization: OrganizationProfile,
) -> dict[str, Any]:
    declared = _unique([organization.country, *organization.countries_of_operation])
    evidence_rows: dict[str, dict[str, Any]] = {}
    contextual_rows: dict[str, dict[str, Any]] = {}
    for event in events:
        text = _event_text(event)
        countries = _countries_in_text(text)
        for country in countries:
            related = event.relationship_to_scope in {"direct", "related"}
            country_label = country["es"] if organization.language == "es" else country["en"]
            marker = f"{'country_mention' if related else 'country_context'}:{country_label}"
            if marker not in event.tags:
                event.tags.append(marker)
            target = evidence_rows if related else contextual_rows
            row = target.setdefault(
                country["code"],
                {
                    "code": country["code"],
                    "country": country["es"] if organization.language == "es" else country["en"],
                    "records": 0,
                    "assured_records": 0,
                    "official_records": 0,
                    "evidence_ids": [],
                    "evidence_urls": [],
                    "status": "mention_only",
                    "what_it_demonstrates": (
                        "The country is explicitly mentioned in scope-related collected material."
                        if organization.language == "en"
                        else "El país se menciona explícitamente en material recolectado relacionado con el alcance."
                    ),
                    "what_it_does_not_demonstrate": (
                        "A mention alone does not prove current corporate operations in that country."
                        if organization.language == "en"
                        else "Una mención por sí sola no demuestra operaciones corporativas vigentes en ese país."
                    ),
                },
            )
            row["records"] += 1
            if event.evidence_status in _ASSURED_STATUSES:
                row["assured_records"] += 1
            tags = {tag.lower() for tag in event.tags or []}
            evidence_type = getattr(event.evidence_type, "value", str(event.evidence_type or ""))
            official = bool(tags.intersection(_OFFICIAL_HINTS)) or (
                event.relationship_to_scope == "direct"
                and evidence_type in {"official_record", "document"}
                and event.evidence_status in _ASSURED_STATUSES
            )
            if official:
                row["official_records"] += 1
                supported_marker = f"country_operation_supported:{country_label}"
                if supported_marker not in event.tags:
                    event.tags.append(supported_marker)
            evidence_id = event.canonical_id or event.id
            if evidence_id and evidence_id not in row["evidence_ids"]:
                row["evidence_ids"].append(evidence_id)
            if event.evidence_url and event.evidence_url not in row["evidence_urls"]:
                row["evidence_urls"].append(event.evidence_url)
            if row["official_records"] > 0 and row["assured_records"] > 0:
                row["status"] = "supported_operational_context"
                row["what_it_demonstrates"] = (
                    "An official or technically assured scope-related record supports organizational context in this country."
                    if organization.language == "en"
                    else "Un registro oficial o técnicamente asegurado y relacionado con el alcance sustenta contexto organizacional en este país."
                )

    evidence_supported = sorted(
        evidence_rows.values(),
        key=lambda row: (row["status"] == "supported_operational_context", row["assured_records"], row["records"]),
        reverse=True,
    )
    contextual = sorted(contextual_rows.values(), key=lambda row: row["records"], reverse=True)
    country_inventory = _build_country_inventory(declared, evidence_supported, organization.language)
    incorporation_country = _country_from_value(organization.country)
    return {
        "incorporation_country": organization.country,
        "incorporation_country_label": (
            _country_label(incorporation_country, organization.language)
            if incorporation_country
            else organization.country
        ),
        "declared_countries_of_operation": declared,
        "declared_country_labels": [
            _country_label(country, organization.language) if country else value
            for value in declared
            for country in [_country_from_value(value)]
        ],
        "country_inventory": country_inventory,
        "evidence_supported_countries": evidence_supported,
        "contextual_country_mentions": contextual,
        "evidence_supported_count": len(evidence_supported),
        "supported_operational_context_count": sum(
            1 for row in evidence_supported if row["status"] == "supported_operational_context"
        ),
        "method": (
            (
                "Countries declared in scope are kept separate from countries found in evidence. "
                "Only an official or assured scope-related record can elevate a mention to supported operational context."
            )
            if organization.language == "en"
            else (
                "Los países declarados en el alcance se mantienen separados de los países identificados en la evidencia. "
                "Solo un registro oficial o asegurado y relacionado con el alcance puede elevar una mención a contexto "
                "operativo sustentado."
            )
        ),
        "limitations": (
            (
                "Source location, hosting country and a country mentioned in an article are not treated as the physical "
                "location of a person or as proof of corporate operations."
            )
            if organization.language == "en"
            else (
                "La ubicación de la fuente, el país de alojamiento y un país mencionado en un artículo no se interpretan "
                "como ubicación física de una persona ni como prueba de operaciones corporativas."
            )
        ),
    }


def _event_text(event: ThreatEvent) -> str:
    validation = event.technical_validation or {}
    extra = [
        str(validation.get("summary") or ""),
        str(validation.get("description") or ""),
        str(validation.get("original_response") or ""),
    ]
    return " ".join(
        [
            event.title,
            event.category,
            event.asset or "",
            event.host or "",
            event.evidence_url or "",
            " ".join(event.tags or []),
            *extra,
        ]
    )


def _countries_in_text(text: str) -> list[dict[str, str]]:
    normalized = _normalize(text)
    found = []
    for country in _country_catalog():
        names = {_normalize(country["en"]), _normalize(country["es"])}
        code = country["code"].lower()
        explicit_code = re.search(
            rf"\b(?:country|country_code|geo_country|location_country):\s*{re.escape(code)}\b",
            normalized,
        )
        named_country = any(
            name
            and len(name) > 3
            and re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", normalized)
            for name in names
        )
        if explicit_code or named_country:
            found.append(country)
    return found


def _build_country_inventory(
    declared: list[str],
    evidence_rows: list[dict[str, Any]],
    language: str,
) -> list[dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for value in declared:
        country = _country_from_value(value)
        code = country["code"] if country else ""
        label = _country_label(country, language) if country else value
        key = code or _normalize(value)
        inventory[key] = {
            "code": code,
            "country": label,
            "declared": True,
            "records": 0,
            "assured_records": 0,
            "official_records": 0,
            "evidence_ids": [],
            "evidence_urls": [],
            "status": "declared_scope",
            "what_it_demonstrates": (
                "The country was supplied as part of the authorized analysis scope."
                if language == "en"
                else "El país fue suministrado como parte del alcance autorizado del análisis."
            ),
            "what_it_does_not_demonstrate": (
                "The declaration is not, by itself, an independent verification of current operations."
                if language == "en"
                else "La declaración no constituye por sí sola una verificación independiente de operaciones vigentes."
            ),
        }

    for evidence in evidence_rows:
        code = str(evidence.get("code") or "")
        label = str(evidence.get("country") or code)
        key = code or _normalize(label)
        row = inventory.setdefault(
            key,
            {
                "code": code,
                "country": label,
                "declared": False,
                "records": 0,
                "assured_records": 0,
                "official_records": 0,
                "evidence_ids": [],
                "evidence_urls": [],
                "status": "mention_only",
                "what_it_demonstrates": evidence.get("what_it_demonstrates") or "",
                "what_it_does_not_demonstrate": evidence.get("what_it_does_not_demonstrate") or "",
            },
        )
        row["records"] = int(evidence.get("records") or 0)
        row["assured_records"] = int(evidence.get("assured_records") or 0)
        row["official_records"] = int(evidence.get("official_records") or 0)
        row["evidence_ids"] = list(evidence.get("evidence_ids") or [])
        row["evidence_urls"] = list(evidence.get("evidence_urls") or [])
        row["what_it_demonstrates"] = evidence.get("what_it_demonstrates") or row["what_it_demonstrates"]
        row["what_it_does_not_demonstrate"] = (
            evidence.get("what_it_does_not_demonstrate") or row["what_it_does_not_demonstrate"]
        )
        evidence_status = str(evidence.get("status") or "mention_only")
        if evidence_status == "supported_operational_context":
            row["status"] = evidence_status
        elif row["declared"]:
            row["status"] = "declared_and_mentioned"
        else:
            row["status"] = "mention_only"

    status_order = {
        "supported_operational_context": 0,
        "declared_and_mentioned": 1,
        "declared_scope": 2,
        "mention_only": 3,
    }
    return sorted(
        inventory.values(),
        key=lambda row: (
            status_order.get(str(row["status"]), 9),
            -int(row["records"]),
            str(row["country"]),
        ),
    )


def _country_from_value(value: str) -> dict[str, str] | None:
    normalized = _normalize(value)
    code = str(value or "").strip().upper()
    for country in _country_catalog():
        if country["code"].upper() == code:
            return country
        if normalized in {_normalize(country["en"]), _normalize(country["es"])}:
            return country
    return None


def _country_label(country: dict[str, str], language: str) -> str:
    return country["en"] if language == "en" else country["es"]


@lru_cache(maxsize=1)
def _country_catalog() -> list[dict[str, str]]:
    path = Path(PROJECT_ROOT) / "config" / "catalogs" / "countries.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [
        {"code": str(row.get("code") or ""), "en": str(row.get("en") or ""), "es": str(row.get("es") or "")}
        for row in payload
        if isinstance(row, dict) and row.get("code")
    ]


def _normalize(value: str) -> str:
    folded = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"\s+", " ", folded.lower()).strip()


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))
