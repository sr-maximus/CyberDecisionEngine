from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from cyberdeck.settings import PROJECT_ROOT


ATTACK_ENTERPRISE_PATH = PROJECT_ROOT / "data" / "frameworks" / "mitre_attack_enterprise.json"
SUPPORTED_ENTITY_TYPES = {"intrusion-set", "threat-actor", "campaign"}


def resolve_attack_entity_profiles(
    names: Iterable[str],
    *,
    allowed_types: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Resolve exact ATT&CK names, aliases or external IDs from the local STIX bundle.

    Ambiguous normalized aliases are deliberately left unresolved. This prevents a
    convenient name match from becoming an unsupported attribution.
    """

    catalog = load_attack_profile_catalog()
    profiles = catalog.get("profiles", {})
    alias_index = catalog.get("alias_index", {})
    allowed = allowed_types or SUPPORTED_ENTITY_TYPES
    resolved: dict[str, dict[str, Any]] = {}
    for raw_name in names:
        name = str(raw_name or "").strip()
        if not name:
            continue
        candidates = [
            profiles[profile_id]
            for profile_id in alias_index.get(_normalize_alias(name), [])
            if profile_id in profiles and profiles[profile_id].get("stix_type") in allowed
        ]
        if not candidates:
            continue
        exact = [
            profile
            for profile in candidates
            if name.casefold()
            in {
                str(profile.get("name") or "").casefold(),
                str(profile.get("external_id") or "").casefold(),
                *(str(value).casefold() for value in profile.get("aliases", [])),
            }
        ]
        selected = exact[0] if len(exact) == 1 else candidates[0] if len(candidates) == 1 else None
        if selected is not None:
            resolved[name] = selected
    return resolved


def load_attack_profile_catalog(path: Path | None = None) -> dict[str, Any]:
    source = path or ATTACK_ENTERPRISE_PATH
    if not source.is_file():
        return {"profiles": {}, "alias_index": {}, "tactic_order": [], "source": None}
    stat = source.stat()
    return _load_attack_profile_catalog_cached(str(source), stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=2)
def _load_attack_profile_catalog_cached(
    path: str,
    _modified_ns: int,
    _size: int,
) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {"profiles": {}, "alias_index": {}, "tactic_order": [], "source": path}
    catalog = build_attack_profile_catalog(payload)
    catalog["source"] = path
    return catalog


def build_attack_profile_catalog(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a compact actor/group/campaign -> ATT&CK technique index."""

    objects = [row for row in payload.get("objects", []) if isinstance(row, dict)]
    active = {
        str(row.get("id")): row
        for row in objects
        if row.get("id") and not row.get("revoked") and not row.get("x_mitre_deprecated")
    }
    tactic_names = {
        str(row.get("x_mitre_shortname")): str(row.get("name"))
        for row in active.values()
        if row.get("type") == "x-mitre-tactic"
        and row.get("x_mitre_shortname")
        and row.get("name")
    }
    tactic_order: list[str] = []
    for row in active.values():
        if row.get("type") != "x-mitre-matrix" or row.get("name") != "Enterprise ATT&CK":
            continue
        tactic_order = [
            str(active[reference].get("name"))
            for reference in row.get("tactic_refs", [])
            if reference in active and active[reference].get("name")
        ]
        break

    parent_by_child = {
        str(row.get("source_ref")): str(row.get("target_ref"))
        for row in active.values()
        if row.get("type") == "relationship"
        and row.get("relationship_type") == "subtechnique-of"
        and row.get("source_ref")
        and row.get("target_ref")
    }
    techniques: dict[str, dict[str, Any]] = {}
    for stix_id, row in active.items():
        if row.get("type") != "attack-pattern":
            continue
        reference = _mitre_reference(row)
        external_id = str(reference.get("external_id") or "")
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", external_id, re.IGNORECASE):
            continue
        tactics = [
            tactic_names.get(
                str(phase.get("phase_name")),
                str(phase.get("phase_name") or "").replace("-", " ").title(),
            )
            for phase in row.get("kill_chain_phases", [])
            if isinstance(phase, dict) and phase.get("phase_name")
        ]
        techniques[stix_id] = {
            "technique_id": external_id.upper(),
            "name": str(row.get("name") or external_id),
            "description": str(row.get("description") or ""),
            "tactics": list(dict.fromkeys(tactics)),
            "platforms": list(row.get("x_mitre_platforms", []) or []),
            "data_sources": list(row.get("x_mitre_data_sources", []) or []),
            "created": row.get("created"),
            "url": reference.get("url"),
            "stix_id": stix_id,
            "modified": row.get("modified"),
            "version": row.get("x_mitre_version"),
            "external_references": _external_references(row),
        }
    for child_id, parent_id in parent_by_child.items():
        if child_id in techniques and parent_id in techniques:
            techniques[child_id]["parent_technique_id"] = techniques[parent_id]["technique_id"]

    profiles: dict[str, dict[str, Any]] = {}
    for stix_id, row in active.items():
        if row.get("type") not in SUPPORTED_ENTITY_TYPES:
            continue
        reference = _mitre_reference(row)
        external_id = str(reference.get("external_id") or "") or None
        entity_type = {
            "intrusion-set": "threat_group",
            "threat-actor": "threat_actor",
            "campaign": "campaign",
        }[str(row.get("type"))]
        aliases = list(
            dict.fromkeys(
                str(value).strip()
                for value in [row.get("name"), *(row.get("aliases", []) or [])]
                if str(value or "").strip()
            )
        )
        profiles[stix_id] = {
            "profile_id": stix_id,
            "stix_id": stix_id,
            "stix_type": row.get("type"),
            "entity_type": entity_type,
            "name": str(row.get("name") or external_id or stix_id),
            "aliases": aliases,
            "external_id": external_id,
            "url": reference.get("url"),
            "description": str(row.get("description") or ""),
            "created": row.get("created"),
            "modified": row.get("modified"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "version": row.get("x_mitre_version"),
            "domains": list(row.get("x_mitre_domains", []) or []),
            "contributors": list(row.get("x_mitre_contributors", []) or []),
            "external_references": _external_references(row),
            "knowledge_source": "MITRE ATT&CK Enterprise",
            "techniques": [],
        }

    for row in active.values():
        if row.get("type") != "relationship" or row.get("relationship_type") != "uses":
            continue
        source_id = str(row.get("source_ref") or "")
        target_id = str(row.get("target_ref") or "")
        if source_id not in profiles or target_id not in techniques:
            continue
        technique = dict(techniques[target_id])
        citations = [
            str(reference.get("url"))
            for reference in row.get("external_references", [])
            if isinstance(reference, dict) and reference.get("url")
        ]
        technique["relationship_references"] = list(dict.fromkeys(citations))
        technique["relationship_description"] = row.get("description")
        technique["relationship_created"] = row.get("created")
        technique["relationship_modified"] = row.get("modified")
        profiles[source_id]["techniques"].append(technique)

    alias_index: dict[str, list[str]] = {}
    for profile_id, profile in profiles.items():
        profile["techniques"] = sorted(
            {row["technique_id"]: row for row in profile["techniques"]}.values(),
            key=lambda row: row["technique_id"],
        )
        aliases = [*profile.get("aliases", []), profile.get("external_id")]
        for alias in aliases:
            normalized = _normalize_alias(str(alias or ""))
            if normalized:
                alias_index.setdefault(normalized, []).append(profile_id)
    for normalized, profile_ids in alias_index.items():
        alias_index[normalized] = list(dict.fromkeys(profile_ids))
    return {
        "profiles": profiles,
        "alias_index": alias_index,
        "tactic_order": tactic_order,
    }


def _mitre_reference(row: dict[str, Any]) -> dict[str, Any]:
    return next(
        (
            reference
            for reference in row.get("external_references", [])
            if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack"
        ),
        {},
    )


def _external_references(row: dict[str, Any]) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for reference in row.get("external_references", []) or []:
        if not isinstance(reference, dict):
            continue
        item = {
            key: str(reference[key])
            for key in ("source_name", "external_id", "url")
            if reference.get(key)
        }
        if not item:
            continue
        marker = (
            item.get("source_name", ""),
            item.get("external_id", ""),
            item.get("url", ""),
        )
        if marker not in seen:
            seen.add(marker)
            references.append(item)
    return references


def _normalize_alias(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    return "".join(character for character in normalized if character.isalnum() or character in {"@"})
