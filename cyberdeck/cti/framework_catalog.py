from __future__ import annotations

import json
import zipfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree

import yaml

from cyberdeck.settings import PROJECT_ROOT


CATALOG_SCHEMA_VERSION = "cti-framework-catalog-v1.0"

FRAMEWORKS: tuple[dict[str, Any], ...] = (
    {
        "id": "attack-enterprise",
        "name": "MITRE ATT&CK Enterprise",
        "short_name": "ATT&CK Enterprise",
        "view_type": "matrix",
        "path": "data/frameworks/mitre_attack_enterprise.json",
        "source_url": "https://attack.mitre.org/matrices/enterprise/",
        "description": "Adversary tactics, techniques, groups and campaigns for enterprise environments.",
        "parser": "stix",
    },
    {
        "id": "attack-mobile",
        "name": "MITRE ATT&CK Mobile",
        "short_name": "ATT&CK Mobile",
        "view_type": "matrix",
        "path": "data/frameworks/mitre_attack_mobile.json",
        "source_url": "https://attack.mitre.org/matrices/mobile/",
        "description": "Adversary behavior affecting mobile devices and platforms.",
        "parser": "stix",
    },
    {
        "id": "attack-ics",
        "name": "MITRE ATT&CK for ICS",
        "short_name": "ATT&CK ICS/OT",
        "view_type": "matrix",
        "path": "data/frameworks/mitre_attack_ics.json",
        "source_url": "https://attack.mitre.org/matrices/ics/",
        "description": "Adversary behavior affecting industrial control and operational technology.",
        "parser": "stix",
    },
    {
        "id": "atlas",
        "name": "MITRE ATLAS",
        "short_name": "ATLAS",
        "view_type": "matrix",
        "path": "data/frameworks/mitre_atlas.json",
        "source_url": "https://atlas.mitre.org/matrices/ATLAS",
        "description": "Threats and techniques affecting AI-enabled systems.",
        "parser": "stix",
    },
    {
        "id": "f3",
        "name": "MITRE Fight Fraud Framework",
        "short_name": "F3",
        "view_type": "matrix",
        "path": "data/frameworks/mitre_f3_v1_1.json",
        "source_url": "https://fightfraudframework.org/",
        "description": "Fraud actor tactics and techniques across cyber and fraud operations.",
        "parser": "f3",
    },
    {
        "id": "aadapt",
        "name": "MITRE AADAPT",
        "short_name": "AADAPT",
        "view_type": "matrix",
        "path": "data/frameworks/mitre_aadapt.yaml",
        "source_url": "https://aadapt.mitre.org/",
        "description": "Adversarial actions in digital asset payment technologies.",
        "parser": "aadapt",
    },
    {
        "id": "d3fend",
        "name": "MITRE D3FEND",
        "short_name": "D3FEND",
        "view_type": "defensive_matrix",
        "path": "data/frameworks/mitre_d3fend.json",
        "source_url": "https://d3fend.mitre.org/",
        "description": "Defensive techniques and their relationships to offensive behavior.",
        "parser": "d3fend",
    },
    {
        "id": "emb3d",
        "name": "MITRE EMB3D",
        "short_name": "EMB3D",
        "view_type": "relationship_model",
        "path": "data/frameworks/mitre_emb3d.json",
        "source_url": "https://emb3d.mitre.org/",
        "description": "Embedded, IoT and OT device properties, threats and mitigations.",
        "parser": "emb3d",
    },
    {
        "id": "capec",
        "name": "MITRE CAPEC",
        "short_name": "CAPEC",
        "view_type": "hierarchy",
        "path": "data/frameworks/capec_latest.zip",
        "source_url": "https://capec.mitre.org/data/",
        "description": "Common attack patterns organized by abstraction and relationships.",
        "parser": "capec",
    },
    {
        "id": "cwe",
        "name": "MITRE CWE",
        "short_name": "CWE",
        "view_type": "hierarchy",
        "path": "data/frameworks/cwe_latest.zip",
        "source_url": "https://cwe.mitre.org/data/",
        "description": "Software and hardware weakness catalog used to explain exposure mechanisms.",
        "parser": "cwe",
    },
    {
        "id": "inform",
        "name": "MITRE INFORM",
        "short_name": "INFORM",
        "view_type": "maturity",
        "path": "data/frameworks/mitre_inform.json",
        "source_url": "https://ctid.mitre.org/inform/",
        "description": "Threat-informed defense maturity assessment for people, process and technology.",
        "parser": "inform",
    },
    {
        "id": "disarm",
        "name": "DISARM",
        "short_name": "DISARM",
        "view_type": "matrix",
        "path": "data/frameworks/disarm_observable.json",
        "source_url": "https://www.disarm.foundation/framework",
        "description": "Observable tactics and techniques used to analyze influence and disinformation operations.",
        "parser": "disarm",
    },
)

_FRAMEWORK_BY_ID = {str(row["id"]): row for row in FRAMEWORKS}


def framework_catalog_index() -> dict[str, Any]:
    families = []
    for metadata in FRAMEWORKS:
        detail = load_framework_family(str(metadata["id"]))
        families.append(_family_summary(detail))
    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "families": families,
        "interpretation": (
            "Catalog coverage is reference knowledge. It becomes run evidence only when the "
            "analysis snapshot explicitly links a technique, entity or control to traceable records."
        ),
    }


def load_framework_family(family_id: str) -> dict[str, Any]:
    metadata = _FRAMEWORK_BY_ID.get(family_id)
    if metadata is None:
        raise KeyError(family_id)
    path = PROJECT_ROOT / str(metadata["path"])
    if not path.is_file():
        return _empty_family(metadata, "missing")
    stat = path.stat()
    return _load_framework_family_cached(
        family_id,
        str(path),
        stat.st_mtime_ns,
        stat.st_size,
    )


@lru_cache(maxsize=24)
def _load_framework_family_cached(
    family_id: str,
    path: str,
    _modified_ns: int,
    _size: int,
) -> dict[str, Any]:
    metadata = _FRAMEWORK_BY_ID[family_id]
    parser_name = str(metadata["parser"])
    parser: Callable[[Path, dict[str, Any]], dict[str, Any]] = {
        "stix": _parse_stix_matrix,
        "f3": _parse_f3,
        "aadapt": _parse_aadapt,
        "d3fend": _parse_d3fend,
        "emb3d": _parse_emb3d,
        "capec": _parse_capec,
        "cwe": _parse_cwe,
        "inform": _parse_inform,
        "disarm": _parse_disarm,
    }[parser_name]
    try:
        payload = parser(Path(path), metadata)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        payload = _empty_family(metadata, "invalid")
        payload["error"] = str(exc)
        return payload
    payload.update(
        {
            "schema_version": CATALOG_SCHEMA_VERSION,
            "id": metadata["id"],
            "name": metadata["name"],
            "short_name": metadata["short_name"],
            "view_type": metadata["view_type"],
            "source_url": metadata["source_url"],
            "description": metadata["description"],
            "status": "active",
        }
    )
    payload.setdefault("tactics", [])
    payload.setdefault("techniques", [])
    payload.setdefault("entities", [])
    payload.setdefault("relationships", [])
    payload.setdefault("collections", {})
    payload["counts"] = _counts(payload)
    return payload


def _empty_family(metadata: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "id": metadata["id"],
        "name": metadata["name"],
        "short_name": metadata["short_name"],
        "view_type": metadata["view_type"],
        "source_url": metadata["source_url"],
        "description": metadata["description"],
        "status": status,
        "version": None,
        "tactics": [],
        "techniques": [],
        "entities": [],
        "relationships": [],
        "collections": {},
        "counts": {"tactics": 0, "techniques": 0, "entities": 0, "relationships": 0},
    }


def _family_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: payload.get(key)
        for key in (
            "id",
            "name",
            "short_name",
            "view_type",
            "source_url",
            "description",
            "status",
            "version",
            "counts",
        )
    }


def _counts(payload: dict[str, Any]) -> dict[str, int]:
    collection_items = sum(
        len(value)
        for value in (payload.get("collections") or {}).values()
        if isinstance(value, list)
    )
    return {
        "tactics": len(payload.get("tactics", [])),
        "techniques": len(payload.get("techniques", [])),
        "entities": len(payload.get("entities", [])),
        "relationships": int(payload.get("relationship_count", len(payload.get("relationships", []))) or 0),
        "items": max(
            int(payload.get("item_count", len(payload.get("techniques", []))) or 0),
            collection_items,
        ),
    }


def _parse_stix_matrix(path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    objects = [row for row in payload.get("objects", []) if isinstance(row, dict)]
    active = {
        str(row["id"]): row
        for row in objects
        if row.get("id") and not row.get("revoked") and not row.get("x_mitre_deprecated")
    }
    tactic_by_ref = {
        stix_id: {
            "id": str(row.get("x_mitre_shortname") or stix_id),
            "name": str(row.get("name") or row.get("x_mitre_shortname") or stix_id),
            "description": str(row.get("description") or ""),
        }
        for stix_id, row in active.items()
        if row.get("type") == "x-mitre-tactic"
    }
    matrix = next(
        (row for row in active.values() if row.get("type") == "x-mitre-matrix"),
        {},
    )
    ordered_tactics = [
        tactic_by_ref[ref]
        for ref in matrix.get("tactic_refs", [])
        if ref in tactic_by_ref
    ]
    if not ordered_tactics:
        ordered_tactics = sorted(tactic_by_ref.values(), key=lambda row: row["name"])
    tactic_name_by_phase = {
        str(active[stix_id].get("x_mitre_shortname")): row["name"]
        for stix_id, row in tactic_by_ref.items()
    }
    parent_by_child = {
        str(row.get("source_ref")): str(row.get("target_ref"))
        for row in active.values()
        if row.get("type") == "relationship"
        and row.get("relationship_type") == "subtechnique-of"
    }
    techniques_by_ref: dict[str, dict[str, Any]] = {}
    for stix_id, row in active.items():
        if row.get("type") != "attack-pattern":
            continue
        reference = _preferred_reference(row)
        external_id = str(reference.get("external_id") or "")
        if not external_id:
            continue
        tactics = [
            tactic_name_by_phase.get(
                str(phase.get("phase_name")),
                str(phase.get("phase_name") or "").replace("-", " ").title(),
            )
            for phase in row.get("kill_chain_phases", [])
            if isinstance(phase, dict) and phase.get("phase_name")
        ]
        techniques_by_ref[stix_id] = {
            "technique_id": external_id.upper(),
            "name": str(row.get("name") or external_id),
            "description": str(row.get("description") or ""),
            "tactics": list(dict.fromkeys(tactics)),
            "platforms": _display_platforms(row.get("x_mitre_platforms", []) or [], str(metadata["id"])),
            "data_sources": list(row.get("x_mitre_data_sources", []) or []),
            "url": reference.get("url"),
            "parent_technique_id": None,
            "entities": [],
        }
    for child_ref, parent_ref in parent_by_child.items():
        if child_ref in techniques_by_ref and parent_ref in techniques_by_ref:
            techniques_by_ref[child_ref]["parent_technique_id"] = techniques_by_ref[parent_ref]["technique_id"]

    entity_types = {
        "intrusion-set": "threat_group",
        "threat-actor": "threat_actor",
        "campaign": "campaign",
        "malware": "malware",
        "tool": "tool",
    }
    entities_by_ref: dict[str, dict[str, Any]] = {}
    for stix_id, row in active.items():
        if row.get("type") not in entity_types:
            continue
        reference = _preferred_reference(row)
        entities_by_ref[stix_id] = {
            "entity_id": str(reference.get("external_id") or stix_id),
            "name": str(row.get("name") or reference.get("external_id") or stix_id),
            "entity_type": entity_types[str(row.get("type"))],
            "aliases": list(row.get("aliases", []) or []),
            "description": str(row.get("description") or ""),
            "url": reference.get("url"),
            "technique_ids": [],
        }
    relationship_count = 0
    for row in active.values():
        if row.get("type") != "relationship" or row.get("relationship_type") != "uses":
            continue
        source_ref = str(row.get("source_ref") or "")
        target_ref = str(row.get("target_ref") or "")
        entity = entities_by_ref.get(source_ref)
        technique = techniques_by_ref.get(target_ref)
        if not entity or not technique:
            continue
        entity["technique_ids"].append(technique["technique_id"])
        technique["entities"].append(
            {
                "entity_id": entity["entity_id"],
                "name": entity["name"],
                "entity_type": entity["entity_type"],
            }
        )
        relationship_count += 1
    techniques = sorted(techniques_by_ref.values(), key=lambda row: row["technique_id"])
    for technique in techniques:
        technique["entities"] = _unique_entities(technique["entities"])
    entities = sorted(entities_by_ref.values(), key=lambda row: (row["entity_type"], row["name"].casefold()))
    for entity in entities:
        entity["technique_ids"] = sorted(set(entity["technique_ids"]))
    tactic_rows = _attach_techniques(ordered_tactics, techniques)
    return {
        "version": _stix_version(payload, objects),
        "tactics": tactic_rows,
        "techniques": techniques,
        "entities": entities,
        "relationships": [],
        "relationship_count": relationship_count,
    }


def _display_platforms(values: list[Any], family_id: str) -> list[str]:
    platforms = [str(value) for value in values if value is not None and str(value).strip()]
    if family_id == "attack-ics" and (not platforms or platforms == ["None"]):
        return ["ICS/OT"]
    return platforms


def _parse_f3(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    tactics = [
        {"id": str(row["id"]), "name": str(row["name"]), "description": str(row.get("description") or "")}
        for row in rows
        if isinstance(row, dict) and row.get("tactic")
    ]
    tactic_names = {row["id"]: row["name"] for row in tactics}
    techniques: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("tactic") or not row.get("id"):
            continue
        technique_tactics = [
            tactic_names.get(str(value), str(value))
            for value in row.get("tactics", []) or []
        ]
        techniques.append(
            {
                "technique_id": str(row["id"]),
                "name": str(row.get("name") or row["id"]),
                "description": str(row.get("description") or ""),
                "tactics": technique_tactics,
                "parent_technique_id": row.get("parentTechnique"),
                "url": row.get("url"),
                "entities": [],
            }
        )
    return {
        "version": str(next((row.get("version") for row in rows if isinstance(row, dict) and row.get("version")), "1.1")),
        "tactics": _attach_techniques(tactics, techniques),
        "techniques": techniques,
        "entities": [],
        "relationships": [],
    }


def _parse_aadapt(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    matrix = (payload.get("matrices") or [{}])[0]
    tactics = [
        {"id": str(row["id"]), "name": str(row["name"]), "description": str(row.get("description") or "")}
        for row in matrix.get("tactics", [])
        if isinstance(row, dict) and row.get("id")
    ]
    tactic_names = {row["id"]: row["name"] for row in tactics}
    techniques: list[dict[str, Any]] = []

    def add_technique(row: dict[str, Any], parent: str | None = None) -> None:
        technique_id = str(row.get("id") or "")
        if not technique_id:
            return
        techniques.append(
            {
                "technique_id": technique_id,
                "name": str(row.get("name") or technique_id),
                "description": str(row.get("description") or ""),
                "tactics": [tactic_names.get(str(value), str(value)) for value in row.get("tactics", []) or []],
                "parent_technique_id": parent or row.get("subtechnique-of"),
                "url": f"https://aadapt.mitre.org/techniques/{technique_id}/",
                "entities": [],
            }
        )
        for child in row.get("subtechniques", []) or []:
            if isinstance(child, dict):
                add_technique(child, technique_id)

    for row in matrix.get("techniques", []) or []:
        if isinstance(row, dict):
            add_technique(row)
    return {
        "version": str(payload.get("version") or "rolling"),
        "tactics": _attach_techniques(tactics, techniques),
        "techniques": techniques,
        "entities": [],
        "relationships": [],
    }


def _parse_d3fend(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("results", {}).get("bindings", [])
    by_id: dict[str, dict[str, Any]] = {}
    relationship_count = 0
    for row in rows:
        uri = _binding(row, "def_tech")
        if not uri:
            continue
        technique_id = uri.rsplit("#", 1)[-1]
        tactic = _binding(row, "def_tactic_label") or "Unclassified"
        item = by_id.setdefault(
            technique_id,
            {
                "technique_id": technique_id,
                "name": _binding(row, "def_tech_label") or technique_id,
                "description": "",
                "tactics": [],
                "entities": [],
                "related_attack_techniques": [],
                "artifacts": [],
            },
        )
        item["tactics"].append(tactic)
        attack_id = _binding(row, "off_tech_id")
        if attack_id:
            item["related_attack_techniques"].append(attack_id)
            relationship_count += 1
        artifact = _binding(row, "def_artifact_label")
        if artifact:
            item["artifacts"].append(artifact)
    techniques = sorted(by_id.values(), key=lambda row: row["name"].casefold())
    for item in techniques:
        item["tactics"] = list(dict.fromkeys(item["tactics"]))
        item["related_attack_techniques"] = sorted(set(item["related_attack_techniques"]))
        item["artifacts"] = sorted(set(item["artifacts"]))
    tactic_order = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]
    tactic_names = list(dict.fromkeys([*tactic_order, *(t for item in techniques for t in item["tactics"])]))
    tactics = [{"id": name.lower(), "name": name, "description": ""} for name in tactic_names]
    return {
        "version": str(payload.get("version") or "rolling"),
        "tactics": _attach_techniques(tactics, techniques),
        "techniques": techniques,
        "entities": [],
        "relationships": [],
        "relationship_count": relationship_count,
    }


def _parse_emb3d(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    objects = [row for row in payload.get("objects", []) if isinstance(row, dict)]
    nodes: dict[str, dict[str, Any]] = {}
    collections: dict[str, list[dict[str, Any]]] = {"properties": [], "threats": [], "mitigations": []}
    for row in objects:
        row_type = row.get("type")
        if row_type == "x-mitre-emb3d-property":
            kind, external_id = "properties", row.get("x_mitre_emb3d_property_id")
        elif row_type == "vulnerability":
            kind, external_id = "threats", row.get("x_mitre_emb3d_threat_id")
        elif row_type == "course-of-action":
            kind, external_id = "mitigations", row.get("x_mitre_emb3d_mitigation_id")
        else:
            continue
        item = {
            "id": str(external_id or row.get("id")),
            "name": str(row.get("name") or external_id or row.get("id")),
            "description": str(row.get("description") or ""),
            "category": str(row.get("category") or row.get("x_mitre_emb3d_threat_category") or "Unclassified"),
            "cwes": list(row.get("x_mitre_emb3d_threat_CWEs", []) or []),
            "cves": list(row.get("x_mitre_emb3d_threat_CVEs", []) or []),
        }
        nodes[str(row.get("id"))] = {**item, "kind": kind}
        collections[kind].append(item)
    relationships: list[dict[str, Any]] = []
    for row in objects:
        if row.get("type") != "relationship":
            continue
        source = nodes.get(str(row.get("source_ref") or ""))
        target = nodes.get(str(row.get("target_ref") or ""))
        if source and target:
            relationships.append(
                {
                    "source": source["id"],
                    "target": target["id"],
                    "type": str(row.get("relationship_type") or "related-to"),
                }
            )
    for values in collections.values():
        values.sort(key=lambda row: (row["category"], row["name"].casefold()))
    return {
        "version": _stix_version(payload, objects),
        "collections": collections,
        "relationships": relationships,
        "tactics": [],
        "techniques": collections["threats"],
        "entities": [],
    }


def _parse_capec(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    return _parse_mitre_xml_catalog(
        path,
        entry_tag="Attack_Pattern",
        related_tag="Related_Attack_Pattern",
        related_id="CAPEC_ID",
        prefix="CAPEC",
        item_url="https://capec.mitre.org/data/definitions/{id}.html",
    )


def _parse_cwe(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    return _parse_mitre_xml_catalog(
        path,
        entry_tag="Weakness",
        related_tag="Related_Weakness",
        related_id="CWE_ID",
        prefix="CWE",
        item_url="https://cwe.mitre.org/data/definitions/{id}.html",
    )


def _parse_mitre_xml_catalog(
    path: Path,
    *,
    entry_tag: str,
    related_tag: str,
    related_id: str,
    prefix: str,
    item_url: str,
) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        xml_name = next(name for name in archive.namelist() if name.lower().endswith(".xml"))
        root = ElementTree.fromstring(archive.read(xml_name))
    version = root.attrib.get("Version") or root.attrib.get("Version_Name") or "rolling"
    entries: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for element in root.iter():
        if _local_name(element.tag) != entry_tag:
            continue
        raw_id = str(element.attrib.get("ID") or "")
        if not raw_id:
            continue
        external_id = f"{prefix}-{raw_id}"
        related: list[dict[str, str]] = []
        for child in element.iter():
            if _local_name(child.tag) != related_tag or not child.attrib.get(related_id):
                continue
            target = f"{prefix}-{child.attrib[related_id]}"
            relation = str(child.attrib.get("Nature") or "related-to")
            related.append({"id": target, "relation": relation})
            relationships.append({"source": external_id, "target": target, "type": relation})
        entries.append(
            {
                "id": external_id,
                "name": str(element.attrib.get("Name") or external_id),
                "abstraction": str(element.attrib.get("Abstraction") or "Unclassified"),
                "status": str(element.attrib.get("Status") or ""),
                "url": item_url.format(id=raw_id),
                "related": related,
            }
        )
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        groups.setdefault(entry["abstraction"], []).append(entry)
    return {
        "version": str(version),
        "collections": {"groups": [{"name": name, "items": values} for name, values in sorted(groups.items())]},
        "tactics": [],
        "techniques": entries,
        "entities": [],
        "relationships": relationships,
    }


def _parse_inform(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    dimensions: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        dimension_id = str(row.get("Dimension ID") or row.get("Dimension") or "Unclassified")
        dimension = dimensions.setdefault(
            dimension_id,
            {
                "id": dimension_id,
                "name": str(row.get("Dimension") or dimension_id),
                "weight": row.get("Dimension Weight"),
                "components": {},
            },
        )
        component_id = str(row.get("Component ID") or row.get("Component") or "Unclassified")
        component = dimension["components"].setdefault(
            component_id,
            {
                "id": component_id,
                "name": str(row.get("Component") or component_id),
                "weight": row.get("Component Weight"),
                "levels": [],
            },
        )
        component["levels"].append(
            {
                "uid": row.get("UID"),
                "question": row.get("Question"),
                "level": row.get("Level Description"),
                "level_id": row.get("Level ID"),
                "impact": row.get("Impact"),
                "complexity": row.get("Complexity"),
                "points": row.get("Points"),
            }
        )
    dimension_rows = []
    for dimension in dimensions.values():
        dimension["components"] = list(dimension["components"].values())
        dimension_rows.append(dimension)
    return {
        "version": "rolling",
        "collections": {"dimensions": dimension_rows},
        "item_count": sum(
            len(component["levels"])
            for dimension in dimension_rows
            for component in dimension["components"]
        ),
        "tactics": [],
        "techniques": [],
        "entities": [],
        "relationships": [],
    }


def _parse_disarm(path: Path, _metadata: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    tactics = [
        {
            "id": str(row.get("id") or ""),
            "name": str(row.get("name") or row.get("id") or "Unclassified"),
            "description": str(row.get("summary") or ""),
        }
        for row in payload.get("tactics", [])
        if isinstance(row, dict) and row.get("id")
    ]
    tactic_names = {row["id"]: row["name"] for row in tactics}
    techniques = [
        {
            "technique_id": str(row.get("id") or ""),
            "name": str(row.get("name") or row.get("id") or ""),
            "description": str(row.get("summary") or ""),
            "tactics": [
                str(row.get("tactic") or tactic_names.get(str(row.get("tactic_id") or "")) or "Unclassified")
            ],
            "parent_technique_id": _disarm_parent_id(str(row.get("id") or "")),
            "url": None,
            "entities": [],
            "status": "usable" if row.get("usable") else "reference",
        }
        for row in payload.get("techniques", [])
        if isinstance(row, dict) and row.get("id")
    ]
    return {
        "version": str(payload.get("version") or "2.0 observable"),
        "tactics": _attach_techniques(tactics, techniques),
        "techniques": techniques,
        "entities": [],
        "relationships": [],
    }


def _disarm_parent_id(technique_id: str) -> str | None:
    return technique_id.rsplit(".", 1)[0] if "." in technique_id else None


def _attach_techniques(
    tactics: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for tactic in tactics:
        members = [row for row in techniques if tactic["name"] in row.get("tactics", [])]
        rows.append({**tactic, "techniques": members, "technique_count": len(members)})
    return rows


def _preferred_reference(row: dict[str, Any]) -> dict[str, Any]:
    references = [ref for ref in row.get("external_references", []) if isinstance(ref, dict)]
    return next((ref for ref in references if ref.get("external_id")), references[0] if references else {})


def _unique_entities(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return list({str(row["entity_id"]): row for row in rows}.values())


def _stix_version(payload: dict[str, Any], objects: list[dict[str, Any]]) -> str:
    collection = next((row for row in objects if row.get("type") == "x-mitre-collection"), {})
    return str(
        collection.get("x_mitre_version")
        or collection.get("version")
        or payload.get("version")
        or "rolling"
    )


def _binding(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value.get("value") or "") if isinstance(value, dict) else ""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
