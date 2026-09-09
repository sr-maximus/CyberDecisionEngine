from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import urlparse

from cyberdeck.analysis.mitre_mapping import describe_attack_technique
from cyberdeck.analysis.threat_news import build_threat_news
from cyberdeck.cti.attack_profiles import resolve_attack_entity_profiles
from cyberdeck.cti.knowledge import build_knowledge_manifest
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RiskFinding, ThreatEvent
from cyberdeck.settings import load_yaml


CTI_SCHEMA_VERSION = "cti-snapshot-v1.0"
CTI_MODEL_VERSION = "contextual-threat-relevance-v1.0.0"
CTI_STATES = ("OBSERVED", "INFERRED", "RELATED", "REFERENCE")
CTI_STATE_PRIORITY = {state: index for index, state in enumerate(reversed(CTI_STATES))}

DEFAULT_WEIGHTS = {
    "direct_evidence": 0.25,
    "ttp_overlap": 0.20,
    "technology_vulnerability_fit": 0.15,
    "sector_fit": 0.15,
    "geography_fit": 0.10,
    "campaign_recency": 0.10,
    "source_diversity": 0.05,
}

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Stealth",
    "Defense Impairment",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def build_cti_snapshot(
    events: Iterable[ThreatEvent],
    findings: Iterable[RiskFinding],
    organization: OrganizationProfile,
    *,
    threat_news: dict[str, Any] | None = None,
    generated_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Build the single CTI source of truth for dashboards, APIs and reports.

    The score is contextual relevance, not attack probability. Contextual and
    reference material can explain the threat landscape but cannot become an
    observed attack without validated adversary telemetry.
    """

    event_rows = [
        event
        for event in events
        if event.evidence_status not in {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}
    ]
    finding_rows = list(findings)
    threat = threat_news or build_threat_news(event_rows)
    weights = _weights()
    event_by_evidence = {
        str(event.canonical_id or event.id): event for event in event_rows
    }

    actors = [
        _actor_view(actor, event_by_evidence, organization, weights)
        for actor in threat.get("actors", []) or []
    ]
    actors.sort(
        key=lambda row: (
            -float(row.get("relevance_score", 0.0)),
            -int(row.get("evidence_count", 0)),
            str(row.get("name", "")),
        )
    )
    campaigns = [_campaign_view(row, actors) for row in threat.get("campaigns", []) or []]
    run_techniques = [_technique_view(row) for row in threat.get("ttps", []) or []]
    actors, campaigns, techniques = _merge_attack_reference_profiles(
        actors,
        campaigns,
        run_techniques,
    )
    attack_matrix = _attack_matrix(techniques)
    attack_flows = _attack_flows(campaigns, techniques)
    graph = _relationship_graph(organization, actors, campaigns, techniques)
    quality = _quality_summary(actors, campaigns, techniques, event_rows)
    detection = _detection_coverage(techniques)
    victimology = _victimology(event_rows, organization)
    evidence_index = _evidence_index(event_rows, actors, campaigns, techniques)
    knowledge = build_knowledge_manifest(generated_at=generated_at)

    return {
        "schema_version": CTI_SCHEMA_VERSION,
        "model_version": CTI_MODEL_VERSION,
        "generated_at": knowledge["generated_at"],
        "states": list(CTI_STATES),
        "scope": {
            "organization": organization.name,
            "domains": list(dict.fromkeys(organization.primary_domains)),
            "sector": organization.sector,
            "country": organization.country,
            "countries_of_operation": list(
                dict.fromkeys(
                    [organization.country, *organization.countries_of_operation]
                    if organization.country
                    else organization.countries_of_operation
                )
            ),
        },
        "relevance_model": {
            "name": "Contextual Threat Relevance Score",
            "weights": weights,
            "range": [0, 100],
            "interpretation": "Priorizacion contextual de inteligencia; no es probabilidad de ataque ni confirma un incidente.",
            "missing_data": "Un factor sin evidencia aporta cero y se conserva como limitacion; no se imputa con IA.",
        },
        "overview": {
            "actor_count": len(actors),
            "campaign_count": len(campaigns),
            "technique_count": len(techniques),
            "run_technique_count": sum(1 for row in techniques if row.get("run_supported")),
            "reference_technique_count": sum(
                1 for row in techniques if row.get("reference_supported")
            ),
            "observed_count": quality["state_counts"]["OBSERVED"],
            "inferred_count": quality["state_counts"]["INFERRED"],
            "related_count": quality["state_counts"]["RELATED"],
            "reference_count": quality["state_counts"]["REFERENCE"],
            "evidence_count": len(evidence_index),
            "top_actor": actors[0]["name"] if actors else None,
            "top_relevance_score": actors[0]["relevance_score"] if actors else None,
            "highest_state": _highest_state(quality["state_counts"]),
        },
        "actors": actors,
        "campaigns": campaigns,
        "techniques": techniques,
        "attack_matrix": attack_matrix,
        "attack_flows": attack_flows,
        "victimology": victimology,
        "detection_coverage": detection,
        "control_coverage": {
            "frameworks": sorted(
                {
                    framework
                    for actor in actors
                    for framework in actor.get("frameworks", [])
                    if framework
                }
            ),
            "d3fend_controls": detection["controls"],
            "validated_finding_count": sum(
                1
                for finding in finding_rows
                if finding.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
            ),
            "interpretation": "Cobertura de mapeo basada en TTP y evidencia; no equivale a cumplimiento ni efectividad interna.",
        },
        "graph": graph,
        "evidence": evidence_index,
        "quality": quality,
        "knowledge_versions": knowledge,
        "limitations": [
            "OBSERVED exige telemetria adversaria validada, activo, tiempo y evidencia; una noticia no cumple por si sola.",
            "INFERRED identifica una hipotesis analitica trazable y nunca se presenta como hecho.",
            "RELATED expresa ajuste de sector, tecnologia, geografia o TTP sin atribuir un ataque al alcance.",
            "REFERENCE conserva conocimiento de marco o contexto sin convertirlo en hallazgo.",
            "La relevancia contextual ordena revision; no estima una probabilidad calibrada de ataque.",
        ],
    }


def _weights() -> dict[str, float]:
    try:
        configured = load_yaml("config/cti.yml").get("relevance", {}).get("weights", {})
    except (FileNotFoundError, ValueError):
        configured = {}
    weights = {
        key: max(0.0, float(configured.get(key, value)))
        for key, value in DEFAULT_WEIGHTS.items()
    }
    total = sum(weights.values()) or 1.0
    return {key: round(value / total, 6) for key, value in weights.items()}


def _actor_view(
    actor: dict[str, Any],
    event_by_evidence: dict[str, ThreatEvent],
    organization: OrganizationProfile,
    weights: dict[str, float],
) -> dict[str, Any]:
    evidence_ids = [str(value) for value in actor.get("evidence_ids", []) if value]
    related_events = [event_by_evidence[value] for value in evidence_ids if value in event_by_evidence]
    relationships = {str(value) for value in actor.get("relationships", [])}
    state = _actor_state(actor, related_events, relationships)
    factors = _actor_factors(actor, related_events, organization, relationships)
    score = round(100 * sum(weights[key] * factors[key] for key in weights), 1)
    urls = list(dict.fromkeys(str(value) for value in actor.get("urls", []) if value))
    source_hosts = sorted(
        {
            (urlparse(url).hostname or "").lower()
            for url in urls
            if (urlparse(url).hostname or "").strip()
        }
    )
    return {
        "actor_id": _stable_id("actor", str(actor.get("actor") or "unknown")),
        "name": str(actor.get("actor") or "Unknown"),
        "entity_type": "threat_actor",
        "aliases": [],
        "state": state,
        "relevance_score": score,
        "relevance_band": _band(score),
        "factors": factors,
        "explanation": _score_explanation(factors, state, organization),
        "evidence_count": int(actor.get("record_count", 0) or 0),
        "validated_evidence_count": int(actor.get("validated_count", 0) or 0),
        "observed_attack_count": int(actor.get("observed_attack_count", 0) or 0),
        "source_count": len(source_hosts),
        "source_hosts": source_hosts,
        "relationships": sorted(relationships),
        "techniques": list(actor.get("techniques", []) or []),
        "run_techniques": list(actor.get("techniques", []) or []),
        "documented_techniques": [],
        "campaigns": list(actor.get("campaigns", []) or []),
        "d3fend": list(actor.get("d3fend", []) or []),
        "frameworks": list(actor.get("frameworks", []) or []),
        "last_observed_at": actor.get("last_observed_at"),
        "evidence_ids": evidence_ids,
        "evidence_urls": urls,
        "limitations": _actor_limitations(state, factors),
    }


def _actor_state(
    actor: dict[str, Any],
    events: list[ThreatEvent],
    relationships: set[str],
) -> str:
    if int(actor.get("observed_attack_count", 0) or 0) > 0 or any(
        event.incident_confirmed
        and event.attack_mapping_status in {"observed_adversary_behavior", "observed_attack"}
        and event.evidence_status == EvidenceStatus.CONFIRMED
        for event in events
    ):
        return "OBSERVED"
    if any(
        str(getattr(event.public_attribution_status, "value", event.public_attribution_status))
        in {"possible", "related"}
        and bool(event.attribution_basis)
        for event in events
    ):
        return "INFERRED"
    if relationships & {"scope_supported"} or any(
        event.relationship_to_scope in {"direct", "group", "sector", "related"}
        for event in events
    ):
        return "RELATED"
    return "REFERENCE"


def _actor_factors(
    actor: dict[str, Any],
    events: list[ThreatEvent],
    organization: OrganizationProfile,
    relationships: set[str],
) -> dict[str, float]:
    direct = 1.0 if "scope_supported" in relationships else 0.55 if any(
        event.relationship_to_scope in {"direct", "group"} for event in events
    ) else 0.35 if any(event.relationship_to_scope in {"sector", "related"} for event in events) else 0.15
    techniques = list(actor.get("techniques", []) or [])
    ttp = min(1.0, len(techniques) / 4.0)
    technology = min(
        1.0,
        max(
            [
                1.0
                if event.vulnerability_status
                in {"cve_applicable", "cve_confirmed", "kev_exposed", "exploitation_observed"}
                else 0.75
                if event.product or event.vendor or event.version
                else 0.45
                if str(getattr(event.primary_technology_domain, "value", event.primary_technology_domain))
                != "unknown"
                else 0.0
                for event in events
            ]
            or [0.0]
        ),
    )
    sector = 1.0 if any(event.relationship_to_scope == "sector" for event in events) else (
        0.75 if organization.sector and any(event.relationship_to_scope in {"direct", "group"} for event in events) else 0.0
    )
    scope_countries = _scope_countries(organization)
    geography = 1.0 if any(
        _event_country(event).casefold() in scope_countries
        for event in events
        if _event_country(event)
    ) else 0.0
    newest_age = min([max(0, int(event.age_days)) for event in events] or [365])
    recency = round(math.exp(-math.log(2) * newest_age / 90.0), 4)
    sources = {
        (urlparse(event.evidence_url or "").hostname or event.source).casefold()
        for event in events
        if event.evidence_url or event.source
    }
    diversity = min(1.0, len(sources) / 3.0)
    return {
        "direct_evidence": round(direct, 4),
        "ttp_overlap": round(ttp, 4),
        "technology_vulnerability_fit": round(technology, 4),
        "sector_fit": round(sector, 4),
        "geography_fit": round(geography, 4),
        "campaign_recency": round(recency, 4),
        "source_diversity": round(diversity, 4),
    }


def _technique_view(row: dict[str, Any]) -> dict[str, Any]:
    frameworks = list(row.get("frameworks", []) or [])
    identifier = str(row.get("technique") or "unmapped")
    if re.fullmatch(r"T\d{4}(?:\.\d{3})?", identifier, re.IGNORECASE):
        family = "ATT&CK"
    elif identifier.upper().startswith("AML."):
        family = "ATLAS"
    elif identifier.upper().startswith("D3-"):
        family = "D3FEND"
    elif identifier.upper().startswith(("TID-", "PID-", "MID-")):
        family = "EMB3D"
    else:
        family = frameworks[0] if frameworks else "REFERENCE"
    return {
        "technique_id": identifier,
        "name": row.get("name") or identifier,
        "family": family,
        "tactics": list(row.get("tactics", []) or []),
        "state": "RELATED" if row.get("evidence_ids") else "REFERENCE",
        "record_count": int(row.get("record_count", 0) or 0),
        "actors": list(row.get("actors", []) or []),
        "campaigns": list(row.get("campaigns", []) or []),
        "run_actors": list(row.get("actors", []) or []),
        "run_campaigns": list(row.get("campaigns", []) or []),
        "reference_actors": [],
        "reference_campaigns": [],
        "run_supported": bool(row.get("evidence_ids")),
        "reference_supported": False,
        "d3fend": list(row.get("d3fend", []) or []),
        "frameworks": frameworks,
        "evidence_ids": list(row.get("evidence_ids", []) or []),
        "evidence_urls": list(row.get("urls", []) or []),
        "knowledge_urls": [],
    }


def _campaign_view(row: dict[str, Any], actors: list[dict[str, Any]]) -> dict[str, Any]:
    actor_rows = {actor["name"].casefold(): actor for actor in actors}
    linked_actors = list(row.get("actors", []) or [])
    evidence_ids = list(row.get("evidence_ids", []) or [])
    observed_evidence = {
        evidence_id
        for name in linked_actors
        for evidence_id in actor_rows.get(name.casefold(), {}).get("evidence_ids", [])
        if actor_rows.get(name.casefold(), {}).get("state") == "OBSERVED"
    }
    if observed_evidence.intersection(evidence_ids):
        state = "OBSERVED"
    elif any(
        actor_rows.get(name.casefold(), {}).get("state") == "INFERRED"
        for name in linked_actors
    ):
        state = "INFERRED"
    else:
        state = "RELATED"
    return {
        "campaign_id": _stable_id("campaign", str(row.get("campaign") or "unknown")),
        "name": row.get("campaign") or "Unnamed campaign",
        "entity_type": "campaign",
        "state": state,
        "record_count": int(row.get("record_count", 0) or 0),
        "actors": linked_actors,
        "techniques": list(row.get("techniques", []) or []),
        "run_techniques": list(row.get("techniques", []) or []),
        "documented_techniques": [],
        "frameworks": list(row.get("frameworks", []) or []),
        "last_observed_at": row.get("last_observed_at"),
        "evidence_ids": evidence_ids,
        "evidence_urls": list(row.get("urls", []) or []),
    }


def _merge_attack_reference_profiles(
    actors: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    run_techniques: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge ATT&CK knowledge without promoting it to run evidence."""

    actor_profiles = resolve_attack_entity_profiles(
        [str(row.get("name") or "") for row in actors],
        allowed_types={"intrusion-set", "threat-actor"},
    )
    campaign_profiles = resolve_attack_entity_profiles(
        [str(row.get("name") or "") for row in campaigns],
        allowed_types={"campaign"},
    )
    technique_by_id = {
        str(row["technique_id"]).upper(): row
        for row in run_techniques
        if row.get("technique_id")
    }

    for entity, profiles, owner_key, reference_owner_key in (
        (actors, actor_profiles, "actors", "reference_actors"),
        (campaigns, campaign_profiles, "campaigns", "reference_campaigns"),
    ):
        for row in entity:
            name = str(row.get("name") or "")
            profile = profiles.get(name)
            row.setdefault("run_techniques", list(row.get("techniques", []) or []))
            row.setdefault("documented_techniques", [])
            row.setdefault("knowledge_references", [])
            row.setdefault("aliases", [])
            if not profile:
                row["profile_status"] = "not_matched"
                continue
            documented_ids = [
                str(technique.get("technique_id") or "").upper()
                for technique in profile.get("techniques", [])
                if technique.get("technique_id")
            ]
            row.update(
                {
                    "entity_type": profile.get("entity_type") or row.get("entity_type"),
                    "attack_id": profile.get("external_id"),
                    "aliases": list(profile.get("aliases", []) or []),
                    "documented_techniques": list(dict.fromkeys(documented_ids)),
                    "techniques": list(
                        dict.fromkeys([*row.get("run_techniques", []), *documented_ids])
                    ),
                    "knowledge_source": profile.get("knowledge_source"),
                    "knowledge_url": profile.get("url"),
                    "knowledge_description": profile.get("description"),
                    "knowledge_created": profile.get("created"),
                    "knowledge_modified": profile.get("modified"),
                    "first_seen": profile.get("first_seen"),
                    "last_seen": profile.get("last_seen"),
                    "attack_version": profile.get("version"),
                    "attack_domains": list(profile.get("domains", []) or []),
                    "contributors": list(profile.get("contributors", []) or []),
                    "external_references": list(
                        profile.get("external_references", []) or []
                    ),
                    "profile_status": "matched",
                }
            )
            if profile.get("url"):
                row["knowledge_references"] = [str(profile["url"])]
            frameworks = list(row.get("frameworks", []) or [])
            if documented_ids and "MITRE ATT&CK Enterprise" not in frameworks:
                frameworks.append("MITRE ATT&CK Enterprise")
            row["frameworks"] = frameworks

            documented_d3fend: list[dict[str, Any]] = []
            for technique in profile.get("techniques", []):
                identifier = str(technique.get("technique_id") or "").upper()
                if not identifier:
                    continue
                descriptor = describe_attack_technique(identifier)
                knowledge_urls = list(
                    dict.fromkeys(
                        str(value)
                        for value in [
                            profile.get("url"),
                            technique.get("url"),
                            *(technique.get("relationship_references", []) or []),
                        ]
                        if value
                    )
                )
                item = technique_by_id.get(identifier)
                if item is None:
                    item = {
                        "technique_id": identifier,
                        "name": technique.get("name") or descriptor.get("name") or identifier,
                        "description": technique.get("description") or "",
                        "family": "ATT&CK",
                        "tactics": list(technique.get("tactics") or descriptor.get("tactics") or []),
                        "platforms": list(technique.get("platforms", []) or []),
                        "data_sources": list(technique.get("data_sources", []) or []),
                        "external_references": list(
                            technique.get("external_references", []) or []
                        ),
                        "relationship_description": technique.get(
                            "relationship_description"
                        ),
                        "relationship_references": list(
                            technique.get("relationship_references", []) or []
                        ),
                        "attack_version": technique.get("version"),
                        "knowledge_created": technique.get("created"),
                        "knowledge_modified": technique.get("modified"),
                        "state": "REFERENCE",
                        "record_count": 0,
                        "actors": [],
                        "campaigns": [],
                        "run_actors": [],
                        "run_campaigns": [],
                        "reference_actors": [],
                        "reference_campaigns": [],
                        "run_supported": False,
                        "reference_supported": True,
                        "d3fend": list(descriptor.get("d3fend", []) or []),
                        "frameworks": ["MITRE ATT&CK Enterprise"],
                        "evidence_ids": [],
                        "evidence_urls": [],
                        "knowledge_urls": knowledge_urls,
                        "parent_technique_id": technique.get("parent_technique_id"),
                    }
                    technique_by_id[identifier] = item
                else:
                    item["description"] = item.get("description") or technique.get(
                        "description"
                    )
                    item["platforms"] = list(
                        dict.fromkeys(
                            [
                                *item.get("platforms", []),
                                *(technique.get("platforms", []) or []),
                            ]
                        )
                    )
                    item["data_sources"] = list(
                        dict.fromkeys(
                            [
                                *item.get("data_sources", []),
                                *(technique.get("data_sources", []) or []),
                            ]
                        )
                    )
                    item["relationship_references"] = list(
                        dict.fromkeys(
                            [
                                *item.get("relationship_references", []),
                                *(technique.get("relationship_references", []) or []),
                            ]
                        )
                    )
                    item["relationship_description"] = item.get(
                        "relationship_description"
                    ) or technique.get("relationship_description")
                item["reference_supported"] = True
                item[reference_owner_key] = list(
                    dict.fromkeys([*item.get(reference_owner_key, []), name])
                )
                item[owner_key] = list(dict.fromkeys([*item.get(owner_key, []), name]))
                item["knowledge_urls"] = list(
                    dict.fromkeys([*item.get("knowledge_urls", []), *knowledge_urls])
                )
                if technique.get("parent_technique_id"):
                    item["parent_technique_id"] = technique["parent_technique_id"]
                documented_d3fend.extend(item.get("d3fend", []) or [])
            row["d3fend"] = _dedupe_named_rows(
                [*row.get("d3fend", []), *documented_d3fend]
            )

    techniques = sorted(
        technique_by_id.values(),
        key=lambda row: str(row.get("technique_id") or ""),
    )
    return actors, campaigns, techniques


def _dedupe_named_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get("id") or row.get("name") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def _attack_matrix(techniques: list[dict[str, Any]]) -> dict[str, Any]:
    tactic_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unmapped: list[dict[str, Any]] = []
    for technique in techniques:
        tactics = technique.get("tactics", []) or []
        if not tactics:
            unmapped.append(technique)
        for tactic in tactics:
            tactic_rows[str(tactic)].append(technique)
    ordered = [*TACTIC_ORDER, *sorted(set(tactic_rows) - set(TACTIC_ORDER))]
    rows = [
        {
            "tactic": tactic,
            "technique_count": len(tactic_rows[tactic]),
            "evidence_count": sum(int(row.get("record_count", 0)) for row in tactic_rows[tactic]),
            "techniques": tactic_rows[tactic],
        }
        for tactic in ordered
        if tactic_rows[tactic]
    ]
    return {
        "tactics": rows,
        "tactic_count": len(rows),
        "technique_count": len(techniques),
        "run_technique_count": sum(
            1 for row in techniques if row.get("run_supported")
        ),
        "reference_technique_count": sum(
            1 for row in techniques if row.get("reference_supported")
        ),
        "unmapped": unmapped,
        "interpretation": (
            "La matriz separa las TTP sustentadas por la corrida del repertorio "
            "documentado en ATT&CK; una referencia no implica actividad observada."
        ),
    }


def _attack_flows(
    campaigns: list[dict[str, Any]], techniques: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {row["technique_id"]: row for row in techniques}
    tactic_rank = {name: index for index, name in enumerate(TACTIC_ORDER)}
    flows: list[dict[str, Any]] = []
    for campaign in campaigns:
        steps = [by_id[value] for value in campaign.get("techniques", []) if value in by_id]
        steps.sort(
            key=lambda row: min(
                [tactic_rank.get(tactic, len(TACTIC_ORDER)) for tactic in row.get("tactics", [])]
                or [len(TACTIC_ORDER)]
            )
        )
        if len(steps) < 2:
            continue
        flows.append(
            {
                "flow_id": _stable_id("flow", campaign["campaign_id"]),
                "name": campaign["name"],
                "state": campaign["state"],
                "steps": [
                    {
                        "sequence": index + 1,
                        "technique_id": step["technique_id"],
                        "name": step["name"],
                        "tactics": step["tactics"],
                    }
                    for index, step in enumerate(steps)
                ],
                "evidence_ids": campaign["evidence_ids"],
                "limitations": "El orden usa la secuencia tactica de ATT&CK; no afirma una cronologia observada sin timestamps por paso.",
            }
        )
    return flows


def _relationship_graph(
    organization: OrganizationProfile,
    actors: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes_by_id: dict[str, dict[str, Any]] = {
        "scope:organization": {
            "id": "scope:organization",
            "label": organization.name or "Declared scope",
            "type": "organization",
            "state": "REFERENCE",
            "size": 28,
            "group_key": "scope:organization",
            "evidence_ids": [],
            "evidence_urls": [],
        }
    }
    edges_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_edge(
        source: str,
        target: str,
        relation: str,
        state: str,
        weight: int | float,
        evidence_ids: Iterable[str] | None = None,
        knowledge_urls: Iterable[str] | None = None,
    ) -> None:
        if source not in nodes_by_id or target not in nodes_by_id:
            return
        key = (source, target, relation)
        identifiers = [str(value) for value in (evidence_ids or []) if value]
        references = [str(value) for value in (knowledge_urls or []) if value]
        if key in edges_by_key:
            edge = edges_by_key[key]
            edge["weight"] = max(float(edge["weight"]), float(weight))
            edge["evidence_ids"] = list(dict.fromkeys([*edge["evidence_ids"], *identifiers]))
            edge["knowledge_urls"] = list(
                dict.fromkeys([*edge.get("knowledge_urls", []), *references])
            )
            if CTI_STATE_PRIORITY.get(state, 0) > CTI_STATE_PRIORITY.get(
                str(edge.get("state") or "REFERENCE"), 0
            ):
                edge["state"] = state
            return
        edges_by_key[key] = {
            "id": _stable_id("edge", "|".join(key)),
            "source": source,
            "target": target,
            "type": relation,
            "state": state,
            "weight": max(1, weight),
            "evidence_ids": identifiers,
            "knowledge_urls": references,
        }

    actor_by_name: dict[str, str] = {}
    campaign_by_name: dict[str, str] = {}
    technique_by_external_id: dict[str, str] = {}

    for actor in actors:
        actor_id = actor["actor_id"]
        actor_by_name[str(actor["name"]).casefold()] = actor_id
        nodes_by_id[actor_id] = {
            "id": actor_id,
            "label": actor["name"],
            "type": actor.get("entity_type") or "threat_actor",
            "entity_type": actor.get("entity_type") or "threat_actor",
            "state": actor["state"],
            "size": 12 + min(20, actor["relevance_score"] / 5),
            "relevance_score": actor["relevance_score"],
            "group_key": actor_id,
            "relationships": list(actor.get("relationships", [])),
            "techniques": list(actor.get("techniques", [])),
            "run_techniques": list(actor.get("run_techniques", [])),
            "documented_techniques": list(actor.get("documented_techniques", [])),
            "campaigns": list(actor.get("campaigns", [])),
            "attack_id": actor.get("attack_id"),
            "aliases": list(actor.get("aliases", [])),
            "profile_status": actor.get("profile_status"),
            "knowledge_url": actor.get("knowledge_url"),
            "knowledge_references": list(actor.get("knowledge_references", [])),
            "knowledge_description": actor.get("knowledge_description"),
            "knowledge_created": actor.get("knowledge_created"),
            "knowledge_modified": actor.get("knowledge_modified"),
            "first_seen": actor.get("first_seen"),
            "last_seen": actor.get("last_seen"),
            "external_references": list(actor.get("external_references", [])),
            "evidence_ids": list(actor.get("evidence_ids", [])),
            "evidence_urls": list(actor.get("evidence_urls", [])),
        }

    for campaign in campaigns:
        campaign_id = campaign["campaign_id"]
        campaign_by_name[str(campaign["name"]).casefold()] = campaign_id
        nodes_by_id[campaign_id] = {
            "id": campaign_id,
            "label": campaign["name"],
            "type": "campaign",
            "entity_type": campaign.get("entity_type") or "campaign",
            "state": campaign["state"],
            "size": 14 + min(12, campaign["record_count"]),
            "group_key": campaign_id,
            "actors": list(campaign.get("actors", [])),
            "techniques": list(campaign.get("techniques", [])),
            "run_techniques": list(campaign.get("run_techniques", [])),
            "documented_techniques": list(campaign.get("documented_techniques", [])),
            "attack_id": campaign.get("attack_id"),
            "aliases": list(campaign.get("aliases", [])),
            "profile_status": campaign.get("profile_status"),
            "knowledge_url": campaign.get("knowledge_url"),
            "knowledge_references": list(campaign.get("knowledge_references", [])),
            "knowledge_description": campaign.get("knowledge_description"),
            "knowledge_created": campaign.get("knowledge_created"),
            "knowledge_modified": campaign.get("knowledge_modified"),
            "first_seen": campaign.get("first_seen"),
            "last_seen": campaign.get("last_seen"),
            "external_references": list(campaign.get("external_references", [])),
            "evidence_ids": list(campaign.get("evidence_ids", [])),
            "evidence_urls": list(campaign.get("evidence_urls", [])),
        }

    for technique in techniques:
        external_id = str(technique["technique_id"])
        technique_id = f"technique:{external_id}"
        technique_by_external_id[external_id] = technique_id
        nodes_by_id[technique_id] = {
            "id": technique_id,
            "label": f"{external_id} · {technique['name']}",
            "type": "technique",
            "state": technique["state"],
            "size": 10 + min(12, technique["record_count"] / 2),
            "group_key": external_id,
            "actors": list(technique.get("actors", [])),
            "campaigns": list(technique.get("campaigns", [])),
            "run_actors": list(technique.get("run_actors", [])),
            "run_campaigns": list(technique.get("run_campaigns", [])),
            "reference_actors": list(technique.get("reference_actors", [])),
            "reference_campaigns": list(technique.get("reference_campaigns", [])),
            "run_supported": bool(technique.get("run_supported")),
            "reference_supported": bool(technique.get("reference_supported")),
            "parent_technique_id": technique.get("parent_technique_id"),
            "knowledge_urls": list(technique.get("knowledge_urls", [])),
            "description": technique.get("description"),
            "platforms": list(technique.get("platforms", [])),
            "data_sources": list(technique.get("data_sources", [])),
            "relationship_description": technique.get("relationship_description"),
            "d3fend": list(technique.get("d3fend", [])),
            "evidence_ids": list(technique.get("evidence_ids", [])),
            "evidence_urls": list(technique.get("evidence_urls", [])),
        }
        for control in technique.get("d3fend", []) or []:
            if not isinstance(control, dict) or not control.get("id"):
                continue
            defense_external_id = str(control["id"])
            defense_id = f"defense:{defense_external_id}"
            nodes_by_id.setdefault(
                defense_id,
                {
                    "id": defense_id,
                    "label": f"{defense_external_id} · {control.get('name') or defense_external_id}",
                    "type": "defense",
                    "state": "REFERENCE",
                    "size": 10,
                    "group_key": defense_external_id,
                    "techniques": [],
                    "evidence_ids": [],
                    "evidence_urls": [],
                },
            )
            nodes_by_id[defense_id]["techniques"] = list(
                dict.fromkeys([*nodes_by_id[defense_id]["techniques"], external_id])
            )

    for actor in actors:
        actor_id = actor["actor_id"]
        add_edge(
            actor_id,
            "scope:organization",
            "contextually_relevant_to",
            actor["state"],
            actor["evidence_count"],
            actor.get("evidence_ids", []),
        )
        run_techniques = {str(value) for value in actor.get("run_techniques", [])}
        for technique in actor.get("techniques", []):
            technique_id = technique_by_external_id.get(str(technique))
            if technique_id:
                run_supported = str(technique) in run_techniques
                add_edge(
                    actor_id,
                    technique_id,
                    "uses",
                    actor["state"] if run_supported else "REFERENCE",
                    actor["evidence_count"] if run_supported else 1,
                    actor.get("evidence_ids", []) if run_supported else [],
                    [
                        *actor.get("knowledge_references", []),
                        *nodes_by_id[technique_id].get("knowledge_urls", []),
                    ],
                )
        for campaign in actor.get("campaigns", []):
            campaign_id = campaign_by_name.get(str(campaign).casefold())
            if campaign_id:
                add_edge(
                    actor_id,
                    campaign_id,
                    "associated_with",
                    actor["state"],
                    actor["evidence_count"],
                    actor.get("evidence_ids", []),
                )

    for campaign in campaigns:
        campaign_id = campaign["campaign_id"]
        for actor_name in campaign.get("actors", []):
            actor_id = actor_by_name.get(str(actor_name).casefold())
            if actor_id:
                add_edge(
                    actor_id,
                    campaign_id,
                    "associated_with",
                    campaign["state"],
                    campaign["record_count"],
                    campaign.get("evidence_ids", []),
                )
        run_techniques = {str(value) for value in campaign.get("run_techniques", [])}
        for technique in campaign.get("techniques", []):
            technique_id = technique_by_external_id.get(str(technique))
            if technique_id:
                run_supported = str(technique) in run_techniques
                add_edge(
                    campaign_id,
                    technique_id,
                    "uses",
                    campaign["state"] if run_supported else "REFERENCE",
                    campaign["record_count"] if run_supported else 1,
                    campaign.get("evidence_ids", []) if run_supported else [],
                    [
                        *campaign.get("knowledge_references", []),
                        *nodes_by_id[technique_id].get("knowledge_urls", []),
                    ],
                )

    for technique in techniques:
        technique_id = technique_by_external_id[str(technique["technique_id"])]
        for actor_name in technique.get("run_actors", []):
            actor_id = actor_by_name.get(str(actor_name).casefold())
            if actor_id:
                add_edge(
                    actor_id,
                    technique_id,
                    "uses",
                    technique["state"],
                    technique["record_count"],
                    technique.get("evidence_ids", []),
                )
        for actor_name in technique.get("reference_actors", []):
            actor_id = actor_by_name.get(str(actor_name).casefold())
            if actor_id:
                add_edge(
                    actor_id,
                    technique_id,
                    "uses",
                    "REFERENCE",
                    1,
                    [],
                    technique.get("knowledge_urls", []),
                )
        for campaign_name in technique.get("run_campaigns", []):
            campaign_id = campaign_by_name.get(str(campaign_name).casefold())
            if campaign_id:
                add_edge(
                    campaign_id,
                    technique_id,
                    "uses",
                    technique["state"],
                    technique["record_count"],
                    technique.get("evidence_ids", []),
                )
        for campaign_name in technique.get("reference_campaigns", []):
            campaign_id = campaign_by_name.get(str(campaign_name).casefold())
            if campaign_id:
                add_edge(
                    campaign_id,
                    technique_id,
                    "uses",
                    "REFERENCE",
                    1,
                    [],
                    technique.get("knowledge_urls", []),
                )
        for control in technique.get("d3fend", []) or []:
            if isinstance(control, dict) and control.get("id"):
                add_edge(
                    technique_id,
                    f"defense:{control['id']}",
                    "countered_by",
                    "REFERENCE",
                    technique["record_count"],
                    [],
                    technique.get("knowledge_urls", []),
                )

    nodes = list(nodes_by_id.values())
    edges = list(edges_by_key.values())
    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "layout": "force_static_after_stabilization",
    }


def _detection_coverage(techniques: list[dict[str, Any]]) -> dict[str, Any]:
    controls: dict[str, dict[str, Any]] = {}
    mapped = 0
    for technique in techniques:
        if technique.get("d3fend"):
            mapped += 1
        for control in technique.get("d3fend", []) or []:
            if not isinstance(control, dict) or not control.get("id"):
                continue
            item = controls.setdefault(
                str(control["id"]),
                {
                    "id": str(control["id"]),
                    "name": str(control.get("name") or control["id"]),
                    "techniques": [],
                    "evidence_ids": [],
                },
            )
            item["techniques"].append(technique["technique_id"])
            item["evidence_ids"].extend(technique["evidence_ids"])
    rows = []
    for item in controls.values():
        item["techniques"] = list(dict.fromkeys(item["techniques"]))
        item["evidence_ids"] = list(dict.fromkeys(item["evidence_ids"]))
        rows.append(item)
    rows.sort(key=lambda row: (-len(row["techniques"]), row["id"]))
    return {
        "mapped_technique_count": mapped,
        "total_technique_count": len(techniques),
        "run_technique_count": sum(
            1 for row in techniques if row.get("run_supported")
        ),
        "reference_technique_count": sum(
            1 for row in techniques if row.get("reference_supported")
        ),
        "mapping_coverage_pct": round(100 * mapped / len(techniques), 1) if techniques else None,
        "controls": rows,
        "interpretation": (
            "Mapeo ATT&CK-D3FEND para orientar deteccion y respuesta; distingue la "
            "corrida del repertorio de referencia y no prueba implementacion del control."
        ),
    }


def _victimology(
    events: list[ThreatEvent], organization: OrganizationProfile
) -> dict[str, Any]:
    sectors = Counter()
    countries = Counter()
    for event in events:
        technical = event.technical_validation or {}
        for value in _as_values(technical.get("sectors") or technical.get("sector")):
            sectors[value] += 1
        country = _event_country(event)
        if country:
            countries[country] += 1
    if organization.sector:
        sectors.setdefault(organization.sector, 0)
    for country in _scope_countries(organization):
        countries.setdefault(country, 0)
    return {
        "sectors": [{"name": key, "count": value} for key, value in sectors.most_common()],
        "countries": [{"name": key, "count": value} for key, value in countries.most_common()],
        "scope_sector": organization.sector,
        "scope_countries": sorted(_scope_countries(organization)),
        "interpretation": "Distribucion declarada o extraida de evidencia; no representa ubicacion fisica del actor sin geolocalizacion validada.",
    }


def _evidence_index(
    events: list[ThreatEvent],
    actors: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    actor_by_evidence: dict[str, list[str]] = defaultdict(list)
    campaign_by_evidence: dict[str, list[str]] = defaultdict(list)
    technique_by_evidence: dict[str, list[str]] = defaultdict(list)
    states_by_evidence: dict[str, list[str]] = defaultdict(list)
    for actor in actors:
        for evidence_id in actor["evidence_ids"]:
            actor_by_evidence[evidence_id].append(actor["name"])
            states_by_evidence[evidence_id].append(actor["state"])
    for campaign in campaigns:
        for evidence_id in campaign["evidence_ids"]:
            campaign_by_evidence[evidence_id].append(campaign["name"])
            states_by_evidence[evidence_id].append(campaign["state"])
    for technique in techniques:
        for evidence_id in technique["evidence_ids"]:
            technique_by_evidence[evidence_id].append(technique["technique_id"])
            states_by_evidence[evidence_id].append(technique["state"])
    rows = []
    seen: set[str] = set()
    for event in events:
        evidence_id = str(event.canonical_id or event.id)
        if evidence_id not in states_by_evidence or evidence_id in seen:
            continue
        seen.add(evidence_id)
        state = next(
            (
                candidate
                for candidate in CTI_STATES
                if candidate in states_by_evidence[evidence_id]
            ),
            "REFERENCE",
        )
        rows.append(
            {
                "evidence_id": evidence_id,
                "title": event.title,
                "url": event.evidence_url,
                "source": event.original_publisher or event.source,
                "observed_at": event.observed_at,
                "state": state,
                "evidence_status": str(
                    getattr(event.evidence_status, "value", event.evidence_status)
                ),
                "relationship": event.relationship_to_scope,
                "actors": sorted(set(actor_by_evidence[evidence_id])),
                "campaigns": sorted(set(campaign_by_evidence[evidence_id])),
                "techniques": sorted(set(technique_by_evidence[evidence_id])),
                "limitations": list(event.limitations),
            }
        )
    rows.sort(key=lambda row: str(row.get("observed_at") or ""), reverse=True)
    return rows


def _quality_summary(
    actors: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
    events: list[ThreatEvent],
) -> dict[str, Any]:
    counts = {state: 0 for state in CTI_STATES}
    for row in [*actors, *campaigns, *techniques]:
        state = str(row.get("state") or "REFERENCE")
        counts[state if state in counts else "REFERENCE"] += 1
    urls = {event.evidence_url for event in events if event.evidence_url}
    sources = {event.original_publisher or event.source for event in events if event.source}
    return {
        "state_counts": counts,
        "record_count": len(events),
        "unique_url_count": len(urls),
        "source_count": len(sources),
        "actor_with_multiple_sources_count": sum(
            1 for actor in actors if actor["source_count"] >= 2
        ),
        "observed_requires_telemetry": True,
        "status": "evidence_backed" if actors or campaigns or techniques else "no_data",
    }


def _score_explanation(
    factors: dict[str, float], state: str, organization: OrganizationProfile
) -> str:
    strongest = sorted(factors.items(), key=lambda item: item[1], reverse=True)[:3]
    labels = {
        "direct_evidence": "relacion directa",
        "ttp_overlap": "TTP relacionadas",
        "technology_vulnerability_fit": "ajuste tecnologico",
        "sector_fit": "ajuste sectorial",
        "geography_fit": "ajuste geografico",
        "campaign_recency": "recencia",
        "source_diversity": "diversidad de fuentes",
    }
    basis = ", ".join(labels[key] for key, value in strongest if value > 0) or "referencia contextual"
    subject = organization.name or "el alcance declarado"
    return f"{state}: relevancia para {subject} sustentada principalmente por {basis}."


def _actor_limitations(state: str, factors: dict[str, float]) -> list[str]:
    limitations = []
    if state != "OBSERVED":
        limitations.append("No existe telemetria validada que confirme actividad del actor contra el alcance.")
    if factors["source_diversity"] < 0.67:
        limitations.append("La atribucion dispone de corroboracion limitada entre fuentes independientes.")
    if factors["technology_vulnerability_fit"] == 0:
        limitations.append("No se confirmo ajuste con tecnologia o vulnerabilidad aplicable del alcance.")
    return limitations


def _band(score: float) -> str:
    if score >= 75:
        return "very_high"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "reference"


def _highest_state(counts: dict[str, int]) -> str:
    return next((state for state in CTI_STATES if counts.get(state, 0)), "REFERENCE")


def _event_country(event: ThreatEvent) -> str:
    technical = event.technical_validation or {}
    for key in ("country", "country_name", "geo_country"):
        value = technical.get(key)
        if value:
            return str(value).strip()
    return ""


def _scope_countries(organization: OrganizationProfile) -> set[str]:
    return {
        value.casefold()
        for value in [organization.country, *organization.countries_of_operation]
        if value
    }


def _as_values(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def _stable_id(prefix: str, value: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-") or "unknown"
    return f"{prefix}:{token}"
