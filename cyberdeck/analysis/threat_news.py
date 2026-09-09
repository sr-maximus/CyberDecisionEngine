from __future__ import annotations

import re
from typing import Any, Iterable

from cyberdeck.analysis.mitre_mapping import describe_attack_technique
from cyberdeck.schemas import EvidenceStatus, ThreatEvent


MODEL_VERSION = "threat-news-attribution-v1.2.0"

_CYBER_ACTION = re.compile(
    r"\b(ransomware|malware|phish\w*|breach|intrusion|exploit\w*|vulnerab\w*|cve-\d+|"
    r"attack|ataque|extortion|filtraci\w*|credential\w*|"
    r"suplant\w*|imperson\w*|fraud\w*|estafa\w*|scam\w*|botnet|ddos)\b",
    re.IGNORECASE,
)
_ATTRIBUTION = re.compile(
    r"\b(?:apt[- ]?\d+|fin\d+|unc\d+|uat[- ]?\d+|ta\d+|lazarus|scattered spider|lockbit|cl0p|akira|black basta|"
    r"ransomhouse|play ransomware|threat actor|actor de amenazas|grupo de ransomware|"
    r"grupo cibernetico|grupo cibernético)\b",
    re.IGNORECASE,
)
_BUSINESS_ONLY = re.compile(
    r"\b(acquisition|adquisicion|merger|sustainab|sostenibil|financial results|resultados financieros|"
    r"dividend|produccion|production|earnings|inversion)\b",
    re.IGNORECASE,
)


def build_threat_news(events: Iterable[ThreatEvent]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in events:
        if not event.evidence_url or event.evidence_url in seen:
            continue
        if event.evidence_status in {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}:
            continue
        text = " ".join([event.title, event.category, event.actor or "", " ".join(event.tags)])
        has_action = bool(_CYBER_ACTION.search(text))
        actor_match = _ATTRIBUTION.search(text)
        has_actor = bool(
            (
                event.actor
                and event.actor.casefold()
                not in {
                    "unattributed",
                    "unknown",
                    "sin atribución",
                    "no atribuido",
                    "open_web",
                    "public_web",
                    "external_exposure",
                }
            )
            or actor_match
            or any(tag.casefold() in {"threat_actor", "actor_attribution"} for tag in event.tags)
        )
        if not has_action or not has_actor:
            continue
        if _BUSINESS_ONLY.search(text) and not _CYBER_ACTION.search(event.title):
            continue
        relationship = str(event.relationship_to_scope or "unassessed")
        if relationship not in {"direct", "group", "sector", "related", "contextual"}:
            continue
        seen.add(event.evidence_url)
        status = str(getattr(event.evidence_status, "value", event.evidence_status))
        actor = (
            event.actor
            if event.actor
            and event.actor.casefold()
            not in {
                "unattributed",
                "unknown",
                "sin atribución",
                "no atribuido",
                "open_web",
                "public_web",
                "external_exposure",
            }
            else actor_match.group(0)
            if actor_match
            else "unattributed"
        )
        techniques = _event_techniques(event)
        attack_techniques = [
            describe_attack_technique(technique)
            for technique in techniques
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique.strip(), re.IGNORECASE)
        ]
        campaigns, campaign_reference = _event_campaigns(event)
        d3fend = _deduplicate_d3fend(attack_techniques)
        frameworks = _event_frameworks(event, techniques)
        if d3fend and "MITRE D3FEND" not in frameworks:
            frameworks.append("MITRE D3FEND")
        rows.append(
            {
                "evidence_id": str(event.canonical_id or event.id),
                "title": event.title,
                "url": event.evidence_url,
                "source": event.original_publisher or event.public_capability_label,
                "observed_at": event.observed_at,
                "actor": actor,
                "technique": techniques[0] if techniques else None,
                "techniques": techniques,
                "attack_techniques": attack_techniques,
                "d3fend": d3fend,
                "campaigns": campaigns,
                "campaign_reference": campaign_reference,
                "frameworks": frameworks,
                "relationship": relationship,
                "relationship_class": _relationship_class(relationship, status),
                "evidence_status": status,
                "classification": "attributed_threat_or_campaign",
                "observed_attack": bool(event.incident_confirmed and status == "confirmed"),
            }
        )
    rows.sort(key=lambda item: item["observed_at"], reverse=True)
    actors = _aggregate_actors(rows)
    ttps = _aggregate_ttps(rows)
    campaigns = _aggregate_campaigns(rows)
    return {
        "model_version": MODEL_VERSION,
        "status": "evidence_backed" if rows else "no_data",
        "record_count": len(rows),
        "validated_count": sum(
            item["evidence_status"] in {"validated", "confirmed"} for item in rows
        ),
        "rows": rows[:40],
        "actors": actors,
        "ttps": ttps,
        "campaigns": campaigns,
        "actor_count": len(actors),
        "ttp_count": len(ttps),
        "campaign_count": len(campaigns),
        "limitations": [
            "La inclusión exige una acción cibernética y una atribución explícita de actor o campaña.",
            "Una noticia atribuida no confirma que la organización analizada haya sufrido un incidente.",
            "Ataque observado solo se utiliza cuando existe incidente confirmado y evidencia confirmada.",
            "La relevancia sectorial o contextual describe el panorama de amenazas; no atribuye una acción contra la organización.",
        ],
    }


def _relationship_class(relationship: str, status: str) -> str:
    if relationship in {"direct", "group"} and status in {"validated", "confirmed"}:
        return "scope_supported"
    if relationship in {"sector", "related", "contextual"}:
        return "contextual_relevance"
    return "candidate"


def _event_techniques(event: ThreatEvent) -> list[str]:
    values: list[str] = []
    if event.technique:
        values.append(str(event.technique))
    values.extend(str(value) for value in event.technique_refs if value)
    technical = event.technical_validation or {}
    for key in ("mitre_mappings", "f3_mappings", "emb3d_mappings"):
        for value in technical.get(key, []) or []:
            if isinstance(value, dict):
                identifier = value.get("id") or value.get("technique_id") or value.get("name")
                if identifier:
                    values.append(str(identifier))
            elif value:
                values.append(str(value))
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def _event_campaigns(event: ThreatEvent) -> tuple[list[str], bool]:
    technical = event.technical_validation or {}
    values: list[str] = []
    for key in ("campaign", "campaign_name"):
        value = technical.get(key)
        if value:
            values.append(str(value))
    for key in ("campaigns", "campaign_names"):
        raw_values = technical.get(key, []) or []
        if isinstance(raw_values, str):
            raw_values = [raw_values]
        for value in raw_values:
            if isinstance(value, dict):
                candidate = value.get("name") or value.get("campaign") or value.get("id")
            else:
                candidate = value
            if candidate:
                values.append(str(candidate))
    for tag in event.tags:
        match = re.match(r"^campaign\s*[:=]\s*(.+)$", str(tag), re.IGNORECASE)
        if match:
            values.append(match.group(1))
    campaigns = list(
        dict.fromkeys(
            value.strip()
            for value in values
            if value.strip() and value.strip().casefold() not in {"campaign", "campaña"}
        )
    )
    text = " ".join([event.title, event.category, *event.tags])
    return campaigns, bool(campaigns or re.search(r"\b(campaign|campaña)\b", text, re.IGNORECASE))


def _deduplicate_d3fend(attack_techniques: list[dict[str, object]]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    seen: set[str] = set()
    for technique in attack_techniques:
        for item in technique.get("d3fend", []) or []:
            if not isinstance(item, dict):
                continue
            identifier = str(item.get("id") or "").strip()
            if not identifier or identifier in seen:
                continue
            seen.add(identifier)
            output.append({"id": identifier, "name": str(item.get("name") or identifier)})
    return output


def _event_frameworks(event: ThreatEvent, techniques: list[str]) -> list[str]:
    values = [str(value) for value in event.framework_refs if value]
    text = " ".join([*values, *techniques]).casefold()
    technology_domains = {
        str(getattr(domain, "value", domain)).casefold()
        for domain in [event.primary_technology_domain, *event.technology_domains]
    }
    technical = event.technical_validation or {}
    if "f3" in text or technical.get("f3_mappings"):
        values.append("MITRE F3")
    if "emb3d" in text or any(
        technique.upper().startswith(("TID-", "PID-", "MID-")) for technique in techniques
    ):
        values.append("MITRE EMB3D")
    if "atlas" in text or any(technique.upper().startswith("AML.") for technique in techniques):
        values.append("MITRE ATLAS")
    if "d3fend" in text or any(technique.upper().startswith("D3-") for technique in techniques):
        values.append("MITRE D3FEND")
    attack_technique = any(
        re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique.strip(), re.IGNORECASE)
        for technique in techniques
    )
    explicit_attack = any(
        "attack" in value.casefold() or "att&ck" in value.casefold() for value in values
    )
    if attack_technique and not explicit_attack:
        values.append(
            "MITRE ATT&CK ICS" if technology_domains & {"ot", "iiot"} else "MITRE ATT&CK Enterprise"
        )
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def _aggregate_actors(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actors: dict[str, dict[str, Any]] = {}
    for row in rows:
        actor_name = str(row.get("actor") or "").strip()
        if not actor_name or actor_name == "unattributed":
            continue
        key = actor_name.casefold()
        item = actors.setdefault(
            key,
            {
                "actor": actor_name,
                "record_count": 0,
                "validated_count": 0,
                "observed_attack_count": 0,
                "relationships": set(),
                "techniques": set(),
                "campaigns": set(),
                "d3fend": {},
                "frameworks": set(),
                "evidence_ids": [],
                "urls": [],
                "last_observed_at": row.get("observed_at"),
            },
        )
        item["record_count"] += 1
        item["validated_count"] += int(row.get("evidence_status") in {"validated", "confirmed"})
        item["observed_attack_count"] += int(bool(row.get("observed_attack")))
        item["relationships"].add(str(row.get("relationship_class") or "candidate"))
        item["techniques"].update(row.get("techniques") or [])
        item["campaigns"].update(row.get("campaigns") or [])
        item["d3fend"].update(
            {
                str(control.get("id")): str(control.get("name") or control.get("id"))
                for control in row.get("d3fend") or []
                if isinstance(control, dict) and control.get("id")
            }
        )
        item["frameworks"].update(row.get("frameworks") or [])
        item["evidence_ids"].append(str(row.get("evidence_id") or ""))
        item["urls"].append(str(row.get("url") or ""))
        item["last_observed_at"] = max(
            str(item.get("last_observed_at") or ""), str(row.get("observed_at") or "")
        )
    result = []
    for item in actors.values():
        result.append(
            {
                **item,
                "relationships": sorted(item["relationships"]),
                "techniques": sorted(item["techniques"]),
                "campaigns": sorted(item["campaigns"]),
                "d3fend": [
                    {"id": identifier, "name": name}
                    for identifier, name in sorted(item["d3fend"].items())
                ],
                "frameworks": sorted(item["frameworks"]),
                "evidence_ids": list(
                    dict.fromkeys(value for value in item["evidence_ids"] if value)
                ),
                "urls": list(dict.fromkeys(value for value in item["urls"] if value))[:12],
            }
        )
    result.sort(key=lambda item: (-item["validated_count"], -item["record_count"], item["actor"]))
    return result[:30]


def _aggregate_ttps(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ttps: dict[str, dict[str, Any]] = {}
    for row in rows:
        for technique in row.get("techniques") or []:
            key = str(technique).casefold()
            item = ttps.setdefault(
                key,
                {
                    "technique": technique,
                    "name": describe_attack_technique(str(technique)).get("name", technique),
                    "tactics": describe_attack_technique(str(technique)).get("tactics", []),
                    "d3fend": describe_attack_technique(str(technique)).get("d3fend", []),
                    "record_count": 0,
                    "actors": set(),
                    "campaigns": set(),
                    "frameworks": set(),
                    "evidence_ids": [],
                    "urls": [],
                },
            )
            item["record_count"] += 1
            if row.get("actor") != "unattributed":
                item["actors"].add(str(row.get("actor")))
            item["campaigns"].update(row.get("campaigns") or [])
            item["frameworks"].update(row.get("frameworks") or [])
            item["evidence_ids"].append(str(row.get("evidence_id") or ""))
            item["urls"].append(str(row.get("url") or ""))
    result = [
        {
            **item,
            "actors": sorted(item["actors"]),
            "campaigns": sorted(item["campaigns"]),
            "frameworks": sorted(item["frameworks"]),
            "evidence_ids": list(dict.fromkeys(value for value in item["evidence_ids"] if value)),
            "urls": list(dict.fromkeys(value for value in item["urls"] if value))[:12],
        }
        for item in ttps.values()
    ]
    result.sort(key=lambda item: (-item["record_count"], item["technique"]))
    return result[:40]


def _aggregate_campaigns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    campaigns: dict[str, dict[str, Any]] = {}
    for row in rows:
        for campaign in row.get("campaigns") or []:
            key = str(campaign).casefold()
            item = campaigns.setdefault(
                key,
                {
                    "campaign": campaign,
                    "record_count": 0,
                    "actors": set(),
                    "techniques": set(),
                    "d3fend": {},
                    "evidence_ids": set(),
                    "urls": [],
                },
            )
            item["record_count"] += 1
            if row.get("actor") != "unattributed":
                item["actors"].add(str(row.get("actor")))
            item["techniques"].update(row.get("techniques") or [])
            item["d3fend"].update(
                {
                    str(control.get("id")): str(control.get("name") or control.get("id"))
                    for control in row.get("d3fend") or []
                    if isinstance(control, dict) and control.get("id")
                }
            )
            if row.get("evidence_id"):
                item["evidence_ids"].add(str(row["evidence_id"]))
            item["urls"].append(str(row.get("url") or ""))
    result = [
        {
            **item,
            "actors": sorted(item["actors"]),
            "techniques": sorted(item["techniques"]),
            "d3fend": [
                {"id": identifier, "name": name}
                for identifier, name in sorted(item["d3fend"].items())
            ],
            "evidence_ids": sorted(item["evidence_ids"]),
            "urls": list(dict.fromkeys(value for value in item["urls"] if value))[:12],
        }
        for item in campaigns.values()
    ]
    result.sort(key=lambda item: (-item["record_count"], item["campaign"]))
    return result[:30]
