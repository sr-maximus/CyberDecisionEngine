from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from functools import lru_cache
from typing import Dict, Iterable, List

from cyberdeck.frameworks.defend import D3FEND_MINIMAL
from cyberdeck.frameworks.sync import mappings
from cyberdeck.schemas import EvidenceStatus, ThreatEvent
from cyberdeck.settings import PROJECT_ROOT


ATTACK_TACTICS = [
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

TECHNIQUE_NAMES = {
    "T1566": "Phishing",
    "T1190": "Exploit Public-Facing Application",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1059": "Command and Scripting Interpreter",
    "T1589": "Gather Victim Identity Information",
    "T1595": "Active Scanning",
    "T1486": "Data Encrypted for Impact",
}

TECHNIQUE_TACTICS = {
    "T1566": ["Initial Access"],
    "T1190": ["Initial Access"],
    "T1078": ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1110": ["Credential Access"],
    "T1059": ["Execution"],
    "T1589": ["Reconnaissance"],
    "T1595": ["Reconnaissance"],
    "T1486": ["Impact"],
}

D3FEND_ACTIONS = {
    "D3-PH": {
        "name": "Phishing Detection",
        "action": "Detectar URLs, adjuntos, dominios lookalike y correos con suplantacion.",
        "tools": "Secure Email Gateway, DMARC/SPF/DKIM, URL rewriting, brand monitoring, SOAR takedown.",
    },
    "D3-MFA": {
        "name": "MFA Enforcement",
        "action": "Reducir abuso de credenciales con MFA resistente a phishing y step-up basado en riesgo.",
        "tools": "FIDO2/WebAuthn, conditional access, identity protection, risk-based authentication.",
    },
    "D3-BA": {
        "name": "Behavioral Analytics",
        "action": "Detectar desviaciones de usuario, dispositivo, beneficiario y sesion.",
        "tools": "UEBA, fraud graph analytics, device intelligence, transaction monitoring.",
    },
    "D3-PM": {
        "name": "Patch Management",
        "action": "Priorizar parches por KEV, EPSS, exposicion externa y criticidad del activo.",
        "tools": "VM platform, patch orchestration, CMDB, exposure management.",
    },
    "D3-NTA": {
        "name": "Network Traffic Analysis",
        "action": "Detectar explotacion, C2, anomalias y movimientos laterales.",
        "tools": "NDR, IDS/IPS, Zeek, NetFlow, SIEM correlation.",
    },
    "D3-EAL": {
        "name": "Endpoint Activity Logging",
        "action": "Capturar actividad de endpoint para investigacion y respuesta.",
        "tools": "EDR/XDR, Sysmon, SIEM, endpoint telemetry lake.",
    },
    "D3-DAM": {
        "name": "Domain Account Monitoring",
        "action": "Monitorear cuentas privilegiadas, valid accounts y cambios sospechosos.",
        "tools": "IAM, AD/Azure AD logs, PAM, identity threat detection.",
    },
}

ATLAS_SECTIONS = [
    {
        "id": "AML.TA0004",
        "name": "Initial Access to AI/automation",
        "risk": "Compromiso de pipelines, agentes, cuentas de servicio o integraciones que alimentan automatizacion.",
        "controls": "Control de identidad, secretos, repositorios, aprobaciones y aislamiento de agentes.",
    },
    {
        "id": "AML.TA0007",
        "name": "Defense Evasion in AI systems",
        "risk": "Uso de prompts, herramientas o datos para evadir filtros, auditoria o politicas de seguridad.",
        "controls": "Logging de prompts, allowlists de herramientas, validacion de entradas y evaluaciones adversariales.",
    },
    {
        "id": "AML.TA0011",
        "name": "Impact on AI-enabled operations",
        "risk": "Manipulacion de decisiones automatizadas, fraude asistido por IA o degradacion de procesos analiticos.",
        "controls": "Human-in-the-loop, monitoreo de drift, circuit breakers y revision de decisiones de alto impacto.",
    },
]

ATLAS_SIGNAL_PATTERN = re.compile(
    r"\b(ai|artificial intelligence|machine learning|ml|llm|large language model|model|agent|prompt|atlas)\b",
    re.IGNORECASE,
)


def build_mitre_profile(events: Iterable[ThreatEvent]) -> Dict[str, object]:
    attack_tactics, technique_names, technique_tactics = _attack_catalog()
    event_list = [
        event
        for event in events
        if event.technique
        and event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    technique_counter = Counter(event.technique or "unmapped" for event in event_list)
    tactic_rows = []
    for tactic in attack_tactics:
        techniques = []
        for technique, tactics in technique_tactics.items():
            if tactic not in tactics:
                continue
            related = [event for event in event_list if event.technique == technique]
            if not related:
                continue
            techniques.append(
                {
                    "id": technique,
                    "name": technique_names.get(technique, technique),
                    "count": len(related),
                    "sources": sorted({event.source for event in related})[:6],
                    "examples": [{"title": event.title, "url": event.evidence_url or ""} for event in related[:4]],
                    "d3fend": _d3fend_for_technique(technique),
                    "mapping_status": (
                        "observed_adversary_behavior"
                        if any(event.attack_mapping_status == "observed_adversary_behavior" for event in related)
                        else "potentially_relevant_technique"
                    ),
                }
            )
        tactic_rows.append({"name": tactic, "count": sum(item["count"] for item in techniques), "techniques": techniques})
    return {
        "tactics": tactic_rows,
        "technique_counts": dict(technique_counter),
        "coverage_count": sum(1 for row in tactic_rows if row["count"] > 0),
        "observed_behavior_count": sum(
            1 for event in event_list if event.attack_mapping_status == "observed_adversary_behavior"
        ),
        "purpose": "ATT&CK organiza tecnicas potencialmente relevantes a partir de evidencia directa. Solo se declara comportamiento adversario observado cuando existe telemetria tecnica validada; el resto es orientacion preventiva.",
    }


@lru_cache(maxsize=1)
def _attack_catalog() -> tuple[list[str], Dict[str, str], Dict[str, list[str]]]:
    """Load names and tactic relationships from the locally synchronized ATT&CK STIX bundle."""
    path = PROJECT_ROOT / "data" / "frameworks" / "mitre_attack_enterprise.json"
    if not path.exists():
        return ATTACK_TACTICS, TECHNIQUE_NAMES, TECHNIQUE_TACTICS
    try:
        objects = json.loads(path.read_text(encoding="utf-8")).get("objects", [])
        by_id = {item.get("id"): item for item in objects if item.get("id")}
        tactic_names = {
            item.get("x_mitre_shortname"): item.get("name")
            for item in objects
            if item.get("type") == "x-mitre-tactic" and item.get("x_mitre_shortname") and item.get("name")
        }
        tactic_order: list[str] = []
        for item in objects:
            if item.get("type") != "x-mitre-matrix" or item.get("name") != "Enterprise ATT&CK":
                continue
            tactic_order = [
                by_id[reference].get("name")
                for reference in item.get("tactic_refs", [])
                if reference in by_id and by_id[reference].get("name")
            ]
            break
        names: Dict[str, str] = {}
        tactics_by_technique: Dict[str, list[str]] = {}
        for item in objects:
            if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
                continue
            external_id = next(
                (
                    reference.get("external_id")
                    for reference in item.get("external_references", [])
                    if reference.get("source_name") == "mitre-attack" and reference.get("external_id")
                ),
                None,
            )
            if not external_id:
                continue
            names[external_id] = item.get("name") or external_id
            tactics_by_technique[external_id] = [
                tactic_names.get(phase.get("phase_name"), str(phase.get("phase_name", "")).replace("-", " ").title())
                for phase in item.get("kill_chain_phases", [])
                if phase.get("phase_name")
            ]
        if tactic_order and names and tactics_by_technique:
            return tactic_order, names, tactics_by_technique
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        pass
    return ATTACK_TACTICS, TECHNIQUE_NAMES, TECHNIQUE_TACTICS


def build_d3fend_profile(events: Iterable[ThreatEvent]) -> Dict[str, object]:
    counter: Dict[str, int] = defaultdict(int)
    samples: Dict[str, List[str]] = defaultdict(list)
    for event in events:
        if event.evidence_status not in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}:
            continue
        for item in _d3fend_for_technique(event.technique or ""):
            counter[item["id"]] += 1
            if len(samples[item["id"]]) < 3:
                samples[item["id"]].append(event.title)
    rows = []
    for d3_id, count in sorted(counter.items(), key=lambda pair: pair[1], reverse=True):
        action = D3FEND_ACTIONS.get(d3_id, {"name": D3FEND_MINIMAL.get(d3_id, d3_id), "action": "Revisar contramedida D3FEND.", "tools": "Controles defensivos existentes."})
        rows.append(
            {
                "id": d3_id,
                "count": count,
                "samples": samples[d3_id],
                "status": "recommended_control",
                "objective": action.get("action", "Revisar la contramedida defensiva."),
                "implementation": action.get("tools", "Definir implementacion tecnica y operativa."),
                "owner": "Por asignar por la organizacion",
                "validation": "Requiere evidencia de configuracion, cobertura y prueba de eficacia.",
                "required_evidence": ["configuracion", "cobertura", "resultado de prueba", "fecha y responsable"],
                **action,
            }
        )
    return {
        "rows": rows,
        "purpose": "D3FEND traduce tecnicas potencialmente relevantes en opciones defensivas. Una recomendacion no demuestra que el control exista ni que sea eficaz; eso requiere validacion y evidencia del propietario.",
    }


def build_atlas_profile(events: Iterable[ThreatEvent]) -> Dict[str, object]:
    eligible_events = [
        event
        for event in events
        if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        and _is_explicit_ai_signal(event)
    ]
    matched_signals = sorted(
        {
            match.group(0).lower()
            for event in eligible_events
            for match in ATLAS_SIGNAL_PATTERN.finditer(" ".join([event.title, event.category, event.actor or "", *event.tags]))
        }
    )
    return {
        "sections": [
            {
                **section,
                "status": "candidate" if eligible_events else "preventive_reference",
                "evidence_count": len(eligible_events),
            }
            for section in ATLAS_SECTIONS
        ],
        "ai_signal_observed": bool(matched_signals),
        "matched_signals": matched_signals,
        "purpose": "ATLAS se activa como candidato solo cuando existe evidencia directa sobre activos, modelos, agentes o prompts de IA. Sin esa evidencia permanece como referencia preventiva y no como actividad adversaria observada.",
    }


def _is_explicit_ai_signal(event: ThreatEvent) -> bool:
    tags = {tag.lower() for tag in event.tags}
    explicit_tags = {
        "ai_asset",
        "ai_model",
        "ai_agent",
        "prompt_injection",
        "model_supply_chain",
        "atlas_signal",
    }
    return bool(tags.intersection(explicit_tags)) or event.category in {"ai_security", "ai_model_exposure"}


def _d3fend_for_technique(technique: str) -> List[Dict[str, str]]:
    attack_to_defend = mappings()["attack_to_defend"]
    output = []
    for d3_id in attack_to_defend.get(technique, []):
        action = D3FEND_ACTIONS.get(d3_id)
        if action:
            output.append({"id": d3_id, "name": action["name"]})
        else:
            output.append({"id": d3_id, "name": D3FEND_MINIMAL.get(d3_id, d3_id)})
    return output
