from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RiskFinding, ThreatEvent


MODEL_VERSION = "framework-evidence-crosswalk-v1.2.0"

FRAMEWORK_CATALOG: tuple[dict[str, str], ...] = (
    {
        "name": "NIST CSF",
        "version": "2.0",
        "domain": "control",
        "reference_url": "https://www.nist.gov/cyberframework",
    },
    {
        "name": "ISO 27001",
        "version": "2022",
        "domain": "control",
        "reference_url": "https://www.iso.org/standard/27001",
    },
    {
        "name": "PCI DSS",
        "version": "4.0.1",
        "domain": "control",
        "reference_url": "https://www.pcisecuritystandards.org/standards/pci-dss/",
    },
    {
        "name": "SOC 2",
        "version": "Trust Services Criteria",
        "domain": "control",
        "reference_url": "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
    },
    {
        "name": "GDPR",
        "version": "consolidated",
        "domain": "privacy",
        "reference_url": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
    },
    {
        "name": "CIS Controls",
        "version": "8.1",
        "domain": "control",
        "reference_url": "https://www.cisecurity.org/controls/v8-1",
    },
    {
        "name": "MITRE ATT&CK Enterprise",
        "version": "19.2",
        "domain": "it",
        "reference_url": "https://attack.mitre.org/matrices/enterprise/",
    },
    {
        "name": "MITRE ATT&CK ICS",
        "version": "19.2",
        "domain": "ot_iiot",
        "reference_url": "https://attack.mitre.org/matrices/ics/",
    },
    {
        "name": "MITRE ATT&CK Mobile",
        "version": "19.2",
        "domain": "mobile",
        "reference_url": "https://attack.mitre.org/matrices/mobile/",
    },
    {
        "name": "MITRE EMB3D",
        "version": "2.0.2",
        "domain": "iot_iiot_ot_embedded",
        "reference_url": "https://emb3d.mitre.org/",
    },
    {
        "name": "MITRE D3FEND",
        "version": "1.5.0",
        "domain": "defense",
        "reference_url": "https://d3fend.mitre.org/",
    },
    {
        "name": "MITRE ATLAS",
        "version": "living knowledge base",
        "domain": "ai_security",
        "reference_url": "https://atlas.mitre.org/",
    },
    {
        "name": "MITRE F3",
        "version": "2026 release",
        "domain": "fraud",
        "reference_url": "https://ctid.mitre.org/fraud",
    },
    {
        "name": "MITRE AADAPT",
        "version": "rolling",
        "domain": "digital_assets",
        "reference_url": "https://aadapt.mitre.org/",
    },
    {
        "name": "MITRE CAPEC",
        "version": "latest",
        "domain": "attack_patterns",
        "reference_url": "https://capec.mitre.org/",
    },
    {
        "name": "MITRE CWE",
        "version": "latest",
        "domain": "weaknesses",
        "reference_url": "https://cwe.mitre.org/",
    },
    {
        "name": "MITRE INFORM",
        "version": "rolling",
        "domain": "threat_informed_maturity",
        "reference_url": "https://ctid.mitre.org/inform/",
    },
    {
        "name": "DISARM",
        "version": "2.0 observable",
        "domain": "disinformation",
        "reference_url": "https://www.disarm.foundation/framework",
    },
    {
        "name": "COBIT 2019",
        "version": "2019",
        "domain": "governance",
        "reference_url": "https://www.isaca.org/resources/cobit",
    },
)

ASSURED_STATUSES = {
    EvidenceStatus.DIRECT,
    EvidenceStatus.VALIDATED,
    EvidenceStatus.CONFIRMED,
}
VALIDATED_STATUSES = {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}

AXIS_RULES: dict[str, tuple[str, ...]] = {
    "governance": ("govern", "risk", "legal", "regulat", "policy", "compliance", "audit"),
    "identity": ("identity", "credential", "account", "login", "password", "mfa", "session", "bec"),
    "protect": ("protect", "hardening", "configuration", "encryption", "backup", "recover"),
    "detect": ("detect", "monitor", "logging", "telemetry", "alert", "hunting", "indicator"),
    "response": (
        "incident",
        "respond",
        "response",
        "contain",
        "recover",
        "takedown",
        "notification",
    ),
    "privacy": ("privacy", "personal data", "pii", "confidential", "breach", "gdpr", "cardholder"),
    "vulnerability": ("vulnerab", "cve-", "kev", "exploit", "patch", "exposure", "port", "surface"),
    "fraud": (
        "fraud",
        "phish",
        "scam",
        "estafa",
        "suplant",
        "imperson",
        "lookalike",
        "typosquat",
        "fake recruitment",
        "empleo falso",
        "oferta falsa",
    ),
    "ai": (
        "artificial intelligence",
        "machine learning",
        " llm",
        "prompt",
        "model",
        "agent",
        "atlas",
    ),
    "adversary": (
        "attack",
        "ransom",
        "malware",
        "campaign",
        "campana",
        "campaña",
        "threat actor",
        "apt",
        "technique",
        "ttp",
        "intrusion",
    ),
    "influence": (
        "disinformation",
        "desinformacion",
        "desinformación",
        "narrative manipulation",
        "influence operation",
        "coordinated amplification",
        "disarm",
    ),
    "digital_asset": (
        "aadapt",
        "digital asset",
        "crypto",
        "blockchain",
        "wallet",
        "stablecoin",
        "token transfer",
        "defi",
    ),
    "maturity": (
        "mitre inform",
        "threat-informed maturity",
        "threat informed maturity",
        "capability assessment",
        "madurez threat-informed",
    ),
}

# These are reference families, not measured control effectiveness or compliance.
FRAMEWORK_CONTROLS: dict[str, dict[str, tuple[str, ...]]] = {
    "NIST CSF": {
        "governance": ("Govern",),
        "identity": ("Identify", "Protect"),
        "protect": ("Protect", "Recover"),
        "detect": ("Detect",),
        "response": ("Respond", "Recover"),
        "privacy": ("Govern", "Protect"),
        "vulnerability": ("Identify", "Protect", "Detect"),
        "fraud": ("Protect", "Detect", "Respond"),
        "ai": ("Govern", "Identify", "Protect"),
        "adversary": ("Identify", "Detect", "Respond"),
    },
    "ISO 27001": {
        "governance": ("Organizational controls",),
        "identity": ("People controls", "Technological controls"),
        "protect": ("Physical controls", "Technological controls"),
        "detect": ("Organizational controls", "Technological controls"),
        "response": ("Organizational controls", "Technological controls"),
        "privacy": ("Organizational controls", "Technological controls"),
        "vulnerability": ("Technological controls",),
        "fraud": ("People controls", "Technological controls"),
        "ai": ("Organizational controls", "Technological controls"),
        "adversary": ("Organizational controls", "Technological controls"),
    },
    "PCI DSS": {
        "governance": ("Requirement 12",),
        "identity": ("Requirements 7 and 8",),
        "protect": ("Requirements 1, 2, 3 and 4",),
        "detect": ("Requirements 10 and 11",),
        "response": ("Requirement 12",),
        "privacy": ("Requirements 3, 4 and 9",),
        "vulnerability": ("Requirements 5, 6 and 11",),
        "fraud": ("Requirements 6, 8, 10 and 12",),
        "adversary": ("Requirements 10, 11 and 12",),
    },
    "SOC 2": {
        "governance": ("Common Criteria",),
        "identity": ("Common Criteria",),
        "protect": ("Security", "Confidentiality"),
        "detect": ("Common Criteria",),
        "response": ("Common Criteria", "Availability"),
        "privacy": ("Privacy", "Confidentiality"),
        "vulnerability": ("Security",),
        "fraud": ("Security", "Processing Integrity"),
        "ai": ("Security", "Processing Integrity"),
        "adversary": ("Security", "Availability"),
    },
    "GDPR": {
        "governance": ("Accountability and governance",),
        "identity": ("Access control and data minimisation",),
        "protect": ("Security of processing",),
        "detect": ("Security monitoring and breach detection",),
        "response": ("Breach notification and response",),
        "privacy": ("Lawful basis and data-subject rights",),
        "vulnerability": ("Security of processing",),
        "fraud": ("Security and accountability",),
        "ai": ("Automated decision-making and accountability",),
    },
    "CIS Controls": {
        "governance": ("Security Awareness and Skills Training", "Service Provider Management"),
        "identity": ("Account Management", "Access Control Management"),
        "protect": ("Data Protection", "Secure Configuration", "Data Recovery"),
        "detect": ("Audit Log Management", "Network Monitoring and Defense"),
        "response": ("Incident Response Management",),
        "privacy": ("Data Protection",),
        "vulnerability": ("Continuous Vulnerability Management",),
        "fraud": ("Email and Web Browser Protections", "Account Management"),
        "ai": ("Application Software Security", "Service Provider Management"),
        "adversary": ("Network Monitoring and Defense", "Incident Response Management"),
    },
    "MITRE ATT&CK Enterprise": {
        "identity": ("Credential Access", "Initial Access"),
        "protect": ("Defense Evasion",),
        "detect": ("Discovery", "Command and Control"),
        "response": ("Impact",),
        "vulnerability": ("Initial Access",),
        "fraud": ("Initial Access", "Credential Access"),
        "adversary": ("Enterprise tactics and techniques",),
    },
    "MITRE ATT&CK ICS": {
        "identity": ("Initial Access", "Discovery"),
        "protect": ("Inhibit Response Function",),
        "detect": ("Discovery", "Collection", "Command and Control"),
        "response": ("Impair Process Control", "Impact"),
        "vulnerability": ("Initial Access", "Lateral Movement"),
        "adversary": ("ICS tactics and techniques",),
    },
    "MITRE ATT&CK Mobile": {
        "identity": ("Credential Access", "Initial Access"),
        "protect": ("Defense Evasion",),
        "detect": ("Discovery", "Collection", "Command and Control"),
        "response": ("Impact",),
        "vulnerability": ("Initial Access", "Exploitation"),
        "fraud": ("Credential Access", "Collection"),
        "adversary": ("Mobile tactics and techniques",),
    },
    "MITRE EMB3D": {
        "identity": ("Device properties", "Threats"),
        "protect": ("Device properties", "Mitigations"),
        "detect": ("Threats", "Mitigations"),
        "response": ("Mitigations",),
        "vulnerability": ("Device properties", "Threats", "Mitigations"),
        "adversary": ("Embedded-device threats",),
    },
    "MITRE D3FEND": {
        "identity": ("Credential Hardening",),
        "protect": ("Harden", "Isolate"),
        "detect": ("Detect",),
        "response": ("Evict", "Restore"),
        "privacy": ("Data Hardening",),
        "vulnerability": ("Platform Hardening",),
        "fraud": ("Credential Hardening", "Detect"),
        "adversary": ("Detect", "Isolate", "Evict"),
    },
    "MITRE ATLAS": {
        "ai": ("ATLAS tactics and techniques",),
    },
    "MITRE F3": {
        "identity": ("Initial Access", "Positioning"),
        "protect": ("Stealth", "Defense Impairment"),
        "detect": ("Reconnaissance", "Stealth", "Defense Impairment"),
        "response": ("Execution", "Monetization"),
        "fraud": (
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Stealth",
            "Defense Impairment",
            "Positioning",
            "Execution",
            "Monetization",
        ),
        "adversary": ("Fraud tactics and techniques",),
    },
    "MITRE AADAPT": {
        "identity": ("Identity and authorization abuse",),
        "protect": ("Digital-asset transaction safeguards",),
        "detect": ("Digital-asset anomaly detection",),
        "response": ("Digital-asset incident response",),
        "fraud": ("Adversarial actions in digital-asset payments",),
        "adversary": ("AADAPT tactics and techniques",),
        "digital_asset": ("AADAPT tactics and techniques",),
    },
    "MITRE CAPEC": {
        "vulnerability": ("Applicable attack patterns",),
        "adversary": ("Applicable attack patterns",),
    },
    "MITRE CWE": {
        "vulnerability": ("Applicable software or hardware weaknesses",),
    },
    "MITRE INFORM": {
        "maturity": ("Threat-informed defense maturity dimensions",),
    },
    "DISARM": {
        "influence": ("Observable influence-operation tactics and techniques",),
        "fraud": ("Impersonation and influence context",),
        "response": ("Influence-operation response context",),
    },
    "COBIT 2019": {
        "governance": ("EDM", "APO", "MEA"),
        "identity": ("APO", "DSS"),
        "protect": ("BAI", "DSS"),
        "detect": ("DSS", "MEA"),
        "response": ("DSS",),
        "privacy": ("APO", "DSS", "MEA"),
        "vulnerability": ("BAI", "DSS"),
        "fraud": ("APO", "DSS", "MEA"),
        "ai": ("EDM", "APO", "BAI"),
        "adversary": ("DSS", "MEA"),
    },
}


def build_framework_evidence_mapping(
    events: Iterable[ThreatEvent],
    findings: Iterable[RiskFinding],
    organization: OrganizationProfile,
) -> dict[str, Any]:
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    unique_records: set[str] = set()
    validated_records: set[str] = set()

    for event in events:
        if event.evidence_status in {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}:
            continue
        if not event.evidence_url:
            continue
        if not _event_is_in_scope(event, organization):
            continue
        axes = _event_axes(event)
        if not axes:
            continue
        evidence_id = str(event.canonical_id or event.id)
        unique_records.add(evidence_id)
        if event.evidence_status in VALIDATED_STATUSES:
            validated_records.add(evidence_id)
        evidence = _evidence_row(event, organization)
        for framework, controls_by_axis in FRAMEWORK_CONTROLS.items():
            for axis in axes:
                if not _framework_applies(framework, axis, event, organization):
                    continue
                controls = controls_by_axis.get(axis)
                if not controls:
                    continue
                key = (framework, axis)
                cell = cells.setdefault(
                    key,
                    {
                        "framework": framework,
                        "axis": axis,
                        "controls": list(controls),
                        "records": {},
                        "finding_count": 0,
                        "mapping_states": set(),
                    },
                )
                cell["records"][evidence_id] = evidence
                cell["mapping_states"].add(_mapping_state(event, framework))

    for finding in findings:
        for axis in _finding_axes(finding):
            for framework, controls_by_axis in FRAMEWORK_CONTROLS.items():
                controls = controls_by_axis.get(axis)
                if not controls:
                    continue
                cell = cells.get((framework, axis))
                if cell is not None:
                    cell["finding_count"] += 1

    mappings = []
    for cell in cells.values():
        evidence = list(cell.pop("records").values())
        mapping_states = set(cell.pop("mapping_states"))
        statuses = [item["evidence_status"] for item in evidence]
        evidence_ids = sorted(
            str(item["evidence_id"]) for item in evidence if item.get("evidence_id")
        )
        validated_evidence_ids = sorted(
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id") and item["evidence_status"] in {"validated", "confirmed"}
        )
        direct_evidence_ids = sorted(
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id") and item["evidence_status"] == "direct"
        )
        direct_relationship_evidence_ids = sorted(
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id") and str(item.get("relationship") or "").lower() == "direct"
        )
        mappings.append(
            {
                **cell,
                "record_count": len(evidence),
                "validated_count": sum(status in {"validated", "confirmed"} for status in statuses),
                "direct_count": sum(status == "direct" for status in statuses),
                "related_count": sum(
                    status in {"raw", "contextual", "potential", "related", "indirect"}
                    for status in statuses
                ),
                "domains": sorted({item["domain"] for item in evidence if item["domain"]}),
                "evidence_ids": evidence_ids,
                "validated_evidence_ids": validated_evidence_ids,
                "direct_evidence_ids": direct_evidence_ids,
                "direct_relationship_evidence_ids": direct_relationship_evidence_ids,
                "evidence": evidence[:12],
                "mapping_basis": "current_run_evidence_and_reference_crosswalk",
                "mapping_status": _strongest_mapping_state(mapping_states),
            }
        )
    mappings.sort(
        key=lambda item: (
            -item["validated_count"],
            -item["direct_count"],
            -item["record_count"],
            item["framework"],
            item["axis"],
        )
    )
    catalog = []
    for framework in FRAMEWORK_CATALOG:
        framework_mappings = [item for item in mappings if item["framework"] == framework["name"]]
        catalog.append(
            {
                **framework,
                "status": "evidence_backed" if framework_mappings else "no_data",
                "mapping_count": len(framework_mappings),
                "record_count": len(
                    {
                        evidence_id
                        for item in framework_mappings
                        for evidence_id in item["evidence_ids"]
                    }
                ),
                "mapping_states": sorted({item["mapping_status"] for item in framework_mappings}),
            }
        )
    return {
        "model_version": MODEL_VERSION,
        "status": "evidence_backed" if mappings else "no_data",
        "record_count": len(unique_records),
        "validated_count": len(validated_records),
        "cell_count": len(mappings),
        "mappings": mappings,
        "framework_catalog": catalog,
        "catalog_verified_at": "2026-08-25",
        "limitations": [
            "El cruce identifica controles de referencia relacionados con registros de la corrida; no mide cumplimiento, madurez ni eficacia.",
            "Un registro directo no equivale a un hallazgo validado. Los conteos validados solo incluyen estados validated o confirmed.",
            "Las vulnerabilidades globales sin coincidencia tecnológica o relación con el alcance no alimentan la matriz.",
            "Las celdas sin registros de la corrida se mantienen sin datos y no reciben porcentajes heurísticos.",
        ],
    }


def _event_axes(event: ThreatEvent) -> set[str]:
    text = " ".join(
        [
            event.title,
            event.category,
            event.actor or "",
            event.technique or "",
            event.asset or "",
            event.indicator or "",
            " ".join(event.tags),
            " ".join(event.framework_refs),
        ]
    ).casefold()
    return {axis for axis, terms in AXIS_RULES.items() if any(term in text for term in terms)}


def _event_is_in_scope(event: ThreatEvent, organization: OrganizationProfile) -> bool:
    relationship = str(event.relationship_to_scope or "").casefold()
    if relationship in {"direct", "group", "sector", "related"}:
        return True
    if _event_domain(event, organization.primary_domains):
        return True
    tags = {tag.casefold() for tag in event.tags}
    if tags.intersection(
        {
            "sector_campaign",
            "country_context",
            "regional_context",
            "sector_context",
            "applicable_vulnerability",
        }
    ):
        return True
    return event.vulnerability_status in {
        "cve_applicable",
        "cve_confirmed",
        "kev_exposed",
        "exploitation_observed",
    }


def _framework_applies(
    framework: str,
    axis: str,
    event: ThreatEvent,
    organization: OrganizationProfile,
) -> bool:
    text = " ".join(
        [
            organization.sector,
            organization.subsector or "",
            event.title,
            event.category,
            " ".join(event.tags),
        ]
    ).casefold()
    framework_refs = " ".join(event.framework_refs).casefold()
    technical = event.technical_validation or {}
    technology_domains = {
        str(getattr(domain, "value", domain)).casefold()
        for domain in [event.primary_technology_domain, *event.technology_domains]
    }
    if framework == "MITRE ATLAS":
        return axis == "ai"
    if framework == "MITRE F3":
        mappings = technical.get("f3_mappings", [])
        return axis in {"identity", "protect", "detect", "response", "fraud", "adversary"} and bool(
            mappings
        )
    if framework == "MITRE AADAPT":
        digital_asset_context = "aadapt" in framework_refs or bool(
            re.search(
                r"\b(digital asset|crypto(?:currency)?|blockchain|wallet|stablecoin|token transfer|defi)\b",
                text,
            )
        )
        return digital_asset_context and axis in {
            "identity",
            "protect",
            "detect",
            "response",
            "fraud",
            "adversary",
            "digital_asset",
        }
    if framework == "MITRE CAPEC":
        return axis in {"vulnerability", "adversary"} and (
            "capec" in framework_refs
            or bool(re.search(r"\b(attack pattern|exploit(?:ation)?|cve-\d|vulnerab)\b", text))
        )
    if framework == "MITRE CWE":
        return axis == "vulnerability" and (
            "cwe" in framework_refs
            or bool(re.search(r"\b(cwe-?\d+|weakness|cve-\d|vulnerab)\b", text))
        )
    if framework == "MITRE INFORM":
        return axis == "maturity" and "inform" in framework_refs
    if framework == "DISARM":
        return axis in {"influence", "fraud", "response"} and (
            "disarm" in framework_refs
            or bool(
                re.search(
                    r"\b(disinformation|desinformaci[oó]n|narrative manipulation|influence operation|coordinated amplification)\b",
                    text,
                )
            )
        )
    if framework == "MITRE ATT&CK ICS":
        return (
            bool(technology_domains & {"ot", "iiot"})
            or "attack ics" in framework_refs
            or "att&ck ics" in framework_refs
        )
    if framework == "MITRE EMB3D":
        return bool(technology_domains & {"iot", "iiot", "ot"}) or "emb3d" in framework_refs
    if framework == "MITRE ATT&CK Mobile":
        mobile_text = " ".join(
            [framework_refs, event.asset_class or "", " ".join(event.tags)]
        ).casefold()
        return bool(re.search(r"\b(mobile|android|ios|smartphone|tablet)\b", mobile_text))
    if framework == "MITRE ATT&CK Enterprise":
        return (
            not bool(technology_domains & {"ot", "iiot"})
            or "attack enterprise" in framework_refs
            or "att&ck enterprise" in framework_refs
        )
    if framework == "PCI DSS":
        return bool(
            re.search(
                r"\b(payment|cardholder|card data|payments|bank|banking|financial|financiero|retail|e-?commerce)\b",
                text,
            )
        )
    if framework == "GDPR":
        return axis == "privacy" or bool(
            re.search(
                r"\b(personal data|personally identifiable|pii|privacy|privacidad|gdpr|data subject|breach notification)\b",
                text,
            )
        )
    return True


_MAPPING_STATE_ORDER = {
    "preventive_reference": 0,
    "potentially_relevant": 1,
    "evidence_supported_candidate": 2,
    "observed_behavior": 3,
    "validated": 4,
}


def _mapping_state(event: ThreatEvent, framework: str) -> str:
    raw_status = str(event.attack_mapping_status or "preventive_reference")
    if raw_status in {"observed_behavior", "validated"}:
        return raw_status
    explicit_references = " ".join([*event.framework_refs, *event.technique_refs]).casefold()
    framework_token = framework.replace("MITRE ", "").casefold()
    explicitly_mapped = framework_token in explicit_references
    if framework == "MITRE F3":
        explicitly_mapped = explicitly_mapped or bool(
            (event.technical_validation or {}).get("f3_mappings", [])
        )
    if explicitly_mapped and event.evidence_status in ASSURED_STATUSES:
        return "evidence_supported_candidate"
    if event.evidence_status in ASSURED_STATUSES:
        return "evidence_supported_candidate"
    return "potentially_relevant"


def _strongest_mapping_state(states: set[str]) -> str:
    if not states:
        return "preventive_reference"
    return max(states, key=lambda state: _MAPPING_STATE_ORDER.get(state, -1))


def _finding_axes(finding: RiskFinding) -> set[str]:
    text = " ".join([finding.title, finding.category, finding.matrix_label]).casefold()
    return {axis for axis, terms in AXIS_RULES.items() if any(term in text for term in terms)}


def _evidence_row(event: ThreatEvent, organization: OrganizationProfile) -> dict[str, Any]:
    return {
        "evidence_id": str(event.canonical_id or event.id),
        "title": event.title,
        "url": event.evidence_url,
        "source": event.source,
        "observed_at": event.observed_at,
        "evidence_status": str(getattr(event.evidence_status, "value", event.evidence_status)),
        "relationship": event.relationship_to_scope,
        "domain": _event_domain(event, organization.primary_domains),
        "validation_method": str(
            (event.technical_validation or {}).get("validation_method")
            or event.validation_result
            or "not_validated"
        ),
    }


def _event_domain(event: ThreatEvent, domains: Iterable[str]) -> str:
    known = [str(domain).casefold() for domain in domains]
    host = str(event.host or event.asset or "").casefold()
    if event.evidence_url:
        host = f"{host} {urlsplit(event.evidence_url).hostname or ''}".casefold()
    text = f"{host} {event.title.casefold()}"
    return next(
        (
            domain
            for domain in known
            if re.search(rf"(^|[^a-z0-9]){re.escape(domain)}([^a-z0-9]|$)", text)
        ),
        "",
    )
