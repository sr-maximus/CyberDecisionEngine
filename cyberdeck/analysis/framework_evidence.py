from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RiskFinding, ThreatEvent


MODEL_VERSION = "framework-evidence-crosswalk-v1.1.0"

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
    "response": ("incident", "respond", "response", "contain", "recover", "takedown", "notification"),
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
    "ai": ("artificial intelligence", "machine learning", " llm", "prompt", "model", "agent", "atlas"),
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
    "MITRE ATT&CK": {
        "identity": ("Credential Access", "Initial Access"),
        "protect": ("Defense Evasion",),
        "detect": ("Discovery", "Command and Control"),
        "response": ("Impact",),
        "vulnerability": ("Initial Access",),
        "fraud": ("Initial Access", "Credential Access"),
        "adversary": ("Enterprise tactics and techniques",),
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
                    },
                )
                cell["records"][evidence_id] = evidence

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
        statuses = [item["evidence_status"] for item in evidence]
        evidence_ids = sorted(
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id")
        )
        validated_evidence_ids = sorted(
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id")
            and item["evidence_status"] in {"validated", "confirmed"}
        )
        direct_evidence_ids = sorted(
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id") and item["evidence_status"] == "direct"
        )
        direct_relationship_evidence_ids = sorted(
            str(item["evidence_id"])
            for item in evidence
            if item.get("evidence_id")
            and str(item.get("relationship") or "").lower() == "direct"
        )
        mappings.append(
            {
                **cell,
                "record_count": len(evidence),
                "validated_count": sum(status in {"validated", "confirmed"} for status in statuses),
                "direct_count": sum(status == "direct" for status in statuses),
                "related_count": sum(status in {"raw", "contextual", "potential", "related", "indirect"} for status in statuses),
                "domains": sorted({item["domain"] for item in evidence if item["domain"]}),
                "evidence_ids": evidence_ids,
                "validated_evidence_ids": validated_evidence_ids,
                "direct_evidence_ids": direct_evidence_ids,
                "direct_relationship_evidence_ids": direct_relationship_evidence_ids,
                "evidence": evidence[:12],
                "mapping_basis": "current_run_evidence_and_reference_crosswalk",
            }
        )
    mappings.sort(key=lambda item: (-item["validated_count"], -item["direct_count"], -item["record_count"], item["framework"], item["axis"]))
    return {
        "model_version": MODEL_VERSION,
        "status": "evidence_backed" if mappings else "no_data",
        "record_count": len(unique_records),
        "validated_count": len(validated_records),
        "cell_count": len(mappings),
        "mappings": mappings,
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
    if tags.intersection({"sector_campaign", "country_context", "regional_context", "sector_context", "applicable_vulnerability"}):
        return True
    return event.vulnerability_status in {"cve_applicable", "cve_confirmed", "kev_exposed", "exploitation_observed"}


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
    if framework == "MITRE ATLAS":
        return axis == "ai"
    if framework == "MITRE F3":
        mappings = (event.technical_validation or {}).get("f3_mappings", [])
        return axis in {"identity", "protect", "detect", "response", "fraud", "adversary"} and bool(mappings)
    if framework == "PCI DSS":
        return bool(re.search(r"\b(payment|cardholder|card data|payments|bank|banking|financial|financiero|retail|e-?commerce)\b", text))
    if framework == "GDPR":
        return axis == "privacy" or bool(
            re.search(r"\b(personal data|personally identifiable|pii|privacy|privacidad|gdpr|data subject|breach notification)\b", text)
        )
    return True


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
        "validation_method": str((event.technical_validation or {}).get("validation_method") or event.validation_result or "not_validated"),
    }


def _event_domain(event: ThreatEvent, domains: Iterable[str]) -> str:
    known = [str(domain).casefold() for domain in domains]
    host = str(event.host or event.asset or "").casefold()
    if event.evidence_url:
        host = f"{host} {urlsplit(event.evidence_url).hostname or ''}".casefold()
    text = f"{host} {event.title.casefold()}"
    return next((domain for domain in known if re.search(rf"(^|[^a-z0-9]){re.escape(domain)}([^a-z0-9]|$)", text)), "")
