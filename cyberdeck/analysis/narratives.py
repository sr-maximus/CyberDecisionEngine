from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Any, Sequence

from cyberdeck.schemas import OrganizationProfile, ThreatEvent


MODEL_VERSION = "narrative-intelligence-v1.1.1"

_CONTENT_RULES: tuple[tuple[str, set[str]], ...] = (
    ("fact_check", {"fact_check", "debunk", "verification"}),
    ("correction_or_denial", {"correction", "denial", "desmentido", "rectification"}),
    ("brand_impersonation", {"brand_impersonation", "impersonation", "suplantacion", "fake_profile"}),
    ("phishing", {"phishing", "credential_phishing"}),
    ("fake_domain", {"fake_domain", "lookalike_domain", "typosquatting", "homograph"}),
    ("fraud_report", {"fraud", "fraud_report", "scam", "estafa"}),
    ("user_complaint", {"complaint", "user_complaint", "queja", "reclamo", "denuncia"}),
    ("potential_disinformation", {"disinformation", "misinformation", "potential_disinformation"}),
    ("rumor", {"rumor"}),
    ("satire", {"satire", "satira"}),
    ("official_statement", {"official_statement", "press_release", "corporate_statement"}),
    ("reputational_criticism", {"reputational_criticism", "criticism"}),
    ("legitimate_news", {"news", "legitimate_news", "media_report"}),
)

_NARRATIVE_TERMS = re.compile(
    r"\b(fraud|fraude|estafa|scam|phish|suplant|imperson|complaint|queja|reclamo|denuncia|"
    r"rumou?r|falso|false|fake|mislead|enganos|desinform|misinform|narrativ|campaign|campana|"
    r"coordin|amplif|propaganda|fact[ -]?check|desment|correction|criticism|reputacion)\w*\b",
    re.IGNORECASE,
)


def build_narrative_intelligence(events: Sequence[ThreatEvent], organization: OrganizationProfile) -> dict[str, Any]:
    claims = [_claim_from_event(event, organization) for event in events]
    claims = [claim for claim in claims if claim is not None]
    groups: dict[str, list[dict[str, Any]]] = {
        "confirmed": [],
        "supported": [],
        "under_review": [],
        "contradicted": [],
        "discarded": [],
    }
    for claim in claims:
        if claim["status"] == "confirmed":
            groups["confirmed"].append(claim)
        elif claim["status"] in {"validated", "supported"}:
            groups["supported"].append(claim)
        elif claim["status"] == "contradicted":
            groups["contradicted"].append(claim)
        elif claim["status"] == "discarded":
            groups["discarded"].append(claim)
        else:
            groups["under_review"].append(claim)
    content_counts = Counter(claim["contentType"] for claim in claims)
    truth_counts = Counter(claim["truthStatus"] for claim in claims)
    coordination_counts = Counter(claim["coordinationStatus"] for claim in claims)
    return {
        "modelVersion": MODEL_VERSION,
        "subject": organization.name,
        "claimCount": len(claims),
        "contentTypeCounts": dict(content_counts),
        "truthStatusCounts": dict(truth_counts),
        "coordinationStatusCounts": dict(coordination_counts),
        "claims": claims,
        "groups": groups,
        "limitations": [
            "La clasificación conserva señales relacionadas, pero no convierte ausencia de corroboración en falsedad.",
            "La coordinación solo se eleva cuando existen indicadores explícitos y trazables; DISARM no se infiere por una palabra aislada.",
            "El alcance estimado permanece N/D cuando la fuente no aporta una métrica verificable.",
        ],
    }


def _claim_from_event(event: ThreatEvent, organization: OrganizationProfile) -> dict[str, Any] | None:
    tags = {str(tag).strip().lower() for tag in event.tags if str(tag).strip()}
    category = str(event.category or "").strip().lower()
    title = str(event.title or "").strip()
    if not _is_subject_related(event, organization, title):
        return None
    body = " ".join([title, category, *sorted(tags)])
    explicit_labels = tags | {category}
    content_type = _content_type(explicit_labels, body)
    if content_type is None:
        return None
    evidence_id = str(event.canonical_id or event.id)
    evidence_status = str(getattr(event.evidence_status, "value", event.evidence_status or "raw"))
    truth_status = _truth_status(explicit_labels, evidence_status)
    coordination_status = _coordination_status(event, explicit_labels, evidence_status)
    status = _claim_status(event, evidence_status, truth_status)
    confidence = _confidence(event, evidence_status, content_type, truth_status)
    relevance = _cybersecurity_relevance(event, explicit_labels, content_type)
    duplicate_count = max(1, int(event.duplicate_count or 1))
    reach = round(100 * (1 - math.exp(-(duplicate_count - 1) / 8)), 2) if duplicate_count > 1 else None
    return {
        "claimId": "ncl-" + hashlib.sha256(f"{evidence_id}|{title}".encode("utf-8")).hexdigest()[:16],
        "claimText": title,
        "subjectIds": [organization.name, *organization.primary_domains],
        "sourceEvidenceIds": [evidence_id],
        "supportingEvidenceIds": [evidence_id] if status in {"supported", "validated", "confirmed"} else [],
        "contradictingEvidenceIds": [evidence_id] if status == "contradicted" else [],
        "primarySourceEvidenceIds": [evidence_id] if content_type in {"official_statement", "correction_or_denial", "fact_check"} else [],
        "contentType": content_type,
        "truthStatus": truth_status,
        "coordinationStatus": coordination_status,
        "cybersecurityRelevance": relevance,
        "reach": reach,
        "confidence": confidence,
        "firstSeen": event.observed_at,
        "lastSeen": event.observed_at,
        "status": status,
        "reviewReason": _review_reason(status, truth_status, coordination_status),
        "title": title,
        "source": event.source,
        "url": event.evidence_url,
        "excerpt": str((event.technical_validation or {}).get("summary") or ""),
        "captureId": evidence_id if "evidence_capture" in tags else None,
        "sourceRefs": list(event.source_refs),
        "disarmEligible": coordination_status in {"probable", "confirmed"},
    }


def _is_subject_related(event: ThreatEvent, organization: OrganizationProfile, title: str) -> bool:
    relationship = str(event.relationship_to_scope or "").strip().lower()
    if relationship in {"direct", "group"}:
        return True
    if relationship not in {"related", "contextual", ""}:
        return False
    haystack = " ".join(
        [title, str(event.evidence_url or ""), str(event.asset or ""), str(event.indicator or "")]
    ).casefold()
    terms = {
        str(value).strip().casefold()
        for value in [
            organization.name,
            organization.legal_name,
            *organization.primary_domains,
            *organization.brands,
            *organization.subsidiaries,
            *organization.entity_aliases,
        ]
        if str(value or "").strip()
    }
    return any(_contains_subject_term(haystack, term) for term in terms)


def _contains_subject_term(haystack: str, term: str) -> bool:
    escaped = re.escape(term).replace(r"\ ", r"\s+")
    return re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", haystack, re.IGNORECASE) is not None


def _content_type(labels: set[str], text: str) -> str | None:
    for content_type, markers in _CONTENT_RULES:
        if labels.intersection(markers):
            return content_type
    if _NARRATIVE_TERMS.search(text):
        return "unverified_claim"
    return None


def _truth_status(labels: set[str], evidence_status: str) -> str:
    if labels.intersection({"verified_false", "fact_check_false"}) and evidence_status in {"validated", "confirmed"}:
        return "false"
    if labels.intersection({"likely_false", "fact_check_likely_false"}) and evidence_status in {"direct", "validated", "confirmed"}:
        return "likely_false"
    if labels.intersection({"misleading", "fact_check_misleading"}) and evidence_status in {"direct", "validated", "confirmed"}:
        return "misleading"
    if labels.intersection({"verified", "official_statement", "correction", "denial"}) and evidence_status in {"validated", "confirmed"}:
        return "verified"
    if evidence_status in {"validated", "confirmed"}:
        return "mostly_supported"
    if evidence_status == "direct":
        return "partially_supported"
    return "unverified"


def _coordination_status(event: ThreatEvent, labels: set[str], evidence_status: str) -> str:
    indicators = labels.intersection({"coordinated_amplification", "shared_infrastructure", "temporal_burst", "high_text_similarity", "coordination_confirmed"})
    if "coordination_confirmed" in indicators and evidence_status == "confirmed" and event.source_refs:
        return "confirmed"
    if len(indicators) >= 2 and evidence_status in {"direct", "validated", "confirmed"}:
        return "probable"
    if indicators:
        return "suspected"
    return "insufficient_data"


def _claim_status(event: ThreatEvent, evidence_status: str, truth_status: str) -> str:
    if event.contradiction_count and truth_status in {"likely_false", "false"}:
        return "contradicted"
    if evidence_status == "confirmed":
        return "confirmed"
    if evidence_status == "validated":
        return "validated"
    if evidence_status == "direct":
        return "supported"
    return "under_review"


def _confidence(event: ThreatEvent, evidence_status: str, content_type: str, truth_status: str) -> float:
    base = float(event.confidence_score or 0.0)
    if base <= 1:
        base *= 100
    status_floor = {"raw": 20, "indirect": 30, "direct": 50, "validated": 70, "confirmed": 85}.get(evidence_status, 20)
    value = max(base, status_floor)
    if content_type in {"unverified_claim", "rumor", "user_complaint"} and truth_status == "unverified":
        value = min(value, 45)
    if event.contradiction_count:
        value *= 0.7
    return round(max(0.0, min(100.0, value)), 2)


def _cybersecurity_relevance(event: ThreatEvent, labels: set[str], content_type: str) -> float:
    score = 25.0
    if content_type in {"phishing", "fake_domain", "brand_impersonation", "fraud_report"}:
        score += 35
    if labels.intersection({"credential", "account_takeover", "identity_theft", "data_breach", "leak", "malware"}):
        score += 20
    if str(event.relationship_to_scope or "") in {"direct", "group"}:
        score += 15
    return round(min(100.0, score), 2)


def _review_reason(status: str, truth_status: str, coordination_status: str) -> str:
    if status == "under_review":
        return "Señal relacionada pendiente de corroboración o validación técnica/humana."
    if status == "contradicted":
        return "La afirmación tiene evidencia contradictoria; revisar la fuente primaria y el método de validación."
    if coordination_status in {"suspected", "probable"}:
        return "Existen indicadores de coordinación, pero su estado debe revisarse antes de activar DISARM."
    if truth_status in {"false", "likely_false", "misleading"}:
        return "El estado de veracidad depende de evidencia de contraste registrada."
    return "Señal respaldada por el estado de evidencia registrado."
