from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cyberdeck.schemas import EvidenceStatus, RecordKind, ThreatEvent


STATUS_RANK = {
    EvidenceStatus.RAW: 0,
    EvidenceStatus.CONTEXTUAL: 1,
    EvidenceStatus.POTENTIAL: 2,
    EvidenceStatus.RELATED: 3,
    EvidenceStatus.DIRECT: 4,
    EvidenceStatus.VALIDATED: 5,
    EvidenceStatus.CONFIRMED: 6,
    EvidenceStatus.FALSE_POSITIVE: -1,
    EvidenceStatus.DISCARDED: -2,
}

TRACKING_QUERY_KEYS = {
    "gclid",
    "fbclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "source",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
}


@dataclass
class EvidenceProcessingResult:
    records: List[ThreatEvent]
    summary: dict[str, int | float | dict[str, int]]


def process_evidence_records(
    events: Iterable[ThreatEvent],
    scope_terms: Sequence[str] = (),
    *,
    raw_count: int | None = None,
) -> EvidenceProcessingResult:
    event_list = list(events)
    normalized = [_classify_event(event, scope_terms) for event in event_list]
    unique: dict[str, ThreatEvent] = {}
    duplicates = 0
    discarded = 0
    for event in normalized:
        if event.evidence_status == EvidenceStatus.DISCARDED:
            discarded += 1
            continue
        key = canonical_evidence_id(event)
        event.canonical_id = key
        event.content_hash = content_hash(event)
        existing = unique.get(key)
        if existing is None:
            unique[key] = event
            continue
        duplicates += 1
        unique[key] = _merge_records(existing, event)

    records = list(unique.values())
    status_counts = {status.value: 0 for status in EvidenceStatus}
    kind_counts = {kind.value: 0 for kind in RecordKind}
    for event in records:
        status_counts[event.evidence_status.value] += 1
        kind_counts[event.record_kind.value] += 1

    direct = status_counts[EvidenceStatus.DIRECT.value]
    validated = status_counts[EvidenceStatus.VALIDATED.value]
    confirmed = status_counts[EvidenceStatus.CONFIRMED.value]
    summary: dict[str, int | float | dict[str, int]] = {
        "raw_records_collected": int(raw_count if raw_count is not None else len(event_list)),
        "normalized_records": len(normalized),
        "unique_records": len(records),
        "discarded_records": discarded,
        "duplicates_removed": duplicates,
        "contextual_evidence": status_counts[EvidenceStatus.CONTEXTUAL.value],
        "potential_evidence": status_counts[EvidenceStatus.POTENTIAL.value],
        "related_evidence": status_counts[EvidenceStatus.RELATED.value],
        "direct_evidence": direct,
        "validated_evidence": validated,
        "confirmed_evidence": confirmed,
        "confirmed_findings": 0,
        "calculated_risks": 0,
        "confirmed_incidents": sum(1 for event in records if event.incident_confirmed),
        "false_positives": status_counts[EvidenceStatus.FALSE_POSITIVE.value],
        "status_counts": status_counts,
        "record_kind_counts": kind_counts,
    }
    return EvidenceProcessingResult(records=records, summary=summary)


def canonical_evidence_id(event: ThreatEvent) -> str:
    canonical_url = canonicalize_url(event.evidence_url)
    domain = _tag_value(event.tags, "domain")
    host = event.host or _tag_value(event.tags, "host") or _host_from_url(canonical_url)
    asset = event.asset or _tag_value(event.tags, "asset")
    indicator = event.indicator or event.cve or event.external_id
    observed_date = _observed_date(event.observed_at)
    # Prefer identifiers controlled by the source. A canonical URL or external
    # indicator must not become a second record merely because its title changed.
    if indicator:
        stable_parts = {
            "indicator": indicator.lower(),
            "type": event.category.lower(),
            "source": event.source.lower(),
        }
    elif canonical_url:
        stable_parts = {"url": canonical_url, "type": event.category.lower()}
    else:
        stable_parts = {
            "domain": (domain or "").lower(),
            "host": (host or "").lower(),
            "asset": (asset or "").lower(),
            "type": event.category.lower(),
            "date": observed_date,
            "title": _normalize_text(event.title),
            "source": event.source.lower(),
        }
    digest = hashlib.sha256(json.dumps(stable_parts, sort_keys=True).encode("utf-8")).hexdigest()
    return f"evd-{digest[:24]}"


def content_hash(event: ThreatEvent) -> str:
    content = "|".join(
        [
            _normalize_text(event.title),
            event.category.lower(),
            canonicalize_url(event.evidence_url),
            (event.indicator or event.cve or "").lower(),
        ]
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def canonicalize_url(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return value.strip().lower()
    if not parsed.scheme or not parsed.netloc:
        return value.strip().lower().rstrip("/")
    query = urlencode(
        sorted((key, item) for key, item in parse_qsl(parsed.query, keep_blank_values=True) if key.lower() not in TRACKING_QUERY_KEYS)
    )
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        return value.strip().lower().rstrip("/")
    netloc = host if port is None or (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80) else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))


def _classify_event(event: ThreatEvent, scope_terms: Sequence[str]) -> ThreatEvent:
    tags = {tag.lower() for tag in event.tags}
    text = " ".join(
        [
            event.title,
            event.category,
            event.evidence_url or "",
            event.asset or "",
            event.host or "",
            " ".join(event.tags),
        ]
    ).lower()
    matched_terms = [term.lower() for term in scope_terms if term and term.lower() in text]
    direct_domain = any(
        term in (canonicalize_url(event.evidence_url) or "")
        or f"domain:{term}" in tags
        or f"host:{term}" in tags
        for term in matched_terms
        if "." in term
    )
    event.relationship_to_scope = "direct" if direct_domain else "related" if matched_terms else "contextual"

    validation = event.technical_validation or {}
    result = str(validation.get("validation_result") or event.validation_result or "not_validated")
    validation_method = str(validation.get("validation_method") or validation.get("method") or "").strip()
    direct_relationship = validation.get("direct_relationship") is True
    event.validation_result = result
    validated_result = result in {"confirmed_missing", "present_invalid", "validated", "confirmed"}
    transient_result = result in {"temporary_resolution_error", "timeout", "failed", "requires_owner_validation"}

    if "false_positive" in tags:
        event.evidence_status = EvidenceStatus.FALSE_POSITIVE
        event.record_kind = RecordKind.FALSE_POSITIVE
    elif "discarded" in tags or not event.title.strip():
        event.evidence_status = EvidenceStatus.DISCARDED
        event.record_kind = RecordKind.SOURCE_LIMITATION
    elif event.incident_confirmed:
        event.evidence_status = EvidenceStatus.CONFIRMED
        event.record_kind = RecordKind.CONFIRMED_INCIDENT
    elif validated_result and event.relationship_to_scope == "direct":
        event.evidence_status = EvidenceStatus.VALIDATED
        event.record_kind = RecordKind.VALIDATED_TECHNICAL_EVIDENCE
    elif event.category in {"attack_surface_dns", "attack_surface_web"} or "dns_inventory_only" in tags:
        event.evidence_status = EvidenceStatus.RELATED if matched_terms else EvidenceStatus.CONTEXTUAL
        event.record_kind = RecordKind.OBSERVED_ASSET
    elif transient_result or "validation_required" in tags or "reputation_checker" in tags:
        event.evidence_status = EvidenceStatus.POTENTIAL
        event.record_kind = RecordKind.CONTEXTUAL_SIGNAL
    elif event.evidence_url and event.relationship_to_scope == "direct" and direct_relationship and validation_method:
        event.evidence_status = EvidenceStatus.DIRECT
        event.record_kind = RecordKind.DIRECT_EVIDENCE
    elif matched_terms:
        event.evidence_status = EvidenceStatus.RELATED
        event.record_kind = RecordKind.RELATED_EVIDENCE
    else:
        event.evidence_status = EvidenceStatus.CONTEXTUAL
        event.record_kind = RecordKind.CONTEXTUAL_SIGNAL

    if event.cve:
        if {"version_confirmed", "cve_applicable"}.issubset(tags) and event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED}:
            event.vulnerability_status = "cve_applicable"
            event.record_kind = RecordKind.APPLICABLE_VULNERABILITY
        else:
            event.vulnerability_status = "cve_candidate"
    elif "technology_observed" in tags or event.category == "attack_surface_web":
        event.vulnerability_status = "version_unknown"

    behavior_evidence = bool(tags.intersection({"telemetry", "security_log", "source_ip", "behavior_pattern"}))
    event.attack_mapping_status = (
        "observed_adversary_behavior"
        if behavior_evidence and event.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        else "potentially_relevant_technique"
    )

    freshness = max(0.0, 1.0 - min(max(event.age_days, 0), 365) / 365)
    score = (
        0.25 * max(0.0, min(1.0, event.source_weight))
        + 0.25 * (1.0 if direct_domain else 0.65 if matched_terms else 0.2)
        + 0.10 * freshness
        + 0.10 * (1.0 if event.evidence_url else 0.0)
        + 0.15 * (1.0 if validated_result else 0.25 if transient_result else 0.0)
        + 0.10 * min(1.0, len(set(event.source_refs or [event.source])) / 2)
        + 0.05 * (1.0 if event.human_reviewed else 0.0)
        - 0.10 * min(1.0, event.contradiction_count)
    )
    event.confidence_score = max(0.0, min(1.0, round(score, 4)))
    event.confidence = event.confidence_score
    event.synchronize_confidence()
    event.asset = event.asset or _tag_value(event.tags, "asset")
    event.host = event.host or _tag_value(event.tags, "host") or _host_from_url(event.evidence_url)
    event.indicator = event.indicator or event.cve
    return event


def _merge_records(left: ThreatEvent, right: ThreatEvent) -> ThreatEvent:
    preferred = right if STATUS_RANK[right.evidence_status] > STATUS_RANK[left.evidence_status] else left
    other = left if preferred is right else right
    preferred.source_refs = sorted(set(preferred.source_refs + other.source_refs + [preferred.source, other.source]))
    preferred.tags = sorted(set(preferred.tags + other.tags))
    preferred.duplicate_count = left.duplicate_count + right.duplicate_count + 1
    preferred.confidence_score = max(left.confidence_score, right.confidence_score)
    preferred.confidence = preferred.confidence_score
    preferred.synchronize_confidence()
    return preferred


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _tag_value(tags: Sequence[str], prefix: str) -> str | None:
    marker = f"{prefix}:"
    for tag in tags:
        if tag.lower().startswith(marker):
            return tag.split(":", 1)[1].strip() or None
    return None


def _host_from_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return urlsplit(value).hostname
    except ValueError:
        return None


def _observed_date(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except (TypeError, ValueError):
        return "unknown"
