from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import unicodedata
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


RELATIONSHIP_RISK_MODEL_VERSION = "cde-relationship-risk-v1.2.0"
_ASSURED = {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
_EXCLUDED = {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}
_RISK_TERMS = re.compile(
    r"\b(?:breach|filtraci[oó]n|ransomware|malware|phishing|fraude|fraud|scam|"
    r"suplantaci[oó]n|vulnerab|incident|ataque|attack|compromise|credencial|leak|"
    r"interrupci[oó]n|outage|supply[ -]chain|tercero|third[ -]party)\b",
    re.IGNORECASE,
)
_RELATIONSHIP_TERMS = re.compile(
    r"\b(?:proveedor|supplier|vendor|tercero|third[ -]party|partner|socio|contratista|"
    r"supply[ -]chain|cadena de suministro)\b",
    re.IGNORECASE,
)
_ABUSE_TERMS = re.compile(
    r"\b(?:phishing|fraude|fraud|scam|estafa|suplantaci[oó]n|impersonation|fake|"
    r"falso|lookalike|typosquat|cybersquat|ciberocupaci[oó]n|credencial|login)\b",
    re.IGNORECASE,
)
_COMMON_MULTI_SUFFIXES = {
    "co.uk",
    "com.ar",
    "com.au",
    "com.br",
    "com.co",
    "com.ec",
    "com.mx",
    "com.pe",
    "co.jp",
    "co.nz",
}
_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})
_BRAND_MODIFIERS = {
    "account",
    "accounts",
    "app",
    "auth",
    "cliente",
    "clientes",
    "help",
    "login",
    "mail",
    "online",
    "portal",
    "secure",
    "security",
    "soporte",
    "support",
    "verify",
    "web",
}


def build_relationship_risk_intelligence(
    events: Sequence[ThreatEvent], organization: OrganizationProfile
) -> dict[str, Any]:
    usable = [event for event in events if event.evidence_status not in _EXCLUDED]
    return {
        "model_version": RELATIONSHIP_RISK_MODEL_VERSION,
        "third_party": _build_third_party_risk(usable, organization),
        "domain_abuse": _build_domain_abuse(usable, organization),
        "competitive_context": _build_competitive_context(usable, organization),
        "limitations": [
            "Una relación declarada no constituye por sí sola un riesgo validado.",
            "Un dominio visualmente similar no demuestra control malicioso ni ciberocupación; se publica como candidato observado hasta validar registro, contenido y relación.",
            "El contexto competitivo y sectorial orienta PESTEL y Porter, pero no incrementa el riesgo técnico sin evidencia directa o validada.",
        ],
    }


def _build_third_party_risk(
    events: Sequence[ThreatEvent], organization: OrganizationProfile
) -> dict[str, Any]:
    declared = _unique(organization.critical_suppliers)
    candidates: dict[str, dict[str, Any]] = {
        _normalize(name): {
            "name": name,
            "relationship_basis": ["declared_supplier"],
            "declared": True,
            "events": [],
        }
        for name in declared
        if _normalize(name)
    }

    for event in events:
        text = _event_text(event)
        matched_keys = [key for key in candidates if _contains_entity(text, key)]
        if not matched_keys and _RELATIONSHIP_TERMS.search(text):
            observed_name = _observed_third_party_name(event)
            key = _normalize(observed_name)
            if key:
                candidates.setdefault(
                    key,
                    {
                        "name": observed_name,
                        "relationship_basis": ["public_relationship_reference"],
                        "declared": False,
                        "events": [],
                    },
                )
                matched_keys = [key]
        for key in matched_keys:
            candidates[key]["events"].append(event)

    rows: list[dict[str, Any]] = []
    for item in candidates.values():
        related: list[ThreatEvent] = item.pop("events")
        assured = [event for event in related if event.evidence_status in _ASSURED]
        risk_events = [event for event in assured if _RISK_TERMS.search(_event_text(event))]
        sources = {ref for event in risk_events for ref in event.source_refs if ref}
        score = _bounded_attention_score(risk_events, len(sources))
        if risk_events:
            status = "evidence_supported_signal"
        elif related:
            status = "context_only"
        else:
            status = "declared_unobserved"
        rows.append(
            {
                **item,
                "status": status,
                "attention_score": score,
                "record_count": len(related),
                "assured_record_count": len(assured),
                "risk_signal_count": len(risk_events),
                "source_count": len(sources),
                "evidence_ids": _evidence_ids(related),
                "urls": _urls(related),
                "what_it_means": (
                    "Existe una señal pública relacionada con riesgo que requiere validar alcance, dependencia y control."
                    if risk_events
                    else "La relación está declarada u observada, pero no existe evidencia suficiente para publicar riesgo."
                ),
                "what_it_does_not_mean": "No confirma compromiso del tercero ni impacto sobre la organización.",
            }
        )
    rows.sort(
        key=lambda row: (
            row["attention_score"] is None,
            -(row["attention_score"] or 0),
            -row["record_count"],
            row["name"].casefold(),
        )
    )
    return {
        "status": "evidence_supported" if any(row["risk_signal_count"] for row in rows) else "context_only" if rows else "no_data",
        "declared_count": len(declared),
        "observed_count": sum(bool(row["record_count"]) for row in rows),
        "assessed_count": sum(row["attention_score"] is not None for row in rows),
        "rows": rows,
    }


def _build_domain_abuse(
    events: Sequence[ThreatEvent], organization: OrganizationProfile
) -> dict[str, Any]:
    targets = _unique(
        _registrable_domain(value)
        for value in organization.primary_domains
        if _registrable_domain(value)
    )
    primary_domains = {_normalize_host(value) for value in organization.primary_domains if value}
    comparison_domains = {_normalize_host(value) for value in organization.comparison_domains if value}
    grouped: dict[tuple[str, str], list[ThreatEvent]] = defaultdict(list)
    observed_hosts: dict[tuple[str, str], set[str]] = defaultdict(set)
    metadata: dict[tuple[str, str], dict[str, Any]] = {}
    best_match_by_candidate: dict[str, tuple[str, dict[str, Any]] | None] = {}

    for event in events:
        for host in _event_hosts(event):
            if not host or _belongs_to_scope(host, primary_domains | comparison_domains):
                continue
            candidate = _registrable_domain(host)
            if not candidate:
                continue
            if candidate not in best_match_by_candidate:
                matches = []
                for target in targets:
                    similarity = _domain_similarity(candidate, target)
                    if similarity["candidate"]:
                        matches.append((target, similarity))
                best_match_by_candidate[candidate] = (
                    sorted(
                        matches,
                        key=lambda item: (
                            -item[1]["similarity"],
                            item[1]["edit_distance"],
                            item[0],
                        ),
                    )[0]
                    if matches
                    else None
                )
            best_match = best_match_by_candidate[candidate]
            if best_match is None:
                continue
            target_host, similarity = best_match
            key = (candidate, target_host)
            grouped[key].append(event)
            observed_hosts[key].add(host)
            metadata[key] = similarity

    rows: list[dict[str, Any]] = []
    for (host, target), related in grouped.items():
        assured = [event for event in related if event.evidence_status in _ASSURED]
        abuse_signals = [event for event in assured if _ABUSE_TERMS.search(_event_text(event))]
        similarity = metadata[(host, target)]
        rows.append(
            {
                "candidate_domain": host,
                "observed_hosts": sorted(observed_hosts[(host, target)]),
                "target_domain": target,
                "status": "suspicious_observed_signal" if abuse_signals else "similar_domain_observed",
                "malicious_intent_confirmed": False,
                "similarity": similarity["similarity"],
                "edit_distance": similarity["edit_distance"],
                "variation_types": similarity["variation_types"],
                "record_count": len(related),
                "assured_record_count": len(assured),
                "abuse_signal_count": len(abuse_signals),
                "observation": _domain_observation_details(
                    related, sorted(observed_hosts[(host, target)])
                ),
                "evidence_ids": _evidence_ids(related),
                "urls": _urls(related),
                "what_it_means": "Se observó públicamente un dominio parecido al alcance y debe validarse su titularidad, contenido y uso.",
                "what_it_does_not_mean": "La similitud por sí sola no prueba phishing, fraude, ciberocupación ni control adversario.",
            }
        )
    rows.sort(
        key=lambda row: (
            -row["abuse_signal_count"],
            -row["similarity"],
            row["candidate_domain"],
        )
    )
    return {
        "status": "observed_candidates" if rows else "no_data",
        "candidate_count": len(rows),
        "suspicious_signal_count": sum(row["abuse_signal_count"] > 0 for row in rows),
        "rows": rows[:200],
        "generation_policy": "observed_only_no_generated_domains",
    }


def _build_competitive_context(
    events: Sequence[ThreatEvent], organization: OrganizationProfile
) -> dict[str, Any]:
    declared = _unique([*organization.declared_competitors, *organization.comparison_domains])
    rows = []
    for competitor in declared:
        key = _normalize(competitor)
        related = [event for event in events if key and _contains_entity(_event_text(event), key)]
        rows.append(
            {
                "name": competitor,
                "status": "evidence_represented" if related else "declared_no_evidence",
                "risk_effect": "none_by_declaration",
                "record_count": len(related),
                "evidence_ids": _evidence_ids(related),
                "urls": _urls(related),
            }
        )
    return {
        "status": "available" if rows else "no_data",
        "declared_count": len(declared),
        "represented_count": sum(bool(row["record_count"]) for row in rows),
        "rows": rows,
        "policy": "Competitors are declared or explicitly evidenced; context does not become technical risk.",
    }


def _event_text(event: ThreatEvent) -> str:
    return " ".join(
        filter(
            None,
            (
                event.title,
                event.category,
                event.actor or "",
                event.host or "",
                event.asset or "",
                event.indicator or "",
                " ".join(event.tags),
            ),
        )
    )


def _observed_third_party_name(event: ThreatEvent) -> str:
    technical = event.technical_validation if isinstance(event.technical_validation, dict) else {}
    for value in (
        technical.get("supplier"),
        technical.get("provider_name"),
        technical.get("third_party"),
        event.vendor,
    ):
        candidate = str(value or "").strip()
        if candidate:
            return candidate
    return ""


def _event_hosts(event: ThreatEvent) -> set[str]:
    values: Iterable[str | None] = (
        event.host,
        event.indicator,
        event.asset,
        event.evidence_url,
        event.original_artifact_url,
    )
    hosts: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        if not candidate:
            continue
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        host = _normalize_host(parsed.hostname or candidate.split("/")[0])
        if host and "." in host and not _looks_like_ip(host):
            hosts.add(host)
    return hosts


def _domain_similarity(candidate: str, target: str) -> dict[str, Any]:
    candidate_label = _domain_label(candidate)
    target_label = _domain_label(target)
    normalized_candidate = candidate_label.translate(_CONFUSABLES).replace("-", "")
    normalized_target = target_label.translate(_CONFUSABLES).replace("-", "")
    distance = _levenshtein(normalized_candidate, normalized_target)
    ratio = SequenceMatcher(None, normalized_candidate, normalized_target).ratio()
    exact_label_on_different_host = normalized_candidate == normalized_target and candidate != target
    visual_confusable = (
        candidate_label != target_label
        and candidate_label.translate(_CONFUSABLES).replace("-", "")
        == target_label.translate(_CONFUSABLES).replace("-", "")
    )
    edit_limit = 1 if len(normalized_target) <= 6 else 2
    bounded_edit = distance <= edit_limit and ratio >= 0.78
    high_similarity = min(len(normalized_candidate), len(normalized_target)) >= 5 and ratio >= 0.88
    brand_modifier = _brand_modifier(candidate_label, target_label)
    candidate_flag = bool(
        normalized_candidate
        and normalized_target
        and candidate != target
        and (
            exact_label_on_different_host
            or visual_confusable
            or bounded_edit
            or high_similarity
            or brand_modifier
        )
    )
    variation_types = []
    if exact_label_on_different_host:
        variation_types.append("same_label_different_tld")
    if visual_confusable:
        variation_types.append("visual_character_substitution")
    if brand_modifier:
        variation_types.append("brand_modifier")
    if len(normalized_candidate) != len(normalized_target):
        variation_types.append("character_insertion_or_deletion")
    elif distance:
        variation_types.append("character_substitution_or_transposition")
    return {
        "candidate": candidate_flag,
        "similarity": round(ratio, 3),
        "edit_distance": distance,
        "variation_types": variation_types or ["lexical_similarity"],
    }


def _brand_modifier(candidate_label: str, target_label: str) -> bool:
    candidate = candidate_label.casefold().replace("-", "")
    target = target_label.casefold().replace("-", "")
    if not candidate or not target or candidate == target:
        return False
    for modifier in _BRAND_MODIFIERS:
        if candidate in {f"{modifier}{target}", f"{target}{modifier}"}:
            return True
    return False


def _domain_observation_details(
    events: Sequence[ThreatEvent], observed_hosts: Sequence[str]
) -> dict[str, Any]:
    fields: dict[str, list[str]] = {
        "ip_addresses": [],
        "countries": [],
        "cities": [],
        "registrars": [],
        "registrants": [],
        "created_at": [],
        "updated_at": [],
        "expires_at": [],
    }
    aliases = {
        "ip": "ip_addresses",
        "ip_address": "ip_addresses",
        "ip_addresses": "ip_addresses",
        "resolved_ip": "ip_addresses",
        "resolved_ips": "ip_addresses",
        "dns_a": "ip_addresses",
        "addresses": "ip_addresses",
        "country": "countries",
        "country_code": "countries",
        "geo_country": "countries",
        "country_name": "countries",
        "city": "cities",
        "geo_city": "cities",
        "registrar": "registrars",
        "registrar_name": "registrars",
        "registrant": "registrants",
        "registrant_name": "registrants",
        "registrant_organization": "registrants",
        "owner": "registrants",
        "creation_date": "created_at",
        "created_at": "created_at",
        "registered_at": "created_at",
        "updated_date": "updated_at",
        "updated_at": "updated_at",
        "expiration_date": "expires_at",
        "expires_at": "expires_at",
        "expiry_date": "expires_at",
    }

    def add_value(bucket: str, value: Any) -> None:
        values = value if isinstance(value, (list, tuple, set)) else [value]
        for raw in values:
            if isinstance(raw, dict):
                for nested in raw.values():
                    add_value(bucket, nested)
                continue
            candidate = str(raw or "").strip()
            if not candidate or len(candidate) > 240:
                continue
            if bucket == "ip_addresses":
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if not address.is_global:
                    continue
                candidate = str(address)
            if candidate not in fields[bucket]:
                fields[bucket].append(candidate)

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                normalized_key = str(key).strip().casefold().replace("-", "_")
                bucket = aliases.get(normalized_key)
                if bucket:
                    add_value(bucket, child)
                elif isinstance(child, (dict, list, tuple)):
                    walk(child, depth + 1)
        elif isinstance(value, (list, tuple)):
            for child in value:
                walk(child, depth + 1)

    captures: list[dict[str, Any]] = []
    first_seen: list[str] = []
    last_seen: list[str] = []
    for event in events:
        walk(event.technical_validation)
        walk(event.internal_raw_metadata)
        if event.first_seen and event.first_seen not in first_seen:
            first_seen.append(event.first_seen)
        if event.last_seen and event.last_seen not in last_seen:
            last_seen.append(event.last_seen)
        for capture in event.captures:
            status = str(capture.validation_status)
            if status not in {"captured", "verified"}:
                continue
            captures.append(
                {
                    "url": capture.final_url or capture.original_page_url,
                    "captured_at": capture.capture_timestamp,
                    "status": status,
                    "image_hash": capture.image_hash,
                }
            )
    return {
        "observed_hosts": list(observed_hosts),
        **{key: values[:20] for key, values in fields.items()},
        "first_seen": sorted(first_seen)[:10],
        "last_seen": sorted(last_seen, reverse=True)[:10],
        "captures": captures[:12],
        "capture_count": len(captures),
    }


def _bounded_attention_score(events: Sequence[ThreatEvent], source_count: int) -> float | None:
    if not events:
        return None
    signal = sum(
        max(0.05, event.confidence_score)
        * max(0.05, event.severity)
        * math.exp(-math.log(2) * max(0, event.age_days) / 60)
        for event in events
    )
    corroboration = min(1.0, source_count / 3)
    return round(100 * (1 - math.exp(-0.35 * signal)) * (0.8 + 0.2 * corroboration), 2)


def _evidence_ids(events: Sequence[ThreatEvent]) -> list[str]:
    return list(dict.fromkeys(str(event.public_evidence_id or event.canonical_id or event.id) for event in events))


def _urls(events: Sequence[ThreatEvent]) -> list[str]:
    urls: list[str] = []
    for event in events:
        for value in (event.original_artifact_url, event.evidence_url):
            candidate = _valid_public_url(value)
            if candidate and candidate not in urls:
                urls.append(candidate)
                if len(urls) >= 30:
                    return urls
    return urls


def _belongs_to_scope(host: str, scope: set[str]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in scope if domain)


def _domain_label(host: str) -> str:
    parts = _normalize_host(host).split(".")
    if len(parts) < 2:
        return parts[0] if parts else ""
    suffix = ".".join(parts[-2:])
    return parts[-3] if suffix in _COMMON_MULTI_SUFFIXES and len(parts) >= 3 else parts[-2]


def _registrable_domain(value: str) -> str:
    host = _normalize_host(value)
    parts = host.split(".")
    if len(parts) < 2:
        return host
    suffix = ".".join(parts[-2:])
    if suffix in _COMMON_MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _valid_public_url(value: str | None) -> str | None:
    candidate = str(value or "").strip()
    if not candidate or any(character.isspace() for character in candidate):
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return candidate


def _normalize_host(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    return candidate.removeprefix("www.")


def _normalize(value: str) -> str:
    ascii_value = unicodedata.normalize("NFKD", value.casefold()).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", " ", ascii_value).strip()


def _contains_entity(text: str, normalized_entity: str) -> bool:
    normalized_text = _normalize(text)
    return bool(normalized_entity and re.search(rf"\b{re.escape(normalized_entity)}\b", normalized_text))


def _looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value))


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    previous = list(range(len(right) + 1))
    for index, char in enumerate(left, start=1):
        current = [index]
        for other_index, other_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[other_index] + 1,
                    previous[other_index - 1] + int(char != other_char),
                )
            )
        previous = current
    return previous[-1]


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def stable_relationship_id(*parts: str) -> str:
    return "REL-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
