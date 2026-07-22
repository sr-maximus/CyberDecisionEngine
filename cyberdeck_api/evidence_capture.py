from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import httpx

from cyberdeck.schemas import EvidenceCapture, RunContext


MAX_REPORT_CAPTURES = 6


async def attach_report_evidence_captures(context: RunContext, run_id: str) -> RunContext:
    endpoint = os.getenv("EVIDENCE_CAPTURE_URL", "").strip()
    candidates = _capture_candidates(context)
    if not endpoint or not candidates:
        context.metrics["evidence_capture"] = {
            "status": "skipped",
            "requested": len(candidates),
            "captured": 0,
            "failed": 0,
            "reason": "capture_endpoint_unavailable" if candidates else "no_public_evidence_urls",
        }
        return context
    payload = {
        "run_id": run_id,
        "targets": [item[1] for item in candidates[:MAX_REPORT_CAPTURES]],
        "timeout_seconds": 35,
        "viewport_width": 1440,
        "viewport_height": 1000,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            result = response.json()
    except Exception as exc:
        context.metrics["evidence_capture"] = {
            "status": "failed",
            "requested": len(payload["targets"]),
            "captured": 0,
            "failed": len(payload["targets"]),
            "reason": f"capture_service_error:{type(exc).__name__}",
        }
        return context

    events_by_id = {event.id: event for event in context.raw_events}
    attached = 0
    failed = 0
    for raw_capture in result.get("captures", []):
        event = events_by_id.get(str(raw_capture.get("evidenceId") or ""))
        if event is None:
            continue
        try:
            capture = EvidenceCapture(**raw_capture)
        except Exception:
            failed += 1
            continue
        event.captures = [capture]
        if capture.validation_status == "verified":
            attached += 1
        else:
            failed += 1
    context.metrics["evidence_capture"] = {
        "status": "completed" if attached else "failed",
        "requested": len(payload["targets"]),
        "captured": attached,
        "failed": failed,
        "reason": None if attached else "no_page_could_be_captured",
    }
    return context


def _capture_candidates(context: RunContext) -> list[tuple[float, dict[str, Any]]]:
    candidates: list[tuple[float, dict[str, Any]]] = []
    seen_urls: set[str] = set()
    primary_domains = [domain.lower().strip(".") for domain in context.organization.primary_domains if domain]
    named_scope_terms = {
        value.lower().strip()
        for value in [context.organization.name, *context.organization.brands, *context.organization.subsidiaries]
        if len(value.strip()) >= 4
    }
    for event in context.raw_events:
        url = (event.evidence_url or "").strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        if parsed.path.lower().endswith(
            (
                ".json",
                ".xml",
                ".csv",
                ".txt",
                ".pdf",
                ".zip",
                ".doc",
                ".docx",
                ".xls",
                ".xlsx",
                ".ppt",
                ".pptx",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".webp",
            )
        ):
            continue
        if event.category == "vulnerability" and event.vulnerability_status not in {
            "cve_applicable",
            "cve_confirmed",
            "kev_exposed",
            "exploitation_observed",
        }:
            continue
        normalized = url.rstrip("/").lower()
        if normalized in seen_urls:
            continue
        seen_urls.add(normalized)
        if any(capture.validation_status == "verified" for capture in event.captures):
            continue
        host = parsed.hostname.lower().strip(".")
        official_host = any(host == domain or host.endswith(f".{domain}") for domain in primary_domains)
        canonical_scope_host = any(host in {domain, f"www.{domain}"} for domain in primary_domains)
        apex_scope_host = any(host == domain for domain in primary_domains)
        event_text = " ".join([event.title, event.category, url, *event.tags]).lower()
        named_match = any(term in event_text for term in named_scope_terms)
        evidence_status = str(event.evidence_status.value)
        strong_status = evidence_status in {"direct", "validated", "confirmed"}
        strong_relationship = event.relationship_to_scope in {"direct", "group", "supplier"}
        related = evidence_status == "related" or event.relationship_to_scope == "related"
        if not (official_host or named_match or strong_status or strong_relationship or related):
            continue
        path = parsed.path.lower().rstrip("/")
        homepage_bonus = 4.0 if path in {"", "/"} else 0.0
        strategic_page_bonus = 2.0 if any(
            token in path
            for token in (
                "sustainab",
                "sostenib",
                "corporate-governance",
                "gobierno-corporativo",
                "quienes-somos",
                "who-we-are",
                "operaciones",
                "operations",
            )
        ) else 0.0
        authentication_penalty = 4.0 if any(
            token in path
            for token in ("/login", "/signin", "/identity/", "/forgotpassword", "/reset-password")
        ) else 0.0
        status_bonus = {"confirmed": 6.0, "validated": 5.5, "direct": 5.0, "related": 2.0}.get(evidence_status, 0.0)
        relationship_bonus = {"direct": 4.0, "group": 3.0, "supplier": 2.5, "related": 1.5}.get(event.relationship_to_scope, 0.0)
        score = (
            status_bonus
            + relationship_bonus
            + (8.0 if official_host else 0.0)
            + (3.0 if canonical_scope_host else 0.0)
            + (1.0 if apex_scope_host else 0.0)
            + (2.0 if parsed.scheme == "https" else 0.0)
            + (3.0 if named_match else 0.0)
            + homepage_bonus
            + strategic_page_bonus
            - authentication_penalty
            + event.confidence_score
            + min(1.0, event.severity)
        )
        candidates.append(
            (
                score,
                {
                    "evidence_id": event.id,
                    "source_id": event.source,
                    "url": url,
                    "title": event.title[:300],
                },
            )
        )
    ranked = sorted(candidates, key=lambda item: item[0], reverse=True)
    diverse: list[tuple[float, dict[str, Any]]] = []
    repeated_hosts: list[tuple[float, dict[str, Any]]] = []
    selected_urls: set[str] = set()
    selected_hosts: set[str] = set()

    for domain in primary_domains:
        representative = next(
            (
                candidate
                for candidate in ranked
                if (urlparse(candidate[1]["url"]).hostname or "").lower().strip(".") == domain
                or (urlparse(candidate[1]["url"]).hostname or "").lower().strip(".").endswith(f".{domain}")
            ),
            None,
        )
        if representative is None:
            continue
        representative_url = representative[1]["url"].rstrip("/").lower()
        representative_host = (urlparse(representative[1]["url"]).hostname or "").lower()
        diverse.append(representative)
        selected_urls.add(representative_url)
        selected_hosts.add(representative_host)

    for candidate in ranked:
        normalized_url = candidate[1]["url"].rstrip("/").lower()
        if normalized_url in selected_urls:
            continue
        host = (urlparse(candidate[1]["url"]).hostname or "").lower()
        if host in selected_hosts:
            repeated_hosts.append(candidate)
            continue
        selected_hosts.add(host)
        selected_urls.add(normalized_url)
        diverse.append(candidate)
    return [*diverse, *repeated_hosts]
