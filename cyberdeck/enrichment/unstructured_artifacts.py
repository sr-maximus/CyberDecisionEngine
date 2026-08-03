from __future__ import annotations

from collections import Counter
from ipaddress import ip_address
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from cyberdeck.schemas import ThreatEvent


ARTIFACT_MODEL_VERSION = "cde-artifact-extraction-v1.0.0"

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[a-z0-9.-]+\.[a-z]{2,63}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s().-]*)?(?:\d[\s().-]*){8,15}(?!\w)")
FILE_RE = re.compile(r"\.((?:pdf|docx?|xlsx?|pptx?|csv|json|xml|txt|log|zip|rar|7z|pem|crt|sql|bak))(?:[?#]|$)", re.IGNORECASE)

TEXT_FIELDS = {
    "canonical_url",
    "content_preview",
    "description",
    "match_preview",
    "page_title",
    "query",
    "raw_response",
    "snippet",
    "summary",
    "url",
}


def enrich_unstructured_artifacts(events: Iterable[ThreatEvent]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    enriched_records = 0
    for event in events:
        artifacts = _extract_event_artifacts(event)
        if not artifacts:
            continue
        enriched_records += 1
        counts.update(str(item["type"]) for item in artifacts)
        validation = dict(event.technical_validation or {})
        validation["unstructured_artifacts"] = artifacts
        validation["artifact_extraction_model"] = ARTIFACT_MODEL_VERSION
        event.technical_validation = validation
        event.tags = _merge_artifact_tags(event.tags, artifacts)
    return {
        "model_version": ARTIFACT_MODEL_VERSION,
        "enriched_records": enriched_records,
        "artifact_count": sum(counts.values()),
        "by_type": dict(sorted(counts.items())),
    }


def _extract_event_artifacts(event: ThreatEvent) -> list[dict[str, Any]]:
    source_values = [
        ("title", event.title),
        ("evidence_url", event.evidence_url or ""),
        ("asset", event.asset or ""),
        ("host", event.host or ""),
        ("indicator", event.indicator or ""),
        ("tags", " ".join(event.tags or [])),
        *list(_selected_validation_text(event.technical_validation or {})),
    ]
    artifacts: dict[tuple[str, str], dict[str, Any]] = {}
    for source_field, text in source_values:
        if not text:
            continue
        for value in EMAIL_RE.findall(text):
            _upsert(artifacts, "email", value.lower(), source_field, 0.88)
        for value in URL_RE.findall(text):
            canonical = value.rstrip(".,;:!?")
            _upsert(artifacts, "url", canonical, source_field, 0.90)
            host = (urlsplit(canonical).hostname or "").lower()
            if host:
                _upsert(artifacts, "domain", host, source_field, 0.90)
            file_match = FILE_RE.search(canonical)
            if file_match:
                _upsert(artifacts, "file", canonical, source_field, 0.88, extension=file_match.group(1).lower())
        for value in IPV4_RE.findall(text):
            if _valid_public_ip(value):
                _upsert(artifacts, "ip", value, source_field, 0.86)
        for value in CVE_RE.findall(text):
            _upsert(artifacts, "cve", value.upper(), source_field, 0.92)
        for value in HASH_RE.findall(text):
            hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
            _upsert(artifacts, "hash", value.lower(), source_field, 0.90, hash_type=hash_type)
        for value in PHONE_RE.findall(text):
            normalized = _normalize_phone(value)
            if normalized:
                _upsert(artifacts, "phone", normalized, source_field, 0.62)

    validation = event.technical_validation or {}
    if validation.get("artifact_type") == "secret_indicator_candidate" and validation.get("value_hash"):
        _upsert(
            artifacts,
            "secret_indicator",
            str(validation["value_hash"]),
            "technical_validation.value_hash",
            0.55,
            raw_value_stored=False,
            validation_status="candidate",
        )
    return sorted(artifacts.values(), key=lambda item: (str(item["type"]), str(item["value"])))[:160]


def _selected_validation_text(value: Any, prefix: str = "technical_validation", depth: int = 0):
    if depth > 3:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            field = str(key)
            next_prefix = f"{prefix}.{field}"
            if isinstance(item, (dict, list)):
                yield from _selected_validation_text(item, next_prefix, depth + 1)
            elif field in TEXT_FIELDS and isinstance(item, (str, int, float)):
                text = str(item)
                if len(text) <= 200_000:
                    yield next_prefix, text
    elif isinstance(value, list):
        for index, item in enumerate(value[:200]):
            if isinstance(item, (dict, list)):
                yield from _selected_validation_text(item, f"{prefix}[{index}]", depth + 1)
            elif isinstance(item, str) and len(item) <= 10_000:
                yield f"{prefix}[{index}]", item


def _upsert(
    artifacts: dict[tuple[str, str], dict[str, Any]],
    artifact_type: str,
    value: str,
    source_field: str,
    confidence: float,
    **metadata: Any,
) -> None:
    cleaned = value.strip()
    if not cleaned:
        return
    key = (artifact_type, cleaned.lower())
    current = artifacts.get(key)
    if current:
        fields = set(current.get("source_fields") or [])
        fields.add(source_field)
        current["source_fields"] = sorted(fields)
        current["confidence"] = max(float(current.get("confidence") or 0), confidence)
        return
    artifacts[key] = {
        "type": artifact_type,
        "value": cleaned,
        "relation": "observed_in_collected_record",
        "status": "collected",
        "confidence": confidence,
        "source_fields": [source_field],
        **metadata,
    }


def _valid_public_ip(value: str) -> bool:
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast)


def _normalize_phone(value: str) -> str:
    compact = value.strip()
    if re.fullmatch(
        r"(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])"
        r"|(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}",
        compact,
    ):
        return ""
    digits = re.sub(r"\D", "", compact)
    if len(digits) < 8 or len(digits) > 15:
        return ""
    if not compact.startswith("+") and not re.search(r"[\s().-]", compact):
        return ""
    return f"+{digits}" if compact.startswith("+") else digits


def _merge_artifact_tags(tags: list[str], artifacts: list[dict[str, Any]]) -> list[str]:
    output = list(tags)
    seen = {item.lower() for item in output}
    for artifact in artifacts:
        artifact_type = str(artifact["type"])
        value = str(artifact["value"])
        if artifact_type not in {"email", "phone", "cve"}:
            continue
        tag = f"{artifact_type}:{value}"
        if tag.lower() not in seen:
            seen.add(tag.lower())
            output.append(tag)
    return output
