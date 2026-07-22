from __future__ import annotations

import asyncio
import csv
import hashlib
import ipaddress
from html.parser import HTMLParser
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import struct
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator


MAX_TARGETS = int(os.getenv("OSINT_TOOLS_MAX_TARGETS", "6"))
DEFAULT_TIMEOUT = int(os.getenv("OSINT_TOOLS_TIMEOUT_SECONDS", "45"))
ALLOW_ACCOUNT_ENUMERATION = os.getenv("ALLOW_ACCOUNT_ENUMERATION", "false").lower() == "true"
ENABLE_USER_SCANNER = os.getenv("ENABLE_USER_SCANNER", "true").lower() == "true"
ENABLE_SOCID_EXTRACTOR = os.getenv("ENABLE_SOCID_EXTRACTOR", "true").lower() == "true"
ENABLE_SOCIAL_ANALYZER = os.getenv("ENABLE_SOCIAL_ANALYZER", "false").lower() == "true"
OSINT_ALLOW_PROXY = os.getenv("OSINT_ALLOW_PROXY", "false").lower() == "true"
OSINT_PRIORITY_MODE = os.getenv("OSINT_PRIORITY_MODE", "false").lower() == "true"
USER_SCANNER_CATEGORY = os.getenv("USER_SCANNER_CATEGORY", "social")
SOCID_EXTRACTOR_MAX_URLS = int(os.getenv("SOCID_EXTRACTOR_MAX_URLS", "10" if OSINT_PRIORITY_MODE else "5"))
SOCID_EXTRACTOR_TIMEOUT = int(os.getenv("SOCID_EXTRACTOR_TIMEOUT_SECONDS", "16" if OSINT_PRIORITY_MODE else "10"))
TARGET_RE = re.compile(r"^[a-zA-Z0-9_.@-]{2,96}$")
URL_RE = re.compile(r"https?://[^\s,\]\)\"']+")
REGISTRY_PATH = Path(__file__).with_name("tool_registry.json")
OSINT_FRAMEWORK_PATH = Path(__file__).with_name("osint_framework_arf.json")
EVIDENCE_CAPTURE_DIR = Path(os.getenv("EVIDENCE_CAPTURE_DIR", "/evidence-assets"))
EVIDENCE_CAPTURE_MAX_TARGETS = int(os.getenv("EVIDENCE_CAPTURE_MAX_TARGETS", "6"))
ToolName = Literal["sherlock", "user-scanner", "social-analyzer"]
OSINT_FRAMEWORK_COMMIT = "a744e613d7ded0aaa854896feb2a1069de34d2f8"
BELLINGCAT_RELEASE_API = "https://api.github.com/repos/bellingcat/toolkit/releases/tags/csv"
BELLINGCAT_SCOPE_TERMS = {
    "domain": ("domain", "dns", "website", "url", "archive", "maps", "geolocation", "companies"),
    "group": ("companies", "finance", "people", "social", "websites", "archive", "data"),
    "person": ("people", "facebook", "instagram", "twitter", "tiktok", "telegram", "youtube", "multiple platforms"),
    "socmint": ("facebook", "instagram", "twitter", "tiktok", "telegram", "youtube", "social", "multiple platforms", "other platforms"),
    "darkweb": ("dark", "tor", "onion", "breach", "leak"),
    "attack_surface": ("websites", "domain", "url", "metadata", "archive", "data"),
    "brand_fraud": ("companies", "finance", "websites", "social", "archive", "reverse image", "metadata"),
    "evidence": ("archiving", "metadata", "reverse image", "image", "video", "geolocation", "maps", "satellite"),
}
OSINT_FRAMEWORK_SCOPE_TERMS = {
    "domain": ("domain", "dns", "whois", "subdomain", "certificate", "url", "ip address", "asn", "company"),
    "group": ("company", "organization", "brand", "domain", "social", "news", "threat", "breach"),
    "person": ("username", "email", "person", "name", "linkedin", "social", "profile"),
    "socmint": ("social", "instagram", "facebook", "tiktok", "twitter", "x.com", "linkedin", "telegram", "profile"),
    "darkweb": ("dark", "tor", "onion", "breach", "leak", "paste", "credential"),
    "attack_surface": ("dns", "whois", "subdomain", "certificate", "ip", "asn", "port", "technology"),
    "brand_fraud": ("brand", "fraud", "phishing", "scam", "domain", "impersonation", "social"),
}
OSINT_FRAMEWORK_HIGH_RISK_TERMS = (
    "ip logger",
    "grabify",
    "track visitor",
    "tracking link",
    "password-reset",
    "password reset",
    "credential lookup",
    "leaked credentials",
    "read receipt",
)
_OSINT_FRAMEWORK_CACHE: list[dict] | None = None
_BELLINGCAT_CACHE: dict | None = None
SOCIAL_PROFILE_HOST_HINTS = (
    "instagram.com",
    "facebook.com",
    "x.com",
    "twitter.com",
    "tiktok.com",
    "linkedin.com",
    "github.com",
    "reddit.com",
    "pinterest.com",
    "threads.net",
    "bsky.app",
    "vk.com",
    "youtube.com",
    "medium.com",
    "substack.com",
    "tumblr.com",
    "flickr.com",
    "patreon.com",
    "twitch.tv",
)

USER_SCANNER_SCRIPT = r"""
import asyncio
import json
import sys

from user_scanner.core import engine


async def main():
    target = sys.argv[1]
    output_path = sys.argv[2]
    category = sys.argv[3]
    is_email = sys.argv[4] == "email"
    results = await engine.check_category(category, target, is_email=is_email)
    rows = []
    for result in results:
        item = result.to_dict()
        status = str(item.get("status") or "").lower()
        if is_email and status != "registered":
            continue
        if not is_email and status != "found":
            continue
        if not item.get("url"):
            continue
        rows.append(item)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False)


asyncio.run(main())
"""

SOCID_EXTRACTOR_SCRIPT = r"""
import json
import sys

import socid_extractor


url = sys.argv[1]
output_path = sys.argv[2]
timeout = int(sys.argv[3])
page, status_code = socid_extractor.parse(url, timeout=timeout)
info = socid_extractor.extract(page) or {}
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump({"url": url, "status_code": status_code, "info": info}, handle, ensure_ascii=False, default=str)
"""

app = FastAPI(title="CyberDecisionEngine OSINT Tools Sidecar", version="0.1.0")


class UsernameSearchRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)
    tools: list[ToolName] = Field(default_factory=lambda: ["sherlock", "user-scanner"])
    timeout_seconds: int = Field(default=DEFAULT_TIMEOUT, ge=10, le=180)
    max_results: int = Field(default=60, ge=1, le=200)
    priority: bool = False
    proxy_url: Optional[str] = None

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in values:
            value = raw.strip().lstrip("@")
            if not TARGET_RE.match(value):
                raise ValueError(f"Unsupported OSINT target format: {raw}")
            key = value.lower()
            if key not in seen:
                seen.add(key)
                cleaned.append(value)
        return cleaned


class AccountCheckRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)
    timeout_seconds: int = Field(default=DEFAULT_TIMEOUT, ge=10, le=120)


class ProfileEnrichRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=30)
    timeout_seconds: int = Field(default=SOCID_EXTRACTOR_TIMEOUT, ge=5, le=45)

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in values:
            value = raw.strip()
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"Unsupported URL format: {raw}")
            key = value.rstrip("/").lower()
            if key not in seen:
                seen.add(key)
                cleaned.append(value)
        return cleaned


class EvidenceExploreRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=80)
    domains: list[str] = Field(default_factory=list, max_length=40)
    terms: list[str] = Field(default_factory=list, max_length=80)
    timeout_seconds: int = Field(default=8, ge=3, le=30)
    max_urls: int = Field(default=30, ge=1, le=80)

    @field_validator("urls")
    @classmethod
    def validate_evidence_urls(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in values:
            value = raw.strip()
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"Unsupported evidence URL format: {raw}")
            key = value.rstrip("/").lower()
            if key not in seen:
                seen.add(key)
                cleaned.append(value)
        return cleaned


class EvidenceCaptureTarget(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=160)
    source_id: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=8, max_length=2048)
    title: str = Field(default="", max_length=300)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Only public HTTP(S) evidence URLs can be captured.")
        return value.strip()


class EvidenceCaptureRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    targets: list[EvidenceCaptureTarget] = Field(min_length=1, max_length=EVIDENCE_CAPTURE_MAX_TARGETS)
    timeout_seconds: int = Field(default=30, ge=10, le=60)
    viewport_width: int = Field(default=1440, ge=1024, le=1920)
    viewport_height: int = Field(default=1000, ge=720, le=1400)


@app.get("/health")
async def health() -> dict:
    registry = _load_tool_registry()
    return {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools": {
            "sherlock": bool(shutil.which("sherlock")),
            "socialscan": bool(shutil.which("socialscan")),
            "user_scanner": _module_available("user_scanner"),
            "user_scanner_enabled": ENABLE_USER_SCANNER,
            "socid_extractor": _module_available("socid_extractor"),
            "socid_extractor_enabled": ENABLE_SOCID_EXTRACTOR,
            "social_analyzer": _module_available("social_analyzer") or bool(shutil.which("social-analyzer")),
            "social_analyzer_enabled": ENABLE_SOCIAL_ANALYZER,
            "reference_catalogs": len([item for item in registry if item.get("mode") == "reference"]),
            "account_enumeration_enabled": ALLOW_ACCOUNT_ENUMERATION,
            "proxy_forwarding_enabled": OSINT_ALLOW_PROXY,
            "priority_mode": OSINT_PRIORITY_MODE,
        },
    }


@app.get("/tools/catalog")
async def tools_catalog() -> dict:
    framework_summary = _osint_framework_summary()
    bellingcat_summary = await asyncio.to_thread(_bellingcat_toolkit_summary)
    return {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools": _load_tool_registry(),
        "reference_catalogs": {
            "osint_framework": framework_summary,
            "bellingcat_toolkit": bellingcat_summary,
        },
    }


@app.get("/tools/osint-framework")
async def osint_framework_catalog(
    scope: Optional[str] = Query(default=None, max_length=40),
    query: Optional[str] = Query(default=None, max_length=120),
    limit: int = Query(default=40, ge=1, le=200),
    safe_only: bool = True,
) -> dict:
    resources = _load_osint_framework_resources()
    filtered: list[dict] = []
    for item in resources:
        if safe_only and item["risk_flags"]:
            continue
        if scope and not _catalog_matches_scope(item, scope):
            continue
        if query and not _catalog_matches_query(item, query):
            continue
        filtered.append(item)
    filtered.sort(key=_catalog_sort_key)
    return {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catalog": "OSINT Framework",
        "repository": "https://github.com/lockfale/osint-framework",
        "commit": OSINT_FRAMEWORK_COMMIT,
        "mode": "reference_only",
        "execution_policy": "CyberDecisionEngine returns catalog metadata only; it does not execute listed third-party resources.",
        "filters": {"scope": scope, "query": query, "safe_only": safe_only},
        "total_matches": len(filtered),
        "returned": min(limit, len(filtered)),
        "resources": filtered[:limit],
    }


@app.get("/tools/bellingcat")
async def bellingcat_toolkit_catalog(
    scope: Optional[str] = Query(default=None, max_length=40),
    query: Optional[str] = Query(default=None, max_length=120),
    limit: int = Query(default=60, ge=1, le=250),
    free_only: bool = False,
) -> dict:
    catalog = await asyncio.to_thread(_load_bellingcat_toolkit)
    resources = catalog.get("resources") or []
    filtered: list[dict] = []
    for item in resources:
        if free_only and "free" not in str(item.get("cost") or "").lower():
            continue
        if scope and not _bellingcat_matches_scope(item, scope):
            continue
        if query and not _bellingcat_matches_query(item, query):
            continue
        filtered.append(item)
    filtered.sort(key=_bellingcat_sort_key)
    return {
        "status": "ok" if catalog.get("available") else "partial",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catalog": "Bellingcat Online Investigation Toolkit CSV",
        "repository": "https://github.com/bellingcat/toolkit",
        "release": catalog.get("release"),
        "mode": "reference_only",
        "execution_policy": "CyberDecisionEngine lists and filters toolkit entries only; third-party tools are not executed automatically.",
        "filters": {"scope": scope, "query": query, "free_only": free_only},
        "total_matches": len(filtered),
        "returned": min(limit, len(filtered)),
        "resources": filtered[:limit],
        "warning": catalog.get("warning"),
    }


@app.post("/username-search")
async def username_search(request: UsernameSearchRequest) -> dict:
    results: list[dict] = []
    warnings: list[str] = []
    requested_tools = set(request.tools)
    proxy_url = request.proxy_url if OSINT_ALLOW_PROXY else None
    if "sherlock" in requested_tools:
        semaphore = asyncio.Semaphore(2)
        target_results = await asyncio.gather(
            *[_run_sherlock_limited(semaphore, target, request.timeout_seconds, proxy_url) for target in request.targets]
        )
        for payload in target_results:
            results.extend(payload["results"])
            warnings.extend(payload["warnings"])
            if len(results) >= request.max_results:
                break
    if "user-scanner" in requested_tools and len(results) < request.max_results:
        if not ENABLE_USER_SCANNER:
            warnings.append("user-scanner is disabled by policy.")
        elif not _module_available("user_scanner"):
            warnings.append("user-scanner is not installed in the OSINT sidecar.")
        else:
            semaphore = asyncio.Semaphore(1)
            target_results = await asyncio.gather(
                *[_run_user_scanner_limited(semaphore, target, request.timeout_seconds) for target in request.targets]
            )
            for payload in target_results:
                results.extend(payload["results"])
                warnings.extend(payload["warnings"])
                if len(results) >= request.max_results:
                    break
    if "social-analyzer" in requested_tools:
        if not ENABLE_SOCIAL_ANALYZER:
            warnings.append("social-analyzer is registered but disabled by policy.")
        else:
            warnings.append("social-analyzer requires a dedicated AGPL/WebDriver runtime and is not executed in this sidecar.")
    enrich_payload = await _enrich_profile_results(results[: request.max_results], request.timeout_seconds, request.priority)
    warnings.extend(enrich_payload["warnings"])
    return {
        "status": "ok" if results and not warnings else "partial" if results else "skipped",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results[: request.max_results],
        "warnings": warnings[:8],
    }


@app.post("/profile-enrich")
async def profile_enrich(request: ProfileEnrichRequest) -> dict:
    if not ENABLE_SOCID_EXTRACTOR:
        raise HTTPException(status_code=403, detail="Profile enrichment is disabled by policy.")
    if not _module_available("socid_extractor"):
        raise HTTPException(status_code=503, detail="socid-extractor is not installed in the OSINT sidecar.")
    semaphore = asyncio.Semaphore(2)
    payloads = await asyncio.gather(
        *[_run_socid_extractor_limited(semaphore, url, request.timeout_seconds) for url in request.urls if _is_supported_profile_url(url)]
    )
    results: list[dict] = []
    warnings: list[str] = []
    for payload in payloads:
        if payload.get("result"):
            results.append(payload["result"])
        warnings.extend(payload.get("warnings") or [])
    skipped = len([url for url in request.urls if not _is_supported_profile_url(url)])
    if skipped:
        warnings.append(f"{skipped} URL(s) skipped because the host is not in the social profile allowlist.")
    return {
        "status": "ok" if results and not warnings else "partial" if results else "skipped",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "warnings": warnings[:8],
    }


@app.post("/evidence/explore")
async def evidence_explore(request: EvidenceExploreRequest) -> dict:
    selected_urls = request.urls[: request.max_urls]
    semaphore = asyncio.Semaphore(2)
    payloads = await asyncio.gather(
        *[
            _explore_evidence_url_limited(
                semaphore,
                url,
                request.domains,
                request.terms,
                request.timeout_seconds,
            )
            for url in selected_urls
        ]
    )
    results: list[dict] = []
    warnings: list[str] = []
    for payload in payloads:
        if payload.get("result"):
            results.append(payload["result"])
        warnings.extend(payload.get("warnings") or [])
    validated = len([item for item in results if float(item.get("relation_score") or 0) > 0])
    return {
        "status": "ok" if validated and not warnings else "partial" if results else "skipped",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "warnings": warnings[:12],
        "policy": "Public evidence fetch only; no login, cookies, captcha bypass, rate-limit bypass or private-source access.",
    }


@app.post("/evidence/capture")
async def evidence_capture(request: EvidenceCaptureRequest) -> dict:
    EVIDENCE_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(2)
    captures = await asyncio.gather(
        *[_capture_evidence_limited(semaphore, request, target) for target in request.targets]
    )
    captured = len([item for item in captures if item.get("validationStatus") == "verified"])
    return {
        "status": "ok" if captured == len(captures) else "partial" if captured else "failed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "captured": captured,
        "requested": len(captures),
        "captures": captures,
        "policy": "Public HTTP(S) capture only; private addresses, authentication and bypass behavior are prohibited.",
    }


async def _capture_evidence_limited(
    semaphore: asyncio.Semaphore,
    request: EvidenceCaptureRequest,
    target: EvidenceCaptureTarget,
) -> dict:
    async with semaphore:
        try:
            return await _capture_evidence(request, target)
        except Exception as exc:
            return _failed_capture(request.run_id, target, str(exc))


async def _capture_evidence(request: EvidenceCaptureRequest, target: EvidenceCaptureTarget) -> dict:
    _assert_public_url(target.url)
    preflight = await asyncio.to_thread(_capture_preflight, target.url, min(request.timeout_seconds, 20))
    final_url = str(preflight["final_url"])
    _assert_public_url(final_url)
    content_type = str(preflight.get("content_type") or "")
    if "html" not in content_type.lower():
        raise ValueError(f"unsupported_content_type:{content_type or 'unknown'}")
    response_status = int(preflight.get("status") or 0)
    if response_status >= 400:
        raise ValueError(f"http_status_{response_status}")

    safe_evidence_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", target.evidence_id)[:80]
    url_digest = hashlib.sha256(final_url.encode("utf-8")).hexdigest()[:12]
    relative_path = Path("assets") / "evidence" / request.run_id / f"{safe_evidence_id}-{url_digest}.png"
    image_path = EVIDENCE_CAPTURE_DIR / "evidence" / request.run_id / relative_path.name
    image_path.parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path("/tmp/cde-osint")
    temp_root.mkdir(parents=True, exist_ok=True)
    profile_dir = Path(tempfile.mkdtemp(prefix="cde-capture-", dir=temp_root))
    chromium = shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium:
        raise RuntimeError("chromium_unavailable")
    command = [
        chromium,
        "--headless=new",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-breakpad",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-first-run",
        "--no-proxy-server",
        f"--user-data-dir={profile_dir}",
        f"--window-size={request.viewport_width},{request.viewport_height}",
        f"--screenshot={image_path}",
        final_url,
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=request.timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.communicate()
            raise TimeoutError("capture_timeout")
        if process.returncode != 0 or not image_path.is_file():
            detail = stderr.decode("utf-8", errors="ignore")[-240:].strip()
            raise RuntimeError(f"chromium_capture_failed:{detail or process.returncode}")
    finally:
        shutil.rmtree(profile_dir, ignore_errors=True)

    image_bytes = image_path.read_bytes()
    width, height = _png_dimensions(image_bytes)
    timestamp = datetime.now(timezone.utc).isoformat()
    image_hash = hashlib.sha256(image_bytes).hexdigest()
    screenshot_id = f"SS-{hashlib.sha256(f'{request.run_id}:{target.evidence_id}:{final_url}'.encode()).hexdigest()[:16]}"
    return {
        "screenshotId": screenshot_id,
        "runId": request.run_id,
        "evidenceId": target.evidence_id,
        "sourceId": target.source_id,
        "originalPageUrl": target.url,
        "pageTitle": str(preflight.get("title") or target.title),
        "captureTimestamp": timestamp,
        "finalUrl": final_url,
        "responseStatus": response_status,
        "contentType": content_type,
        "viewport": {"width": request.viewport_width, "height": request.viewport_height},
        "fullPage": False,
        "captureType": "viewport",
        "imagePath": relative_path.as_posix(),
        "imageHash": f"sha256:{image_hash}",
        "imageFormat": "png",
        "imageSizeBytes": len(image_bytes),
        "dimensions": {"width": width, "height": height},
        "browserEngine": "chromium_isolated_sidecar",
        "browserEngineVersion": await _chromium_version(chromium),
        "validationStatus": "verified",
        "errors": [],
        "failureReason": None,
        "redactionApplied": False,
        "redactionNotes": [],
        "relatedEvidenceId": target.evidence_id,
    }


def _failed_capture(run_id: str, target: EvidenceCaptureTarget, reason: str) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "screenshotId": f"SS-{hashlib.sha256(f'{run_id}:{target.evidence_id}:failed'.encode()).hexdigest()[:16]}",
        "runId": run_id,
        "evidenceId": target.evidence_id,
        "sourceId": target.source_id,
        "originalPageUrl": target.url,
        "pageTitle": target.title,
        "captureTimestamp": timestamp,
        "finalUrl": target.url,
        "viewport": {},
        "fullPage": False,
        "captureType": "viewport",
        "validationStatus": "failed",
        "errors": [reason[:300]],
        "failureReason": reason[:300],
        "relatedEvidenceId": target.evidence_id,
    }


def _assert_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("unsupported_url")
    if parsed.username or parsed.password:
        raise ValueError("credentials_in_url_prohibited")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)}
    except socket.gaierror as exc:
        raise ValueError("dns_resolution_failed") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("private_or_reserved_address_prohibited")


def _capture_preflight(url: str, timeout_seconds: int) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "CyberDecisionEngine-EvidenceCapture/1.0"})
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        final_url = response.geturl()
        status = int(getattr(response, "status", 200))
        content_type = str(response.headers.get("Content-Type") or "")
        body = response.read(512_000).decode("utf-8", errors="ignore")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:300] if title_match else ""
    return {"final_url": final_url, "status": status, "content_type": content_type, "title": title}


def _png_dimensions(image_bytes: bytes) -> tuple[int, int]:
    if len(image_bytes) < 24 or image_bytes[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("invalid_png_capture")
    return struct.unpack(">II", image_bytes[16:24])


async def _chromium_version(binary: str) -> str:
    process = await asyncio.create_subprocess_exec(binary, "--version", stdout=asyncio.subprocess.PIPE)
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore").strip()[:120] or "unknown"


async def _run_sherlock_limited(semaphore: asyncio.Semaphore, target: str, timeout_seconds: int, proxy_url: Optional[str]) -> dict:
    async with semaphore:
        try:
            return {"results": await _run_sherlock(target, timeout_seconds, proxy_url), "warnings": []}
        except TimeoutError as exc:
            return {"results": [], "warnings": [str(exc)]}
        except Exception as exc:
            return {"results": [], "warnings": [f"sherlock {target}: {exc}"]}


async def _run_user_scanner_limited(semaphore: asyncio.Semaphore, target: str, timeout_seconds: int) -> dict:
    async with semaphore:
        try:
            return {"results": await _run_user_scanner(target, timeout_seconds), "warnings": []}
        except TimeoutError as exc:
            return {"results": [], "warnings": [str(exc)]}
        except PermissionError as exc:
            return {"results": [], "warnings": [str(exc)]}
        except Exception as exc:
            return {"results": [], "warnings": [f"user-scanner {target}: {exc}"]}


async def _run_socid_extractor_limited(semaphore: asyncio.Semaphore, url: str, timeout_seconds: int) -> dict:
    async with semaphore:
        try:
            return {"result": await _run_socid_extractor(url, timeout_seconds), "warnings": []}
        except TimeoutError as exc:
            return {"result": None, "warnings": [str(exc)]}
        except Exception as exc:
            return {"result": None, "warnings": [f"profile enrichment {url}: {exc}"]}


async def _explore_evidence_url_limited(
    semaphore: asyncio.Semaphore,
    url: str,
    domains: list[str],
    terms: list[str],
    timeout_seconds: int,
) -> dict:
    async with semaphore:
        try:
            return {"result": await asyncio.to_thread(_explore_evidence_url, url, domains, terms, timeout_seconds), "warnings": []}
        except Exception as exc:
            return {"result": None, "warnings": [f"evidence {url}: {exc}"]}


@app.post("/account-check")
async def account_check(request: AccountCheckRequest) -> dict:
    if not ALLOW_ACCOUNT_ENUMERATION:
        raise HTTPException(status_code=403, detail="Account enumeration checks are disabled by policy.")
    results: list[dict] = []
    warnings: list[str] = []
    for target in request.targets:
        try:
            results.extend(await _run_socialscan(target, request.timeout_seconds))
        except Exception as exc:
            warnings.append(f"socialscan {target}: {exc}")
    return {
        "status": "ok" if results and not warnings else "partial" if results else "skipped",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "warnings": warnings[:8],
    }


async def _run_sherlock(target: str, timeout_seconds: int, proxy_url: Optional[str]) -> list[dict]:
    temp_root = Path("/tmp/cde-osint")
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cde-sherlock-", dir=temp_root) as tmp_dir:
        cmd = [
            "sherlock",
            "--print-found",
            "--no-color",
            "--timeout",
            "8",
            "--folderoutput",
            tmp_dir,
        ]
        if proxy_url:
            cmd.extend(["--proxy", proxy_url])
        cmd.append(target)
        stdout, stderr = await _run_command(cmd, timeout_seconds)
        output_text = "\n".join([stdout, stderr])
        urls = _extract_urls(output_text)
        for text_file in Path(tmp_dir).glob("*.txt"):
            urls.extend(_extract_urls(text_file.read_text(encoding="utf-8", errors="ignore")))
        results = []
        seen = set()
        for url in urls:
            key = url.rstrip("/").lower()
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "tool": "sherlock",
                    "target": target,
                    "platform": _platform_from_url(url),
                    "url": url,
                    "confidence": 0.58,
                }
            )
        return results


async def _run_user_scanner(target: str, timeout_seconds: int) -> list[dict]:
    is_email = "@" in target
    if is_email and not ALLOW_ACCOUNT_ENUMERATION:
        raise PermissionError("Email/account enumeration checks are disabled by policy.")
    temp_root = Path("/tmp/cde-osint")
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cde-user-scanner-", dir=temp_root) as tmp_dir:
        output_path = Path(tmp_dir) / "results.json"
        cmd = [
            sys.executable,
            "-c",
            USER_SCANNER_SCRIPT,
            target,
            str(output_path),
            USER_SCANNER_CATEGORY,
            "email" if is_email else "username",
        ]
        stdout, stderr = await _run_command(cmd, timeout_seconds)
        if not output_path.exists():
            debug = "\n".join([stdout, stderr]).strip()
            raise RuntimeError(debug[:240] or "No structured user-scanner output.")
        rows = json.loads(output_path.read_text(encoding="utf-8"))
        results: list[dict] = []
        seen: set[str] = set()
        for item in rows:
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            key = url.rstrip("/").lower()
            if key in seen:
                continue
            seen.add(key)
            site_name = str(item.get("site_name") or "").strip()
            results.append(
                {
                    "tool": "user-scanner",
                    "target": target,
                    "platform": site_name or _platform_from_url(url),
                    "url": url,
                    "confidence": 0.56,
                    "category": item.get("category") or USER_SCANNER_CATEGORY,
                    "status": item.get("status") or ("Registered" if is_email else "Found"),
                }
            )
        return results


async def _enrich_profile_results(results: list[dict], timeout_seconds: int, priority: bool = False) -> dict:
    warnings: list[str] = []
    if not results or not ENABLE_SOCID_EXTRACTOR:
        return {"warnings": warnings}
    if not _module_available("socid_extractor"):
        return {"warnings": ["socid-extractor is not installed in the OSINT sidecar."]}
    candidates: list[dict] = []
    seen: set[str] = set()
    max_urls = 10 if priority or OSINT_PRIORITY_MODE else SOCID_EXTRACTOR_MAX_URLS
    for result in results:
        url = str(result.get("url") or "").strip()
        if not url or not _is_supported_profile_url(url):
            continue
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        candidates.append(result)
        if len(candidates) >= max_urls:
            break
    if not candidates:
        return {"warnings": warnings}
    semaphore = asyncio.Semaphore(2)
    payloads = await asyncio.gather(
        *[_run_socid_extractor_limited(semaphore, str(item["url"]), min(timeout_seconds, SOCID_EXTRACTOR_TIMEOUT)) for item in candidates]
    )
    metadata_by_url: dict[str, dict] = {}
    for payload in payloads:
        if payload.get("result"):
            result = payload["result"]
            metadata_by_url[str(result.get("url") or "").rstrip("/").lower()] = result
        warnings.extend(payload.get("warnings") or [])
    for result in results:
        key = str(result.get("url") or "").rstrip("/").lower()
        enriched = metadata_by_url.get(key)
        if enriched and enriched.get("metadata"):
            result["metadata"] = enriched["metadata"]
            result["confidence"] = min(0.88, float(result.get("confidence") or 0.50) + 0.08)
    return {"warnings": warnings}


async def _run_socid_extractor(url: str, timeout_seconds: int) -> dict:
    temp_root = Path("/tmp/cde-osint")
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cde-socid-", dir=temp_root) as tmp_dir:
        output_path = Path(tmp_dir) / "profile.json"
        cmd = [
            sys.executable,
            "-c",
            SOCID_EXTRACTOR_SCRIPT,
            url,
            str(output_path),
            str(max(3, min(timeout_seconds, SOCID_EXTRACTOR_TIMEOUT))),
        ]
        stdout, stderr = await _run_command(cmd, max(6, min(timeout_seconds + 3, SOCID_EXTRACTOR_TIMEOUT + 5)))
        if not output_path.exists():
            debug = "\n".join([stdout, stderr]).strip()
            raise RuntimeError(debug[:240] or "No structured profile enrichment output.")
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        return {
            "url": url,
            "status_code": payload.get("status_code"),
            "metadata": _clean_profile_metadata(payload.get("info") or {}),
        }


async def _run_socialscan(target: str, timeout_seconds: int) -> list[dict]:
    stdout, stderr = await _run_command(["socialscan", target], timeout_seconds)
    rows = []
    for line in "\n".join([stdout, stderr]).splitlines():
        clean = line.strip()
        if clean:
            rows.append({"tool": "socialscan", "target": target, "line": clean, "confidence": 0.42})
    return rows[:80]


def _explore_evidence_url(url: str, domains: list[str], terms: list[str], timeout_seconds: int) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CyberDecisionEngine Evidence Explorer/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
            "Accept-Language": "es,en;q=0.7",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(getattr(response, "status", 0) or 0)
            content_type = str(response.headers.get("content-type") or "")
            raw = response.read(512_000)
    except urllib.error.HTTPError as exc:
        status_code = int(exc.code)
        content_type = str(exc.headers.get("content-type") or "") if exc.headers else ""
        raw = exc.read(64_000)
    decoded = raw.decode(_charset_from_content_type(content_type), errors="replace")
    title, visible_text, links = _extract_visible_page(decoded, content_type)
    snippet = _truncate_text(visible_text, 900)
    relation = _evidence_relation(url, title, snippet, links, domains, terms)
    return {
        "url": url,
        "host": urlparse(url).netloc.lower().removeprefix("www."),
        "status_code": status_code,
        "content_type": content_type.split(";", 1)[0].strip().lower() or "unknown",
        "title": title or _truncate_text(url, 140),
        "snippet": snippet,
        "links": links[:12],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "relation_score": relation["score"],
        "relationship": relation["relationship"],
        "matched_terms": relation["matched_terms"],
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }


async def _run_command(cmd: list[str], timeout_seconds: int) -> tuple[str, str]:
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"{cmd[0]} timed out after {timeout_seconds}s") from exc
    return stdout.decode("utf-8", errors="ignore"), stderr.decode("utf-8", errors="ignore")


def _extract_urls(text: str) -> list[str]:
    return [item.rstrip(".,;") for item in URL_RE.findall(text)]


def _platform_from_url(url: str) -> str:
    host = re.sub(r"^www\.", "", re.sub(r"^https?://", "", url).split("/", 1)[0].lower())
    return host or "unknown"


def _is_supported_profile_url(url: str) -> bool:
    host = urlparse(url).netloc.lower().removeprefix("www.")
    return any(host == hint or host.endswith(f".{hint}") for hint in SOCIAL_PROFILE_HOST_HINTS)


def _clean_profile_metadata(info: dict) -> dict:
    allowed_prefixes = (
        "username",
        "fullname",
        "display",
        "bio",
        "avatar",
        "location",
        "created",
        "joined",
        "followers",
        "following",
        "posts",
        "links",
        "website",
        "is_verified",
        "verified",
        "id",
    )
    cleaned: dict[str, object] = {}
    for key, value in (info or {}).items():
        normalized_key = str(key).strip().lower()
        if normalized_key.startswith("_"):
            continue
        if not any(token in normalized_key for token in allowed_prefixes):
            continue
        if isinstance(value, (list, tuple)):
            cleaned[normalized_key] = [str(item)[:240] for item in value[:8]]
        elif isinstance(value, dict):
            cleaned[normalized_key] = {str(k)[:80]: str(v)[:240] for k, v in list(value.items())[:8]}
        else:
            text = str(value).strip()
            if text:
                cleaned[normalized_key] = text[:320]
        if len(cleaned) >= 14:
            break
    return cleaned


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _load_tool_registry() -> list[dict]:
    try:
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def _osint_framework_summary() -> dict:
    resources = _load_osint_framework_resources()
    return {
        "available": bool(resources),
        "commit": OSINT_FRAMEWORK_COMMIT,
        "resources": len(resources),
        "safe_default_resources": len([item for item in resources if not item["risk_flags"]]),
        "google_dorks": len([item for item in resources if item.get("google_dork")]),
        "api_resources": len([item for item in resources if item.get("api")]),
        "passive_resources": len([item for item in resources if str(item.get("opsec") or "").lower() == "passive"]),
    }


def _bellingcat_toolkit_summary() -> dict:
    catalog = _load_bellingcat_toolkit()
    resources = catalog.get("resources") or []
    categories = sorted({str(item.get("category") or "") for item in resources if item.get("category")})
    return {
        "available": bool(catalog.get("available")),
        "release": catalog.get("release"),
        "resources": len(resources),
        "categories": len(categories),
        "free_resources": len([item for item in resources if "free" in str(item.get("cost") or "").lower()]),
        "reference_only": True,
        "warning": catalog.get("warning"),
    }


def _load_bellingcat_toolkit() -> dict:
    global _BELLINGCAT_CACHE
    if _BELLINGCAT_CACHE is not None:
        return _BELLINGCAT_CACHE
    try:
        release_request = urllib.request.Request(
            BELLINGCAT_RELEASE_API,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "CyberDecisionEngine/1.0"},
        )
        with urllib.request.urlopen(release_request, timeout=12) as response:
            release = json.loads(response.read().decode("utf-8"))
        asset = next((item for item in release.get("assets") or [] if item.get("name") == "all-tools.csv"), None)
        if not asset:
            raise RuntimeError("Bellingcat all-tools.csv asset was not found.")
        csv_request = urllib.request.Request(
            str(asset.get("browser_download_url") or ""),
            headers={"User-Agent": "CyberDecisionEngine/1.0"},
        )
        with urllib.request.urlopen(csv_request, timeout=16) as response:
            raw_csv = response.read().decode("utf-8-sig", errors="replace")
        rows = list(csv.DictReader(io.StringIO(raw_csv)))
        resources = [_normalize_bellingcat_row(row) for row in rows if row.get("Name") and row.get("URL")]
        _BELLINGCAT_CACHE = {
            "available": True,
            "release": {
                "tag": release.get("tag_name"),
                "name": release.get("name"),
                "published_at": release.get("published_at"),
                "asset_count": len(release.get("assets") or []),
                "all_tools_updated_at": asset.get("updated_at"),
            },
            "resources": resources,
            "warning": None,
        }
    except Exception as exc:
        _BELLINGCAT_CACHE = {
            "available": False,
            "release": {"tag": "csv", "name": "Bellingcat Online Investigation Toolkit CSV"},
            "resources": [],
            "warning": f"Bellingcat toolkit catalog unavailable: {exc}",
        }
    return _BELLINGCAT_CACHE


def _normalize_bellingcat_row(row: dict) -> dict:
    category = str(row.get("Category") or "").strip()
    name = str(row.get("Name") or "").strip()
    url = str(row.get("URL") or "").strip()
    description = _truncate_text(row.get("Description"), 360)
    cost = str(row.get("Cost") or "unknown").strip() or "unknown"
    details = str(row.get("Details") or "").strip()
    haystack = " ".join([category, name, url, description, cost, details]).lower()
    scopes = sorted(scope for scope, terms in BELLINGCAT_SCOPE_TERMS.items() if any(term in haystack for term in terms))
    return {
        "name": name,
        "url": url,
        "category": category,
        "description": description,
        "cost": cost,
        "details_url": details,
        "scopes": scopes,
        "mode": "reference",
        "runtime_allowed": False,
        "reason": "catalog_reference_only",
    }


def _bellingcat_matches_scope(item: dict, scope: str) -> bool:
    normalized = scope.strip().lower()
    if normalized in {str(value).lower() for value in item.get("scopes") or []}:
        return True
    terms = BELLINGCAT_SCOPE_TERMS.get(normalized, (normalized,))
    haystack = _bellingcat_haystack(item)
    return any(term in haystack for term in terms)


def _bellingcat_matches_query(item: dict, query: str) -> bool:
    terms = [term for term in re.split(r"[^a-z0-9_.-]+", query.lower()) if len(term) >= 2]
    haystack = _bellingcat_haystack(item)
    return all(term in haystack for term in terms)


def _bellingcat_haystack(item: dict) -> str:
    return " ".join(
        [
            str(item.get("name") or ""),
            str(item.get("url") or ""),
            str(item.get("category") or ""),
            str(item.get("description") or ""),
            str(item.get("cost") or ""),
            " ".join(item.get("scopes") or []),
        ]
    ).lower()


def _bellingcat_sort_key(item: dict) -> tuple[int, str, str]:
    cost_rank = 0 if "free" in str(item.get("cost") or "").lower() else 1
    return (cost_rank, str(item.get("category") or ""), str(item.get("name") or ""))


def _load_osint_framework_resources() -> list[dict]:
    global _OSINT_FRAMEWORK_CACHE
    if _OSINT_FRAMEWORK_CACHE is not None:
        return _OSINT_FRAMEWORK_CACHE
    try:
        payload = json.loads(OSINT_FRAMEWORK_PATH.read_text(encoding="utf-8"))
    except Exception:
        _OSINT_FRAMEWORK_CACHE = []
        return _OSINT_FRAMEWORK_CACHE
    resources: list[dict] = []
    _flatten_osint_framework(payload.get("children") or [], (), resources)
    _OSINT_FRAMEWORK_CACHE = resources
    return resources


def _flatten_osint_framework(nodes: list[dict], path: tuple[str, ...], output: list[dict]) -> None:
    for node in nodes:
        name = str(node.get("name") or "").strip()
        if not name:
            continue
        node_type = str(node.get("type") or "").strip().lower()
        next_path = (*path, name)
        if node_type == "url" and node.get("url"):
            output.append(_normalize_catalog_entry(node, path))
        children = node.get("children")
        if isinstance(children, list):
            _flatten_osint_framework(children, next_path, output)


def _normalize_catalog_entry(item: dict, path: tuple[str, ...]) -> dict:
    text = " ".join(
        str(item.get(field) or "")
        for field in ("name", "description", "bestFor", "input", "output", "opsecNote", "url")
    ).lower()
    risk_flags = [term for term in OSINT_FRAMEWORK_HIGH_RISK_TERMS if term in text]
    if str(item.get("opsec") or "").lower() == "unknown":
        risk_flags.append("unknown_opsec")
    runtime_allowed = (
        str(item.get("opsec") or "").lower() == "passive"
        and not bool(item.get("localInstall"))
        and not bool(item.get("invitationOnly"))
        and not risk_flags
    )
    return {
        "name": str(item.get("name") or "").strip(),
        "url": str(item.get("url") or "").strip(),
        "category_path": list(path),
        "description": _truncate_text(item.get("description"), 360),
        "best_for": _truncate_text(item.get("bestFor"), 220),
        "input": _truncate_text(item.get("input"), 160),
        "output": _truncate_text(item.get("output"), 220),
        "opsec": str(item.get("opsec") or "unknown"),
        "opsec_note": _truncate_text(item.get("opsecNote"), 280),
        "status": str(item.get("status") or "unknown"),
        "pricing": str(item.get("pricing") or "unknown"),
        "local_install": bool(item.get("localInstall")),
        "google_dork": bool(item.get("googleDork")),
        "registration": bool(item.get("registration")),
        "edit_url": bool(item.get("editUrl")),
        "api": bool(item.get("api")),
        "runtime_allowed": runtime_allowed,
        "risk_flags": sorted(set(risk_flags)),
    }


def _catalog_matches_scope(item: dict, scope: str) -> bool:
    normalized = scope.strip().lower()
    terms = OSINT_FRAMEWORK_SCOPE_TERMS.get(normalized, (normalized,))
    haystack = _catalog_haystack(item)
    return any(term in haystack for term in terms)


def _catalog_matches_query(item: dict, query: str) -> bool:
    terms = [term for term in re.split(r"[^a-z0-9_.-]+", query.lower()) if len(term) >= 2]
    haystack = _catalog_haystack(item)
    return all(term in haystack for term in terms)


def _catalog_haystack(item: dict) -> str:
    return " ".join(
        [
            str(item.get("name") or ""),
            str(item.get("description") or ""),
            str(item.get("best_for") or ""),
            str(item.get("input") or ""),
            str(item.get("output") or ""),
            str(item.get("opsec_note") or ""),
            " ".join(item.get("category_path") or []),
        ]
    ).lower()


def _catalog_sort_key(item: dict) -> tuple[int, int, int, str]:
    status_rank = 0 if str(item.get("status") or "").lower() == "live" else 1
    runtime_rank = 0 if item.get("runtime_allowed") else 1
    opsec_rank = 0 if str(item.get("opsec") or "").lower() == "passive" else 1
    return (status_rank, runtime_rank, opsec_rank, str(item.get("name") or "").lower())


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._hidden_depth = 0
        self._in_title = False
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "template", "svg"}:
            self._hidden_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "a":
            href = dict(attrs).get("href")
            if href and href.startswith(("http://", "https://")):
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "template", "svg"} and self._hidden_depth:
            self._hidden_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        text = re.sub(r"\s+", " ", data).strip()
        if not text:
            return
        if self._in_title:
            self.title_parts.append(text)
            return
        if not self._hidden_depth:
            self.text_parts.append(text)


def _extract_visible_page(raw: str, content_type: str) -> tuple[str, str, list[str]]:
    if "html" not in content_type.lower():
        text = re.sub(r"\s+", " ", raw).strip()
        return "", text, _extract_urls(raw)[:20]
    parser = _VisibleTextParser()
    parser.feed(raw)
    title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()
    visible = re.sub(r"\s+", " ", " ".join(parser.text_parts)).strip()
    links: list[str] = []
    seen: set[str] = set()
    for link in parser.links:
        key = link.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        links.append(link)
        if len(links) >= 20:
            break
    return title, visible, links


def _charset_from_content_type(content_type: str) -> str:
    match = re.search(r"charset=([a-zA-Z0-9_.-]+)", content_type or "")
    return match.group(1) if match else "utf-8"


def _evidence_relation(url: str, title: str, snippet: str, links: list[str], domains: list[str], terms: list[str]) -> dict:
    host = urlparse(url).netloc.lower().removeprefix("www.")
    haystack = " ".join([url, host, title, snippet, " ".join(links[:8])]).lower()
    normalized_domains = [item.strip().lower().removeprefix("www.") for item in domains if item.strip()]
    normalized_terms = [item.strip().lower() for item in terms if len(item.strip()) >= 4]
    score = 0.0
    matched: list[str] = []
    for domain in normalized_domains:
        if domain and (domain in host or domain in url.lower()):
            score += 0.52
            matched.append(domain)
        elif domain and domain in haystack:
            score += 0.34
            matched.append(domain)
    compact_haystack = re.sub(r"[^a-z0-9]+", "", haystack)
    for term in normalized_terms:
        if term in haystack:
            score += 0.12
            matched.append(term)
        compact = re.sub(r"[^a-z0-9]+", "", term)
        if compact and compact in compact_haystack:
            score += 0.08
            matched.append(compact)
    score = round(min(1.0, score), 3)
    if score >= 0.5:
        relationship = "direct_domain_or_brand_match"
    elif score > 0:
        relationship = "contextual_text_match"
    else:
        relationship = "unrelated_or_unconfirmed"
    return {"score": score, "relationship": relationship, "matched_terms": sorted(set(matched))[:12]}


def _truncate_text(value: object, limit: int) -> str:
    text = str(value or "").strip()
    return text[:limit]
