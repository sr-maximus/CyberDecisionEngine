from __future__ import annotations

import asyncio
import os
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx


async def build_attack_surface(domains: List[str], competitor_domains: List[str] | None = None) -> Dict[str, Any]:
    competitor_domains = competitor_domains or []
    owned = [(domain, "own") for domain in domains]
    competitors = [(domain, "competitor") for domain in competitor_domains]
    rows = await asyncio.gather(*[_safe_domain_surface(domain, scope) for domain, scope in [*owned, *competitors]])
    kali_surface = await _kali_surface_lookup([domain for domain, _scope in [*owned, *competitors]])
    kali_by_domain = {item.get("domain"): item for item in kali_surface.get("domains", []) if item.get("domain")}
    for row in rows:
        row["tool_surface"] = kali_by_domain.get(
            row["domain"],
            {
                "status": kali_surface.get("status", "skipped"),
                "subdomains": [],
                "web_assets": [],
                "findings": [],
                "tool_runs": [],
                "warning": kali_surface.get("warning"),
            },
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domains": rows,
        "summary": _summary(rows, kali_surface),
    }


async def _safe_domain_surface(domain: str, scope: str) -> Dict[str, Any]:
    try:
        return await asyncio.wait_for(_domain_surface(domain, scope), timeout=float(os.getenv("ATTACK_SURFACE_DOMAIN_TIMEOUT_SECONDS", "14")))
    except Exception as exc:
        return {
            "domain": domain,
            "scope": scope,
            "risk_score": 0,
            "dns": {"status": "error", "addresses": [], "error": f"Passive DNS/TLS/RDAP timeout: {exc}"},
            "certificate": {"status": "error", "error": f"Passive DNS/TLS/RDAP timeout: {exc}", "days_remaining": None},
            "rdap": {"status": "error", "error": f"Passive DNS/TLS/RDAP timeout: {exc}", "events": [], "nameservers": []},
        }


async def _domain_surface(domain: str, scope: str) -> Dict[str, Any]:
    dns_task = asyncio.to_thread(_dns_lookup, domain)
    cert_task = asyncio.to_thread(_certificate_lookup, domain)
    rdap_task = _rdap_lookup(domain)
    dns, certificate, rdap = await asyncio.gather(dns_task, cert_task, rdap_task)
    risk_score = _risk_score(dns, certificate, rdap)
    return {
        "domain": domain,
        "scope": scope,
        "risk_score": risk_score,
        "dns": dns,
        "certificate": certificate,
        "rdap": rdap,
    }


def _dns_lookup(domain: str) -> Dict[str, Any]:
    try:
        records = sorted({item[4][0] for item in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)})
        return {"status": "ok", "addresses": records}
    except Exception as exc:
        return {"status": "error", "addresses": [], "error": str(exc)}


def _certificate_lookup(domain: str) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
        not_after = cert.get("notAfter")
        expires_at = _parse_cert_date(not_after)
        days_remaining = None
        if expires_at:
            days_remaining = max(0, (expires_at - datetime.now(timezone.utc)).days)
        issuer = _flatten_name(cert.get("issuer", ()))
        subject = _flatten_name(cert.get("subject", ()))
        return {
            "status": "ok",
            "issuer": issuer,
            "subject": subject,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "days_remaining": days_remaining,
            "san_count": len(cert.get("subjectAltName", [])),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "days_remaining": None}


async def _rdap_lookup(domain: str) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True, headers={"User-Agent": "CyberDecisionEngine/0.1"}) as client:
            response = await client.get(f"https://rdap.org/domain/{domain}")
            response.raise_for_status()
            payload = response.json()
        return {
            "status": "ok",
            "handle": payload.get("handle"),
            "registrar": _registrar(payload),
            "events": payload.get("events", [])[:8],
            "nameservers": [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")][:8],
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "events": [], "nameservers": []}


def _parse_cert_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _flatten_name(parts: Any) -> str:
    values = []
    for group in parts or []:
        for key, value in group:
            if key in {"commonName", "organizationName", "countryName"}:
                values.append(str(value))
    return " / ".join(values[:4])


def _registrar(payload: Dict[str, Any]) -> str | None:
    for entity in payload.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            name = entity.get("vcardArray", [None, []])[1]
            for item in name:
                if item and item[0] == "fn":
                    return item[3]
    return None


def _risk_score(dns: Dict[str, Any], certificate: Dict[str, Any], rdap: Dict[str, Any]) -> int:
    score = 0
    if dns.get("status") != "ok":
        score += 25
    if certificate.get("status") != "ok":
        score += 35
    elif certificate.get("days_remaining") is not None and certificate["days_remaining"] < 30:
        score += 28
    if rdap.get("status") != "ok":
        score += 12
    return min(100, score)


async def _kali_surface_lookup(domains: List[str]) -> Dict[str, Any]:
    endpoint = os.getenv("KALI_SURFACE_URL", "http://kali-surface:7010").rstrip("/")
    if not domains:
        return {"status": "skipped", "domains": []}
    try:
        client_timeout = min(float(os.getenv("ATTACK_SURFACE_TOOL_TIMEOUT_SECONDS", "28")), 45.0)
        async with httpx.AsyncClient(timeout=client_timeout) as client:
            health = await client.get(f"{endpoint}/health")
            health.raise_for_status()
            payload: Dict[str, Any] = {"status": "ok", "domains": [], "warnings": []}
            for batch in _chunks(domains, 12):
                response = await client.post(
                    f"{endpoint}/surface-scan",
                    json={
                        "domains": batch,
                        "mode": os.getenv("KALI_SURFACE_MODE", "light"),
                        "max_hosts": int(os.getenv("KALI_SURFACE_MAX_HOSTS", "24")),
                        "timeout_seconds": int(os.getenv("KALI_SURFACE_TIMEOUT_SECONDS", "22")),
                        "light_probe": os.getenv("KALI_SURFACE_LIGHT_PROBE", "true").lower() == "true",
                    },
                )
                response.raise_for_status()
                batch_payload = response.json()
                payload["domains"].extend(batch_payload.get("domains") or [])
                payload["warnings"].extend(batch_payload.get("warnings") or [])
            return payload
    except Exception as exc:
        return {"status": "skipped", "domains": [], "warning": f"Kali sidecar unavailable or timed out; passive DNS/TLS/RDAP was still returned. Detail: {exc}"}


def _chunks(values: List[str], size: int) -> List[List[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _summary(rows: List[Dict[str, Any]], kali_surface: Dict[str, Any] | None = None) -> Dict[str, Any]:
    own = [row for row in rows if row["scope"] == "own"]
    competitors = [row for row in rows if row["scope"] == "competitor"]
    tool_domains = kali_surface.get("domains", []) if kali_surface else []
    tool_findings = sum(len([finding for finding in item.get("findings", []) if finding.get("severity") != "info"]) for item in tool_domains)
    tool_subdomains = sum(len(item.get("subdomains", [])) for item in tool_domains)
    tool_web_assets = sum(len(item.get("web_assets", [])) for item in tool_domains)
    return {
        "own_count": len(own),
        "competitor_count": len(competitors),
        "own_avg_risk": round(sum(row["risk_score"] for row in own) / max(1, len(own)), 1),
        "competitor_avg_risk": round(sum(row["risk_score"] for row in competitors) / max(1, len(competitors)), 1),
        "cert_errors": len([row for row in rows if row["certificate"].get("status") != "ok"]),
        "rdap_errors": len([row for row in rows if row["rdap"].get("status") != "ok"]),
        "tool_surface_status": (kali_surface or {}).get("status", "skipped"),
        "tool_surface_warning": (kali_surface or {}).get("warning"),
        "tool_findings": tool_findings,
        "tool_subdomains": tool_subdomains,
        "tool_web_assets": tool_web_assets,
    }
