from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, List

import httpx

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus, ThreatEvent


class KaliSurfaceCollector(Collector):
    name = "Superficie externa"

    def __init__(
        self,
        domains: Iterable[str],
        endpoint: str = "http://kali-surface:7010",
        enabled: bool = True,
        mode: str = "light",
        max_records: int = 120,
        max_hosts: int = 40,
        timeout_seconds: float = 120.0,
    ):
        self.domains = [item for item in domains if item]
        self.endpoint = endpoint.rstrip("/")
        self.enabled = enabled
        self.mode = mode if mode in {"passive", "light"} else "passive"
        self.max_records = max(1, int(max_records))
        self.max_hosts = max(1, int(max_hosts))
        self.timeout_seconds = max(20.0, float(timeout_seconds))

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(SourceStatus(name=self.name, status="disabled", records=0, mode="real"))
        if not self.domains:
            return CollectionResult(SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning="No domains configured."), [])
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                health = await client.get(f"{self.endpoint}/health")
                health.raise_for_status()
                payload = {"domains": [], "warnings": []}
                for batch in _chunks(self.domains, 12):
                    try:
                        response = await client.post(
                            f"{self.endpoint}/surface-scan",
                            json={
                                "domains": batch,
                                "mode": self.mode,
                                "max_hosts": self.max_hosts,
                                "timeout_seconds": min(300, int(self.timeout_seconds)),
                                "light_probe": self.mode == "light",
                            },
                        )
                        response.raise_for_status()
                        batch_payload = response.json()
                        payload["domains"].extend(batch_payload.get("domains") or [])
                        payload["warnings"].extend(batch_payload.get("warnings") or [])
                    except Exception as exc:  # pragma: no cover - sidecar/network dependent
                        payload["warnings"].append(f"{', '.join(batch)}: {exc}")
        except Exception as exc:  # pragma: no cover - sidecar/network dependent
            return CollectionResult(
                SourceStatus(name=self.name, status="skipped", records=0, mode="real", warning=f"Colector de superficie no disponible: {exc}"),
                [],
            )
        events = _events_from_payload(payload, self.max_records)
        warnings = payload.get("warnings") or []
        status = "ok" if events and not warnings else "partial" if events else "skipped"
        return CollectionResult(
            SourceStatus(name=self.name, status=status, records=len(events), mode="real", warning="; ".join(warnings[:6]) or None),
            events,
        )


def _chunks(values: List[str], size: int) -> Iterable[List[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _events_from_payload(payload: dict[str, Any], limit: int) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    seen: set[str] = set()
    for domain_item in payload.get("domains") or []:
        domain = str(domain_item.get("domain") or "").strip()
        for finding in domain_item.get("findings") or []:
            _append_event(events, seen, _event_from_finding(domain, finding), limit)
        for asset in domain_item.get("web_assets") or []:
            _append_event(events, seen, _event_from_web_asset(domain, asset), limit)
        for host in domain_item.get("subdomains") or []:
            if str(host).strip() and str(host).strip() != domain:
                _append_event(events, seen, _event_from_subdomain(domain, str(host).strip()), limit)
    return events[:limit]


def _append_event(events: List[ThreatEvent], seen: set[str], event: ThreatEvent, limit: int) -> None:
    if len(events) >= limit:
        return
    key = f"{event.category}|{event.title}|{event.evidence_url or ''}".lower()
    if key in seen:
        return
    seen.add(key)
    events.append(event)


def _event_from_finding(domain: str, finding: dict[str, Any]) -> ThreatEvent:
    severity = _severity_value(str(finding.get("severity") or "info"))
    title = str(finding.get("title") or "Hallazgo de superficie de ataque")
    asset = str(finding.get("asset") or domain)
    finding_type = str(finding.get("type") or "attack_surface")
    validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
    validation_result = str(validation.get("validation_result") or "requires_owner_validation")
    evidence_url = None if finding_type == "email_security" else f"https://{asset}" if "." in asset else None
    return ThreatEvent(
        id=f"KALI-SURFACE-{abs(hash((domain, title, asset))) % 10_000_000}",
        title=f"{domain}: {title}",
        category="attack_surface",
        source="Superficie externa",
        source_weight=0.70,
        confidence=0.68 if finding_type != "subdomain" else 0.55,
        age_days=0,
        severity=severity,
        epss=0.02,
        cvss=0.0,
        actor="external_exposure",
        technique=_technique_for_finding(finding_type),
        tags=["external_surface", finding_type, "technical_query", f"domain:{domain}", f"asset:{asset}"],
        evidence_url=evidence_url,
        observed_at=datetime.now(timezone.utc).isoformat(),
        demo=False,
        asset=asset,
        host=asset.removeprefix("_dmarc."),
        validation_result=validation_result,
        technical_validation=validation,
        attack_mapping_status="preventive_reference",
    )


def _event_from_web_asset(domain: str, asset: dict[str, Any]) -> ThreatEvent:
    url = str(asset.get("url") or "").strip()
    host = str(asset.get("host") or domain).strip()
    status_code = asset.get("status_code")
    tech = ", ".join([str(item) for item in asset.get("technologies") or []][:5])
    title = f"{domain}: servicio web observado en {host}"
    if status_code:
        title += f" ({status_code})"
    if tech:
        title += f" - {tech}"
    return ThreatEvent(
        id=f"KALI-WEB-{abs(hash((domain, url, host))) % 10_000_000}",
        title=title,
        category="attack_surface_web",
        source="Superficie web externa",
        source_weight=0.72,
        confidence=0.70,
        age_days=0,
        severity=0.48,
        epss=0.02,
        cvss=0.0,
        actor="external_exposure",
        technique="T1595",
        tags=["external_surface", "web_asset", f"domain:{domain}", f"host:{host}", f"status:{status_code or 'unknown'}"],
        evidence_url=url if url.startswith("http") else None,
        observed_at=datetime.now(timezone.utc).isoformat(),
        demo=False,
    )


def _event_from_subdomain(domain: str, host: str) -> ThreatEvent:
    labels = host.split(".")
    sensitive_name = any(label in {"admin", "adm", "vpn", "portal", "login", "test", "dev", "stage", "staging"} for label in labels)
    title = f"{domain}: subdominio observado {host}"
    tags = ["external_surface", "subdomain", "dns_inventory_only", f"domain:{domain}", f"host:{host}"]
    if sensitive_name:
        title += " (nombre sensible; validar si expone servicio)"
        tags.extend(["validation_required", "administrative_name"])
    return ThreatEvent(
        id=f"KALI-SUBDOMAIN-{abs(hash((domain, host))) % 10_000_000}",
        title=title,
        category="attack_surface_dns",
        source="Inventario DNS externo",
        source_weight=0.66,
        confidence=0.60,
        age_days=0,
        severity=0.42 if sensitive_name else 0.32,
        epss=0.01,
        cvss=0.0,
        actor="external_exposure",
        technique="T1590",
        tags=tags,
        evidence_url=None,
        observed_at=datetime.now(timezone.utc).isoformat(),
        demo=False,
    )


def _severity_value(label: str) -> float:
    return {
        "critical": 0.90,
        "high": 0.78,
        "medium": 0.58,
        "low": 0.40,
        "info": 0.28,
    }.get(label.lower(), 0.42)


def _technique_for_finding(finding_type: str) -> str:
    if finding_type == "email_security":
        return "T1589"
    if finding_type == "tls":
        return "T1595"
    if finding_type == "subdomain":
        return "T1590"
    return "T1592"
