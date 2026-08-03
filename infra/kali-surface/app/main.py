from __future__ import annotations

import asyncio
from contextlib import suppress
import hashlib
import json
import os
import re
import signal
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

app = FastAPI(title="CyberDecisionEngine Kali Surface Sidecar", version="0.1.0")


class SurfaceRequest(BaseModel):
    domains: list[str] = Field(default_factory=list, max_length=50)
    mode: str = "passive"
    max_hosts: int = Field(default=40, ge=1, le=120)
    timeout_seconds: int = Field(default=22, ge=5, le=300)
    light_probe: bool = True
    web_crawl: bool = True
    crawl_depth: int = Field(default=1, ge=1, le=3)
    crawl_concurrency: int = Field(default=4, ge=1, le=12)

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        for raw in values:
            domain = raw.strip().lower().removeprefix("www.")
            if not DOMAIN_RE.match(domain):
                raise ValueError(f"Invalid domain: {raw}")
            if domain not in seen:
                seen.add(domain)
                output.append(domain)
        if not output:
            raise ValueError("At least one domain is required.")
        return output


class ExploitSearchRequest(BaseModel):
    cves: list[str] = Field(default_factory=list, max_length=40)
    max_records: int = Field(default=40, ge=1, le=100)
    timeout_seconds: int = Field(default=30, ge=5, le=90)

    @field_validator("cves")
    @classmethod
    def validate_cves(cls, values: list[str]) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        for raw in values:
            value = raw.strip().upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", value):
                raise ValueError(f"Invalid CVE identifier: {raw}")
            if value not in seen:
                seen.add(value)
                output.append(value)
        if not output:
            raise ValueError("At least one CVE identifier is required.")
        return output


@dataclass
class CommandResult:
    tool: str
    status: str
    records: int = 0
    warning: str | None = None


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "tools": {name: _tool_path(name) is not None for name in _tool_names()},
        "light_probe_enabled": _allow_light_probe(),
        "nuclei_enabled": _allow_nuclei(),
    }


@app.post("/exploit-search")
async def exploit_search(request: ExploitSearchRequest) -> dict[str, Any]:
    binary = _tool_path("searchsploit")
    if not binary:
        return {
            "status": "unavailable",
            "results": [],
            "warnings": ["searchsploit is not installed"],
        }

    results: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for cve in request.cves:
        completed = await _run(
            [binary, "--cve", cve, "--json"],
            request.timeout_seconds,
        )
        if completed.get("timeout"):
            warnings.append(f"{cve}: search timeout")
            continue
        payload = _parse_searchsploit_json(completed.get("stdout") or "")
        for item in payload:
            edb_id = str(item.get("EDB-ID") or item.get("edb_id") or "").strip()
            key = (cve, edb_id or str(item.get("Title") or ""))
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "cve": cve,
                    "edb_id": edb_id,
                    "title": str(item.get("Title") or item.get("title") or "Public exploit reference"),
                    "date": item.get("Date") or item.get("date"),
                    "author": item.get("Author") or item.get("author"),
                    "type": item.get("Type") or item.get("type"),
                    "platform": item.get("Platform") or item.get("platform"),
                    "url": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else "https://www.exploit-db.com/",
                }
            )
            if len(results) >= request.max_records:
                break
        if len(results) >= request.max_records:
            break
    return {
        "status": "ok",
        "results": results,
        "warnings": warnings,
        "interpretation": "Public exploit references only; no asset applicability or exploitation is asserted.",
    }


@app.post("/surface-scan")
async def surface_scan(request: SurfaceRequest) -> dict[str, Any]:
    light_probe = request.light_probe and request.mode != "passive" and _allow_light_probe()
    web_crawl = request.web_crawl and request.mode != "passive" and _allow_web_crawl()
    semaphore = asyncio.Semaphore(_domain_concurrency())

    async def scan(domain: str) -> dict[str, Any]:
        async with semaphore:
            return await _safe_scan_domain(
                domain,
                request.max_hosts,
                request.timeout_seconds,
                light_probe,
                web_crawl,
                request.mode,
                request.crawl_depth,
                request.crawl_concurrency,
            )

    domains = await asyncio.gather(*(scan(domain) for domain in request.domains))
    warnings = [warning for result in domains for warning in result.get("warnings", [])]
    return {
        "status": "ok",
        "mode": request.mode,
        "domains": domains,
        "warnings": warnings[:20],
    }


async def _safe_scan_domain(
    domain: str,
    max_hosts: int,
    timeout_seconds: int,
    light_probe: bool,
    web_crawl: bool,
    mode: str,
    crawl_depth: int,
    crawl_concurrency: int,
) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(
            _scan_domain(
                domain,
                max_hosts,
                timeout_seconds,
                light_probe,
                web_crawl,
                mode,
                crawl_depth,
                crawl_concurrency,
            ),
            timeout=max(12, timeout_seconds + 10),
        )
    except Exception as exc:
        return {
            "domain": domain,
            "subdomains": [domain],
            "dns_records": [],
            "web_assets": [],
            "findings": [],
            "tool_runs": [{"tool": "kali-surface", "status": "timeout", "records": 0, "warning": str(exc)}],
            "warnings": [f"{domain}: passive sidecar timed out; base DNS/TLS/RDAP remains available in API response."],
        }


async def _scan_domain(
    domain: str,
    max_hosts: int,
    timeout_seconds: int,
    light_probe: bool,
    web_crawl: bool,
    mode: str,
    crawl_depth: int,
    crawl_concurrency: int,
) -> dict[str, Any]:
    tool_runs: list[CommandResult] = []
    warnings: list[str] = []
    subdomains: set[str] = {domain}
    dns_records: list[dict[str, str]] = []
    web_assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    subfinder_result, amass_result, dns_result, mail_result = await asyncio.gather(
        _run_subfinder(domain, timeout_seconds),
        _run_amass(domain, timeout_seconds),
        _run_dnsrecon(domain, timeout_seconds),
        _mail_findings(domain, timeout_seconds),
    )

    subfinder_hosts, run = subfinder_result
    tool_runs.append(run)
    subdomains.update(subfinder_hosts)

    amass_hosts, run = amass_result
    tool_runs.append(run)
    subdomains.update(amass_hosts)

    dns_items, run = dns_result
    tool_runs.append(run)
    dns_records.extend(dns_items)
    for item in dns_items:
        name = item.get("name") or item.get("target")
        if name and name.endswith(domain):
            subdomains.add(name.lower().rstrip("."))

    mail_findings, mail_runs = mail_result
    tool_runs.extend(mail_runs)
    findings.extend(mail_findings)
    warnings.append(
        f"{domain}: DKIM no evaluado; sin selectores declarados no es técnicamente válido afirmar ausencia del registro."
    )

    selected_hosts = sorted(subdomains)[:max_hosts]
    if light_probe:
        httpx_result, whatweb_result, waf_result, tls_result = await asyncio.gather(
            _run_httpx(selected_hosts, timeout_seconds),
            _run_whatweb(domain, timeout_seconds),
            _run_wafw00f(domain, timeout_seconds),
            _run_sslscan(domain, timeout_seconds),
        )

        web_assets, run = httpx_result
        tool_runs.append(run)
        whatweb_items, run = whatweb_result
        tool_runs.append(run)
        web_assets.extend(whatweb_items)
        waf_items, run = waf_result
        tool_runs.append(run)
        findings.extend(waf_items)
        tls_items, run = tls_result
        tool_runs.append(run)
        findings.extend(tls_items)
        if web_crawl:
            crawl_urls = [
                str(item.get("url") or "").strip()
                for item in web_assets
                if str(item.get("url") or "").startswith(("http://", "https://"))
            ]
            if not crawl_urls:
                crawl_urls = [f"https://{domain}"]
            crawl_assets, crawl_findings, run = await _run_cariddi(
                crawl_urls,
                mode=mode,
                timeout_seconds=max(15, min(60, timeout_seconds // 2)),
                max_depth=crawl_depth,
                concurrency=crawl_concurrency,
            )
            tool_runs.append(run)
            web_assets.extend(crawl_assets)
            findings.extend(crawl_findings)
    elif request_nuclei := _allow_nuclei():
        warnings.append(f"nuclei_enabled={request_nuclei} ignored in passive mode")

    normalized_runs = [run.__dict__ for run in tool_runs]
    return {
        "domain": domain,
        "subdomains": selected_hosts,
        "dns_records": dns_records[:max_hosts],
        "web_assets": _dedupe_web_assets(web_assets)[:max_hosts],
        "findings": findings[: max_hosts * 2],
        "tool_runs": normalized_runs,
        "warnings": warnings,
    }


async def _run_subfinder(domain: str, timeout_seconds: int) -> tuple[list[str], CommandResult]:
    binary = _tool_path("subfinder")
    if not binary:
        return [], CommandResult("subfinder", "missing", warning="subfinder not installed")
    completed = await _run([binary, "-silent", "-timeout", "8", "-max-time", "1", "-d", domain], min(timeout_seconds, 10))
    hosts = _extract_domains(completed["stdout"], domain)
    return hosts, _command_status("subfinder", completed, len(hosts))


async def _run_amass(domain: str, timeout_seconds: int) -> tuple[list[str], CommandResult]:
    if os.getenv("KALI_SURFACE_ALLOW_AMASS", "false").lower() != "true":
        return [], CommandResult("amass", "disabled", warning="amass disabled by policy for fast non-privileged runs")
    binary = _tool_path("amass")
    if not binary:
        return [], CommandResult("amass", "missing", warning="amass not installed")
    completed = await _run([binary, "enum", "-passive", "-norecursive", "-noalts", "-d", domain], min(timeout_seconds, 12))
    hosts = _extract_domains(completed["stdout"], domain)
    return hosts, _command_status("amass", completed, len(hosts))


async def _run_dnsrecon(domain: str, timeout_seconds: int) -> tuple[list[dict[str, str]], CommandResult]:
    binary = _tool_path("dnsrecon")
    if not binary:
        return [], CommandResult("dnsrecon", "missing", warning="dnsrecon not installed")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "dnsrecon.json"
        completed = await _run([binary, "-d", domain, "-t", "std", "-j", str(output)], min(timeout_seconds, 10))
        records: list[dict[str, str]] = []
        if output.exists():
            try:
                payload = json.loads(output.read_text(encoding="utf-8", errors="ignore"))
                for item in payload:
                    if isinstance(item, dict):
                        record = {
                            "type": str(item.get("type") or item.get("record_type") or "").upper(),
                            "name": str(item.get("name") or item.get("target") or "").lower().rstrip("."),
                            "value": str(item.get("address") or item.get("exchange") or item.get("strings") or item.get("target") or ""),
                            "tool": "dnsrecon",
                        }
                        if record["type"] or record["name"] or record["value"]:
                            records.append(record)
            except json.JSONDecodeError:
                pass
        return records, _command_status("dnsrecon", completed, len(records))


async def _mail_findings(domain: str, timeout_seconds: int) -> tuple[list[dict[str, Any]], list[CommandResult]]:
    findings: list[dict[str, Any]] = []
    runs: list[CommandResult] = []
    root_txt, root_run = await _dig_record(domain, "TXT", timeout_seconds)
    runs.append(root_run)
    dmarc_txt, dmarc_run = await _dig_record(f"_dmarc.{domain}", "TXT", timeout_seconds)
    runs.append(dmarc_run)
    mx_records, mx_run = await _dig_record(domain, "MX", timeout_seconds)
    runs.append(mx_run)
    observed_at = datetime.now(timezone.utc).isoformat()
    sends_mail = bool(mx_records)
    if root_run.status in {"ok", "empty"} and sends_mail and not any("v=spf1" in item.lower() for item in root_txt):
        findings.append(
            {
                "type": "email_security",
                "severity": "low",
                "title": "SPF no observado en TXT raiz",
                "asset": domain,
                "validation": {
                    "query_performed": f"TXT {domain}",
                    "resolver_used": "system resolver via dig",
                    "timestamp": observed_at,
                    "raw_response": root_txt,
                    "record_found": False,
                    "record_value": None,
                    "validation_result": "confirmed_missing",
                    "mx_observed": True,
                    "mx_records": mx_records,
                },
            }
        )
    if dmarc_run.status in {"ok", "empty"} and sends_mail and not any("v=dmarc1" in item.lower() for item in dmarc_txt):
        findings.append(
            {
                "type": "email_security",
                "severity": "medium",
                "title": "DMARC no observado",
                "asset": f"_dmarc.{domain}",
                "validation": {
                    "query_performed": f"TXT _dmarc.{domain}",
                    "resolver_used": "system resolver via dig",
                    "timestamp": observed_at,
                    "raw_response": dmarc_txt,
                    "record_found": False,
                    "record_value": None,
                    "validation_result": "confirmed_missing",
                    "mx_observed": True,
                    "mx_records": mx_records,
                },
            }
        )
    return findings, runs


async def _dig_txt(host: str, timeout_seconds: int) -> tuple[list[str], CommandResult]:
    return await _dig_record(host, "TXT", timeout_seconds)


async def _dig_record(host: str, record_type: str, timeout_seconds: int) -> tuple[list[str], CommandResult]:
    binary = _tool_path("dig")
    if not binary:
        return [], CommandResult(f"dig {record_type} {host}", "missing", warning="dig not installed")
    completed = await _run([binary, "+short", record_type, host], min(timeout_seconds, 6))
    values = [line.strip().strip('"') for line in completed["stdout"].splitlines() if line.strip()]
    return values, _command_status(f"dig {record_type} {host}", completed, len(values))


async def _run_httpx(hosts: list[str], timeout_seconds: int) -> tuple[list[dict[str, Any]], CommandResult]:
    binary = _tool_path("httpx-toolkit") or _tool_path("httpx")
    if not binary:
        return [], CommandResult("httpx-toolkit", "missing", warning="httpx-toolkit not installed")
    input_data = "\n".join(hosts) + "\n"
    completed = await _run(
        [
            binary,
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-web-server",
            "-tls-probe",
            "-cdn",
            "-timeout",
            "6",
        ],
        min(timeout_seconds, 10),
        input_data=input_data,
    )
    assets: list[dict[str, Any]] = []
    for line in completed["stdout"].splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = item.get("url") or item.get("input")
        if not url:
            continue
        assets.append(
            {
                "url": url,
                "host": item.get("host") or item.get("input"),
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "webserver": item.get("webserver"),
                "technologies": item.get("tech") or [],
                "cdn": item.get("cdn_name") or item.get("cdn"),
                "tool": "httpx-toolkit",
            }
        )
    return assets, _command_status("httpx-toolkit", completed, len(assets))


async def _run_whatweb(domain: str, timeout_seconds: int) -> tuple[list[dict[str, Any]], CommandResult]:
    binary = _tool_path("whatweb")
    if not binary:
        return [], CommandResult("whatweb", "missing", warning="whatweb not installed")
    completed = await _run([binary, "--no-errors", "--color=never", f"https://{domain}"], min(timeout_seconds, 8))
    line = " ".join(completed["stdout"].split())
    assets = [{"url": f"https://{domain}", "title": line[:240], "tool": "whatweb"}] if line else []
    return assets, _command_status("whatweb", completed, len(assets))


async def _run_wafw00f(domain: str, timeout_seconds: int) -> tuple[list[dict[str, Any]], CommandResult]:
    if os.getenv("KALI_SURFACE_ALLOW_WAF_FINGERPRINT", "false").lower() != "true":
        return [], CommandResult("wafw00f", "disabled", warning="WAF fingerprint disabled by policy")
    binary = _tool_path("wafw00f")
    if not binary:
        return [], CommandResult("wafw00f", "missing", warning="wafw00f not installed")
    completed = await _run([binary, f"https://{domain}"], min(timeout_seconds, 8))
    summary = " ".join(completed["stdout"].split())[:260]
    findings = []
    if summary:
        findings.append({"type": "waf", "severity": "info", "title": summary, "asset": domain, "tool": "wafw00f"})
    return findings, _command_status("wafw00f", completed, len(findings))


async def _run_sslscan(domain: str, timeout_seconds: int) -> tuple[list[dict[str, Any]], CommandResult]:
    if os.getenv("KALI_SURFACE_ALLOW_SSLSCAN", "true").lower() != "true":
        return [], CommandResult("sslscan", "disabled", warning="sslscan disabled by policy")
    binary = _tool_path("sslscan")
    if not binary:
        return [], CommandResult("sslscan", "missing", warning="sslscan not installed")
    completed = await _run([binary, "--no-colour", f"{domain}:443"], min(timeout_seconds, 10))
    findings: list[dict[str, Any]] = []
    stdout = completed["stdout"].lower()
    if stdout:
        weak_markers = ["ssl 2", "ssl 3", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "rc4", "des-cbc3"]
        for marker in weak_markers:
            matching_lines = [line for line in stdout.splitlines() if marker in line]
            risky_lines = [
                line
                for line in matching_lines
                if "disabled" not in line
                and "not supported" not in line
                and ("enabled" in line or "accepted" in line)
            ]
            if risky_lines:
                findings.append(
                    {
                        "type": "tls",
                        "severity": "medium",
                        "title": f"Indicador TLS debil observado: {marker.upper()}",
                        "asset": f"{domain}:443",
                        "tool": "sslscan",
                    }
                )
    return findings, _command_status("sslscan", completed, len(findings))


async def _run_cariddi(
    urls: list[str],
    *,
    mode: str,
    timeout_seconds: int,
    max_depth: int,
    concurrency: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], CommandResult]:
    binary = _tool_path("cariddi")
    if not binary:
        return [], [], CommandResult("web-crawler", "missing", warning="web crawler not installed")

    target_limit = 6 if mode == "deep" else 3
    targets = list(dict.fromkeys(url.rstrip("/") + "/" for url in urls if url))[:target_limit]
    command = [
        binary,
        "-json",
        "-e",
        "-info",
        "-err",
        "-ext",
        "3",
        "-md",
        str(max_depth),
        "-c",
        str(concurrency),
        "-d",
        "1",
        "-t",
        "8",
    ]
    if mode == "deep":
        command.append("-s")
    completed = await _run(command, timeout_seconds, input_data="\n".join(targets) + "\n")

    assets: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for line in completed.get("stdout", "").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        host = (urlsplit(url).hostname or "").lower()
        matches = item.get("matches") if isinstance(item.get("matches"), dict) else {}
        assets.append(
            {
                "url": url,
                "host": host,
                "status_code": item.get("status_code"),
                "content_type": item.get("content_type"),
                "content_length": item.get("content_length"),
                "tool": "web-crawler",
            }
        )
        filetype = matches.get("filetype") if isinstance(matches.get("filetype"), dict) else {}
        extension = str(filetype.get("extension") or "").strip().lower()
        if extension:
            findings.append(
                _crawl_finding(
                    "public_file",
                    "info",
                    f"Archivo publico indexado ({extension})",
                    url,
                    {
                        "artifact_type": "file",
                        "extension": extension,
                        "crawler_severity_reference": filetype.get("severity"),
                    },
                )
            )
        parameters = matches.get("parameters") if isinstance(matches.get("parameters"), list) else []
        names = sorted(
            {
                str(value.get("name") or "").strip()
                for value in parameters
                if isinstance(value, dict) and str(value.get("name") or "").strip()
            }
        )
        if names:
            findings.append(
                _crawl_finding(
                    "web_parameter",
                    "info",
                    f"Parametros publicos observados: {', '.join(names[:8])}",
                    url,
                    {
                        "artifact_type": "web_parameter",
                        "parameter_names": names[:20],
                        "does_not_demonstrate": "explotabilidad, vulnerabilidad o acceso no autorizado",
                    },
                )
            )
        for match_type, severity, artifact_type in (
            ("errors", "low", "application_error_candidate"),
            ("infos", "info", "information_indicator"),
        ):
            rows = matches.get(match_type) if isinstance(matches.get(match_type), list) else []
            for row in rows[:12]:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name") or artifact_type).strip()
                findings.append(
                    _crawl_finding(
                        artifact_type,
                        severity,
                        f"Indicador web recolectado: {name}",
                        url,
                        {
                            "artifact_type": artifact_type,
                            "indicator_name": name,
                            "match_preview": _redacted_preview(str(row.get("match") or "")),
                            "does_not_demonstrate": "una vulnerabilidad aplicable ni un incidente confirmado",
                        },
                    )
                )
        secrets = matches.get("secrets") if isinstance(matches.get("secrets"), list) else []
        for row in secrets[:12]:
            if not isinstance(row, dict):
                continue
            raw_match = str(row.get("match") or "")
            findings.append(
                _crawl_finding(
                    "secret_indicator_candidate",
                    "medium",
                    f"Indicador de secreto candidato: {str(row.get('name') or 'patron sensible')}",
                    url,
                    {
                        "artifact_type": "secret_indicator_candidate",
                        "indicator_name": str(row.get("name") or "sensitive_pattern"),
                        "value_hash": hashlib.sha256(raw_match.encode("utf-8", errors="ignore")).hexdigest(),
                        "raw_value_stored": False,
                        "requires_manual_validation": True,
                        "does_not_demonstrate": "que el valor sea vigente, utilizable o perteneciente al alcance",
                    },
                )
            )
    records = len(assets) + len(findings)
    return assets, findings, _command_status("web-crawler", completed, records)


def _crawl_finding(
    finding_type: str,
    severity: str,
    title: str,
    url: str,
    validation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity,
        "title": title,
        "asset": urlsplit(url).hostname or url,
        "url": url,
        "validation": {
            "validation_method": "bounded_public_web_crawl",
            "validation_result": "collected_candidate",
            "canonical_url": url,
            "direct_relationship": False,
            **validation,
        },
    }


def _redacted_preview(value: str) -> str:
    compact = " ".join(value.split())
    if not compact:
        return ""
    return compact[:80] + ("..." if len(compact) > 80 else "")


async def _run(command: list[str], timeout_seconds: int, input_data: str | None = None) -> dict[str, Any]:
    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        if process.stdin is not None and input_data is not None:
            process.stdin.write(input_data.encode())
            await process.stdin.drain()
            process.stdin.close()
        output_limit = _command_output_limit()
        stdout_task = asyncio.create_task(_read_stream_limited(process.stdout, output_limit))
        stderr_task = asyncio.create_task(_read_stream_limited(process.stderr, min(output_limit, 1_000_000)))
        stdout, stderr, _ = await asyncio.wait_for(
            asyncio.gather(stdout_task, stderr_task, process.wait()),
            timeout=timeout_seconds,
        )
        return {
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="ignore"),
            "stderr": stderr.decode("utf-8", errors="ignore"),
            "timeout": False,
        }
    except asyncio.TimeoutError:
        if process is not None:
            with suppress(Exception):
                os.killpg(process.pid, signal.SIGKILL)
            with suppress(Exception):
                await process.wait()
        return {"returncode": -1, "stdout": "", "stderr": "timeout", "timeout": True}
    except Exception as exc:
        return {"returncode": -1, "stdout": "", "stderr": str(exc), "timeout": False}


async def _read_stream_limited(
    stream: asyncio.StreamReader | None,
    limit: int,
) -> bytes:
    if stream is None:
        return b""
    chunks: list[bytes] = []
    captured = 0
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            break
        if captured < limit:
            remaining = limit - captured
            chunks.append(chunk[:remaining])
            captured += min(len(chunk), remaining)
    return b"".join(chunks)


def _command_status(tool: str, completed: dict[str, Any], records: int) -> CommandResult:
    if completed.get("timeout"):
        return CommandResult(tool, "timeout", records=records, warning="Command timeout")
    if completed.get("returncode", 0) not in {0, None} and records == 0:
        warning = (completed.get("stderr") or completed.get("stdout") or "Command failed").strip().splitlines()
        return CommandResult(tool, "partial", records=records, warning=(warning[0][:180] if warning else None))
    return CommandResult(tool, "ok" if records else "empty", records=records)


def _extract_domains(text: str, base_domain: str) -> list[str]:
    found = set()
    pattern = re.compile(rf"(?:[a-z0-9-]+\.)+{re.escape(base_domain)}", re.IGNORECASE)
    for match in pattern.findall(text or ""):
        found.add(match.lower().rstrip("."))
    return sorted(found)


def _dedupe_web_assets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = str(item.get("url") or item.get("host") or "").rstrip("/").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _parse_searchsploit_json(value: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    rows: list[dict[str, Any]] = []
    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE", "results"):
        items = payload.get(key)
        if isinstance(items, list):
            rows.extend(item for item in items if isinstance(item, dict))
    return rows


def _tool_names() -> list[str]:
    return [
        "amass",
        "subfinder",
        "theHarvester",
        "dnsrecon",
        "dig",
        "httpx-toolkit",
        "whatweb",
        "wafw00f",
        "sslscan",
        "nuclei",
        "searchsploit",
        "cariddi",
    ]


def _tool_path(name: str) -> str | None:
    return shutil.which(name)


def _allow_light_probe() -> bool:
    return os.getenv("KALI_SURFACE_ALLOW_LIGHT_PROBES", "true").lower() == "true"


def _allow_nuclei() -> bool:
    return os.getenv("KALI_SURFACE_ALLOW_NUCLEI", "false").lower() == "true"


def _allow_web_crawl() -> bool:
    return os.getenv("KALI_SURFACE_ALLOW_WEB_CRAWL", "true").lower() == "true"


def _domain_concurrency() -> int:
    return max(1, min(6, int(os.getenv("KALI_SURFACE_DOMAIN_CONCURRENCY", "2"))))


def _command_output_limit() -> int:
    return max(1_000_000, min(50_000_000, int(os.getenv("KALI_SURFACE_MAX_OUTPUT_BYTES", "12000000"))))
