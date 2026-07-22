from __future__ import annotations

import asyncio
from contextlib import suppress
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


@app.post("/surface-scan")
async def surface_scan(request: SurfaceRequest) -> dict[str, Any]:
    light_probe = request.light_probe and request.mode != "passive" and _allow_light_probe()
    domains = await asyncio.gather(
        *[_safe_scan_domain(domain, request.max_hosts, request.timeout_seconds, light_probe) for domain in request.domains]
    )
    warnings = [warning for result in domains for warning in result.get("warnings", [])]
    return {
        "status": "ok",
        "mode": "light" if light_probe else "passive",
        "domains": domains,
        "warnings": warnings[:20],
    }


async def _safe_scan_domain(domain: str, max_hosts: int, timeout_seconds: int, light_probe: bool) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(_scan_domain(domain, max_hosts, timeout_seconds, light_probe), timeout=max(8, timeout_seconds + 5))
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


async def _scan_domain(domain: str, max_hosts: int, timeout_seconds: int, light_probe: bool) -> dict[str, Any]:
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


async def _run(command: list[str], timeout_seconds: int, input_data: str | None = None) -> dict[str, Any]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input_data.encode() if input_data is not None else None),
            timeout=timeout_seconds,
        )
        return {
            "returncode": process.returncode,
            "stdout": stdout.decode("utf-8", errors="ignore"),
            "stderr": stderr.decode("utf-8", errors="ignore"),
            "timeout": False,
        }
    except asyncio.TimeoutError:
        with suppress(Exception):
            process.kill()
        return {"returncode": -1, "stdout": "", "stderr": "timeout", "timeout": True}
    except Exception as exc:
        return {"returncode": -1, "stdout": "", "stderr": str(exc), "timeout": False}


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
    ]


def _tool_path(name: str) -> str | None:
    return shutil.which(name)


def _allow_light_probe() -> bool:
    return os.getenv("KALI_SURFACE_ALLOW_LIGHT_PROBES", "true").lower() == "true"


def _allow_nuclei() -> bool:
    return os.getenv("KALI_SURFACE_ALLOW_NUCLEI", "false").lower() == "true"
