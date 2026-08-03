from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator


SPIDERFOOT_DIR = Path("/opt/spiderfoot")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RAW_TYPE_PREFIXES = ("raw data", "raw dns", "raw whois", "raw rir")
MAX_DATA_LENGTH = 600
STANDARD_PASSIVE_MODULES = [
    "sfp_dnsraw",
    "sfp_dnsresolve",
    "sfp_sslcert",
    "sfp_crt",
    "sfp_whois",
]
DEEP_PASSIVE_MODULES = [
    *STANDARD_PASSIVE_MODULES,
    "sfp_bgpview",
    "sfp_urlscan",
    "sfp_commoncrawl",
    "sfp_duckduckgo",
    "sfp_threatminer",
    "sfp_openphish",
    "sfp_phishtank",
    "sfp_abusech",
]
SCAN_CONCURRENCY = max(1, min(3, int(os.getenv("SPIDERFOOT_SCAN_CONCURRENCY", "2"))))

app = FastAPI(title="CyberDecisionEngine SpiderFoot Sidecar", version="1.0.0")


class SpiderFootScanRequest(BaseModel):
    domains: list[str] = Field(default_factory=list, min_length=1, max_length=50)
    use_case: Literal["passive"] = "passive"
    depth: Literal["standard", "deep"] = "deep"
    timeout_seconds: int = Field(default=0, ge=0, le=86_400)
    max_records: int = Field(default=160, ge=1, le=5000)
    max_threads: int = Field(default=4, ge=1, le=8)
    include_raw: bool = False

    @field_validator("domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            candidate = value.strip().lower().removeprefix("www.").lstrip("@").strip(".")
            if not DOMAIN_RE.match(candidate):
                raise ValueError(f"Invalid domain: {value}")
            if candidate not in seen:
                normalized.append(candidate)
                seen.add(candidate)
        if not normalized:
            raise ValueError("At least one domain is required.")
        return normalized


@app.get("/health")
async def health() -> dict[str, Any]:
    sf_cli = SPIDERFOOT_DIR / "sf.py"
    return {
        "status": "ok",
        "mode": "passive_cli",
        "spiderfoot_cli": sf_cli.exists(),
        "python": sys.version.split()[0],
    }


@app.post("/scan")
async def scan(request: SpiderFootScanRequest) -> dict[str, Any]:
    warnings: list[str] = []
    domains = []
    per_domain_timeout = request.timeout_seconds
    semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)
    domains = await asyncio.gather(
        *[
            _scan_domain_limited(
                semaphore,
                domain,
                depth=request.depth,
                timeout_seconds=per_domain_timeout,
                max_records=request.max_records,
                max_threads=request.max_threads,
                include_raw=request.include_raw,
            )
            for domain in request.domains
        ]
    )
    for result in domains:
        warnings.extend(result.get("warnings") or [])
    return {
        "status": "ok" if any(item.get("records") for item in domains) else "partial",
        "mode": request.use_case,
        "domains": domains,
        "warnings": warnings[:20],
    }


async def _scan_domain_limited(
    semaphore: asyncio.Semaphore,
    domain: str,
    depth: str,
    timeout_seconds: int,
    max_records: int,
    max_threads: int,
    include_raw: bool,
) -> dict[str, Any]:
    async with semaphore:
        return await _scan_domain(domain, depth, timeout_seconds, max_records, max_threads, include_raw)


async def _scan_domain(
    domain: str,
    depth: str,
    timeout_seconds: int,
    max_records: int,
    max_threads: int,
    include_raw: bool,
) -> dict[str, Any]:
    sf_cli = SPIDERFOOT_DIR / "sf.py"
    if not sf_cli.exists():
        return {"domain": domain, "records": [], "warnings": ["SpiderFoot CLI is not installed."], "tool_runs": []}

    command = [
        sys.executable,
        str(sf_cli),
        "-s",
        domain,
        "-m",
        ",".join(_modules_for_depth(depth)),
        "-o",
        "json",
        "-q",
        "-n",
        "-S",
        str(MAX_DATA_LENGTH),
        "-max-threads",
        str(max_threads),
    ]
    command_display = f"python sf.py -s <domain> -m {depth}_passive_modules -o json -q -n"
    run = await _run_command(command, timeout_seconds)
    records, parse_warning = _parse_records(run["stdout"])
    warnings: list[str] = []
    if run["timeout"]:
        warnings.append(f"SpiderFoot timeout for {domain}; partial records were used.")
    if run["returncode"] not in (0, None) and not records:
        warnings.append(f"SpiderFoot exited with code {run['returncode']} for {domain}.")
    if parse_warning:
        warnings.append(parse_warning)
    if run["stderr"]:
        warnings.extend(_trim_stderr(run["stderr"]))

    filtered: list[dict[str, Any]] = []
    raw_records_filtered = 0
    for record in records:
        normalized = _normalize_record(domain, record)
        if not normalized:
            continue
        if _is_raw_record(normalized) and not include_raw:
            raw_records_filtered += 1
            continue
        filtered.append(normalized)
        if len(filtered) >= max_records:
            break

    return {
        "domain": domain,
        "records": filtered,
        "record_count": len(filtered),
        "raw_records_filtered": raw_records_filtered,
        "warnings": warnings[:8],
        "tool_runs": [
            {
                "tool": "spiderfoot",
                "mode": depth,
                "timeout": run["timeout"],
                "returncode": run["returncode"],
                "command": command_display,
            }
        ],
    }


async def _run_command(command: list[str], timeout_seconds: int) -> dict[str, Any]:
    return await asyncio.to_thread(_run_command_sync, command, timeout_seconds)


def _run_command_sync(command: list[str], timeout_seconds: int) -> dict[str, Any]:
    if shutil.which(command[0]) is None:
        return {"stdout": "", "stderr": f"{command[0]} not found", "returncode": None, "timeout": False}
    timed_out = False
    with tempfile.TemporaryDirectory(prefix="cde-spiderfoot-") as temp_dir:
        stdout_path = Path(temp_dir) / "stdout.json"
        stderr_path = Path(temp_dir) / "stderr.log"
        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            process = subprocess.Popen(
                command,
                cwd=str(SPIDERFOOT_DIR),
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=timeout_seconds) if timeout_seconds > 0 else process.wait()
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    returncode = process.wait(timeout=8)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    returncode = process.wait(timeout=8)
        return {
            "stdout": stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else "",
            "stderr": stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else "",
            "returncode": returncode,
            "timeout": timed_out,
        }


def _modules_for_depth(depth: str) -> list[str]:
    return DEEP_PASSIVE_MODULES if depth == "deep" else STANDARD_PASSIVE_MODULES


def _parse_records(text: str) -> tuple[list[dict[str, Any]], str | None]:
    cleaned = text.strip()
    if not cleaned:
        return [], "SpiderFoot did not return JSON records."
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)], None
    except json.JSONDecodeError:
        pass

    recovered: list[dict[str, Any]] = []
    for line in cleaned.splitlines():
        candidate = line.strip().rstrip(",")
        if not candidate.startswith("{") or not candidate.endswith("}"):
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            recovered.append(parsed)
    if recovered:
        return recovered, "SpiderFoot JSON was partial; recovered complete event rows only."
    return [], "SpiderFoot JSON could not be parsed."


def _normalize_record(domain: str, record: dict[str, Any]) -> dict[str, Any] | None:
    event_type = str(record.get("type") or "").strip()
    data = str(record.get("data") or "").strip()
    module = str(record.get("module") or "").strip()
    source = str(record.get("source") or "").strip()
    if not event_type or not data:
        return None
    return {
        "domain": domain,
        "type": event_type[:120],
        "data": _compact(data, MAX_DATA_LENGTH),
        "module": module[:120] or "spiderfoot",
        "source": _compact(source, 300),
        "generated": record.get("generated"),
    }


def _is_raw_record(record: dict[str, Any]) -> bool:
    return str(record.get("type") or "").strip().lower().startswith(RAW_TYPE_PREFIXES)


def _compact(value: str, limit: int) -> str:
    compacted = re.sub(r"\s+", " ", value).strip()
    if len(compacted) <= limit:
        return compacted
    return compacted[: limit - 3].rstrip() + "..."


def _trim_stderr(stderr: str) -> list[str]:
    warnings = []
    for line in stderr.splitlines():
        compacted = _compact(line, 240)
        if compacted:
            warnings.append(compacted)
        if len(warnings) >= 3:
            break
    return warnings
