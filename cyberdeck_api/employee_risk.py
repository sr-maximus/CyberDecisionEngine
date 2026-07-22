from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import BinaryIO

from cyberdeck.settings import PROJECT_ROOT
from cyberdeck_api.models import EmployeeRiskRunResponse


MODULE_DIR = PROJECT_ROOT / "integrations" / "employee_virtual_risk_osint"
INPUT_ROOT = PROJECT_ROOT / "data" / "employee_risk_runs"
REPORT_ROOT = PROJECT_ROOT / "reports" / "employee-risk"
ALLOWED_INPUT_SUFFIXES = {".csv", ".xlsx"}
ALLOWED_SEARCH_CLIENTS = {"mock", "duckduckgo_lite", "ddg", "bing_html", "multi_noapi", "noapi", "bing", "google_cse"}


def run_employee_risk_module(
    employee_file: BinaryIO,
    employee_filename: str,
    manual_results_file: BinaryIO | None,
    manual_results_filename: str | None,
    search_client: str,
    results_per_query: int,
    max_keywords_per_dimension: int,
    max_queries_per_employee: int | None,
    min_confidence: float | None,
    allow_personal_email: bool,
    skip_web_search: bool,
    no_identity_discovery: bool,
) -> EmployeeRiskRunResponse:
    if not MODULE_DIR.is_dir():
        raise FileNotFoundError("Employee risk module is not installed.")
    if search_client not in ALLOWED_SEARCH_CLIENTS:
        raise ValueError("Unsupported search client.")

    run_id = uuid.uuid4().hex[:12]
    input_dir = INPUT_ROOT / run_id
    output_dir = REPORT_ROOT / run_id
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    employee_path = _save_upload(employee_file, employee_filename, input_dir, "employees")
    manual_path = None
    if manual_results_file and manual_results_filename:
        manual_path = _save_upload(manual_results_file, manual_results_filename, input_dir, "manual_results")

    command = [
        sys.executable,
        "-m",
        "app.main",
        "analyze",
        "--input",
        str(employee_path),
        "--output",
        str(output_dir),
        "--catalogs-dir",
        "catalogs",
        "--search-client",
        search_client,
        "--formats",
        "html,json,csv",
        "--results-per-query",
        str(max(1, min(results_per_query, 20))),
        "--max-keywords-per-dimension",
        str(max(1, min(max_keywords_per_dimension, 50))),
    ]
    if max_queries_per_employee:
        command.extend(["--max-queries-per-employee", str(max(1, min(max_queries_per_employee, 100)))])
    if min_confidence is not None:
        command.extend(["--min-confidence", str(max(0.0, min(min_confidence, 1.0)))])
    if allow_personal_email:
        command.append("--allow-personal-email")
    if skip_web_search:
        command.append("--skip-web-search")
    if no_identity_discovery:
        command.append("--no-identity-discovery")
    if manual_path:
        command.extend(["--manual-results", str(manual_path)])

    env = os.environ.copy()
    env.setdefault("MPLCONFIGDIR", "/tmp/cyberdecisionengine-matplotlib")
    process = subprocess.run(
        command,
        cwd=MODULE_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    output = "\n".join(part for part in [process.stdout.strip(), process.stderr.strip()] if part).strip()
    if process.returncode != 0:
        return EmployeeRiskRunResponse(id=run_id, status="failed", stage="Employee risk module failed", command_output=output)

    return _response_from_output(run_id, output_dir, output)


def _save_upload(file_obj: BinaryIO, filename: str, directory: Path, stem: str) -> Path:
    suffix = Path(filename or "").suffix.lower()
    if suffix not in ALLOWED_INPUT_SUFFIXES:
        raise ValueError("Only CSV/XLSX files are supported.")
    path = directory / f"{stem}{suffix}"
    with path.open("wb") as handle:
        shutil.copyfileobj(file_obj, handle)
    return path


def _response_from_output(run_id: str, output_dir: Path, command_output: str) -> EmployeeRiskRunResponse:
    report_path = output_dir / "cyberintelligence_report.html"
    results_path = output_dir / "analysis_results.json"
    evidence_path = output_dir / "evidence.csv"
    summary_path = output_dir / "employee_risk_summary.csv"
    employee_count = 0
    evidence_count = 0
    max_risk = 0.0

    if results_path.exists():
        results = json.loads(results_path.read_text(encoding="utf-8"))
        employee_count = len(results)
        max_risk = max((float(item.get("total_risk", 0) or 0) for item in results), default=0.0)
    if evidence_path.exists():
        with evidence_path.open(newline="", encoding="utf-8") as handle:
            evidence_count = max(0, sum(1 for _ in csv.reader(handle)) - 1)

    output_urls = {}
    for path in [results_path, evidence_path, summary_path]:
        if path.exists():
            output_urls[path.name] = f"/reports/{path.relative_to(PROJECT_ROOT / 'reports').as_posix()}"
    report_url = None
    download_url = None
    if report_path.exists():
        relative = report_path.relative_to(PROJECT_ROOT / "reports").as_posix()
        report_url = f"/reports/{relative}"
        download_url = f"/api/reports/{relative}/download"
    return EmployeeRiskRunResponse(
        id=run_id,
        status="completed",
        stage="Employee risk report ready",
        report_url=report_url,
        download_url=download_url,
        output_urls=output_urls,
        employee_count=employee_count,
        evidence_count=evidence_count,
        max_risk=round(max_risk, 2),
        command_output=command_output,
    )
