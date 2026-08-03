from __future__ import annotations

import asyncio
import json
import re
import time
from io import BytesIO
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from cyberdeck.settings import PROJECT_ROOT
from cyberdeck.methodology import load_methodology_registry
from cyberdeck_api.attack_surface import build_attack_surface
from cyberdeck_api.ai_orchestration import (
    CHAT_PROMPT_VERSION,
    ai_orchestration_config,
    build_ai_analysis_package,
    execute_openclaw_analysis,
    execute_ollama_chat,
    ollama_runtime_status,
    openclaw_runtime_status,
)
from cyberdeck_api.disinformation import load_disinformation_framework
from cyberdeck_api.domain_scope import normalize_domains
from cyberdeck_api.employee_risk import run_employee_risk_module
from cyberdeck_api.jobs import RunStore
from cyberdeck_api.licensing import (
    CreateCompanyRequest,
    CreateLicenseRequest,
    CreateLicenseUserRequest,
    LicensingOverview,
    LicensingStore,
    UpdateLicenseRequest,
    UpdateLicenseUserRequest,
)
from cyberdeck_api.models import (
    AIAnalysisPackage,
    AIAnalysisRequest,
    AIChatRequest,
    AIExecutionRequest,
    AIExecutionResult,
    DomainAnalysisRequest,
    EmployeeRiskRunResponse,
    EvidenceReviewRequest,
    HealthResponse,
    MitreGroup,
    MonitoringAlert,
    MonitoringAlertUpdate,
    MonitoringOverview,
    MonitoringProfile,
    MonitoringProfileRequest,
    MonitoringProfileUpdate,
    PlatformLogEntry,
    ReportCatalogItem,
    RunRecord,
    SupportTicket,
    SupportTicketRequest,
    SupportTicketUpdate,
)
from cyberdeck_api.monitoring import MonitoringStore
from cyberdeck_api.scenarios import load_scenario_library


store = RunStore()
license_store = LicensingStore()
monitoring_store = MonitoringStore()
MITRE_ENTERPRISE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_CACHE_TTL_SECONDS = 60 * 60 * 6
_mitre_cache: tuple[float, list[MitreGroup]] | None = None

MITRE_FALLBACK_GROUPS = [
    MitreGroup(id="G0016", name="APT29", aliases=["Cozy Bear", "NOBELIUM"]),
    MitreGroup(id="G0007", name="APT28", aliases=["Fancy Bear", "Sofacy"]),
    MitreGroup(id="G0032", name="Lazarus Group", aliases=["HIDDEN COBRA"]),
    MitreGroup(id="G0096", name="APT41", aliases=["BARIUM", "Winnti"]),
    MitreGroup(id="G0132", name="FIN7", aliases=["Carbanak"]),
    MitreGroup(id="G0037", name="FIN6", aliases=[]),
    MitreGroup(id="G0069", name="MuddyWater", aliases=[]),
    MitreGroup(id="G0050", name="APT32", aliases=["OceanLotus"]),
    MitreGroup(id="G0046", name="FIN8", aliases=[]),
    MitreGroup(id="G1015", name="Scattered Spider", aliases=["UNC3944"]),
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await store.load()
    await license_store.load()
    await monitoring_store.load(store)
    await monitoring_store.start()
    try:
        yield
    finally:
        await monitoring_store.stop()


app = FastAPI(
    title="CyberDecisionEngine API",
    version="0.1.0",
    description="Local defensive cyber intelligence API for domain analysis runs.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8080", "http://127.0.0.1:5173", "http://127.0.0.1:8080"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

reports_dir = PROJECT_ROOT / "reports"
reports_dir.mkdir(parents=True, exist_ok=True)
app.mount("/reports", StaticFiles(directory=str(reports_dir), html=True), name="reports")


def _report_download_url(relative_path: str) -> str:
    return f"/api/reports/{relative_path}/download"


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/api/methodologies")
async def methodologies() -> Dict[str, Any]:
    return load_methodology_registry().public_payload()


@app.post("/api/analysis", response_model=RunRecord, status_code=202)
async def create_analysis(request: DomainAnalysisRequest) -> RunRecord:
    try:
        return await store.create_run(request)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/runs", response_model=list[RunRecord])
async def list_runs() -> list[RunRecord]:
    return await store.list_runs()


@app.get("/api/reports", response_model=list[ReportCatalogItem])
async def list_reports() -> list[ReportCatalogItem]:
    reports = []
    for path in sorted(reports_dir.rglob("*.html"), key=lambda item: item.stat().st_mtime, reverse=True):
        if path.name.endswith(("_executive.html", "_technical.html")):
            continue
        stat = path.stat()
        report_type = "technical" if path.name.endswith("-technical.html") else "executive"
        run_id_match = re.match(r"^([0-9a-f]{12})(?:-|$)", path.name, re.IGNORECASE)
        reports.append(
            ReportCatalogItem(
                name=path.name,
                path=str(path),
                url=f"/reports/{path.relative_to(reports_dir).as_posix()}",
                download_url=_report_download_url(path.relative_to(reports_dir).as_posix()),
                size_bytes=stat.st_size,
                modified_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                report_type=report_type,
                run_id=run_id_match.group(1) if run_id_match else None,
            )
        )
    return reports


@app.get("/api/reports/{report_path:path}/download")
async def download_report(report_path: str) -> FileResponse:
    root = reports_dir.resolve()
    candidate = (root / report_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Report not found.") from exc
    if not candidate.is_file() or candidate.suffix.lower() != ".html":
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(
        candidate,
        media_type="text/html; charset=utf-8",
        filename=candidate.name,
    )


@app.delete("/api/reports/{report_path:path}")
async def delete_report(report_path: str) -> dict:
    root = reports_dir.resolve()
    candidate = (root / report_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Report not found.") from exc
    if not candidate.is_file() or candidate.suffix.lower() != ".html":
        raise HTTPException(status_code=404, detail="Report not found.")
    candidate.unlink()
    return {"status": "deleted", "report": report_path}


@app.get("/api/reports/archive")
async def download_reports_archive(kind: Optional[str] = Query(default=None, pattern="^(executive|technical)$")) -> Response:
    selected = []
    for path in sorted(reports_dir.rglob("*.html"), key=lambda item: item.stat().st_mtime, reverse=True):
        if path.name.endswith(("_executive.html", "_technical.html")):
            continue
        is_technical = path.name.endswith("-technical.html")
        if kind == "technical" and not is_technical:
            continue
        if kind == "executive" and is_technical:
            continue
        selected.append(path)
    if not selected:
        raise HTTPException(status_code=404, detail="No reports found.")

    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for path in selected:
            archive.write(path, path.relative_to(reports_dir).as_posix())
    suffix = f"-{kind}" if kind else ""
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="cyberdecisionengine-reports{suffix}.zip"'},
    )


@app.get("/api/attack-surface")
async def attack_surface(
    domains: list[str] = Query(default_factory=list),
    competitors: list[str] = Query(default_factory=list),
) -> dict:
    try:
        normalized_domains = normalize_domains(domains)
        normalized_competitors = normalize_domains(competitors) if competitors else []
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await build_attack_surface(normalized_domains, normalized_competitors)


@app.get("/api/monitoring", response_model=MonitoringOverview)
async def monitoring_overview() -> MonitoringOverview:
    return await monitoring_store.overview()


@app.post("/api/monitoring/profiles", response_model=MonitoringProfile, status_code=201)
async def create_monitoring_profile(request: MonitoringProfileRequest) -> MonitoringProfile:
    if not request.request.authorized_scope:
        raise HTTPException(status_code=403, detail="Monitoring requires authorized_scope=true.")
    try:
        return await monitoring_store.create_profile(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.patch("/api/monitoring/profiles/{profile_id}", response_model=MonitoringProfile)
async def update_monitoring_profile(profile_id: str, request: MonitoringProfileUpdate) -> MonitoringProfile:
    profile = await monitoring_store.update_profile(profile_id, request)
    if profile is None:
        raise HTTPException(status_code=404, detail="Monitoring profile not found.")
    return profile


@app.patch("/api/monitoring/alerts/{alert_id}", response_model=MonitoringAlert)
async def update_monitoring_alert(alert_id: str, request: MonitoringAlertUpdate) -> MonitoringAlert:
    alert = await monitoring_store.update_alert_status(alert_id, request.status, user=request.user)
    if alert is None:
        raise HTTPException(status_code=404, detail="Monitoring alert not found.")
    return alert


@app.post("/api/support/tickets", response_model=SupportTicket, status_code=201)
async def create_support_ticket(request: SupportTicketRequest) -> SupportTicket:
    return await monitoring_store.create_support_ticket(request)


@app.patch("/api/support/tickets/{ticket_id}", response_model=SupportTicket)
async def update_support_ticket(ticket_id: str, request: SupportTicketUpdate) -> SupportTicket:
    ticket = await monitoring_store.update_support_ticket(ticket_id, request)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Support ticket not found.")
    return ticket


@app.post("/api/platform/logs", response_model=PlatformLogEntry, status_code=201)
async def create_platform_log(entry: PlatformLogEntry) -> PlatformLogEntry:
    return await monitoring_store.record_log(
        entry.level,
        entry.component,
        entry.message,
        run_id=entry.run_id,
        profile_id=entry.profile_id,
        user=entry.user,
    )


@app.post("/api/employee-risk/analyze", response_model=EmployeeRiskRunResponse)
async def employee_risk_analyze(
    employees_file: UploadFile = File(...),
    manual_results_file: Optional[UploadFile] = File(default=None),
    search_client: str = Form(default="multi_noapi"),
    results_per_query: int = Form(default=3),
    max_keywords_per_dimension: int = Form(default=8),
    max_queries_per_employee: Optional[int] = Form(default=10),
    min_confidence: Optional[float] = Form(default=None),
    allow_personal_email: bool = Form(default=False),
    skip_web_search: bool = Form(default=False),
    no_identity_discovery: bool = Form(default=False),
) -> EmployeeRiskRunResponse:
    try:
        return await asyncio.to_thread(
            run_employee_risk_module,
            employees_file.file,
            employees_file.filename or "employees.csv",
            manual_results_file.file if manual_results_file else None,
            manual_results_file.filename if manual_results_file else None,
            search_client,
            results_per_query,
            max_keywords_per_dimension,
            max_queries_per_employee,
            min_confidence,
            allow_personal_email,
            skip_web_search,
            no_identity_discovery,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/mitre/groups", response_model=list[MitreGroup])
async def list_mitre_groups() -> list[MitreGroup]:
    global _mitre_cache
    now = time.time()
    if _mitre_cache and now - _mitre_cache[0] < MITRE_CACHE_TTL_SECONDS:
        return _mitre_cache[1]

    try:
        groups = await asyncio.to_thread(_fetch_mitre_groups)
    except Exception:
        groups = MITRE_FALLBACK_GROUPS
    _mitre_cache = (now, groups)
    return groups


@app.get("/api/disinformation/framework")
async def disinformation_framework() -> dict:
    return load_disinformation_framework()


@app.get("/api/scenarios/library")
async def scenario_library() -> dict:
    return load_scenario_library()


@app.get("/api/ai/config")
async def ai_config() -> dict:
    config = ai_orchestration_config()
    runtime = await openclaw_runtime_status()
    chat_runtime = await ollama_runtime_status("OLLAMA_CHAT_MODEL")
    config["openclaw_gateway"].update(runtime)
    config["ollama_chat"].update(chat_runtime)
    for provider in config["provider_catalog"]:
        if provider.get("key") == "openclaw_gateway":
            provider["enabled"] = runtime.get("ready", False)
            provider["runtime_status"] = runtime.get("runtime_status")
            provider["model_status"] = runtime.get("model_status")
    return config


@app.post("/api/ai/package", response_model=AIAnalysisPackage)
async def ai_package(request: AIAnalysisRequest) -> AIAnalysisPackage:
    run = await store.get_run(request.run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return build_ai_analysis_package(run, request)


@app.post("/api/ai/analyze", response_model=AIExecutionResult)
async def ai_analyze(request: AIExecutionRequest) -> AIExecutionResult:
    run = await store.get_run(request.run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return await execute_openclaw_analysis(run, request)


@app.post("/api/ai/chat", response_model=AIExecutionResult)
async def ai_chat(request: AIChatRequest) -> AIExecutionResult:
    run = await store.get_run(request.run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    if _requests_report_generation(request.message):
        try:
            run = await store.generate_report(request.run_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if run is None or run.report is None:
            raise HTTPException(status_code=409, detail="Report generation did not produce an output.")
        executive_url = run.report.url
        technical_url = run.report.technical_url
        answer = (
            "Los informes ejecutivo y técnico fueron generados desde la corrida seleccionada y están listos para revisión."
            if request.language == "es"
            else "The executive and technical reports were generated from the selected run and are ready for review."
        )
        return AIExecutionResult(
            id=f"ai-report-{run.id}",
            run_id=run.id,
            status="completed",
            provider="CyberDecisionEngine · generación determinista",
            model="report-engine",
            prompt_version=CHAT_PROMPT_VERSION,
            analysis={
                "answer": answer,
                "facts": [],
                "inferences": [],
                "decision_options": [],
                "technical_checks": [],
                "dashboard_targets": [{"module": "overview", "reason": "report status and run summary"}],
                "report_guidance": {
                    "executive": executive_url,
                    "technical": technical_url,
                },
                "evidence_refs": [],
                "limitations": [],
                "follow_up_questions": [],
            },
            evidence_validation={
                "requested_count": 0,
                "validated_count": 0,
                "validated_refs": [],
                "unknown_refs": [],
                "all_refs_valid": True,
            },
            usage={"mode": "deterministic_report_generation"},
        )
    return await execute_ollama_chat(run, request)


def _requests_report_generation(message: str) -> bool:
    normalized = message.casefold()
    action = any(token in normalized for token in ("genera", "generar", "crear", "create", "generate"))
    artifact = any(token in normalized for token in ("informe", "reporte", "report"))
    return action and artifact


@app.get("/api/licensing/overview", response_model=LicensingOverview)
async def licensing_overview() -> LicensingOverview:
    return await license_store.overview()


@app.post("/api/licensing/companies", response_model=LicensingOverview, status_code=201)
async def create_license_company(request: CreateCompanyRequest) -> LicensingOverview:
    try:
        return await license_store.create_company(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/licensing/licenses", response_model=LicensingOverview, status_code=201)
async def create_company_license(request: CreateLicenseRequest) -> LicensingOverview:
    try:
        return await license_store.create_license(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.patch("/api/licensing/licenses/{license_id}", response_model=LicensingOverview)
async def update_company_license(license_id: str, request: UpdateLicenseRequest) -> LicensingOverview:
    try:
        return await license_store.update_license(license_id, request)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/licensing/users", response_model=LicensingOverview, status_code=201)
async def create_license_user(request: CreateLicenseUserRequest) -> LicensingOverview:
    try:
        return await license_store.create_user(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.patch("/api/licensing/users/{user_id}", response_model=LicensingOverview)
async def update_license_user(user_id: str, request: UpdateLicenseUserRequest) -> LicensingOverview:
    try:
        return await license_store.update_user(user_id, request)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _fetch_mitre_groups() -> list[MitreGroup]:
    request = Request(MITRE_ENTERPRISE_STIX_URL, headers={"User-Agent": "CyberDecisionEngine/0.1"})
    with urlopen(request, timeout=12) as response:
        payload = json.loads(response.read().decode("utf-8"))

    objects = payload.get("objects", [])
    relationships = [item for item in objects if item.get("type") == "relationship" and item.get("relationship_type") == "uses"]
    technique_by_id = {
        item.get("id"): _external_id(item)
        for item in objects
        if item.get("type") == "attack-pattern" and not item.get("revoked") and not item.get("x_mitre_deprecated")
    }
    techniques_by_group: dict[str, set[str]] = {}
    for relationship in relationships:
        source = relationship.get("source_ref")
        target = relationship.get("target_ref")
        technique = technique_by_id.get(target)
        if source and technique:
            techniques_by_group.setdefault(source, set()).add(technique)

    groups = []
    for item in objects:
        if item.get("type") != "intrusion-set" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        groups.append(
            MitreGroup(
                id=_external_id(item) or item.get("id", ""),
                name=item.get("name", "Unknown group"),
                aliases=[alias for alias in item.get("aliases", []) if alias != item.get("name")],
                techniques=sorted(techniques_by_group.get(item.get("id"), set())),
                description=item.get("description"),
            )
        )
    return sorted(groups, key=lambda group: group.name.lower())


def _external_id(item: dict) -> str:
    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return reference["external_id"]
    return ""


@app.get("/api/runs/{run_id}", response_model=RunRecord)
async def get_run(run_id: str) -> RunRecord:
    run = await store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


@app.get("/api/runs/{run_id}/snapshot", response_model=Dict[str, Any])
async def get_run_snapshot(run_id: str) -> Dict[str, Any]:
    run = await store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    if not run.summary.decision_snapshot:
        raise HTTPException(status_code=409, detail="Decision snapshot is not available for this run.")
    return run.summary.decision_snapshot


@app.post("/api/runs/{run_id}/rerun", response_model=RunRecord, status_code=202)
async def rerun(run_id: str) -> RunRecord:
    run = await store.rerun(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


@app.post("/api/runs/{run_id}/report", response_model=RunRecord)
async def generate_run_report(run_id: str) -> RunRecord:
    try:
        run = await store.generate_report(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


@app.patch("/api/runs/{run_id}/evidence/{evidence_id}", response_model=RunRecord)
async def review_run_evidence(
    run_id: str,
    evidence_id: str,
    request: EvidenceReviewRequest,
) -> RunRecord:
    try:
        run = await store.review_evidence(
            run_id,
            evidence_id,
            request.status,
            request.reviewer,
            request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run
