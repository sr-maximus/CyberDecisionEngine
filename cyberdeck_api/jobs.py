from __future__ import annotations

import asyncio
from concurrent.futures import ProcessPoolExecutor
from contextlib import suppress
from copy import deepcopy
import hashlib
import json
import multiprocessing
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cyberdeck.cli import run_pipeline
from cyberdeck.analysis.multidomain import (
    enrich_multidomain_findings,
    enrich_multidomain_intelligence,
    project_context_by_intelligence_filters,
    public_source_status,
    sanitize_public_payload,
)
from cyberdeck.analysis.evidence_review import build_evidence_review_summary
from cyberdeck.decision_intelligence import (
    DecisionIntelligenceSnapshot,
    DecisionMetric,
    METRIC_CATALOG,
    SNAPSHOT_SCHEMA_VERSION,
    SNAPSHOT_VERSION,
    snapshot_from_context,
)
from cyberdeck.reporting.html_report import (
    REPORT_GENERATOR_VERSION,
    prepare_context_for_report,
    render_report,
)
from cyberdeck.schemas import EvidenceStatus, RecordKind, RunContext
from cyberdeck.semantics import get_term_registry
from cyberdeck.settings import PROJECT_ROOT, load_sources_config, write_yaml
from cyberdeck.snapshot_integrity import seal_snapshot, verify_snapshot
from cyberdeck_api.domain_scope import (
    build_organization_profile,
    build_source_config,
    normalize_domains,
    slug_from_domains,
)
from cyberdeck_api.evidence_capture import attach_report_evidence_captures
from cyberdeck_api.models import (
    AnalysisSummary,
    DomainAnalysisRequest,
    DomainSignal,
    KpiSummary,
    ReportSummary,
    RunRecord,
    normalize_analysis_window,
    utcnow_iso,
)


_SCOPE_PROFILE_SCALARS = (
    "organization_name",
    "legal_name",
    "sector",
    "subsector",
    "country",
)
_SCOPE_PROFILE_LISTS = (
    "brands",
    "subsidiaries",
    "parent_organizations",
    "products",
    "strategic_assets",
    "critical_suppliers",
    "declared_competitors",
    "countries_of_operation",
    "entity_aliases",
)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _parse_iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _prepare_and_render_report_process(
    context_path: str,
    prepared_context_path: str,
    run_id: str,
    technology_domains: List[str],
    analysis_domains: List[str],
    output_path: str,
) -> str:
    """Prepare and render reports outside the API event-loop process."""
    context = RunContext.model_validate_json(Path(context_path).read_text(encoding="utf-8"))
    report_context = project_context_by_intelligence_filters(
        context,
        technology_domains,
        analysis_domains,
    )
    report_context = prepare_context_for_report(report_context, run_id)
    output = render_report(report_context, output_path, prepared=True)
    prepared_path = Path(prepared_context_path)
    prepared_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = prepared_path.with_suffix(f"{prepared_path.suffix}.tmp")
    temporary_path.write_text(report_context.model_dump_json(indent=2), encoding="utf-8")
    temporary_path.replace(prepared_path)
    return str(output)


def _report_filter_suffix(technology_domains: List[str], analysis_domains: List[str]) -> str:
    values = [*technology_domains, *analysis_domains]
    if not values:
        return ""
    normalized = "-".join(re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") for value in values)
    digest = hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()[:8]
    return f"-view-{normalized[:48]}-{digest}"


def _future_iso(seconds: int, *, base: Optional[str] = None) -> str:
    origin = _parse_iso(base) if base else datetime.now(timezone.utc)
    return (origin + timedelta(seconds=max(0, seconds))).isoformat()


def _compact_run(run: RunRecord) -> RunRecord:
    compact_summary = AnalysisSummary(
        kpis=run.summary.kpis.model_copy(deep=True),
        domain_signals=[item.model_copy(deep=True) for item in run.summary.domain_signals],
        semantic_registry_version=run.summary.semantic_registry_version,
        claim_evidence_model_version=run.summary.claim_evidence_model_version,
    )
    # The status view replaces the large summary completely. A deep copy here
    # traversed every collected record before discarding it, making polling
    # proportional to the full evidence corpus.
    return run.model_copy(update={"summary": compact_summary})


def _drop_reference_lists(rows: object) -> None:
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in list(row):
            if key.endswith(("_ids", "_urls")) or key in {"evidence", "events"}:
                row.pop(key, None)


def _dashboard_run(run: RunRecord) -> RunRecord:
    """Return the complete analytical view without raw persistence duplicates."""
    source = run.summary
    summary = AnalysisSummary(
        kpis=source.kpis.model_copy(deep=True),
        domain_signals=[item.model_copy(deep=True) for item in source.domain_signals],
        findings=deepcopy(source.findings),
        events=deepcopy(source.events),
        records=[],
        source_statuses=deepcopy(source.source_statuses),
        metrics=deepcopy(source.metrics),
        processing_summary=deepcopy(source.processing_summary),
        decision_snapshot=deepcopy(source.decision_snapshot),
        claims=deepcopy(source.claims),
        evidence_items=deepcopy(source.evidence_items),
        claim_evidence_links=deepcopy(source.claim_evidence_links),
        contradicting_evidence=deepcopy(source.contradicting_evidence),
        interpretations=deepcopy(source.interpretations),
        decisions=deepcopy(source.decisions),
        semantic_registry_version=source.semantic_registry_version,
        claim_evidence_model_version=source.claim_evidence_model_version,
    )
    projected = run.model_copy(update={"summary": summary}, deep=False)

    referenced_evidence = {
        str(evidence_id)
        for claim in summary.claims
        for evidence_id in claim.get("evidence_ids", [])
        if evidence_id
    }
    referenced_evidence.update(
        str(link.get("evidence_id"))
        for link in summary.claim_evidence_links
        if link.get("evidence_id")
    )
    summary.evidence_items = [
        item
        for item in summary.evidence_items
        if str(item.get("evidence_id")) in referenced_evidence
    ]

    metrics = summary.metrics
    strategic_news = metrics.get("strategic_news")
    if isinstance(strategic_news, dict):
        strategic_news.pop("rejected_articles", None)
        strategic_news.pop("pestel", None)
        strategic_news.pop("porter", None)

    framework_mapping = metrics.get("framework_mapping")
    if isinstance(framework_mapping, dict):
        mappings = framework_mapping.get("mappings")
        if isinstance(mappings, list):
            for mapping in mappings:
                if not isinstance(mapping, dict):
                    continue
                for key in (
                    "evidence_ids",
                    "validated_evidence_ids",
                    "direct_evidence_ids",
                    "direct_relationship_evidence_ids",
                ):
                    mapping.pop(key, None)
                evidence = mapping.get("evidence")
                if isinstance(evidence, list):
                    mapping["evidence"] = evidence[:6]

    for metric_name in ("geographic_intelligence", "sector_intelligence"):
        metric = metrics.get(metric_name)
        if not isinstance(metric, dict):
            continue
        for value in metric.values():
            _drop_reference_lists(value)

    pivot_intelligence = metrics.get("pivot_intelligence")
    if isinstance(pivot_intelligence, dict):
        pivot_intelligence.pop("entities", None)
    public_entities = metrics.get("public_entity_intelligence")
    if isinstance(public_entities, dict):
        public_entities.pop("rows", None)
    narrative = metrics.get("narrative_intelligence")
    if isinstance(narrative, dict):
        narrative.pop("groups", None)
    source_coverage = metrics.get("source_coverage")
    if isinstance(source_coverage, dict):
        for key in ("connector_diagnostics", "connectors", "osint", "socmint", "darkweb"):
            source_coverage.pop(key, None)

    # These snapshot sections duplicate the canonical top-level metrics. The
    # decision cards only consume snapshot identity, KPIs, domains and actions.
    for key in (
        "coverage",
        "strategic_news",
        "pestel",
        "porter",
        "strategic_drivers",
        "strategic_models",
        "evidence_references",
        "metric_definitions",
    ):
        summary.decision_snapshot.pop(key, None)
    return projected


def _refresh_report_validation(run: RunRecord) -> bool:
    if not run.report or not run.report.validation_path:
        return False
    validation_path = Path(run.report.validation_path)
    if not validation_path.is_file():
        return False
    try:
        payload = json.loads(validation_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    status = str(payload.get("status") or "")
    if status not in {"approved", "approved_with_observations", "rejected"}:
        return False
    final = status != "rejected"
    changed = run.report.validation_status != status or run.report.final != final
    run.report.validation_status = status
    run.report.final = final
    return changed


def _report_matches_snapshot(run: RunRecord) -> bool:
    report = run.report
    if report is None or not report.report_snapshot_hash or not report.source_snapshot_hash:
        return False
    if report.generator_version != REPORT_GENERATOR_VERSION:
        return False
    expected_source_hash = str(run.summary.decision_snapshot.get("snapshot_hash") or "")
    if not expected_source_hash or report.source_snapshot_hash != expected_source_hash:
        return False
    snapshot_path = Path(report.path).with_name(f"{Path(report.path).stem}_decision_snapshot.json")
    try:
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(
        isinstance(payload, dict)
        and verify_snapshot(payload)
        and payload.get("snapshot_hash") == report.report_snapshot_hash
    )


def _hydrate_report_lifecycle(run: RunRecord) -> bool:
    changed = _refresh_report_validation(run)
    if run.report:
        if not _report_matches_snapshot(run):
            run.report_status = "not_requested"
            run.report_error = (
                "Stored report requires regeneration for the current decision snapshot."
            )
            run.report.final = False
            run.report.validation_status = "rejected"
            run.report_auto_due_at = None
            return True
        run.report_status = "ready"
        run.report_error = None
        run.report_auto_due_at = None
        return changed
    interrupted = run.report_status in {"queued", "generating"} or run.stage.lower().startswith(
        (
            "capturing public evidence",
            "generating html",
            "generating executive",
            "report generation queued",
        )
    )
    if interrupted:
        run.report_status = "not_requested"
        run.report_error = (
            "Report generation was interrupted when the API restarted; it was rescheduled."
        )
    # Only resume reports that were explicitly queued before a restart. Historical
    # completed runs predate automatic reporting and must never create a backlog.
    if (
        run.status == "completed"
        and not run.report_auto_due_at
        and (interrupted or run.report_requested_at)
    ):
        run.report_auto_due_at = _future_iso(
            _env_int("CDE_AUTO_REPORT_DELAY_SECONDS", 600), base=run.updated_at
        )
        changed = True
    return changed


def _reuse_exact_scope_profile(
    request: DomainAnalysisRequest,
    domains: List[str],
    runs: List[RunRecord],
) -> DomainAnalysisRequest:
    """Fill missing declared profile fields from the newest completed exact scope."""
    if request.subject_type != "organization" or not domains:
        return request
    domain_key = tuple(sorted(domain.lower() for domain in domains))
    candidates = sorted(runs, key=lambda item: item.created_at, reverse=True)
    for candidate in candidates:
        if candidate.status != "completed" or candidate.request.subject_type != "organization":
            continue
        candidate_key = tuple(sorted(domain.lower() for domain in candidate.domains))
        if candidate_key != domain_key:
            continue
        source = candidate.request
        if request.organization_name and source.organization_name:
            if (
                request.organization_name.strip().casefold()
                != source.organization_name.strip().casefold()
            ):
                continue
        hydrated = request.model_copy(deep=True)
        applied: List[str] = []
        for field_name in _SCOPE_PROFILE_SCALARS:
            if getattr(hydrated, field_name) or not getattr(source, field_name):
                continue
            setattr(hydrated, field_name, getattr(source, field_name))
            applied.append(field_name)
        for field_name in _SCOPE_PROFILE_LISTS:
            if getattr(hydrated, field_name) or not getattr(source, field_name):
                continue
            setattr(hydrated, field_name, list(getattr(source, field_name)))
            applied.append(field_name)
        if applied:
            hydrated.scope_profile_source_run_id = candidate.id
            hydrated.scope_profile_applied_fields = applied
            return hydrated
    return request


class RunStore:
    def __init__(self, state_path: Optional[Path] = None) -> None:
        self.state_path = state_path or PROJECT_ROOT / "data" / "web_runs.json"
        self.run_dir = PROJECT_ROOT / "data" / "web_runs"
        self.report_dir = PROJECT_ROOT / "reports" / "web"
        self.database_url = os.getenv("DATABASE_URL")
        self._runs: Dict[str, RunRecord] = {}
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Optional[asyncio.AbstractEventLoop] = None
        self._report_tasks: Dict[str, asyncio.Task[None]] = {}
        self._auto_report_tasks: Dict[str, asyncio.Task[None]] = {}
        self._report_locks: Dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Lock]] = {}
        self._report_semaphore: Optional[asyncio.Semaphore] = None
        self._report_semaphore_loop: Optional[asyncio.AbstractEventLoop] = None
        self._report_concurrency = max(1, _env_int("CDE_REPORT_CONCURRENCY", 1))
        self._report_executor = ProcessPoolExecutor(
            max_workers=self._report_concurrency,
            mp_context=multiprocessing.get_context("spawn"),
        )
        self._auto_report_delay_seconds = max(0, _env_int("CDE_AUTO_REPORT_DELAY_SECONDS", 600))
        self._report_capture_timeout_seconds = max(
            30, _env_int("CDE_REPORT_CAPTURE_TIMEOUT_SECONDS", 180)
        )

    def _active_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def _active_report_lock(self, run_id: str) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        current = self._report_locks.get(run_id)
        if current is None or current[0] is not loop:
            current = (loop, asyncio.Lock())
            self._report_locks[run_id] = current
        return current[1]

    def _active_report_semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._report_semaphore is None or self._report_semaphore_loop is not loop:
            self._report_semaphore = asyncio.Semaphore(self._report_concurrency)
            self._report_semaphore_loop = loop
        return self._report_semaphore

    async def load(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        if self.database_url:
            await asyncio.to_thread(self._load_postgres)
            await self._mark_interrupted_runs()
            self._resume_report_schedules()
            return
        if not self.state_path.exists():
            return
        payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        for item in payload.get("runs", []):
            run = RunRecord(**item)
            _remove_legacy_opencti_source(run)
            _hydrate_source_lifecycle(run)
            _hydrate_report_lifecycle(run)
            self._runs[run.id] = run
        await self._mark_interrupted_runs()
        self._resume_report_schedules()

    async def stop(self) -> None:
        tasks = [*self._report_tasks.values(), *self._auto_report_tasks.values()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.to_thread(
            self._report_executor.shutdown,
            wait=True,
            cancel_futures=True,
        )

    async def list_runs(self) -> List[RunRecord]:
        async with self._active_lock():
            return sorted(self._runs.values(), key=lambda item: item.created_at, reverse=True)

    async def list_run_statuses(self) -> List[RunRecord]:
        async with self._active_lock():
            runs = sorted(self._runs.values(), key=lambda item: item.created_at, reverse=True)
            return [_compact_run(run) for run in runs]

    async def get_run(self, run_id: str) -> Optional[RunRecord]:
        async with self._active_lock():
            return self._runs.get(run_id)

    async def get_dashboard_run(self, run_id: str) -> Optional[RunRecord]:
        async with self._active_lock():
            run = self._runs.get(run_id)
            return _dashboard_run(run) if run else None

    async def create_run(self, request: DomainAnalysisRequest) -> RunRecord:
        request = normalize_analysis_window(request)
        if not request.authorized_scope:
            raise PermissionError("Analysis requires authorized_scope=true.")
        domains = normalize_domains(request.domains) if request.domains else []
        if not domains and not request.subject_name:
            raise ValueError(
                "At least one domain, organization/brand name, or person name is required."
            )
        competitors = (
            normalize_domains(request.competitor_domains) if request.competitor_domains else []
        )
        request.domains = domains
        request.competitor_domains = competitors
        async with self._active_lock():
            request = _reuse_exact_scope_profile(request, domains, list(self._runs.values()))
            if (
                request.subject_type == "organization"
                and len(domains) > 1
                and not request.subject_name
            ):
                raise ValueError(
                    "Marca, grupo o conglomerado is required for a new multi-domain analysis. "
                    "An exact prior scope can supply a previously declared profile."
                )
            run = RunRecord(
                id=uuid4().hex[:12],
                status="queued",
                stage="Queued",
                request=request,
                domains=domains,
                progress=5,
                estimated_seconds=_estimated_run_seconds(request, domains),
                summary=_planned_summary(domains, request),
            )
            self._runs[run.id] = run
            # A new run is independent from historical payloads. Persisting only
            # this row keeps large multi-domain histories out of the launch path.
            await self._persist_run_locked(run)
        asyncio.create_task(self._execute(run.id))
        return run

    async def rerun(self, run_id: str) -> Optional[RunRecord]:
        run = await self.get_run(run_id)
        if run is None:
            return None
        return await self.create_run(run.request)

    async def _execute(self, run_id: str) -> None:
        await self._update(
            run_id, status="running", stage="Preparing authorized domain scope", progress=15
        )
        run = await self.get_run(run_id)
        if run is None:
            return
        try:
            org_profile = build_organization_profile(run.request, run.domains)
            org_path = self.run_dir / run.id / "org.yml"
            write_yaml(org_path, org_profile)

            base_sources = load_sources_config().get("sources", {})
            source_config = build_source_config(
                base_sources,
                run.domains,
                run.request.subject_name,
                run.request.competitor_domains,
                run.request.country,
                run.request.mode,
                run.request.scan_time_budget_minutes,
                run.request.sector,
                run.request.subject_type,
                run.request.person_aliases,
                {
                    "brands": run.request.brands,
                    "subsidiaries": run.request.subsidiaries,
                    "parent_organizations": run.request.parent_organizations,
                    "products": run.request.products,
                    "strategic_assets": run.request.strategic_assets,
                    "critical_suppliers": run.request.critical_suppliers,
                    "declared_competitors": run.request.declared_competitors,
                    "competitor_domains": run.request.competitor_domains,
                    "countries_of_operation": run.request.countries_of_operation,
                    "subsector": run.request.subsector,
                },
            )
            slug = slug_from_domains(run.domains or [run.request.subject_name or "subject"])
            report_path = self.report_dir / f"{run.id}-{slug}.html"
            context_path = self._context_path(run.id)

            await self._update(
                run_id,
                stage="Collecting public OSINT, strategic RSS, SOCMINT, dark-web indexes and external-surface evidence",
                progress=35,
                estimated_seconds=_estimated_collection_seconds(source_config),
            )
            async def progress_callback(stage, progress, source_status=None):
                await self._collection_progress(run_id, stage, progress, source_status)

            run_timeout = min(172800, max(120, _env_int("CDE_RUN_TIMEOUT_SECONDS", 172800)))
            try:
                _, context = await asyncio.wait_for(run_pipeline(
                    str(org_path),
                    run.request.mode,
                    run.request.lookback_days,
                    str(report_path),
                    real_only=run.request.real_only,
                    source_config_override=source_config,
                    return_context=True,
                    render_html=False,
                    progress_callback=progress_callback,
                ), timeout=run_timeout)
            except asyncio.TimeoutError:
                raise RuntimeError(f"Analysis exceeded its {run_timeout}-second safety deadline; review source coverage before retrying.")
            context = await asyncio.to_thread(prepare_context_for_report, context, run.id)
            await asyncio.to_thread(self._write_context, context_path, context)
            await self._update(run_id, stage="Building decision dashboards", progress=94)
            await self._complete(run_id, context)
        except Exception as exc:  # pragma: no cover - runtime and network dependent
            await self._fail(run_id, str(exc))

    async def _collection_progress(self, run_id, stage, progress, source_status=None) -> None:
        async with self._active_lock():
            run = self._runs.get(run_id)
            if run is None or run.status != "running":
                return
            if source_status is not None:
                run.summary.source_statuses = [
                    item for item in run.summary.source_statuses if item.get("name") != source_status.name
                ] + [source_status.model_dump(mode="json")]
            run.stage = stage
            run.progress = max(run.progress, progress)
            run.updated_at = utcnow_iso()
            await self._persist_run_locked(run)

    async def _update(self, run_id: str, **changes: object) -> None:
        async with self._active_lock():
            run = self._runs.get(run_id)
            if run is None:
                return
            for key, value in changes.items():
                setattr(run, key, value)
            run.updated_at = utcnow_iso()
            await self._persist_run_locked(run)

    async def _complete(self, run_id: str, context: RunContext) -> None:
        summary = summarize_context((await self.get_run(run_id)).domains, context)  # type: ignore[union-attr]
        async with self._active_lock():
            run = self._runs[run_id]
            run.status = "completed"
            run.stage = "Analysis ready - report pending user request"
            run.progress = 100
            run.report = None
            run.summary = summary
            run.report_status = "not_requested"
            run.report_error = None
            run.report_requested_at = None
            run.report_auto_due_at = _future_iso(self._auto_report_delay_seconds)
            run.updated_at = utcnow_iso()
            await self._persist_run_locked(run)
            auto_due_at = run.report_auto_due_at
        self._schedule_auto_report(run_id, auto_due_at)

    async def request_report(
        self,
        run_id: str,
        language: str = "es",
        technology_domains: Optional[List[str]] = None,
        analysis_domains: Optional[List[str]] = None,
        review_mode: str = "manual",
        force: bool = False,
    ) -> Optional[RunRecord]:
        selected_language = "en" if language == "en" else "es"
        selected_technology = sorted(set(technology_domains or []))
        selected_analysis = sorted(set(analysis_domains or []))
        selected_review_mode = "ai_assisted" if review_mode == "ai_assisted" else "manual"
        async with self._active_lock():
            run = self._runs.get(run_id)
            if run is None:
                return None
            if run.status != "completed":
                raise ValueError("Report can only be generated for a completed analysis.")
            if force and run.report_status not in {"queued", "generating"}:
                run.report = None
            if (
                run.report
                and run.report.language == selected_language
                and sorted(run.report.technology_domains) == selected_technology
                and sorted(run.report.analysis_domains) == selected_analysis
                and run.report.review_mode == selected_review_mode
                and _report_matches_snapshot(run)
            ):
                run.report_status = "ready"
                if _refresh_report_validation(run):
                    run.updated_at = utcnow_iso()
                    await self._persist_run_locked(run)
                return _compact_run(run)
            if run.report_status in {"queued", "generating"}:
                return _compact_run(run)
            run.request.language = selected_language
            run.report_status = "queued"
            run.report_error = None
            run.report_requested_at = utcnow_iso()
            run.report_auto_due_at = None
            run.report_review_mode = selected_review_mode
            run.evidence_review_status = "not_started"
            run.evidence_review_summary = {}
            run.stage = "Report generation queued"
            run.updated_at = utcnow_iso()
            await self._persist_report_state_locked(run)
            response = _compact_run(run)
        self._cancel_auto_report(run_id)
        task = self._report_tasks.get(run_id)
        if task is None or task.done():
            self._report_tasks[run_id] = asyncio.create_task(
                self._run_report_task(
                    run_id,
                    selected_language,
                    selected_technology,
                    selected_analysis,
                    selected_review_mode,
                )
            )
        return response

    async def generate_report(
        self,
        run_id: str,
        language: Optional[str] = None,
        technology_domains: Optional[List[str]] = None,
        analysis_domains: Optional[List[str]] = None,
        review_mode: Optional[str] = None,
    ) -> Optional[RunRecord]:
        report_lock = self._active_report_lock(run_id)
        async with report_lock, self._active_report_semaphore():
            run = await self.get_run(run_id)
            if run is None:
                return None
            if run.status != "completed":
                raise ValueError("Report can only be generated for a completed analysis.")
            selected_language = "en" if (language or run.request.language) == "en" else "es"
            selected_technology = sorted(set(technology_domains or []))
            selected_analysis = sorted(set(analysis_domains or []))
            selected_review_mode = (
                "ai_assisted"
                if (review_mode or run.report_review_mode) == "ai_assisted"
                else "manual"
            )
            is_canonical_report = not selected_technology and not selected_analysis
            source_snapshot_hash = str(run.summary.decision_snapshot.get("snapshot_hash") or "")
            if (
                run.report
                and run.report.language == selected_language
                and sorted(run.report.technology_domains) == selected_technology
                and sorted(run.report.analysis_domains) == selected_analysis
                and run.report.review_mode == selected_review_mode
                and _report_matches_snapshot(run)
            ):
                await self._update_report_state(run_id, report_status="ready", stage="Report ready")
                return run
            context_path = self._context_path(run_id)
            try:
                context = await asyncio.to_thread(self._read_context, context_path)
            except FileNotFoundError:
                if run.report:
                    return run
                raise ValueError("Stored analysis context is not available for this run.")

            context.organization.language = selected_language
            await self._update_report_state(
                run_id,
                report_status="generating",
                stage="Capturing public evidence for the report",
                report_error=None,
            )
            try:
                context = await asyncio.wait_for(
                    attach_report_evidence_captures(context, run_id),
                    timeout=self._report_capture_timeout_seconds,
                )
            except asyncio.TimeoutError:
                context.metrics.setdefault("report_generation", {})["capture_warning"] = (
                    f"Evidence capture exceeded {self._report_capture_timeout_seconds} seconds; "
                    "the report continues with the evidence already persisted."
                )
            review_summary = await asyncio.to_thread(
                build_evidence_review_summary,
                context.raw_events,
                selected_review_mode,
            )
            context.metrics["evidence_review"] = review_summary
            await self._update_report_state(
                run_id,
                evidence_review_status="prepared",
                evidence_review_summary=review_summary,
                report_review_mode=selected_review_mode,
                stage="Evidence review prepared and report analytics queued",
            )
            await self._update_report_state(
                run_id,
                stage="Persisting evidence and preparing multidomain report analytics",
            )
            await asyncio.to_thread(self._write_context, context_path, context)
            slug = slug_from_domains(run.domains or [run.request.subject_name or "subject"])
            filter_suffix = _report_filter_suffix(selected_technology, selected_analysis)
            report_path = self.report_dir / f"{run.id}-{slug}{filter_suffix}.html"
            prepared_context_path = self.run_dir / f"{run.id}.report-prepared.json"
            await self._update_report_state(
                run_id, stage="Generating executive and technical HTML reports"
            )
            loop = asyncio.get_running_loop()
            try:
                output_value = await loop.run_in_executor(
                    self._report_executor,
                    _prepare_and_render_report_process,
                    str(context_path),
                    str(prepared_context_path),
                    run_id,
                    selected_technology,
                    selected_analysis,
                    str(report_path),
                )
                output = Path(output_value)
                prepared_payload = await asyncio.to_thread(
                    prepared_context_path.read_text,
                    encoding="utf-8",
                )
                report_context = RunContext.model_validate_json(prepared_payload)
            finally:
                prepared_context_path.unlink(missing_ok=True)
            technical_output = output.with_name(f"{output.stem}-technical{output.suffix}")
            validation_path = output.with_name(f"{output.stem}_validation.json")
            validation_payload = json.loads(validation_path.read_text(encoding="utf-8"))
            validation_status = str(validation_payload.get("status") or "rejected")
            report_snapshot_hash = str(report_context.decision_snapshot.get("snapshot_hash") or "")
            if is_canonical_report:
                source_snapshot_hash = report_snapshot_hash
            if is_canonical_report:
                await asyncio.to_thread(self._write_context, context_path, report_context)
            relative_report = output.relative_to(PROJECT_ROOT / "reports").as_posix()
            relative_technical = technical_output.relative_to(PROJECT_ROOT / "reports").as_posix()
            async with self._active_lock():
                current = self._runs[run_id]
                generated_report = ReportSummary(
                    path=str(output),
                    url=f"/reports/{relative_report}",
                    download_url=f"/api/reports/{relative_report}/download",
                    technical_path=str(technical_output),
                    technical_url=f"/reports/{relative_technical}",
                    technical_download_url=f"/api/reports/{relative_technical}/download",
                    generated_at=report_context.report_display_at or report_context.generated_at,
                    validation_status=validation_status,
                    validation_path=str(validation_path),
                    final=validation_status != "rejected",
                    language=selected_language,
                    technology_domains=selected_technology,
                    analysis_domains=selected_analysis,
                    source_snapshot_hash=source_snapshot_hash,
                    report_snapshot_hash=report_snapshot_hash,
                    generator_version=REPORT_GENERATOR_VERSION,
                    review_mode=selected_review_mode,
                )
                if is_canonical_report:
                    current.request.language = selected_language
                    current.stage = "Report ready"
                    current.report_status = "ready"
                    current.report_error = None
                    current.report_auto_due_at = None
                    current.report = generated_report
                    current.summary = summarize_context(current.domains, report_context)
                    current.evidence_review_status = "completed"
                    current.evidence_review_summary = review_summary
                    current.report_review_mode = selected_review_mode
                elif current.report:
                    current.stage = "Filtered export ready"
                    current.report_status = "ready"
                    current.report_error = None
                else:
                    current.stage = "Filtered export ready; canonical report pending"
                    current.report_status = "not_requested"
                    current.report_error = None
                current.updated_at = utcnow_iso()
                await self._persist_run_locked(current)
                return current

    async def _run_report_task(
        self,
        run_id: str,
        language: str,
        technology_domains: List[str],
        analysis_domains: List[str],
        review_mode: str,
    ) -> None:
        try:
            await self.generate_report(
                run_id,
                language,
                technology_domains,
                analysis_domains,
                review_mode,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - network and renderer dependent
            await self._update_report_state(
                run_id,
                report_status="failed",
                stage="Report generation failed",
                report_error=str(exc),
            )
        finally:
            self._report_tasks.pop(run_id, None)

    async def _update_report_state(self, run_id: str, **changes: object) -> None:
        async with self._active_lock():
            run = self._runs.get(run_id)
            if run is None:
                return
            for key, value in changes.items():
                setattr(run, key, value)
            run.updated_at = utcnow_iso()
            await self._persist_report_state_locked(run)

    def _schedule_auto_report(self, run_id: str, due_at: Optional[str]) -> None:
        if not due_at:
            return
        task = self._auto_report_tasks.get(run_id)
        if task is None or task.done():
            self._auto_report_tasks[run_id] = asyncio.create_task(
                self._auto_generate_report(run_id, due_at)
            )

    def _resume_report_schedules(self) -> None:
        for run in self._runs.values():
            if run.status == "completed" and not run.report and run.report_auto_due_at:
                self._schedule_auto_report(run.id, run.report_auto_due_at)

    async def _auto_generate_report(self, run_id: str, due_at: str) -> None:
        try:
            delay = max(0.0, (_parse_iso(due_at) - datetime.now(timezone.utc)).total_seconds())
            await asyncio.sleep(delay)
            run = await self.get_run(run_id)
            if (
                run
                and run.status == "completed"
                and not run.report
                and run.report_status not in {"queued", "generating"}
            ):
                await self.request_report(run_id, run.request.language)
        except asyncio.CancelledError:
            raise
        finally:
            self._auto_report_tasks.pop(run_id, None)

    def _cancel_auto_report(self, run_id: str) -> None:
        task = self._auto_report_tasks.pop(run_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()

    @staticmethod
    def _apply_evidence_review(event: Any, status: str, reviewer: str, reason: str) -> None:
        validation = dict(event.technical_validation or {})
        if "review_previous_evidence_status" not in validation:
            validation["review_previous_evidence_status"] = str(
                getattr(event.evidence_status, "value", event.evidence_status)
            )
            validation["review_previous_record_kind"] = str(
                getattr(event.record_kind, "value", event.record_kind)
            )
        validation["human_review"] = {
            "status": status,
            "reviewer": reviewer,
            "reason": reason,
            "reviewed_at": utcnow_iso(),
        }

        if status == "validated":
            event.tags = [tag for tag in event.tags if tag != "false_positive"]
            event.evidence_status = EvidenceStatus.VALIDATED
            event.record_kind = RecordKind.VALIDATED_TECHNICAL_EVIDENCE
            event.validation_result = "human_review"
            event.human_reviewed = True
            validation["validation_method"] = "human_review"
            validation["validator"] = reviewer
        elif status == "false_positive":
            event.evidence_status = EvidenceStatus.FALSE_POSITIVE
            event.record_kind = RecordKind.FALSE_POSITIVE
            event.validation_result = "human_false_positive"
            event.human_reviewed = True
            validation["validation_method"] = "human_review"
            validation["validator"] = reviewer
            if "false_positive" not in event.tags:
                event.tags.append("false_positive")
        elif status == "pending":
            previous_status = str(validation.get("review_previous_evidence_status") or "related")
            previous_kind = str(validation.get("review_previous_record_kind") or "collected_record")
            event.evidence_status = EvidenceStatus(previous_status)
            event.record_kind = RecordKind(previous_kind)
            event.validation_result = "not_validated"
            event.human_reviewed = False
            event.tags = [tag for tag in event.tags if tag != "false_positive"]
            validation.pop("validation_method", None)
            validation.pop("validator", None)
        else:
            raise ValueError("Unsupported evidence review status.")
        event.technical_validation = validation

    async def review_evidence(
        self, run_id: str, evidence_id: str, status: str, reviewer: str, reason: str = ""
    ) -> Optional[RunRecord]:
        return await self.review_evidence_batch(run_id, [{
            "evidence_id": evidence_id, "status": status, "reviewer": reviewer, "reason": reason,
        }])

    async def review_evidence_batch(
        self, run_id: str, reviews: List[Dict[str, str]]
    ) -> Optional[RunRecord]:
        # Serialize the entire read/modify/write cycle, including report generation.
        async with self._active_report_lock(run_id):
            return await self._review_evidence_batch(run_id, reviews)

    async def get_evidence(self, run_id: str) -> Optional[List[Dict[str, Any]]]:
        if await self.get_run(run_id) is None:
            return None
        def read_evidence() -> List[Dict[str, Any]]:
            context = self._read_context(self._context_path(run_id))
            fields = {"id", "canonical_id", "public_evidence_id", "title", "category", "source", "evidence_url", "original_artifact_url", "evidence_type", "evidence_status", "technical_validation", "tags", "asset", "host"}
            return sanitize_public_payload([
                event.model_dump(mode="json", include=fields)
                for event in context.raw_events if event.evidence_url or event.original_artifact_url
            ])
        return await asyncio.to_thread(read_evidence)

    async def _review_evidence_batch(
        self, run_id: str, reviews: List[Dict[str, str]]
    ) -> Optional[RunRecord]:
        if not 1 <= len(reviews) <= 500:
            raise ValueError("A review batch must contain between 1 and 500 changes.")
        run = await self.get_run(run_id)
        if run is None:
            return None
        if run.status != "completed":
            raise ValueError("Evidence can only be reviewed after the analysis completes.")
        context_path = self._context_path(run_id)
        context = await asyncio.to_thread(self._read_context, context_path)
        events_by_id = {}
        for event in context.raw_events:
            seed = str(event.canonical_id or event.content_hash or event.id)
            public_id = str(event.public_evidence_id or "").strip() or (
                "CDE-EV-" + hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:16].upper()
            )
            for identifier in (str(event.id), str(event.canonical_id or ""), public_id):
                if identifier:
                    events_by_id[identifier] = event
        # Validate the whole batch before modifying any stored evidence.
        for review in reviews:
            if review.get("evidence_id") not in events_by_id:
                raise ValueError("Evidence record was not found in the stored run context.")
            if review.get("status") not in {"validated", "false_positive", "pending"}:
                raise ValueError("Unsupported evidence review status.")
        for review in reviews:
            self._apply_evidence_review(
                events_by_id[review["evidence_id"]], review["status"],
                review.get("reviewer", "authorized_user"), review.get("reason", ""),
            )

        false_positive_ids = {
            str(item.canonical_id or item.id)
            for item in context.raw_events
            if item.evidence_status == EvidenceStatus.FALSE_POSITIVE
        }
        context.risk_findings = [
            finding
            for finding in context.risk_findings
            if not finding.linked_evidence_ids
            or not set(finding.linked_evidence_ids).issubset(false_positive_ids)
        ]
        context.processing_summary["false_positives"] = len(false_positive_ids)
        # A review changes the evidence counts even when the record count is unchanged.
        context.processing_summary.pop("unique_records", None)
        context.claim_evidence_model_version = ""
        context.claims = []
        context.evidence_items = []
        context.claim_evidence_links = []
        context.contradicting_evidence = []
        context.interpretations = []
        context.decisions = []
        context = await asyncio.to_thread(prepare_context_for_report, context, run_id)
        await asyncio.to_thread(self._write_context, context_path, context)
        summary = await asyncio.to_thread(summarize_context, run.domains, context)
        async with self._active_lock():
            current = self._runs[run_id]
            current.summary = summary
            current.report = None
            current.report_status = "not_requested"
            current.report_error = None
            current.report_requested_at = None
            current.report_auto_due_at = _future_iso(self._auto_report_delay_seconds)
            current.stage = "Evidence review applied - report regeneration required"
            current.updated_at = utcnow_iso()
            await self._persist_run_locked(current)
            auto_due_at = current.report_auto_due_at
        self._schedule_auto_report(run_id, auto_due_at)
        return await asyncio.to_thread(_dashboard_run, current)

    def _context_path(self, run_id: str) -> Path:
        return self.run_dir / run_id / "context.json"

    def _write_context(self, path: Path, context: RunContext) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = context.model_dump_json(indent=2)
        temporary_path = path.with_suffix(".tmp")
        temporary_path.write_text(payload, encoding="utf-8")
        temporary_path.replace(path)
        if self.database_url:
            self._persist_context_postgres(path.parent.name, payload)

    def _read_context(self, path: Path) -> RunContext:
        if path.exists():
            return RunContext(**json.loads(path.read_text(encoding="utf-8")))
        if self.database_url:
            payload = self._load_context_postgres(path.parent.name)
            if payload is not None:
                return RunContext(**payload)
        raise FileNotFoundError(path)

    def _persist_context_postgres(self, run_id: str, payload: str) -> None:
        if not self.database_url:
            return
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - dependency/runtime guard
            raise RuntimeError("DATABASE_URL is configured but psycopg is not installed.") from exc
        parsed = json.loads(payload)
        processing = parsed.get("processing_summary", {}) or {}
        with psycopg.connect(self.database_url) as conn:
            _ensure_runs_table(conn)
            conn.execute(
                """
                INSERT INTO run_contexts
                    (run_id, schema_version, raw_records, unique_records, payload, updated_at)
                VALUES (%s, %s, %s, %s, %s::jsonb, now())
                ON CONFLICT (run_id) DO UPDATE SET
                    schema_version = EXCLUDED.schema_version,
                    raw_records = EXCLUDED.raw_records,
                    unique_records = EXCLUDED.unique_records,
                    payload = EXCLUDED.payload,
                    updated_at = now()
                """,
                (
                    run_id,
                    str(parsed.get("model_version") or "1"),
                    int(
                        processing.get(
                            "raw_records_collected", len(parsed.get("raw_events", []) or [])
                        )
                    ),
                    int(processing.get("unique_records", len(parsed.get("raw_events", []) or []))),
                    payload,
                ),
            )
            _persist_strategic_rows(conn, run_id, parsed)
            conn.commit()

    def _load_context_postgres(self, run_id: str) -> Optional[Dict[str, Any]]:
        if not self.database_url:
            return None
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - dependency/runtime guard
            raise RuntimeError("DATABASE_URL is configured but psycopg is not installed.") from exc
        with psycopg.connect(self.database_url) as conn:
            _ensure_runs_table(conn)
            row = conn.execute(
                "SELECT payload FROM run_contexts WHERE run_id = %s", (run_id,)
            ).fetchone()
        return _json_payload(row[0]) if row else None

    async def _fail(self, run_id: str, message: str) -> None:
        async with self._active_lock():
            run = self._runs.get(run_id)
            if run is None:
                return
            run.status = "failed"
            run.stage = "Run failed"
            run.error = message
            run.progress = 100
            run.updated_at = utcnow_iso()
            await self._persist_run_locked(run)

    async def _persist_run_locked(self, run: RunRecord) -> None:
        if self.database_url:
            await asyncio.to_thread(self._persist_postgres, [run.model_dump(mode="json")])
            return
        await self._persist_locked()

    async def _persist_report_state_locked(self, run: RunRecord) -> None:
        if self.database_url:
            await asyncio.to_thread(self._persist_report_state_postgres, run)
            return
        await self._persist_locked()

    async def _persist_locked(self) -> None:
        if self.database_url:
            payloads = [run.model_dump(mode="json") for run in self._runs.values()]
            await asyncio.to_thread(self._persist_postgres, payloads)
            return
        payload = {
            "runs": [run.model_dump(mode="json") for run in self._runs.values()],
        }
        tmp_path = self.state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp_path.replace(self.state_path)

    async def _mark_interrupted_runs(self) -> None:
        async with self._active_lock():
            changed = False
            for run in self._runs.values():
                changed = _hydrate_report_lifecycle(run) or changed
                if run.status in {"queued", "running"}:
                    run.status = "failed"
                    run.stage = "Interrupted before completion"
                    run.error = "The API restarted while this run was active."
                    run.updated_at = utcnow_iso()
                    run.progress = 100
                    changed = True
                if run.report_error and run.status == "completed":
                    changed = True
            if changed:
                await self._persist_locked()

    def _load_postgres(self) -> None:
        if not self.database_url:
            return
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - dependency/runtime guard
            raise RuntimeError("DATABASE_URL is configured but psycopg is not installed.") from exc
        with psycopg.connect(self.database_url) as conn:
            _ensure_runs_table(conn)
            rows = conn.execute("SELECT payload FROM web_runs ORDER BY updated_at DESC").fetchall()
        for row in rows:
            payload = _json_payload(row[0])
            run = RunRecord(**payload)
            _remove_legacy_opencti_source(run)
            _hydrate_source_lifecycle(run)
            self._runs[run.id] = run

    def _persist_postgres(self, payloads: List[Dict[str, Any]]) -> None:
        if not self.database_url:
            return
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - dependency/runtime guard
            raise RuntimeError("DATABASE_URL is configured but psycopg is not installed.") from exc
        with psycopg.connect(self.database_url) as conn:
            _ensure_runs_table(conn)
            with conn.cursor() as cur:
                for payload in payloads:
                    cur.execute(
                        """
                        INSERT INTO web_runs (id, status, created_at, updated_at, payload)
                        VALUES (%s, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (id) DO UPDATE SET
                            status = EXCLUDED.status,
                            updated_at = EXCLUDED.updated_at,
                            payload = EXCLUDED.payload
                        """,
                        (
                            payload["id"],
                            payload["status"],
                            payload["created_at"],
                            payload["updated_at"],
                            json.dumps(payload),
                        ),
                    )
            conn.commit()

    def _persist_report_state_postgres(self, run: RunRecord) -> None:
        if not self.database_url:
            return
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - dependency/runtime guard
            raise RuntimeError("DATABASE_URL is configured but psycopg is not installed.") from exc
        patch = {
            "stage": run.stage,
            "updated_at": run.updated_at,
            "report_status": run.report_status,
            "report_error": run.report_error,
            "report_requested_at": run.report_requested_at,
            "report_auto_due_at": run.report_auto_due_at,
            "request": run.request.model_dump(mode="json"),
        }
        with psycopg.connect(self.database_url) as conn:
            _ensure_runs_table(conn)
            conn.execute(
                """
                UPDATE web_runs
                SET status = %s, updated_at = %s, payload = payload || %s::jsonb
                WHERE id = %s
                """,
                (run.status, run.updated_at, json.dumps(patch), run.id),
            )
            conn.commit()


def summarize_context(domains: List[str], context: RunContext) -> AnalysisSummary:
    context.source_statuses = [
        status for status in context.source_statuses if status.name.strip().lower() != "opencti"
    ]
    _remove_opencti_from_coverage(context.metrics.get("source_coverage", {}))
    context.multidomain_intelligence = enrich_multidomain_intelligence(
        context.raw_events,
        context.organization,
    )
    enrich_multidomain_findings(context.risk_findings, context.raw_events)
    context.metrics["multidomain_intelligence"] = context.multidomain_intelligence
    context.metrics["public_technology_footprint"] = context.multidomain_intelligence.get(
        "technology_footprint",
        {},
    )
    snapshot = snapshot_from_context(context)
    snapshot_payload = seal_snapshot(sanitize_public_payload(snapshot.model_dump(mode="json")))
    snapshot_metrics = snapshot.metrics
    findings = sanitize_public_payload(
        [item.model_dump(mode="json") for item in context.risk_findings[:25]]
    )
    summary_events = _prioritize_summary_events(domains, context)
    max_dashboard_events = max(100, int(os.getenv("CDE_DASHBOARD_EVENT_LIMIT", "800")))
    events = sanitize_public_payload(
        [item.model_dump(mode="json") for item in summary_events[:max_dashboard_events]]
    )
    statuses = [
        public_source_status(item.model_dump(mode="json")) for item in context.source_statuses
    ]
    processing = context.processing_summary or {}
    unique_records = int(snapshot_metrics["unique_records"].value or 0)
    domain_signals = [
        DomainSignal(
            domain=row.domain,
            events=row.record_count,
            findings=row.validated_findings_count,
            max_residual_risk=round(row.max_residual_risk, 2)
            if row.max_residual_risk is not None
            else None,
            last_seen=row.last_observed_at,
        )
        for row in snapshot.domains
    ]
    return AnalysisSummary(
        kpis=KpiSummary(
            active_domains=int(snapshot_metrics["active_domains"].value or 0),
            new_events=unique_records,
            raw_records=int(snapshot_metrics["raw_records"].value or 0),
            unique_records=unique_records,
            validated_evidence=int(snapshot_metrics["validated_evidence"].value or 0),
            validated_findings=int(snapshot_metrics["validated_findings"].value or 0),
            confirmed_findings=int(processing.get("confirmed_findings", 0)),
            confirmed_incidents=int(snapshot_metrics["confirmed_incidents"].value or 0),
            false_positives=int(processing.get("false_positives", 0)),
            max_residual_risk=round(snapshot_metrics["max_residual_risk"].value, 2)
            if snapshot_metrics["max_residual_risk"].value is not None
            else None,
            avg_residual_risk=round(snapshot_metrics["avg_residual_risk"].value, 2)
            if snapshot_metrics["avg_residual_risk"].value is not None
            else None,
            healthy_sources=int(snapshot_metrics["healthy_sources"].value or 0),
            total_sources=int(snapshot_metrics["total_sources"].value or 0),
            eligible_sources=int(snapshot_metrics["eligible_sources"].value or 0),
            queried_sources=int(snapshot_metrics["queried_sources"].value or 0),
            successful_sources=int(snapshot_metrics["successful_sources"].value or 0),
            productive_sources=int(snapshot_metrics["productive_sources"].value or 0),
            registered_sources=int(snapshot_metrics["registered_sources"].value or 0),
            empty_sources=int(snapshot_metrics["empty_sources"].value or 0),
            degraded_sources=int(snapshot_metrics["degraded_sources"].value or 0),
            failed_sources=int(snapshot_metrics["failed_sources"].value or 0),
            skipped_sources=int(snapshot_metrics["skipped_sources"].value or 0),
        ),
        domain_signals=domain_signals,
        findings=findings,
        events=events,
        records=events,
        source_statuses=statuses,
        metrics=sanitize_public_payload(context.metrics),
        processing_summary=sanitize_public_payload(processing),
        decision_snapshot=snapshot_payload,
        claims=sanitize_public_payload(context.claims),
        evidence_items=sanitize_public_payload(context.evidence_items),
        claim_evidence_links=sanitize_public_payload(context.claim_evidence_links),
        contradicting_evidence=sanitize_public_payload(context.contradicting_evidence),
        interpretations=sanitize_public_payload(context.interpretations),
        decisions=sanitize_public_payload(context.decisions),
        semantic_registry_version=get_term_registry().version,
        claim_evidence_model_version=context.claim_evidence_model_version,
    )


def _remove_legacy_opencti_source(run: RunRecord) -> None:
    summary = run.summary
    original_count = len(summary.source_statuses)
    summary.source_statuses = [
        status
        for status in summary.source_statuses
        if str(status.get("name") or "").strip().lower() != "opencti"
    ]
    removed = max(0, original_count - len(summary.source_statuses))
    if removed:
        summary.kpis.total_sources = max(0, int(summary.kpis.total_sources or 0) - removed)
    _remove_opencti_from_coverage(summary.metrics.get("source_coverage", {}))


def _hydrate_source_lifecycle(run: RunRecord) -> bool:
    """Backfill lifecycle KPIs in historical runs from their persisted coverage."""
    coverage = run.summary.metrics.get("source_coverage", {})
    lifecycle = coverage.get("source_lifecycle", {}) if isinstance(coverage, dict) else {}
    if not isinstance(lifecycle, dict) or not lifecycle:
        return False

    values = {
        "registered_sources": int(lifecycle.get("registered") or 0),
        "eligible_sources": int(lifecycle.get("eligible") or 0),
        "queried_sources": int(lifecycle.get("attempted") or 0),
        "successful_sources": int(lifecycle.get("succeeded") or 0),
        "productive_sources": int(lifecycle.get("productive") or 0),
        "empty_sources": int(lifecycle.get("empty") or 0),
        "degraded_sources": int(lifecycle.get("degraded") or 0),
        "failed_sources": int(lifecycle.get("failed") or 0),
        "skipped_sources": int(lifecycle.get("skipped") or 0),
    }
    values["total_sources"] = values["eligible_sources"]
    values["healthy_sources"] = values["successful_sources"]
    changed = False
    for field_name, value in values.items():
        if getattr(run.summary.kpis, field_name) != value:
            setattr(run.summary.kpis, field_name, value)
            changed = True

    snapshot = run.summary.decision_snapshot
    if not isinstance(snapshot, dict) or not snapshot:
        return changed
    snapshot_metrics = snapshot.setdefault("metrics", {})
    source_health = snapshot.get("source_health")
    health_fields = {
        "registered": values["registered_sources"],
        "eligible": values["eligible_sources"],
        "healthy": values["successful_sources"],
        "successful": values["successful_sources"],
        "queried": values["queried_sources"],
        "productive": values["productive_sources"],
        "empty": values["empty_sources"],
        "degraded": values["degraded_sources"],
        "failed": values["failed_sources"],
        "skipped": values["skipped_sources"],
        "total": values["eligible_sources"],
    }
    metrics_complete = all(
        isinstance(snapshot_metrics.get(metric_id), dict) for metric_id in values
    )
    health_complete = isinstance(source_health, dict) and all(
        source_health.get(field_name) == value for field_name, value in health_fields.items()
    )
    if metrics_complete and health_complete:
        return changed

    existing_period = next(
        (
            str(metric.get("period"))
            for metric in snapshot_metrics.values()
            if isinstance(metric, dict) and metric.get("period")
        ),
        "",
    )
    for metric_id, value in values.items():
        config = METRIC_CATALOG[metric_id]
        denominator = None
        if metric_id in {"healthy_sources", "queried_sources"}:
            denominator = values["eligible_sources"]
        elif metric_id in {
            "successful_sources",
            "productive_sources",
            "empty_sources",
            "degraded_sources",
            "failed_sources",
        }:
            denominator = values["queried_sources"]
        elif metric_id in {"eligible_sources", "skipped_sources"}:
            denominator = values["registered_sources"]
        snapshot_metrics[metric_id] = DecisionMetric(
            metric_id=metric_id,
            label=config["label"],
            value=float(value),
            unit=config["unit"],
            value_status="observed_zero" if value == 0 else "valid_value",
            numerator=float(value) if denominator is not None else None,
            denominator=float(denominator) if denominator is not None else None,
            period=existing_period,
            confidence=1.0,
            definition=config["definition"],
            formula=config["formula"],
        ).model_dump(mode="json")

    snapshot["source_health"] = {
        **health_fields,
        "value_status": (
            "partial_data"
            if values["queried_sources"] < values["eligible_sources"]
            or values["successful_sources"] < values["queried_sources"]
            else "valid_value"
        ),
        "definition": METRIC_CATALOG["healthy_sources"]["definition"],
    }
    snapshot["schema_version"] = SNAPSHOT_SCHEMA_VERSION
    report_context = snapshot.get("report_context")
    if isinstance(report_context, dict):
        report_context["snapshot_version"] = SNAPSHOT_VERSION
    try:
        snapshot_model = DecisionIntelligenceSnapshot(**snapshot)
        run.summary.decision_snapshot = seal_snapshot(snapshot_model)
    except Exception:
        run.summary.decision_snapshot = seal_snapshot(snapshot)
    return True


def _remove_opencti_from_coverage(coverage: Any) -> None:
    if not isinstance(coverage, dict):
        return
    for key in ("connectors",):
        rows = coverage.get(key)
        if isinstance(rows, list):
            coverage[key] = [
                row
                for row in rows
                if str((row or {}).get("name") or "").strip().lower() != "opencti"
            ]
    for section_name in ("osint", "socmint", "darkweb"):
        section = coverage.get(section_name)
        if not isinstance(section, dict):
            continue
        statuses = section.get("statuses")
        if isinstance(statuses, list):
            section["statuses"] = [
                row
                for row in statuses
                if str((row or {}).get("name") or "").strip().lower() != "opencti"
            ]
    web_layers = coverage.get("web_layers")
    if isinstance(web_layers, dict):
        for layer in web_layers.values():
            if isinstance(layer, dict) and isinstance(layer.get("sources"), list):
                layer["sources"] = [
                    source
                    for source in layer["sources"]
                    if str(source).strip().lower() != "opencti"
                ]


def _prioritize_summary_events(domains: List[str], context: RunContext) -> List[Any]:
    terms = _summary_scope_terms(domains, context)
    if not terms:
        return list(context.raw_events)
    scoped = []
    other = []
    for event in context.raw_events:
        if _summary_event_matches(event, terms):
            scoped.append(event)
        else:
            other.append(event)
    return scoped + other


def _summary_scope_terms(domains: List[str], context: RunContext) -> List[str]:
    terms: List[str] = []
    for domain in list(domains or []) + list(
        getattr(context.organization, "primary_domains", []) or []
    ):
        cleaned = str(domain).strip().lower()
        if not cleaned:
            continue
        terms.append(cleaned)
        label = cleaned.split(".", 1)[0].replace("-", " ").replace("_", " ").strip()
        compact = label.replace(" ", "")
        if len(label) >= 4:
            terms.append(label)
        if len(compact) >= 4:
            terms.append(compact)
    org_name = str(getattr(context.organization, "name", "") or "").strip().lower()
    if org_name and not org_name.startswith("domain intelligence:") and len(org_name) >= 4:
        terms.append(org_name)
        terms.append(org_name.replace(" ", ""))
    deduped: List[str] = []
    seen = set()
    for term in terms:
        if len(term) < 4 or term in seen:
            continue
        seen.add(term)
        deduped.append(term)
    return deduped


def _summary_event_matches(event: Any, terms: List[str]) -> bool:
    text = " ".join(
        [
            getattr(event, "title", ""),
            getattr(event, "category", ""),
            getattr(event, "source", ""),
            getattr(event, "actor", "") or "",
            getattr(event, "technique", "") or "",
            getattr(event, "evidence_url", "") or "",
            " ".join(getattr(event, "tags", []) or []),
        ]
    ).lower()
    return any(term in text for term in terms)


PLANNED_COLLECTORS = [
    "CISA KEV",
    "NVD CVE",
    "FIRST EPSS",
    "Exploit-DB",
    "Busqueda publica",
    "Indice publico",
    "Indice historico publico",
    "Evidencia web validada",
    "Correlacion OSINT",
    "Superficie externa",
    "Inventario pasivo",
    "Fuentes RSS",
    "GitHub Advisories",
    "SOCMINT Public",
    "Indice dark web autorizado",
    "AlienVault OTX",
    "Revision TOR autorizada",
    "Dark web autorizada",
    "STIX/TAXII",
    "MISP",
    "Shodan Passive",
    "Censys Passive",
]


def _planned_summary(domains: List[str], request: DomainAnalysisRequest) -> AnalysisSummary:
    subjects = domains or [request.subject_name or "subject"]
    return AnalysisSummary(
        kpis=KpiSummary(
            active_domains=len(subjects),
            new_events=0,
            max_residual_risk=None,
            avg_residual_risk=None,
            healthy_sources=0,
            total_sources=0,
            queried_sources=0,
            productive_sources=0,
            registered_sources=len(PLANNED_COLLECTORS),
        ),
        domain_signals=[
            DomainSignal(domain=subject, events=0, findings=0, max_residual_risk=None)
            for subject in subjects
        ],
        source_statuses=[
            {
                "name": name,
                "status": "pending",
                "records": 0,
                "mode": "planned",
                "warning": _planned_collector_warning(name, request),
            }
            for name in PLANNED_COLLECTORS
        ],
        metrics={
            "collection_status": {
                "stage": "queued",
                "mode": request.mode,
                "analysis_window": request.analysis_window,
                "scan_time_budget_minutes": request.scan_time_budget_minutes,
                "subjects": subjects,
            }
        },
    )


def _estimated_collection_seconds(config: dict) -> int:
    search = config.get("web_search", {})
    queries = len(search.get("queries", []))
    cap = int(search.get("max_queries") or queries)
    queries = min(queries, cap)
    providers = search.get("providers") or ["duckduckgo_lite", "google_news_rss", "gdelt", "hacker_news"]
    if isinstance(providers, str):
        providers = [providers]
    limits = search.get("provider_query_limits") or {}
    requests = sum(min(queries, int(limits.get(provider) or queries)) * (2 if "duckduckgo" in provider else 1) for provider in providers)
    search_seconds = requests * (float(search.get("timeout_seconds") or 8) + float(search.get("request_delay_seconds") or 0))
    if search.get("collection_timeout_seconds"):
        search_seconds = min(search_seconds, float(search["collection_timeout_seconds"]))
    social_seconds = min(len(config.get("socmint_public", {}).get("keywords", [])), int(config.get("socmint_public", {}).get("max_queries") or 5)) * 40
    return max(120, round(max(search_seconds, social_seconds, 900) + 600))


def _estimated_run_seconds(request: DomainAnalysisRequest, domains: List[str]) -> int:
    if request.scan_time_budget_minutes > 0:
        return min(14400, max(120, request.scan_time_budget_minutes * 60))
    domain_factor = max(1, len(domains) or 1)
    subject_factor = 1 if request.subject_name else 0
    window_factor = 1.0
    if request.analysis_window in {"180d", "365d"}:
        window_factor = 1.25
    elif request.analysis_window in {"1h", "24h"}:
        window_factor = 0.85
    if request.mode == "deep":
        return min(780, round((150 + domain_factor * 48 + subject_factor * 35) * window_factor))
    return min(420, round((75 + domain_factor * 26 + subject_factor * 20) * window_factor))


def _planned_collector_warning(name: str, request: DomainAnalysisRequest) -> str:
    if name == "Revision TOR autorizada":
        if request.allow_tor and request.authorized_scope:
            return "Revision TOR aislada en Docker; se valida antes de cualquier consulta dark web autorizada."
        return (
            "La revision TOR queda cerrada hasta que el alcance autorizado y TOR esten habilitados."
        )
    if name == "Dark web autorizada":
        return "Se revisan fuentes dark web seguras, configuradas y redactedas; no se navega fuera del alcance autorizado."
    if name == "Superficie externa":
        return "Exploracion externa autorizada: DNS, subdominios, HTTP/TLS y controles de correo."
    if name == "SOCMINT Public":
        return "Public SOCMINT is rate-limit aware; private scraping is not performed."
    if name == "Exploit-DB":
        return "Consulta contextual por CVE; una referencia publica no demuestra aplicabilidad ni explotacion."
    if request.mode == "deep":
        return "Deep collector planned; records appear when the run completes or as a partial source status."
    return "Collector planned; records appear when the run completes or as a partial source status."


def _ensure_runs_table(conn: Any) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS web_runs (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            payload JSONB NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS run_contexts (
            run_id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL DEFAULT '1',
            raw_records INTEGER NOT NULL DEFAULT 0,
            unique_records INTEGER NOT NULL DEFAULT 0,
            payload JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS strategic_news_articles (
            run_id TEXT NOT NULL,
            article_id TEXT NOT NULL,
            canonical_url TEXT NOT NULL,
            event_cluster_id TEXT,
            relationship TEXT NOT NULL,
            event_type TEXT,
            published_at TIMESTAMPTZ,
            payload JSONB NOT NULL,
            PRIMARY KEY (run_id, article_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS strategic_event_clusters (
            run_id TEXT NOT NULL,
            event_cluster_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            relationship TEXT NOT NULL,
            independent_source_count INTEGER NOT NULL DEFAULT 0,
            article_count INTEGER NOT NULL DEFAULT 0,
            payload JSONB NOT NULL,
            PRIMARY KEY (run_id, event_cluster_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS strategic_score_snapshots (
            run_id TEXT NOT NULL,
            model TEXT NOT NULL,
            dimension TEXT NOT NULL,
            window_days INTEGER NOT NULL,
            score DOUBLE PRECISION,
            confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            payload JSONB NOT NULL,
            PRIMARY KEY (run_id, model, dimension, window_days)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_web_runs_updated_at ON web_runs (updated_at DESC)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_run_contexts_updated_at ON run_contexts (updated_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_strategic_articles_cluster ON strategic_news_articles (run_id, event_cluster_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_strategic_clusters_type ON strategic_event_clusters (run_id, event_type)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_strategic_scores_model ON strategic_score_snapshots (run_id, model, status)"
    )
    conn.commit()


def _persist_strategic_rows(conn: Any, run_id: str, context: Dict[str, Any]) -> None:
    strategic = (context.get("metrics", {}) or {}).get("strategic_news", {}) or {}
    conn.execute("DELETE FROM strategic_news_articles WHERE run_id = %s", (run_id,))
    conn.execute("DELETE FROM strategic_event_clusters WHERE run_id = %s", (run_id,))
    conn.execute("DELETE FROM strategic_score_snapshots WHERE run_id = %s", (run_id,))
    for article in strategic.get("articles", []) or []:
        conn.execute(
            """
            INSERT INTO strategic_news_articles
                (run_id, article_id, canonical_url, event_cluster_id, relationship, event_type, published_at, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                run_id,
                article.get("article_id"),
                article.get("canonical_url"),
                article.get("event_cluster_id"),
                article.get("directness", "unassessed"),
                article.get("event_type"),
                article.get("published_at"),
                json.dumps(article, ensure_ascii=False),
            ),
        )
    for cluster in strategic.get("clusters", []) or []:
        conn.execute(
            """
            INSERT INTO strategic_event_clusters
                (run_id, event_cluster_id, event_type, relationship, independent_source_count, article_count, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                run_id,
                cluster.get("event_cluster_id"),
                cluster.get("event_type"),
                cluster.get("relationship", "unassessed"),
                int(cluster.get("independent_source_count", 0)),
                int(cluster.get("article_count", 0)),
                json.dumps(cluster, ensure_ascii=False),
            ),
        )
    for model in ("pestel", "porter"):
        payload = strategic.get(model, {}) or {}
        for dimension in payload.get("dimensions", []) or []:
            conn.execute(
                """
                INSERT INTO strategic_score_snapshots
                    (run_id, model, dimension, window_days, score, confidence, status, payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    run_id,
                    model,
                    dimension.get("key"),
                    int(payload.get("window_days", 30)),
                    dimension.get("score"),
                    float(dimension.get("confidence", 0)),
                    dimension.get("status", "insufficient_evidence"),
                    json.dumps(dimension, ensure_ascii=False),
                ),
            )


def _json_payload(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    return dict(value)


def _domain_signal(domain: str, context: RunContext) -> DomainSignal:
    needle = domain.lower()
    events = [
        item
        for item in context.raw_events
        if needle in " ".join([item.title, item.source, item.evidence_url or ""]).lower()
    ]
    findings = [
        item
        for item in context.risk_findings
        if needle in " ".join([item.title, item.category, " ".join(item.evidence)]).lower()
    ]
    return DomainSignal(
        domain=domain,
        events=len(events),
        findings=len(findings),
        max_residual_risk=round(max(item.residual_risk for item in findings), 2)
        if findings
        else None,
        last_seen=max((item.observed_at for item in events), default=None),
    )
