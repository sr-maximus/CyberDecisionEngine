from __future__ import annotations

import asyncio
from contextlib import suppress
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cyberdeck.cli import run_pipeline
from cyberdeck.decision_intelligence import snapshot_from_context
from cyberdeck.reporting.html_report import prepare_context_for_report, render_report
from cyberdeck.schemas import RunContext
from cyberdeck.semantics import get_term_registry
from cyberdeck.settings import PROJECT_ROOT, load_sources_config, write_yaml
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
            if request.organization_name.strip().casefold() != source.organization_name.strip().casefold():
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
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        if self.database_url:
            await asyncio.to_thread(self._load_postgres)
            await self._mark_interrupted_runs()
            return
        if not self.state_path.exists():
            return
        payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        for item in payload.get("runs", []):
            run = RunRecord(**item)
            _remove_legacy_opencti_source(run)
            if run.status in {"queued", "running"}:
                run.status = "failed"
                run.stage = "Interrupted before completion"
                run.error = "The API restarted while this run was active."
                run.updated_at = utcnow_iso()
                run.progress = 100
            self._runs[run.id] = run
        await self._persist_locked()

    async def list_runs(self) -> List[RunRecord]:
        async with self._lock:
            return sorted(self._runs.values(), key=lambda item: item.created_at, reverse=True)

    async def get_run(self, run_id: str) -> Optional[RunRecord]:
        async with self._lock:
            return self._runs.get(run_id)

    async def create_run(self, request: DomainAnalysisRequest) -> RunRecord:
        request = normalize_analysis_window(request)
        if not request.authorized_scope:
            raise PermissionError("Analysis requires authorized_scope=true.")
        domains = normalize_domains(request.domains) if request.domains else []
        if not domains and not request.subject_name:
            raise ValueError("At least one domain, organization/brand name, or person name is required.")
        competitors = normalize_domains(request.competitor_domains) if request.competitor_domains else []
        request.domains = domains
        request.competitor_domains = competitors
        async with self._lock:
            request = _reuse_exact_scope_profile(request, domains, list(self._runs.values()))
            if request.subject_type == "organization" and len(domains) > 1 and not request.subject_name:
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
            await self._persist_locked()
        asyncio.create_task(self._execute(run.id))
        return run

    async def rerun(self, run_id: str) -> Optional[RunRecord]:
        run = await self.get_run(run_id)
        if run is None:
            return None
        return await self.create_run(run.request)

    async def _execute(self, run_id: str) -> None:
        await self._update(run_id, status="running", stage="Preparing authorized domain scope", progress=15)
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
                },
            )
            slug = slug_from_domains(run.domains or [run.request.subject_name or "subject"])
            report_path = self.report_dir / f"{run.id}-{slug}.html"
            context_path = self._context_path(run.id)

            await self._update(run_id, stage="Collecting public OSINT, SOCMINT, dark web indexes and external-surface evidence", progress=35)
            progress_task = asyncio.create_task(self._progress_while_running(run_id, run.estimated_seconds))
            pipeline_timeout = max(240, min(14400, int(run.estimated_seconds) + 180))
            try:
                _, context = await asyncio.wait_for(
                    run_pipeline(
                        str(org_path),
                        run.request.mode,
                        run.request.lookback_days,
                        str(report_path),
                        real_only=run.request.real_only,
                        source_config_override=source_config,
                        return_context=True,
                        render_html=False,
                    ),
                    timeout=pipeline_timeout,
                )
            finally:
                progress_task.cancel()
                with suppress(asyncio.CancelledError):
                    await progress_task
            context = await asyncio.to_thread(prepare_context_for_report, context, run.id)
            await asyncio.to_thread(self._write_context, context_path, context)
            await self._update(run_id, stage="Building decision dashboards", progress=94)
            await self._complete(run_id, context)
        except asyncio.TimeoutError:  # pragma: no cover - runtime and network dependent
            await self._fail(run_id, "Analysis exceeded the configured time budget. Partial collectors may still have produced external logs; relaunch with a longer monitoring duration if deeper collection is required.")
        except Exception as exc:  # pragma: no cover - runtime and network dependent
            await self._fail(run_id, str(exc))

    async def _progress_while_running(self, run_id: str, estimated_seconds: int) -> None:
        loop = asyncio.get_running_loop()
        started_at = loop.time()
        stages = [
            (42, "Checking public OSINT indexes and news/search evidence"),
            (52, "Validating external attack-surface evidence"),
            (64, "Reviewing SOCMINT, brand, fraud and public mention signals"),
            (74, "Checking ransomware, dark web indexes and TOR policy status"),
            (84, "Mapping ATT&CK, D3FEND, ATLAS, DISARM and compliance scenarios"),
            (90, "Calculating risk, forecast and dashboard context"),
        ]
        while True:
            elapsed = loop.time() - started_at
            estimated_progress = min(90, max(35, int(35 + (elapsed / max(30, estimated_seconds)) * 55)))
            stage = next((label for threshold, label in reversed(stages) if estimated_progress >= threshold), stages[0][1])
            await self._update(run_id, stage=stage, progress=estimated_progress)
            await asyncio.sleep(6)

    async def _update(self, run_id: str, **changes: object) -> None:
        async with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return
            for key, value in changes.items():
                setattr(run, key, value)
            run.updated_at = utcnow_iso()
            await self._persist_locked()

    async def _complete(self, run_id: str, context: RunContext) -> None:
        summary = summarize_context((await self.get_run(run_id)).domains, context)  # type: ignore[union-attr]
        async with self._lock:
            run = self._runs[run_id]
            run.status = "completed"
            run.stage = "Analysis ready - report pending user request"
            run.progress = 100
            run.report = None
            run.summary = summary
            run.updated_at = utcnow_iso()
            await self._persist_locked()

    async def generate_report(self, run_id: str) -> Optional[RunRecord]:
        run = await self.get_run(run_id)
        if run is None:
            return None
        if run.status != "completed":
            raise ValueError("Report can only be generated for a completed analysis.")
        context_path = self._context_path(run_id)
        try:
            context = await asyncio.to_thread(self._read_context, context_path)
        except FileNotFoundError:
            if run.report:
                return run
            raise ValueError("Stored analysis context is not available for this run.")
        await self._update(run_id, stage="Capturing public evidence for the report", progress=100)
        context = await attach_report_evidence_captures(context, run_id)
        context = await asyncio.to_thread(prepare_context_for_report, context, run_id)
        slug = slug_from_domains(run.domains or [run.request.subject_name or "subject"])
        report_path = self.report_dir / f"{run.id}-{slug}.html"
        await self._update(run_id, stage="Generating HTML report by user request", progress=100)
        output = await asyncio.to_thread(render_report, context, str(report_path), prepared=True)
        technical_output = output.with_name(f"{output.stem}-technical{output.suffix}")
        validation_path = output.with_name(f"{output.stem}_validation.json")
        validation_payload = json.loads(validation_path.read_text(encoding="utf-8"))
        validation_status = str(validation_payload.get("status") or "rejected")
        await asyncio.to_thread(self._write_context, context_path, context)
        relative_report = output.relative_to(PROJECT_ROOT / "reports").as_posix()
        relative_technical = technical_output.relative_to(PROJECT_ROOT / "reports").as_posix()
        async with self._lock:
            current = self._runs[run_id]
            current.stage = "Report ready"
            current.report = ReportSummary(
                path=str(output),
                url=f"/reports/{relative_report}",
                download_url=f"/api/reports/{relative_report}/download",
                technical_path=str(technical_output),
                technical_url=f"/reports/{relative_technical}",
                technical_download_url=f"/api/reports/{relative_technical}/download",
                generated_at=context.report_display_at or context.generated_at,
                validation_status=validation_status,
                validation_path=str(validation_path),
                final=validation_status != "rejected",
            )
            current.summary = summarize_context(current.domains, context)
            current.updated_at = utcnow_iso()
            await self._persist_locked()
            return current

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
                    int(processing.get("raw_records_collected", len(parsed.get("raw_events", []) or []))),
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
            row = conn.execute("SELECT payload FROM run_contexts WHERE run_id = %s", (run_id,)).fetchone()
        return _json_payload(row[0]) if row else None

    async def _fail(self, run_id: str, message: str) -> None:
        async with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return
            run.status = "failed"
            run.stage = "Run failed"
            run.error = message
            run.progress = 100
            run.updated_at = utcnow_iso()
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
        async with self._lock:
            changed = False
            for run in self._runs.values():
                if run.status in {"queued", "running"}:
                    run.status = "failed"
                    run.stage = "Interrupted before completion"
                    run.error = "The API restarted while this run was active."
                    run.updated_at = utcnow_iso()
                    run.progress = 100
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


def summarize_context(domains: List[str], context: RunContext) -> AnalysisSummary:
    context.source_statuses = [status for status in context.source_statuses if status.name.strip().lower() != "opencti"]
    _remove_opencti_from_coverage(context.metrics.get("source_coverage", {}))
    snapshot = snapshot_from_context(context)
    snapshot_payload = snapshot.model_dump(mode="json")
    snapshot_metrics = snapshot.metrics
    findings = [item.model_dump(mode="json") for item in context.risk_findings[:25]]
    summary_events = _prioritize_summary_events(domains, context)
    max_dashboard_events = max(100, int(os.getenv("CDE_DASHBOARD_EVENT_LIMIT", "800")))
    events = [item.model_dump(mode="json") for item in summary_events[:max_dashboard_events]]
    statuses = [item.model_dump(mode="json") for item in context.source_statuses]
    processing = context.processing_summary or {}
    unique_records = int(snapshot_metrics["unique_records"].value or 0)
    domain_signals = [
        DomainSignal(
            domain=row.domain,
            events=row.record_count,
            findings=row.validated_findings_count,
            max_residual_risk=round(row.max_residual_risk, 2) if row.max_residual_risk is not None else None,
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
            max_residual_risk=round(snapshot_metrics["max_residual_risk"].value, 2) if snapshot_metrics["max_residual_risk"].value is not None else None,
            avg_residual_risk=round(snapshot_metrics["avg_residual_risk"].value, 2) if snapshot_metrics["avg_residual_risk"].value is not None else None,
            healthy_sources=int(snapshot_metrics["healthy_sources"].value or 0),
            total_sources=int(snapshot_metrics["total_sources"].value or 0),
            queried_sources=int(snapshot_metrics["queried_sources"].value or 0),
            productive_sources=int(snapshot_metrics["productive_sources"].value or 0),
            registered_sources=int(snapshot_metrics["registered_sources"].value or 0),
        ),
        domain_signals=domain_signals,
        findings=findings,
        events=events,
        records=events,
        source_statuses=statuses,
        metrics=context.metrics,
        processing_summary=processing,
        decision_snapshot=snapshot_payload,
        claims=context.claims,
        evidence_items=context.evidence_items,
        claim_evidence_links=context.claim_evidence_links,
        contradicting_evidence=context.contradicting_evidence,
        interpretations=context.interpretations,
        decisions=context.decisions,
        semantic_registry_version=get_term_registry().version,
        claim_evidence_model_version=context.claim_evidence_model_version,
    )


def _remove_legacy_opencti_source(run: RunRecord) -> None:
    summary = run.summary
    original_count = len(summary.source_statuses)
    summary.source_statuses = [
        status for status in summary.source_statuses if str(status.get("name") or "").strip().lower() != "opencti"
    ]
    removed = max(0, original_count - len(summary.source_statuses))
    if removed:
        summary.kpis.total_sources = max(0, int(summary.kpis.total_sources or 0) - removed)
    _remove_opencti_from_coverage(summary.metrics.get("source_coverage", {}))


def _remove_opencti_from_coverage(coverage: Any) -> None:
    if not isinstance(coverage, dict):
        return
    for key in ("connectors",):
        rows = coverage.get(key)
        if isinstance(rows, list):
            coverage[key] = [row for row in rows if str((row or {}).get("name") or "").strip().lower() != "opencti"]
    for section_name in ("osint", "socmint", "darkweb"):
        section = coverage.get(section_name)
        if not isinstance(section, dict):
            continue
        statuses = section.get("statuses")
        if isinstance(statuses, list):
            section["statuses"] = [row for row in statuses if str((row or {}).get("name") or "").strip().lower() != "opencti"]
    web_layers = coverage.get("web_layers")
    if isinstance(web_layers, dict):
        for layer in web_layers.values():
            if isinstance(layer, dict) and isinstance(layer.get("sources"), list):
                layer["sources"] = [source for source in layer["sources"] if str(source).strip().lower() != "opencti"]


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
    for domain in list(domains or []) + list(getattr(context.organization, "primary_domains", []) or []):
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
        domain_signals=[DomainSignal(domain=subject, events=0, findings=0, max_residual_risk=None) for subject in subjects],
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
        return "La revision TOR queda cerrada hasta que el alcance autorizado y TOR esten habilitados."
    if name == "Dark web autorizada":
        return "Se revisan fuentes dark web seguras, configuradas y redactedas; no se navega fuera del alcance autorizado."
    if name == "Superficie externa":
        return "Exploracion externa autorizada: DNS, subdominios, HTTP/TLS y controles de correo."
    if name == "SOCMINT Public":
        return "Public SOCMINT is rate-limit aware; private scraping is not performed."
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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_run_contexts_updated_at ON run_contexts (updated_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_strategic_articles_cluster ON strategic_news_articles (run_id, event_cluster_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_strategic_clusters_type ON strategic_event_clusters (run_id, event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_strategic_scores_model ON strategic_score_snapshots (run_id, model, status)")
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
            (run_id, article.get("article_id"), article.get("canonical_url"), article.get("event_cluster_id"), article.get("directness", "unassessed"), article.get("event_type"), article.get("published_at"), json.dumps(article, ensure_ascii=False)),
        )
    for cluster in strategic.get("clusters", []) or []:
        conn.execute(
            """
            INSERT INTO strategic_event_clusters
                (run_id, event_cluster_id, event_type, relationship, independent_source_count, article_count, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (run_id, cluster.get("event_cluster_id"), cluster.get("event_type"), cluster.get("relationship", "unassessed"), int(cluster.get("independent_source_count", 0)), int(cluster.get("article_count", 0)), json.dumps(cluster, ensure_ascii=False)),
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
                (run_id, model, dimension.get("key"), int(payload.get("window_days", 30)), dimension.get("score"), float(dimension.get("confidence", 0)), dimension.get("status", "insufficient_evidence"), json.dumps(dimension, ensure_ascii=False)),
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
        max_residual_risk=round(max(item.residual_risk for item in findings), 2) if findings else None,
        last_seen=max((item.observed_at for item in events), default=None),
    )
