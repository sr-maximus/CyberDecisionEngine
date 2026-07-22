from __future__ import annotations

import asyncio
import hashlib
import json
import re
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional
from uuid import uuid4

from cyberdeck.settings import PROJECT_ROOT
from cyberdeck_api.jobs import RunStore
from cyberdeck_api.models import (
    MonitoringAlert,
    MonitoringOverview,
    MonitoringProfile,
    MonitoringProfileRequest,
    MonitoringProfileUpdate,
    PlatformLogEntry,
    RunRecord,
    SupportTicket,
    SupportTicketRequest,
    SupportTicketUpdate,
    normalize_analysis_window,
    utcnow_iso,
)


INTERVAL_MINUTES = {
    "manual": 0,
    "1h": 60,
    "6h": 360,
    "24h": 1440,
    "7d": 10080,
    "continuous": 60,
}

CONTEXT_ONLY_TAGS = {"validation_required", "reputation_checker", "dns_inventory_only"}
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)


class MonitoringStore:
    def __init__(self, state_path: Optional[Path] = None) -> None:
        self.state_path = state_path or PROJECT_ROOT / "data" / "monitoring_state.json"
        self._profiles: Dict[str, MonitoringProfile] = {}
        self._alerts: Dict[str, MonitoringAlert] = {}
        self._logs: list[PlatformLogEntry] = []
        self._tickets: Dict[str, SupportTicket] = {}
        self._lock = asyncio.Lock()
        self._worker: asyncio.Task[None] | None = None
        self._run_store: RunStore | None = None

    async def load(self, run_store: RunStore) -> None:
        self._run_store = run_store
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            return
        payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        self._profiles = {item["id"]: MonitoringProfile(**item) for item in payload.get("profiles", [])}
        self._alerts = {item["id"]: MonitoringAlert(**item) for item in payload.get("alerts", [])}
        self._logs = [PlatformLogEntry(**item) for item in payload.get("logs", [])][-500:]
        self._tickets = {item["id"]: SupportTicket(**item) for item in payload.get("support_tickets", [])}

    async def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        if self._worker:
            self._worker.cancel()
            with suppress(asyncio.CancelledError):
                await self._worker

    async def overview(self) -> MonitoringOverview:
        await self._sync_completed_runs()
        async with self._lock:
            return MonitoringOverview(
                profiles=sorted(self._profiles.values(), key=lambda item: item.created_at, reverse=True),
                alerts=sorted(self._alerts.values(), key=lambda item: item.created_at, reverse=True),
                logs=list(reversed(self._logs[-100:])),
                support_tickets=sorted(self._tickets.values(), key=lambda item: item.created_at, reverse=True),
            )

    async def create_profile(self, request: MonitoringProfileRequest) -> MonitoringProfile:
        normalized_request = normalize_analysis_window(request.request)
        profile = MonitoringProfile(
            id=uuid4().hex[:12],
            name=request.name.strip(),
            request=normalized_request,
            cadence=request.cadence,
            collection_duration_minutes=request.collection_duration_minutes,
            status="active" if request.enabled else "paused",
            created_by=request.created_by,
            next_run_at=utcnow_iso() if request.enabled and request.cadence != "manual" else None,
        )
        async with self._lock:
            self._profiles[profile.id] = profile
            self._log_locked("info", "monitoring", f"Monitoring profile created: {profile.name}", profile_id=profile.id, user=request.created_by)
            await self._persist_locked()
        if profile.status == "active" and profile.cadence != "manual":
            asyncio.create_task(self._try_launch_profile(profile.id))
        return profile

    async def update_profile(self, profile_id: str, request: MonitoringProfileUpdate) -> Optional[MonitoringProfile]:
        async with self._lock:
            profile = self._profiles.get(profile_id)
            if profile is None:
                return None
            if request.name is not None:
                profile.name = request.name.strip()
            if request.cadence is not None:
                profile.cadence = request.cadence
                profile.next_run_at = self._next_run_at(profile.cadence) if profile.status == "active" and profile.cadence != "manual" else None
            if request.collection_duration_minutes is not None:
                profile.collection_duration_minutes = request.collection_duration_minutes
            if request.enabled is not None:
                profile.status = "active" if request.enabled else "paused"
                profile.next_run_at = self._next_run_at(profile.cadence) if profile.status == "active" and profile.cadence != "manual" else None
            profile.updated_at = utcnow_iso()
            self._log_locked("info", "monitoring", f"Monitoring profile updated: {profile.name}", profile_id=profile.id)
            await self._persist_locked()
            return profile

    async def create_support_ticket(self, request: SupportTicketRequest) -> SupportTicket:
        ticket = SupportTicket(id=uuid4().hex[:12], **request.model_dump())
        async with self._lock:
            self._tickets[ticket.id] = ticket
            self._log_locked(
                "warning" if ticket.severity == "high" else "info",
                "support",
                f"Support ticket created: {ticket.subject}",
                run_id=ticket.run_id,
                user=ticket.user,
            )
            await self._persist_locked()
            return ticket

    async def update_alert_status(self, alert_id: str, status: str, user: str = "system") -> Optional[MonitoringAlert]:
        async with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                return None
            alert.status = status  # type: ignore[assignment]
            self._log_locked("info", "alerts", f"Alert marked as {status}: {alert.title}", run_id=alert.run_id, profile_id=alert.profile_id, user=user)
            await self._persist_locked()
            return alert

    async def update_support_ticket(self, ticket_id: str, request: SupportTicketUpdate) -> Optional[SupportTicket]:
        async with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                return None
            ticket.status = request.status
            ticket.updated_at = utcnow_iso()
            self._log_locked("info", "support", f"Support ticket {ticket.id} marked as {request.status}: {ticket.subject}", run_id=ticket.run_id, user=request.user)
            await self._persist_locked()
            return ticket

    async def record_log(
        self,
        level: str,
        component: str,
        message: str,
        run_id: Optional[str] = None,
        profile_id: Optional[str] = None,
        user: Optional[str] = None,
    ) -> PlatformLogEntry:
        async with self._lock:
            entry = self._log_locked(level, component, message, run_id=run_id, profile_id=profile_id, user=user)
            await self._persist_locked()
            return entry

    async def _run_loop(self) -> None:
        while True:
            try:
                await self._sync_completed_runs()
                await self._launch_due_profiles()
            except Exception as exc:  # pragma: no cover - operational guard
                await self.record_log("error", "monitoring", f"Monitoring worker error: {exc}")
            await asyncio.sleep(15)

    async def _launch_due_profiles(self) -> None:
        async with self._lock:
            profile_ids = [
                profile.id
                for profile in self._profiles.values()
                if profile.status == "active"
                and profile.cadence != "manual"
                and self._is_due(profile)
            ]
        for profile_id in profile_ids:
            await self._try_launch_profile(profile_id)

    async def _try_launch_profile(self, profile_id: str) -> None:
        if self._run_store is None:
            return
        async with self._lock:
            profile = self._profiles.get(profile_id)
            if profile is None or profile.status != "active" or profile.cadence == "manual":
                return
            last_run_id = profile.last_run_id
        if last_run_id:
            current = await self._run_store.get_run(last_run_id)
            if current and current.status in {"queued", "running"}:
                return
        async with self._lock:
            profile = self._profiles.get(profile_id)
            if profile is None:
                return
            run_request = profile.request.model_copy(deep=True)
            run_request.scan_time_budget_minutes = profile.collection_duration_minutes
            run_request.report_display_at = None
        try:
            run = await self._run_store.create_run(run_request)
        except Exception as exc:
            async with self._lock:
                profile = self._profiles.get(profile_id)
                if profile:
                    profile.last_error = str(exc)
                    profile.updated_at = utcnow_iso()
                self._log_locked("error", "monitoring", f"Unable to launch monitored run: {exc}", profile_id=profile_id)
                await self._persist_locked()
            return
        async with self._lock:
            profile = self._profiles[profile_id]
            profile.last_run_id = run.id
            profile.last_started_at = utcnow_iso()
            profile.next_run_at = self._next_run_at(profile.cadence)
            profile.updated_at = utcnow_iso()
            self._log_locked("info", "monitoring", f"Monitored collection launched: run {run.id}", run_id=run.id, profile_id=profile_id)
            await self._persist_locked()

    async def _sync_completed_runs(self) -> None:
        if self._run_store is None:
            return
        async with self._lock:
            profiles = list(self._profiles.values())
        for profile in profiles:
            if not profile.last_run_id or profile.last_run_id in profile.processed_run_ids:
                continue
            run = await self._run_store.get_run(profile.last_run_id)
            if run is None or run.status not in {"completed", "failed"}:
                continue
            await self._process_finished_run(profile.id, run)

    async def _process_finished_run(self, profile_id: str, run: RunRecord) -> None:
        alerts = _alerts_from_run(profile_id, run)
        async with self._lock:
            profile = self._profiles.get(profile_id)
            if profile is None:
                return
            new_count = 0
            for alert in alerts:
                if alert.fingerprint in profile.seen_fingerprints:
                    continue
                self._alerts[alert.id] = alert
                profile.seen_fingerprints.append(alert.fingerprint)
                new_count += 1
            profile.seen_fingerprints = profile.seen_fingerprints[-5000:]
            profile.processed_run_ids.append(run.id)
            profile.processed_run_ids = profile.processed_run_ids[-250:]
            profile.last_completed_at = utcnow_iso()
            profile.alert_count = len([item for item in self._alerts.values() if item.profile_id == profile.id])
            profile.new_signal_count += new_count
            profile.last_error = run.error if run.status == "failed" else None
            profile.updated_at = utcnow_iso()
            if run.status == "failed":
                self._log_locked("error", "analysis", f"Monitored run failed: {run.error}", run_id=run.id, profile_id=profile.id)
            elif new_count:
                self._log_locked("warning", "alerts", f"{new_count} new monitored alert(s) generated", run_id=run.id, profile_id=profile.id)
            else:
                self._log_locked("info", "alerts", "Monitored run completed with no new deduplicated alerts", run_id=run.id, profile_id=profile.id)
            await self._persist_locked()

    def _is_due(self, profile: MonitoringProfile) -> bool:
        if not profile.next_run_at:
            return True
        try:
            next_run = datetime.fromisoformat(profile.next_run_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        return next_run <= datetime.now(timezone.utc)

    def _next_run_at(self, cadence: str) -> Optional[str]:
        minutes = INTERVAL_MINUTES.get(cadence, 0)
        if minutes <= 0:
            return None
        return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()

    def _log_locked(
        self,
        level: str,
        component: str,
        message: str,
        run_id: Optional[str] = None,
        profile_id: Optional[str] = None,
        user: Optional[str] = None,
    ) -> PlatformLogEntry:
        entry = PlatformLogEntry(
            id=uuid4().hex[:12],
            level=level if level in {"info", "warning", "error"} else "info",
            component=component,
            message=message,
            run_id=run_id,
            profile_id=profile_id,
            user=user,
        )
        self._logs.append(entry)
        self._logs = self._logs[-500:]
        return entry

    async def _persist_locked(self) -> None:
        payload = {
            "profiles": [item.model_dump(mode="json") for item in self._profiles.values()],
            "alerts": [item.model_dump(mode="json") for item in self._alerts.values()],
            "logs": [item.model_dump(mode="json") for item in self._logs[-500:]],
            "support_tickets": [item.model_dump(mode="json") for item in self._tickets.values()],
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _alerts_from_run(profile_id: str, run: RunRecord) -> list[MonitoringAlert]:
    alerts: list[MonitoringAlert] = []
    for finding in run.summary.findings:
        title = str(finding.get("title") or "Risk finding")
        evidence_text = " ".join(str(item) for item in finding.get("evidence") or [])
        url = _first_url(evidence_text)
        residual = float(finding.get("residual_risk") or 0)
        if residual < 18 and not url:
            continue
        fingerprint = _fingerprint("finding", title, url, str(finding.get("category") or "risk"))
        alerts.append(
            MonitoringAlert(
                id=uuid4().hex[:12],
                profile_id=profile_id,
                run_id=run.id,
                fingerprint=fingerprint,
                severity=_severity_from_score(residual / 100),
                title=title,
                category=str(finding.get("category") or "risk"),
                evidence_url=url,
                validation=str(finding.get("matrix_label") or "validated finding"),
            )
        )
    for event in run.summary.events:
        tags = {str(item).lower() for item in event.get("tags") or []}
        if tags & CONTEXT_ONLY_TAGS:
            continue
        title = str(event.get("title") or "Threat signal")
        url = str(event.get("evidence_url") or "") or None
        severity = float(event.get("severity") or 0.0)
        if severity < 0.55 and not url:
            continue
        category = str(event.get("category") or "event")
        fingerprint = _fingerprint("event", title, url, category, str(event.get("technique") or ""))
        alerts.append(
            MonitoringAlert(
                id=uuid4().hex[:12],
                profile_id=profile_id,
                run_id=run.id,
                fingerprint=fingerprint,
                severity=_severity_from_score(severity),
                title=title,
                category=category,
                evidence_url=url,
                validation="validated evidence" if url else "signal without direct URL",
            )
        )
    return alerts


def _fingerprint(*parts: str | None) -> str:
    normalized = "|".join((part or "").strip().lower() for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]


def _first_url(text: str) -> Optional[str]:
    match = URL_RE.search(text)
    return match.group(0).rstrip(".,;") if match else None


def _severity_from_score(score: float) -> str:
    if score >= 0.78:
        return "critical"
    if score >= 0.62:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"
