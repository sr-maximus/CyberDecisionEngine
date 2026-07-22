from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from cyberdeck.schemas import RunContext


REPORT_VALIDATOR_VERSION = "1.0.0"


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    severity: str
    message: str
    location: str = ""


@dataclass
class ReportValidationResult:
    run_id: str
    status: str
    validator_version: str = REPORT_VALIDATOR_VERSION
    checked_at: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    issues: list[ValidationIssue] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)

    @property
    def is_final(self) -> bool:
        return self.status != "rejected"

    def model_dump(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["is_final"] = self.is_final
        return payload


def validate_report_bundle(
    context: RunContext,
    executive_path: Path,
    technical_path: Path,
) -> ReportValidationResult:
    snapshot = context.decision_snapshot or {}
    report_context = snapshot.get("report_context", {}) or {}
    run_id = str(report_context.get("run_id") or executive_path.stem.split("-", 1)[0])
    issues: list[ValidationIssue] = []

    _validate_identity(context, snapshot, run_id, issues)
    _validate_evidence(context, issues)
    _validate_claims(context, issues)
    _validate_metrics(snapshot, issues)
    _validate_strategic_contract(context, executive_path, issues)
    snapshot_hash = str(snapshot.get("snapshot_hash") or "")
    _validate_rendered_files(executive_path, technical_path, snapshot_hash, issues)
    counts = _validate_exports(context, executive_path, snapshot_hash, issues)

    result = ReportValidationResult(
        run_id=run_id,
        status=_status_for(issues),
        issues=issues,
        counts=counts,
        artifacts={
            "executive_html": str(executive_path),
            "technical_html": str(technical_path),
            "evidence_json": str(executive_path.with_name(f"{executive_path.stem}_evidence.json")),
            "evidence_csv": str(executive_path.with_name(f"{executive_path.stem}_evidence.csv")),
            "decision_snapshot": str(executive_path.with_name(f"{executive_path.stem}_decision_snapshot.json")),
            "decision_snapshot_csv": str(
                executive_path.with_name(f"{executive_path.stem}_decision_snapshot.csv")
            ),
            "strategic_json": str(
                executive_path.with_name(f"{executive_path.stem}_strategic_scores.json")
            ),
            "strategic_csv": str(
                executive_path.with_name(f"{executive_path.stem}_strategic_scores.csv")
            ),
        },
    )
    validation_path = executive_path.with_name(f"{executive_path.stem}_validation.json")
    result.artifacts["validation"] = str(validation_path)
    validation_path.write_text(
        json.dumps(result.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return result


def _validate_strategic_contract(context: RunContext, executive_path: Path, issues: list[ValidationIssue]) -> None:
    expected = {
        "pestel": {
            "cyber_geopolitics", "cyber_economy", "cyber_human", "cyber_technology", "cyber_resilience", "cyber_legal",
        },
        "porter": {
            "cyber_rivalry", "cyber_new_entrants", "cyber_suppliers", "cyber_customers", "cyber_substitutes",
        },
    }
    signal_present = False
    for model, expected_ids in expected.items():
        result = context.metrics.get(model, {}) or {}
        if not result:
            continue
        dimensions = result.get("dimensions", []) or []
        actual_ids = {str(row.get("dimensionId") or row.get("key") or "") for row in dimensions}
        if actual_ids != expected_ids:
            issues.append(ValidationIssue("STRATEGIC_DIMENSION_SET_MISMATCH", "critical", f"{model} does not expose the complete canonical dimension set.", f"metrics.{model}.dimensions"))
        for row in dimensions:
            score = row.get("signalScore")
            evidence_ids = row.get("evidence_ids", []) or row.get("evidenceIds", []) or []
            if score is not None:
                signal_present = True
                if not evidence_ids:
                    issues.append(ValidationIssue("STRATEGIC_SCORE_WITHOUT_EVIDENCE", "critical", "A strategic SignalScore has no linked evidence.", f"metrics.{model}.{row.get('key')}"))
            if score is None and row.get("status") not in {"no_data", "insufficient_evidence"}:
                issues.append(ValidationIssue("STRATEGIC_ABSENCE_STATE_INVALID", "high", "A missing SignalScore is not marked as no data.", f"metrics.{model}.{row.get('key')}"))
    narratives = context.metrics.get("narrative_intelligence", {}) or {}
    for claim in narratives.get("claims", []) or []:
        content_type = claim.get("contentType")
        truth_status = claim.get("truthStatus")
        coordination_status = claim.get("coordinationStatus")
        evidence_ids = claim.get("sourceEvidenceIds", []) or []
        if content_type == "user_complaint" and truth_status in {"false", "likely_false"} and not claim.get("contradictingEvidenceIds"):
            issues.append(ValidationIssue("COMPLAINT_MISCLASSIFIED", "critical", "A complaint was classified as false without contradiction evidence.", str(claim.get("claimId"))))
        if truth_status in {"false", "likely_false"} and not (claim.get("contradictingEvidenceIds") or claim.get("primarySourceEvidenceIds")):
            issues.append(ValidationIssue("FALSE_CLAIM_WITHOUT_SUPPORT", "critical", "A false/likely-false state has no primary or contradicting evidence.", str(claim.get("claimId"))))
        if coordination_status == "confirmed" and not claim.get("disarmEligible"):
            issues.append(ValidationIssue("COORDINATION_WITHOUT_INDICATORS", "critical", "Confirmed coordination has no eligible coordination evidence.", str(claim.get("claimId"))))
        if not evidence_ids:
            issues.append(ValidationIssue("NARRATIVE_WITHOUT_EVIDENCE", "critical", "A narrative claim has no evidence identifier.", str(claim.get("claimId"))))
    if signal_present and executive_path.is_file():
        body = executive_path.read_text(encoding="utf-8", errors="replace")
        for marker in ("Cyber-PESTEL · SignalScore", "Cyber-Porter · SignalScore", "strategic-heatmap"):
            if marker not in body:
                issues.append(ValidationIssue("STRATEGIC_VISUAL_MISSING", "critical", "An expected strategic radar or heatmap is missing.", marker))


def _validate_identity(
    context: RunContext,
    snapshot: dict[str, Any],
    run_id: str,
    issues: list[ValidationIssue],
) -> None:
    report_context = snapshot.get("report_context", {}) or {}
    if not run_id:
        issues.append(ValidationIssue("RUN_ID_MISSING", "critical", "The report has no runId."))
    if not context.organization.name.strip():
        issues.append(ValidationIssue("SUBJECT_MISSING", "critical", "The analysis subject is empty."))
    if report_context.get("organization_name") not in {None, context.organization.name}:
        issues.append(
            ValidationIssue(
                "ORGANIZATION_MISMATCH",
                "critical",
                "The report subject differs from the persisted run context.",
                "decision_snapshot.report_context.organization_name",
            )
        )
    integrity = snapshot.get("reference_integrity", {}) or {}
    if integrity.get("status") == "fail" or int(integrity.get("invalid_reference_ids", 0) or 0) > 0:
        issues.append(
            ValidationIssue(
                "REFERENCE_INTEGRITY",
                "critical",
                "The decision snapshot contains evidence references that cannot be resolved.",
                "decision_snapshot.reference_integrity",
            )
        )
    for key in ("snapshot_version", "engine_version", "run_id", "snapshot_hash"):
        if not report_context.get(key) and not snapshot.get(key):
            issues.append(
                ValidationIssue(
                    "VERSION_OR_ID_MISSING",
                    "high",
                    f"Required traceability field is missing: {key}.",
                    f"decision_snapshot.{key}",
                )
            )


def _validate_evidence(context: RunContext, issues: list[ValidationIssue]) -> None:
    for index, evidence in enumerate(context.evidence_items):
        if not evidence.get("source_id"):
            issues.append(
                ValidationIssue(
                    "EVIDENCE_SOURCE_MISSING",
                    "critical",
                    "An evidence item has no source identifier.",
                    f"evidence_items[{index}]",
                )
            )
        if not evidence.get("evidence_id"):
            issues.append(
                ValidationIssue(
                    "EVIDENCE_ID_MISSING",
                    "critical",
                    "An evidence item has no stable evidenceId.",
                    f"evidence_items[{index}]",
                )
            )
    for index, event in enumerate(context.raw_events):
        if not event.source.strip():
            issues.append(
                ValidationIssue(
                    "RECORD_SOURCE_MISSING",
                    "critical",
                    "A collected record has no source.",
                    f"raw_events[{index}]",
                )
            )


def _validate_claims(context: RunContext, issues: list[ValidationIssue]) -> None:
    known_evidence = {str(item.get("evidence_id")) for item in context.evidence_items if item.get("evidence_id")}
    links_by_claim: dict[str, set[str]] = {}
    for link in context.claim_evidence_links:
        claim_id = str(link.get("claim_id") or "")
        evidence_id = str(link.get("evidence_id") or "")
        if claim_id and evidence_id:
            links_by_claim.setdefault(claim_id, set()).add(evidence_id)
        if evidence_id and evidence_id not in known_evidence:
            issues.append(
                ValidationIssue(
                    "CLAIM_LINK_ORPHAN",
                    "critical",
                    "A claim points to an evidenceId absent from the evidence ledger.",
                    claim_id,
                )
            )
    for claim in context.claims:
        claim_id = str(claim.get("claim_id") or "")
        evidence_ids = {str(item) for item in claim.get("evidence_ids", []) if item}
        evidence_ids.update(links_by_claim.get(claim_id, set()))
        status = str(claim.get("claim_status") or "").lower()
        if status in {"supported", "validated", "confirmed", "materialized"} and not evidence_ids:
            issues.append(
                ValidationIssue(
                    "SUPPORTED_CLAIM_WITHOUT_EVIDENCE",
                    "critical",
                    "A supported or validated claim has no linked evidence.",
                    claim_id,
                )
            )
    for index, finding in enumerate(context.risk_findings):
        location = finding.finding_id or f"risk_findings[{index}]"
        if finding.evidence_status.value in {"validated", "confirmed"} and not (
            finding.linked_evidence_ids or finding.evidence
        ):
            issues.append(
                ValidationIssue(
                    "FINDING_WITHOUT_EVIDENCE",
                    "critical",
                    "A validated finding has no evidence reference.",
                    location,
                )
            )
        if not finding.validation_method.strip():
            issues.append(
                ValidationIssue(
                    "VALIDATION_METHOD_MISSING",
                    "critical",
                    "A validated finding has no validation method.",
                    location,
                )
            )


def _validate_metrics(snapshot: dict[str, Any], issues: list[ValidationIssue]) -> None:
    for metric_id, metric in (snapshot.get("metrics", {}) or {}).items():
        if not isinstance(metric, dict):
            continue
        value = metric.get("value")
        value_status = str(metric.get("value_status") or "")
        if value == 0 and value_status in {"no_data", "not_calculated", "unavailable"}:
            issues.append(
                ValidationIssue(
                    "ZERO_WITHOUT_OBSERVATION",
                    "critical",
                    "A zero is displayed while the metric state indicates missing data.",
                    f"decision_snapshot.metrics.{metric_id}",
                )
            )
        if value is not None and not metric.get("definition"):
            issues.append(
                ValidationIssue(
                    "METRIC_DEFINITION_MISSING",
                    "medium",
                    "A reported metric has no definition.",
                    f"decision_snapshot.metrics.{metric_id}",
                )
            )


def _validate_rendered_files(
    executive_path: Path,
    technical_path: Path,
    snapshot_hash: str,
    issues: list[ValidationIssue],
) -> None:
    secret_pattern = re.compile(
        r"(?i)(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{12,}"
    )
    local_path_pattern = re.compile(r"/(Users|home|app)/[^\s<\"']+")
    for path in (executive_path, technical_path):
        if not path.is_file() or path.stat().st_size < 500:
            issues.append(
                ValidationIssue(
                    "REPORT_FILE_MISSING",
                    "critical",
                    "A report artifact is missing or empty.",
                    str(path),
                )
            )
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        if snapshot_hash and snapshot_hash not in body:
            issues.append(
                ValidationIssue(
                    "REPORT_SNAPSHOT_MISMATCH",
                    "critical",
                    "The report does not identify the decision snapshot used to render it.",
                    path.name,
                )
            )
        if secret_pattern.search(body):
            issues.append(
                ValidationIssue("SECRET_EXPOSURE", "critical", "A possible secret is present in the report.", path.name)
            )
        if local_path_pattern.search(body):
            issues.append(
                ValidationIssue("LOCAL_PATH_EXPOSURE", "high", "A local filesystem path is present in the report.", path.name)
            )
        for image_src in re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', body, flags=re.IGNORECASE):
            if image_src.startswith(("data:", "https://", "http://")):
                if image_src.startswith(("https://", "http://")):
                    issues.append(
                        ValidationIssue(
                            "REMOTE_REPORT_IMAGE",
                            "high",
                            "A report image depends on a remote resource instead of a persisted capture.",
                            f"{path.name}:{image_src}",
                        )
                    )
                continue
            image_path = (path.parent / image_src).resolve()
            if not image_path.is_file() or image_path.stat().st_size == 0:
                issues.append(
                    ValidationIssue(
                        "CAPTURE_FILE_MISSING",
                        "critical",
                        "A referenced evidence capture is missing or empty.",
                        f"{path.name}:{image_src}",
                    )
                )


def _validate_exports(
    context: RunContext,
    executive_path: Path,
    snapshot_hash: str,
    issues: list[ValidationIssue],
) -> dict[str, int]:
    json_path = executive_path.with_name(f"{executive_path.stem}_evidence.json")
    csv_path = executive_path.with_name(f"{executive_path.stem}_evidence.csv")
    json_count = _json_record_count(json_path)
    csv_count = _csv_record_count(csv_path)
    expected = len(context.raw_events)
    for label, count, path in (("JSON", json_count, json_path), ("CSV", csv_count, csv_path)):
        if count < 0:
            issues.append(
                ValidationIssue("EXPORT_MISSING", "critical", f"The {label} evidence export is missing or invalid.", str(path))
            )
        elif count != expected:
            issues.append(
                ValidationIssue(
                    "EXPORT_COUNT_MISMATCH",
                    "critical",
                    f"The {label} export contains {count} records; the source context contains {expected}.",
                    str(path),
                )
            )
    snapshot_json_path = executive_path.with_name(f"{executive_path.stem}_decision_snapshot.json")
    snapshot_csv_path = executive_path.with_name(f"{executive_path.stem}_decision_snapshot.csv")
    json_snapshot_hash = _snapshot_json_hash(snapshot_json_path)
    csv_snapshot_hashes = _snapshot_csv_hashes(snapshot_csv_path)
    if not snapshot_hash or json_snapshot_hash != snapshot_hash:
        issues.append(
            ValidationIssue(
                "SNAPSHOT_JSON_MISMATCH",
                "critical",
                "The JSON decision snapshot does not match the report context.",
                str(snapshot_json_path),
            )
        )
    if csv_snapshot_hashes != {snapshot_hash}:
        issues.append(
            ValidationIssue(
                "SNAPSHOT_CSV_MISMATCH",
                "critical",
                "The CSV decision snapshot does not match the report context.",
                str(snapshot_csv_path),
            )
        )
    strategic_dimension_count = _validate_strategic_exports(context, executive_path, issues)
    return {
        "context_records": expected,
        "json_records": max(0, json_count),
        "csv_records": max(0, csv_count),
        "claims": len(context.claims),
        "evidence_items": len(context.evidence_items),
        "findings": len(context.risk_findings),
        "strategic_dimensions": strategic_dimension_count,
    }


def _validate_strategic_exports(
    context: RunContext,
    executive_path: Path,
    issues: list[ValidationIssue],
) -> int:
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    for model_name in ("pestel", "porter"):
        for dimension in (context.metrics.get(model_name, {}) or {}).get("dimensions", []) or []:
            dimension_id = str(dimension.get("dimensionId") or dimension.get("key") or "")
            if dimension_id:
                expected[(model_name, dimension_id)] = dimension
    if not expected:
        return 0

    json_path = executive_path.with_name(f"{executive_path.stem}_strategic_scores.json")
    csv_path = executive_path.with_name(f"{executive_path.stem}_strategic_scores.csv")
    json_rows = _strategic_json_rows(json_path)
    csv_rows = _strategic_csv_rows(csv_path)
    if json_rows is None or csv_rows is None:
        issues.append(
            ValidationIssue(
                "STRATEGIC_EXPORT_MISSING",
                "critical",
                "The strategic JSON or CSV export is missing or invalid.",
                str(json_path if json_rows is None else csv_path),
            )
        )
        return len(expected)
    if set(json_rows) != set(expected) or set(csv_rows) != set(expected):
        issues.append(
            ValidationIssue(
                "STRATEGIC_EXPORT_DIMENSION_MISMATCH",
                "critical",
                "Strategic JSON/CSV dimensions do not match the report context.",
                executive_path.stem,
            )
        )
    for key, dimension in expected.items():
        expected_signal = _optional_float(dimension.get("signalScore", dimension.get("signal_score")))
        expected_pressure = _optional_float(dimension.get("validatedPressure", dimension.get("score")))
        json_dimension = json_rows.get(key, {})
        csv_dimension = csv_rows.get(key, {})
        values = (
            _optional_float(json_dimension.get("signalScore", json_dimension.get("signal_score"))),
            _optional_float(csv_dimension.get("signal_score")),
            _optional_float(json_dimension.get("validatedPressure", json_dimension.get("score"))),
            _optional_float(csv_dimension.get("validated_pressure")),
        )
        if not (_same_optional_number(values[0], expected_signal) and _same_optional_number(values[1], expected_signal)):
            issues.append(
                ValidationIssue(
                    "STRATEGIC_SIGNAL_EXPORT_MISMATCH",
                    "critical",
                    "SignalScore differs between context, strategic JSON and strategic CSV.",
                    f"{key[0]}.{key[1]}",
                )
            )
        if not (_same_optional_number(values[2], expected_pressure) and _same_optional_number(values[3], expected_pressure)):
            issues.append(
                ValidationIssue(
                    "STRATEGIC_PRESSURE_EXPORT_MISMATCH",
                    "critical",
                    "Validated pressure differs between context, strategic JSON and strategic CSV.",
                    f"{key[0]}.{key[1]}",
                )
            )
    return len(expected)


def _strategic_json_rows(path: Path) -> dict[tuple[str, str], dict[str, Any]] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for model_name in ("pestel", "porter"):
        for dimension in (payload.get(model_name, {}) or {}).get("dimensions", []) or []:
            dimension_id = str(dimension.get("dimensionId") or dimension.get("key") or "")
            if dimension_id:
                rows[(model_name, dimension_id)] = dimension
    return rows


def _strategic_csv_rows(path: Path) -> dict[tuple[str, str], dict[str, Any]] | None:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return {
                (str(row.get("model") or ""), str(row.get("dimension") or "")): row
                for row in csv.DictReader(handle)
                if row.get("model") and row.get("dimension")
            }
    except OSError:
        return None


def _optional_float(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _same_optional_number(left: float | None, right: float | None) -> bool:
    if left is None or right is None:
        return left is right
    return abs(left - right) <= 1e-6


def _json_record_count(path: Path) -> int:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return -1
    records = payload.get("records") if isinstance(payload, dict) else None
    return len(records) if isinstance(records, list) else -1


def _csv_record_count(path: Path) -> int:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return sum(1 for _ in csv.DictReader(handle))
    except OSError:
        return -1


def _snapshot_json_hash(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    return str(payload.get("snapshot_hash") or "") if isinstance(payload, dict) else ""


def _snapshot_csv_hashes(path: Path) -> set[str]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return {str(row.get("snapshot_hash") or "") for row in csv.DictReader(handle)} - {""}
    except OSError:
        return set()


def _status_for(issues: Iterable[ValidationIssue]) -> str:
    severities = {issue.severity for issue in issues}
    if "critical" in severities:
        return "rejected"
    if severities:
        return "approved_with_observations"
    return "approved"
