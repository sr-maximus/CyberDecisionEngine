from __future__ import annotations

import csv
import html
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from cyberdeck.analysis.multidomain import INTERNAL_PROVIDER_PATTERNS
from cyberdeck.schemas import RunContext
from cyberdeck.snapshot_integrity import verify_snapshot


REPORT_VALIDATOR_VERSION = "1.3.0"
_PUBLIC_ARTIFACT_FORBIDDEN_PATTERN = re.compile(
    "|".join(
        re.escape(pattern)
        for pattern in sorted(INTERNAL_PROVIDER_PATTERNS, key=len, reverse=True)
    ),
    flags=re.IGNORECASE,
)
_INTERNAL_EVIDENCE_ID_PATTERN = re.compile(
    r"(?i)(?:spiderfoot|collector|sidecar|urlscan|shodan|censys)[-_][a-z0-9-]{4,}"
)
_HTTP_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", flags=re.IGNORECASE)
_VISIBLE_INTERNAL_MARKERS = {
    "Run ID": re.compile(r"\brun\s+id\b", flags=re.IGNORECASE),
    "engine label": re.compile(r"\b(?:engine|motor)\s*:", flags=re.IGNORECASE),
    "snapshot label": re.compile(r"\bsnapshot(?:\s+(?:version|hash))?\b", flags=re.IGNORECASE),
    "CTI implementation label": re.compile(
        r"\b(?:cti-snapshot|contextual-threat-relevance|evidence-pipeline)\b",
        flags=re.IGNORECASE,
    ),
}


def _visible_body_text(document: str) -> str:
    body_match = re.search(
        r"<body\b[^>]*>(.*?)</body>",
        document,
        flags=re.IGNORECASE | re.DOTALL,
    )
    body = body_match.group(1) if body_match else document
    body = re.sub(
        r"<(?:script|style)\b[^>]*>.*?</(?:script|style)>",
        " ",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    body = re.sub(r"<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", html.unescape(body)).strip()


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
    _validate_cti_snapshot(snapshot, issues)
    if not verify_snapshot(snapshot):
        issues.append(
            ValidationIssue(
                "SNAPSHOT_HASH_INVALID",
                "critical",
                "The decision snapshot digest does not match its published content.",
                "decision_snapshot",
            )
        )
    _validate_strategic_contract(context, executive_path, issues)
    snapshot_hash = str(snapshot.get("snapshot_hash") or "")
    _validate_rendered_files(executive_path, technical_path, snapshot_hash, issues)
    _validate_cti_rendering(snapshot, executive_path, technical_path, issues)
    counts = _validate_exports(context, executive_path, snapshot_hash, issues)
    _validate_public_export_references(executive_path, issues)
    _validate_public_artifact_boundary(executive_path, technical_path, issues)

    result = ReportValidationResult(
        run_id=run_id,
        status=_status_for(issues),
        issues=issues,
        counts=counts,
        artifacts={
            "executive_html": executive_path.name,
            "technical_html": technical_path.name,
            "evidence_json": executive_path.with_name(f"{executive_path.stem}_evidence.json").name,
            "evidence_csv": executive_path.with_name(f"{executive_path.stem}_evidence.csv").name,
            "decision_snapshot": executive_path.with_name(f"{executive_path.stem}_decision_snapshot.json").name,
            "decision_snapshot_csv": executive_path.with_name(
                f"{executive_path.stem}_decision_snapshot.csv"
            ).name,
            "strategic_json": executive_path.with_name(f"{executive_path.stem}_strategic_scores.json").name,
            "strategic_csv": executive_path.with_name(f"{executive_path.stem}_strategic_scores.csv").name,
        },
    )
    validation_path = executive_path.with_name(f"{executive_path.stem}_validation.json")
    result.artifacts["validation"] = validation_path.name
    validation_path.write_text(
        json.dumps(result.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return result


def _validate_public_artifact_boundary(
    executive_path: Path,
    technical_path: Path,
    issues: list[ValidationIssue],
) -> None:
    artifact_paths = [
        executive_path,
        technical_path,
        executive_path.with_name(f"{executive_path.stem}_evidence.json"),
        executive_path.with_name(f"{executive_path.stem}_evidence.csv"),
        executive_path.with_name(f"{executive_path.stem}_decision_snapshot.json"),
        executive_path.with_name(f"{executive_path.stem}_decision_snapshot.csv"),
        executive_path.with_name(f"{executive_path.stem}_strategic_scores.json"),
        executive_path.with_name(f"{executive_path.stem}_strategic_scores.csv"),
    ]
    for path in artifact_paths:
        if not path.is_file():
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        prose_without_urls = _HTTP_URL_PATTERN.sub("", body)
        if _PUBLIC_ARTIFACT_FORBIDDEN_PATTERN.search(prose_without_urls):
            issues.append(
                ValidationIssue(
                    "INTERNAL_PROVIDER_EXPOSURE",
                    "critical",
                    "A public artifact exposes an internal collection or analysis provider.",
                    path.name,
                )
            )
        if _INTERNAL_EVIDENCE_ID_PATTERN.search(body):
            issues.append(
                ValidationIssue(
                    "INTERNAL_EVIDENCE_ID_EXPOSURE",
                    "critical",
                    "A public artifact exposes an internal evidence identifier.",
                    path.name,
                )
            )


def _validate_public_export_references(
    executive_path: Path,
    issues: list[ValidationIssue],
) -> None:
    evidence_path = executive_path.with_name(f"{executive_path.stem}_evidence.json")
    evidence_csv_path = executive_path.with_name(f"{executive_path.stem}_evidence.csv")
    strategic_path = executive_path.with_name(f"{executive_path.stem}_strategic_scores.json")
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        records = payload.get("records", []) or []
        record_ids = [str(item.get("id") or "") for item in records]
    except (OSError, json.JSONDecodeError, AttributeError):
        return

    public_pattern = re.compile(r"^CDE-EV-[A-F0-9]{16}$")
    if any(not public_pattern.fullmatch(item) for item in record_ids):
        issues.append(
            ValidationIssue(
                "PUBLIC_EVIDENCE_ID_INVALID",
                "critical",
                "The evidence export contains an invalid public evidence identifier.",
                evidence_path.name,
            )
        )
    if len(record_ids) != len(set(record_ids)):
        issues.append(
            ValidationIssue(
                "PUBLIC_EVIDENCE_ID_DUPLICATE",
                "critical",
                "The evidence export contains duplicate public evidence identifiers.",
                evidence_path.name,
            )
        )
    record_id_set = set(record_ids)

    try:
        with evidence_csv_path.open(encoding="utf-8", newline="") as handle:
            csv_ids = [str(row.get("id") or "") for row in csv.DictReader(handle)]
    except OSError:
        csv_ids = []
    if record_ids != csv_ids:
        issues.append(
            ValidationIssue(
                "PUBLIC_EVIDENCE_JSON_CSV_MISMATCH",
                "critical",
                "JSON and CSV evidence exports do not contain the same ordered public identifiers.",
                evidence_csv_path.name,
            )
        )

    reference_groups: dict[str, set[str]] = {
        "evidence_items": {
            str(item.get("evidence_id") or "")
            for item in payload.get("evidence_items", []) or []
            if item.get("evidence_id")
        },
        "claim_evidence_links": {
            str(item.get("evidence_id") or "")
            for item in payload.get("claim_evidence_links", []) or []
            if item.get("evidence_id")
        },
        "claims": {
            str(evidence_id)
            for claim in payload.get("claims", []) or []
            for evidence_id in claim.get("evidence_ids", []) or []
            if evidence_id
        },
    }
    try:
        strategic = json.loads(strategic_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        strategic = {}
    reference_groups["strategic_scores"] = {
        str(evidence_id)
        for model_name in ("pestel", "porter")
        for dimension in (strategic.get(model_name, {}) or {}).get("dimensions", []) or []
        for evidence_id in dimension.get("evidence_ids", []) or []
        if evidence_id
    }
    for group, references in reference_groups.items():
        unresolved = references - record_id_set
        if unresolved:
            issues.append(
                ValidationIssue(
                    "PUBLIC_EVIDENCE_REFERENCE_UNRESOLVED",
                    "critical",
                    f"{group} contains {len(unresolved)} public evidence references absent from the evidence export.",
                    group,
                )
            )


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


def _validate_cti_snapshot(
    snapshot: dict[str, Any], issues: list[ValidationIssue]
) -> None:
    cti = snapshot.get("cti_snapshot", {}) or {}
    if not cti:
        return
    overview = cti.get("overview", {}) or {}
    actors = cti.get("actors", []) or []
    campaigns = cti.get("campaigns", []) or []
    techniques = cti.get("techniques", []) or []
    expected_counts = {
        "actor_count": len(actors),
        "campaign_count": len(campaigns),
        "technique_count": len(techniques),
    }
    for key, expected in expected_counts.items():
        if int(overview.get(key, 0) or 0) != expected:
            issues.append(
                ValidationIssue(
                    "CTI_COUNT_MISMATCH",
                    "critical",
                    "A CTI overview count differs from the canonical entity collection.",
                    f"decision_snapshot.cti_snapshot.overview.{key}",
                )
            )

    valid_states = {"OBSERVED", "INFERRED", "RELATED", "REFERENCE"}
    state_counts = {state: 0 for state in valid_states}
    evidence_ids = {
        str(row.get("evidence_id"))
        for row in (cti.get("evidence", []) or [])
        if isinstance(row, dict) and row.get("evidence_id")
    }
    observed_actors = {
        str(actor.get("name") or "").casefold()
        for actor in actors
        if actor.get("state") == "OBSERVED"
        and int(actor.get("observed_attack_count", 0) or 0) > 0
        and actor.get("evidence_ids")
    }
    for collection_name, rows in (
        ("actors", actors),
        ("campaigns", campaigns),
        ("techniques", techniques),
    ):
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            state = str(row.get("state") or "REFERENCE")
            state_counts[state if state in valid_states else "REFERENCE"] += 1
            linked_ids = {str(value) for value in row.get("evidence_ids", []) if value}
            if not linked_ids.issubset(evidence_ids):
                issues.append(
                    ValidationIssue(
                        "CTI_EVIDENCE_ORPHAN",
                        "critical",
                        "A CTI entity references evidence absent from the CTI evidence index.",
                        f"decision_snapshot.cti_snapshot.{collection_name}.{index}",
                    )
                )
            if state == "OBSERVED":
                telemetry_supported = bool(linked_ids)
                if collection_name == "actors":
                    telemetry_supported = telemetry_supported and int(
                        row.get("observed_attack_count", 0) or 0
                    ) > 0
                elif collection_name == "campaigns":
                    telemetry_supported = telemetry_supported and any(
                        str(name).casefold() in observed_actors
                        for name in row.get("actors", [])
                    )
                else:
                    telemetry_supported = False
                if not telemetry_supported:
                    issues.append(
                        ValidationIssue(
                            "CTI_OBSERVED_WITHOUT_TELEMETRY",
                            "critical",
                            "OBSERVED was used without traceable confirmed adversary telemetry.",
                            f"decision_snapshot.cti_snapshot.{collection_name}.{index}",
                        )
                    )

    published_state_counts = (cti.get("quality", {}) or {}).get("state_counts", {}) or {}
    for state, expected in state_counts.items():
        if int(published_state_counts.get(state, 0) or 0) != expected:
            issues.append(
                ValidationIssue(
                    "CTI_COUNT_MISMATCH",
                    "critical",
                    "CTI state totals differ from the canonical entity states.",
                    f"decision_snapshot.cti_snapshot.quality.state_counts.{state}",
                )
            )

    weights = (cti.get("relevance_model", {}) or {}).get("weights", {}) or {}
    try:
        weight_total = sum(float(value) for value in weights.values())
    except (TypeError, ValueError):
        weight_total = -1.0
    if not weights or abs(weight_total - 1.0) > 0.001:
        issues.append(
            ValidationIssue(
                "CTI_SCORE_INVALID",
                "critical",
                "CTI relevance weights are missing or do not sum to one.",
                "decision_snapshot.cti_snapshot.relevance_model.weights",
            )
        )
    for index, actor in enumerate(actors):
        try:
            score = float(actor.get("relevance_score"))
        except (TypeError, ValueError):
            score = -1.0
        if score < 0 or score > 100:
            issues.append(
                ValidationIssue(
                    "CTI_SCORE_INVALID",
                    "critical",
                    "An actor contextual relevance score is outside 0..100.",
                    f"decision_snapshot.cti_snapshot.actors.{index}.relevance_score",
                )
            )


def _validate_cti_rendering(
    snapshot: dict[str, Any],
    executive_path: Path,
    technical_path: Path,
    issues: list[ValidationIssue],
) -> None:
    cti = snapshot.get("cti_snapshot", {}) or {}
    if not cti:
        return
    overview = cti.get("overview", {}) or {}
    expected = {
        "actor": int(overview.get("actor_count", 0) or 0),
        "campaign": int(overview.get("campaign_count", 0) or 0),
        "technique": int(overview.get("technique_count", 0) or 0),
    }
    for path in (executive_path, technical_path):
        if not path.is_file():
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        for key, value in expected.items():
            match = re.search(rf'data-cti-{key}-count=["\'](\d+)["\']', body)
            if match is None or int(match.group(1)) != value:
                issues.append(
                    ValidationIssue(
                        "CTI_RENDER_MISMATCH",
                        "critical",
                        "Rendered CTI counts differ from the decision snapshot.",
                        f"{path.name}:data-cti-{key}-count",
                    )
                )
            row_class = {
                "actor": "threat-entity-row" if path == executive_path else "threat-report-row",
                "campaign": "cti-campaign-row",
                "technique": "cti-technique-row",
            }[key]
            rendered_rows = len(
                re.findall(
                    rf'class=["\'][^"\']*\b{re.escape(row_class)}\b[^"\']*["\']',
                    body,
                )
            )
            if rendered_rows != value:
                issues.append(
                    ValidationIssue(
                        "CTI_DETAIL_RENDER_MISMATCH",
                        "critical",
                        "Rendered CTI detail does not contain the complete summarized inventory.",
                        f"{path.name}:{row_class}:{rendered_rows}/{value}",
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
        visible_text = _visible_body_text(body)
        for label, pattern in _VISIBLE_INTERNAL_MARKERS.items():
            if pattern.search(visible_text):
                issues.append(
                    ValidationIssue(
                        "VISIBLE_INTERNAL_METADATA",
                        "high",
                        "Internal implementation metadata is visible in the report body.",
                        f"{path.name}:{label}",
                    )
                )
        body_without_web_urls = re.sub(r"https?://[^\s<\"']+", "", body, flags=re.IGNORECASE)
        if local_path_pattern.search(body_without_web_urls):
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
