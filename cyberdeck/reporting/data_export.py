from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from cyberdeck.schemas import RunContext
from cyberdeck.semantics import get_term_registry


def export_evidence(context: RunContext, html_path: Path) -> Dict[str, Any]:
    stem = html_path.stem
    json_path = html_path.with_name(f"{stem}_evidence.json")
    csv_path = html_path.with_name(f"{stem}_evidence.csv")
    payload = _payload(context)
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_events_csv(csv_path, payload["records"])
    snapshot_files = export_decision_snapshot(context.decision_snapshot, html_path)
    return {
        "json": json_path.name,
        "csv": csv_path.name,
        "json_path": str(json_path),
        "csv_path": str(csv_path),
        "record_count": len(payload["records"]),
        "event_count": len(payload["records"]),
        "risk_count": len(payload["risk_findings"]),
        "source_count": len(payload["source_statuses"]),
        **snapshot_files,
    }


def export_decision_snapshot(snapshot: Dict[str, Any], html_path: Path) -> Dict[str, Any]:
    stem = html_path.stem
    json_path = html_path.with_name(f"{stem}_decision_snapshot.json")
    csv_path = html_path.with_name(f"{stem}_decision_snapshot.csv")
    payload = snapshot or {}
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    rows = _snapshot_rows(payload)
    _write_snapshot_csv(csv_path, rows)
    return {
        "snapshot_json": json_path.name,
        "snapshot_csv": csv_path.name,
        "snapshot_json_path": str(json_path),
        "snapshot_csv_path": str(csv_path),
        "snapshot_row_count": len(rows),
    }


def _payload(context: RunContext) -> Dict[str, Any]:
    records = [_event_row(event) for event in context.raw_events]
    claims_by_evidence: Dict[str, List[str]] = {}
    for link in context.claim_evidence_links:
        evidence_id = str(link.get("evidence_id") or "")
        claim_id = str(link.get("claim_id") or "")
        if evidence_id and claim_id:
            claims_by_evidence.setdefault(evidence_id, []).append(claim_id)
    for record in records:
        evidence_id = str(record.get("canonical_id") or record.get("id") or "")
        record["claim_ids"] = ",".join(sorted(set(claims_by_evidence.get(evidence_id, []))))
        record["semantic_registry_version"] = get_term_registry().version
        record["claim_evidence_model_version"] = context.claim_evidence_model_version
    return {
        "generated_at": context.generated_at,
        "organization": _dump(context.organization),
        "mode": context.mode,
        "analysis_window": context.analysis_window,
        "lookback_hours": context.lookback_hours,
        "lookback_days": context.lookback_days,
        "records": records,
        "events": records,
        "processing_summary": context.processing_summary,
        "connector_coverage": context.connector_coverage,
        "confirmed_incidents": context.incidents_confirmed,
        "false_positive_count": context.false_positive_count,
        "risk_findings": [_dump(finding) for finding in context.risk_findings],
        "source_statuses": [_dump(status) for status in context.source_statuses],
        "references": context.references,
        "metrics": context.metrics,
        "claims": context.claims,
        "evidence_items": context.evidence_items,
        "claim_evidence_links": context.claim_evidence_links,
        "contradicting_evidence": context.contradicting_evidence,
        "interpretations": context.interpretations,
        "decisions": context.decisions,
        "semantic_registry_version": get_term_registry().version,
        "claim_evidence_model_version": context.claim_evidence_model_version,
    }


def _event_row(event: Any) -> Dict[str, Any]:
    data = _dump(event)
    return {
        "id": data.get("id"),
        "canonical_id": data.get("canonical_id"),
        "content_hash": data.get("content_hash"),
        "title": data.get("title"),
        "category": data.get("category"),
        "source": data.get("source"),
        "source_weight": data.get("source_weight"),
        "confidence": data.get("confidence"),
        "confidence_score": data.get("confidence_score"),
        "confidence_level": data.get("confidence_level"),
        "record_kind": data.get("record_kind"),
        "evidence_status": data.get("evidence_status"),
        "relationship_to_scope": data.get("relationship_to_scope"),
        "validation_result": data.get("validation_result"),
        "age_days": data.get("age_days"),
        "severity": data.get("severity"),
        "epss": data.get("epss"),
        "cvss": data.get("cvss"),
        "cve": data.get("cve"),
        "vulnerability_status": data.get("vulnerability_status"),
        "actor": data.get("actor"),
        "technique": data.get("technique"),
        "attack_mapping_status": data.get("attack_mapping_status"),
        "asset": data.get("asset"),
        "host": data.get("host"),
        "indicator": data.get("indicator"),
        "source_refs": ",".join(data.get("source_refs") or []),
        "duplicate_count": data.get("duplicate_count", 0),
        "tags": ",".join(data.get("tags") or []),
        "evidence_url": data.get("evidence_url"),
        "observed_at": data.get("observed_at"),
        "data_mode": "real" if not data.get("demo") else "demo",
    }


def _write_events_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fieldnames = [
        "id",
        "canonical_id",
        "content_hash",
        "title",
        "category",
        "source",
        "source_weight",
        "confidence",
        "confidence_score",
        "confidence_level",
        "record_kind",
        "evidence_status",
        "relationship_to_scope",
        "validation_result",
        "age_days",
        "severity",
        "epss",
        "cvss",
        "cve",
        "vulnerability_status",
        "actor",
        "technique",
        "attack_mapping_status",
        "asset",
        "host",
        "indicator",
        "source_refs",
        "duplicate_count",
        "tags",
        "evidence_url",
        "observed_at",
        "data_mode",
        "claim_ids",
        "semantic_registry_version",
        "claim_evidence_model_version",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _snapshot_rows(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    snapshot_hash = snapshot.get("snapshot_hash", "")
    for metric_id, metric in (snapshot.get("metrics") or {}).items():
        rows.append(
            {
                "record_type": "metric",
                "record_id": metric_id,
                "name": metric.get("label", metric_id),
                "domain": "",
                "value": metric.get("value"),
                "unit": metric.get("unit", ""),
                "value_status": metric.get("value_status", ""),
                "confidence": metric.get("confidence", ""),
                "evidence_ids": ",".join(metric.get("evidence_ids") or []),
                "snapshot_hash": snapshot_hash,
            }
        )
    for entity in snapshot.get("analyzed_entities", []) or []:
        rows.append(
            {
                "record_type": "entity",
                "record_id": entity.get("entity_id", ""),
                "name": entity.get("canonical_name", ""),
                "domain": ",".join(entity.get("domains") or []),
                "value": entity.get("entity_type", ""),
                "unit": "subject",
                "value_status": entity.get("validation_status", ""),
                "confidence": "",
                "evidence_ids": "",
                "snapshot_hash": snapshot_hash,
            }
        )
    for domain in snapshot.get("domains", []) or []:
        rows.append(
            {
                "record_type": "domain",
                "record_id": domain.get("domain", ""),
                "name": domain.get("top_signal", ""),
                "domain": domain.get("domain", ""),
                "value": domain.get("max_residual_risk"),
                "unit": "risk_points",
                "value_status": domain.get("risk_value_status", ""),
                "confidence": "",
                "evidence_ids": ",".join(domain.get("evidence_ids") or []),
                "snapshot_hash": snapshot_hash,
            }
        )
    for scenario in snapshot.get("supported_scenarios", []) or []:
        rows.append(
            {
                "record_type": "scenario",
                "record_id": scenario.get("scenario_id", ""),
                "name": scenario.get("title", ""),
                "domain": scenario.get("domain", ""),
                "value": "",
                "unit": "",
                "value_status": scenario.get("status", ""),
                "confidence": scenario.get("confidence", ""),
                "evidence_ids": ",".join(scenario.get("evidence_ids") or []),
                "snapshot_hash": snapshot_hash,
            }
        )
    for decision in snapshot.get("decisions", []) or []:
        rows.append(
            {
                "record_type": "decision",
                "record_id": decision.get("decision_id", ""),
                "name": decision.get("title", ""),
                "domain": "",
                "value": "",
                "unit": "",
                "value_status": decision.get("status", ""),
                "confidence": decision.get("confidence", ""),
                "evidence_ids": ",".join(decision.get("evidence_ids") or []),
                "snapshot_hash": snapshot_hash,
            }
        )
    return rows


def _write_snapshot_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fieldnames = [
        "record_type",
        "record_id",
        "name",
        "domain",
        "value",
        "unit",
        "value_status",
        "confidence",
        "evidence_ids",
        "snapshot_hash",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _dump(value: Any) -> Dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return dict(value)
