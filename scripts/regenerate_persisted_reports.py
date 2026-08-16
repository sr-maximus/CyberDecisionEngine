from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPT_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_PROJECT_ROOT))

from cyberdeck.reporting.html_report import prepare_context_for_report, render_report  # noqa: E402
from cyberdeck.schemas import RunContext  # noqa: E402
from cyberdeck.settings import PROJECT_ROOT  # noqa: E402
from cyberdeck_api.jobs import RunStore, summarize_context  # noqa: E402


@dataclass(frozen=True)
class ReportTarget:
    run_id: str
    stem: str
    output_directory: str | None = None


def regenerate(target: ReportTarget) -> dict[str, object]:
    context_path = PROJECT_ROOT / "data" / "web_runs" / target.run_id / "context.json"
    if not context_path.is_file():
        raise FileNotFoundError(f"Missing persisted context: {context_path}")

    context = RunContext.model_validate_json(context_path.read_text(encoding="utf-8"))
    prepared = prepare_context_for_report(context, run_id=target.run_id)
    _atomic_write(context_path, prepared.model_dump_json(indent=2))

    report_path = PROJECT_ROOT / "reports" / "web" / f"{target.stem}.html"
    rendered = render_report(prepared, str(report_path))
    validation_path = rendered.with_name(f"{rendered.stem}_validation.json")
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    if validation.get("status") == "rejected":
        raise RuntimeError(f"Report validation rejected {target.run_id}: {validation_path}")

    _sync_output_directory(target, rendered, context_path, prepared)

    return _result(target, prepared, rendered, validation)


async def regenerate_database_targets(targets: list[ReportTarget]) -> list[dict[str, object]]:
    store = RunStore()
    await store.load()
    results: list[dict[str, object]] = []
    for target in targets:
        run = await store.generate_report(target.run_id)
        if run is None or run.report is None:
            raise RuntimeError(f"Persisted run is unavailable: {target.run_id}")
        context_path = PROJECT_ROOT / "data" / "web_runs" / target.run_id / "context.json"
        context = RunContext.model_validate_json(context_path.read_text(encoding="utf-8"))
        rendered = Path(run.report.path)
        validation_path = rendered.with_name(f"{rendered.stem}_validation.json")
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        if validation.get("status") == "rejected":
            raise RuntimeError(f"Report validation rejected {target.run_id}: {validation_path}")
        _sync_output_directory(
            target,
            rendered,
            context_path,
            context,
            run_payload=run.model_dump(mode="json"),
        )
        results.append(_result(target, context, rendered, validation))
    return results


def _sync_output_directory(
    target: ReportTarget,
    rendered: Path,
    context_path: Path,
    context: RunContext,
    *,
    run_payload: dict[str, object] | None = None,
) -> None:
    if not target.output_directory:
        return
    destination = PROJECT_ROOT / target.output_directory
    destination.mkdir(parents=True, exist_ok=True)
    _copy_run_bundle(rendered, destination)
    shutil.copy2(context_path, destination / "context.json")
    summary_path = destination / "run-summary.json"
    existing_payload = _read_json_object(summary_path)
    synchronized = _build_run_summary_payload(
        target,
        context,
        rendered,
        run_payload=run_payload or existing_payload,
    )
    _atomic_write(summary_path, json.dumps(synchronized, indent=2, ensure_ascii=False))


def _build_run_summary_payload(
    target: ReportTarget,
    context: RunContext,
    rendered: Path,
    *,
    run_payload: dict[str, object] | None = None,
) -> dict[str, object]:
    payload = dict(run_payload or {})
    domains = [str(item) for item in payload.get("domains", []) if str(item).strip()]
    if not domains:
        domains = list(context.organization.primary_domains)

    validation_path = rendered.with_name(f"{rendered.stem}_validation.json")
    validation = _read_json_object(validation_path)
    validation_status = str(validation.get("status") or "rejected")
    try:
        relative_report = rendered.relative_to(PROJECT_ROOT / "reports").as_posix()
    except ValueError:
        relative_report = f"web/{rendered.name}"

    payload.update(
        {
            "id": target.run_id,
            "status": "completed",
            "stage": "Report ready",
            "domains": domains,
            "progress": 100,
            "error": None,
            "summary": summarize_context(domains, context).model_dump(mode="json"),
            "report": {
                "path": str(rendered),
                "url": f"/reports/{relative_report}",
                "download_url": f"/api/reports/{relative_report}/download",
                "generated_at": context.report_display_at or context.generated_at,
                "validation_status": validation_status,
                "validation_path": str(validation_path),
                "final": validation_status != "rejected",
            },
        }
    )
    return payload


def _read_json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _result(
    target: ReportTarget,
    context: RunContext,
    rendered: Path,
    validation: dict[str, object],
) -> dict[str, object]:
    metrics = context.decision_snapshot.get("metrics", {})

    return {
        "run_id": target.run_id,
        "organization": context.organization.name,
        "domains": context.organization.primary_domains,
        "executive_report": str(rendered),
        "technical_report": str(rendered.with_name(f"{rendered.stem}-technical.html")),
        "validation": validation.get("status"),
        "snapshot_version": context.decision_snapshot.get("schema_version"),
        "snapshot_hash": context.decision_snapshot.get("snapshot_hash"),
        "raw_records": _metric_value(metrics, "raw_records"),
        "unique_records": _metric_value(metrics, "unique_records"),
        "validated_findings": _metric_value(metrics, "validated_findings"),
        "registered_sources": _metric_value(metrics, "registered_sources"),
        "eligible_sources": _metric_value(metrics, "total_sources"),
        "attempted_sources": _metric_value(metrics, "queried_sources"),
        "productive_sources": _metric_value(metrics, "productive_sources"),
    }


def _copy_run_bundle(executive_path: Path, destination: Path) -> None:
    for source in executive_path.parent.glob(f"{executive_path.stem}*"):
        if source.is_file():
            shutil.copy2(source, destination / source.name)


def _metric_value(metrics: dict[str, object], metric_id: str) -> int | float | None:
    metric = metrics.get(metric_id)
    if not isinstance(metric, dict):
        return None
    value = metric.get("value")
    return value if isinstance(value, (int, float)) else None


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Regenerate validated report bundles from persisted run contexts."
    )
    parser.add_argument(
        "run_ids",
        nargs="+",
        help="Persisted run IDs supplied locally; no IDs are embedded in the repository.",
    )
    parser.add_argument(
        "--output-root",
        help="Optional local output root. Each run is written beneath its own ID.",
    )
    args = parser.parse_args()
    targets = [
        ReportTarget(
            run_id=run_id,
            stem=run_id,
            output_directory=(f"{args.output_root.rstrip('/')}/{run_id}" if args.output_root else None),
        )
        for run_id in args.run_ids
    ]
    if os.getenv("DATABASE_URL"):
        results = asyncio.run(regenerate_database_targets(targets))
    else:
        results = [regenerate(target) for target in targets]
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
