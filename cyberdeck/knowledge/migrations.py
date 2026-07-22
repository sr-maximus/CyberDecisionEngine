from __future__ import annotations

from typing import Any


_LEGACY_OPTIONAL_COLLECTOR = "opencti"


def remove_legacy_optional_collector(context: Any) -> None:
    """Remove the former optional knowledge backend from collector telemetry."""
    statuses = list(getattr(context, "source_statuses", []) or [])
    context.source_statuses = [
        status
        for status in statuses
        if str(getattr(status, "name", "") or "").strip().lower() != _LEGACY_OPTIONAL_COLLECTOR
    ]
    metrics = getattr(context, "metrics", {}) or {}
    remove_legacy_optional_collector_from_coverage(metrics.get("source_coverage", {}))
    remove_legacy_optional_collector_from_coverage(getattr(context, "connector_coverage", {}) or {})


def remove_legacy_optional_collector_from_coverage(coverage: Any) -> None:
    if not isinstance(coverage, dict):
        return
    connectors = coverage.get("connectors")
    if isinstance(connectors, list):
        coverage["connectors"] = [
            row
            for row in connectors
            if str((row or {}).get("name") or "").strip().lower() != _LEGACY_OPTIONAL_COLLECTOR
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
                if str((row or {}).get("name") or "").strip().lower() != _LEGACY_OPTIONAL_COLLECTOR
            ]
    web_layers = coverage.get("web_layers")
    if isinstance(web_layers, dict):
        for layer in web_layers.values():
            if not isinstance(layer, dict) or not isinstance(layer.get("sources"), list):
                continue
            layer["sources"] = [
                source
                for source in layer["sources"]
                if str(source).strip().lower() != _LEGACY_OPTIONAL_COLLECTOR
            ]
