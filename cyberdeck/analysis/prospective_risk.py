from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Iterable, Mapping

from cyberdeck.analysis.risk_engine import decay
from cyberdeck.schemas import EvidenceStatus, RiskFinding, ThreatEvent


MODEL_VERSION = "cde-prospective-pressure-v2.0.0"
ASSURED_STATUSES = {
    EvidenceStatus.DIRECT,
    EvidenceStatus.VALIDATED,
    EvidenceStatus.CONFIRMED,
}
APPLICABLE_VULNERABILITY_STATES = {
    "cve_applicable",
    "cve_confirmed",
    "kev_exposed",
    "exploitation_observed",
}


def build_prospective_attack_risk(
    events: Iterable[ThreatEvent],
    findings: Iterable[RiskFinding],
    *,
    sector: str = "",
    controls: Mapping[str, float] | None = None,
    source_coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    event_list = [
        event
        for event in events
        if event.evidence_status in ASSURED_STATUSES
        and event.evidence_status not in {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}
    ]
    finding_list = list(findings)
    coverage = source_coverage or {}
    if not event_list:
        return _empty_model()

    current_weight = sum(_event_weight(event) for event in event_list if event.age_days <= 7)
    previous_weight = sum(_event_weight(event) for event in event_list if 7 < event.age_days <= 30)
    current_daily = current_weight / 7
    previous_daily = previous_weight / 23
    trend_ratio = (current_daily - previous_daily) / max(previous_daily, 0.05)
    trend_direction = "rising" if trend_ratio >= 0.20 else "falling" if trend_ratio <= -0.20 else "stable"

    applicable = [event for event in event_list if event.vulnerability_status in APPLICABLE_VULNERABILITY_STATES]
    direct_exploitation = [
        event
        for event in applicable
        if event.vulnerability_status == "exploitation_observed"
        or "kev" in {tag.lower() for tag in event.tags}
    ]
    attack_surface = [
        event
        for event in event_list
        if event.category.startswith("attack_surface")
        and "dns_inventory_only" not in {tag.lower() for tag in event.tags}
    ]
    social = [event for event in event_list if _matches(event, "social", "socmint", "phishing", "fraud", "brand")]
    darkweb = [event for event in event_list if _matches(event, "darkweb", "dark_web", "ransomware", ".onion")]
    adversary = [
        event
        for event in event_list
        if event.technique
        or (event.actor and event.actor.lower() not in {"unknown", "unattributed"})
    ]

    source_count = len({event.source for event in event_list})
    source_diversity = min(1.0, math.log1p(source_count) / math.log(9))
    evidence_activity = 1 - math.exp(-0.18 * sum(_event_weight(event) for event in event_list))
    recency = min(1.0, current_weight / 8)
    vulnerability = max(
        (
            min(1.0, event.cvss / 10)
            * (0.65 + 0.35 * max(0.0, min(1.0, event.epss)))
            for event in applicable
        ),
        default=0.0,
    )
    exploitation = min(1.0, len(direct_exploitation) / 3)
    surface = max((event.severity * event.confidence_score for event in attack_surface), default=0.0)
    social_pressure = min(1.0, sum(_event_weight(event) for event in social) / 7)
    darkweb_pressure = min(1.0, sum(_event_weight(event) for event in darkweb) / 5)
    adversary_pressure = min(1.0, sum(_event_weight(event) for event in adversary) / 6)
    sector_context = 0.15 if sector.strip() else 0.0
    control_effect = _declared_control_effect(controls or {})

    raw_pressure = (
        0.18 * evidence_activity
        + 0.14 * recency
        + 0.18 * vulnerability
        + 0.15 * exploitation
        + 0.12 * surface
        + 0.08 * social_pressure
        + 0.07 * darkweb_pressure
        + 0.06 * adversary_pressure
        + 0.02 * sector_context
    )
    if control_effect is not None:
        raw_pressure *= 1 - min(0.45, control_effect * 0.45)
    raw_pressure = _clip(raw_pressure)
    daily_rate = min(0.045, 0.001 + 0.035 * raw_pressure)

    evidence_assurance = len(event_list) / max(1, int(coverage.get("unique_records", len(event_list)) or len(event_list)))
    source_health = _clip(float(coverage.get("source_health_score", 0.0) or 0.0))
    confidence = _clip(
        0.30 * min(1.0, len(event_list) / 20)
        + 0.25 * source_diversity
        + 0.20 * min(1.0, evidence_assurance * 4)
        + 0.15 * source_health
        + 0.10 * min(1.0, (current_weight + previous_weight) / 12)
    )
    horizons = _horizons(daily_rate, confidence)
    scenarios = _scenario_rows(event_list, finding_list, horizons["30"]["signal_pressure_index"])

    return {
        "model_version": MODEL_VERSION,
        "model_type": "prospective_signal_pressure",
        "status": "assessed",
        "prediction_is_calibrated": False,
        "attack_probability": {
            "value": None,
            "status": "not_calibrated",
            "defined_outcome": "confirmed cyber attack within the selected horizon",
            "calibration_metrics": None,
            "model_version": MODEL_VERSION,
            "reason": (
                "No se publica probabilidad de ataque hasta disponer de resultados históricos etiquetados "
                "y métricas de calibración verificables."
            ),
        },
        "pressure_index_30d": round(float(horizons["30"]["signal_pressure_index"]), 4),
        "daily_signal_rate": round(daily_rate, 6),
        "evidence_confidence": round(confidence * 100, 1),
        "trend": {
            "direction": trend_direction,
            "change_ratio": round(trend_ratio, 4),
            "current_7d_daily_weight": round(current_daily, 4),
            "previous_23d_daily_weight": round(previous_daily, 4),
            "meaning": "Compara la intensidad diaria ponderada de evidencia validada reciente con los 23 días anteriores.",
        },
        "horizons": horizons,
        "drivers": [
            _driver("Actividad validada", evidence_activity, len(event_list), "Concentración temporal de registros directos o validados."),
            _driver("Recencia", recency, sum(1 for event in event_list if event.age_days <= 7), "Peso de señales observadas en los últimos siete días."),
            _driver("Vulnerabilidades aplicables", vulnerability, len(applicable), "Solo CVE/KEV relacionadas con tecnología o activo confirmado."),
            _driver("Explotación observada", exploitation, len(direct_exploitation), "KEV aplicable o explotación observada con evidencia trazable."),
            _driver("Superficie expuesta", surface, len(attack_surface), "Exposición externa validada; inventario DNS aislado no incrementa el índice."),
            _driver("SOCMINT y fraude", social_pressure, len(social), "Señales públicas de fraude, suplantación o marca validadas."),
            _driver("Dark web", darkweb_pressure, len(darkweb), "Registros dark web o ransomware relacionados y validados."),
            _driver("Comportamiento adversario", adversary_pressure, len(adversary), "Actor o técnica explícitos en la evidencia; no inferidos por palabras aisladas."),
        ],
        "scenarios": scenarios,
        "limitations": [
            "Es un índice prospectivo de presión de señales, no una probabilidad calibrada de ataque.",
            "El volumen bruto, los duplicados, las fuentes fallidas y los registros contextuales no aumentan el índice.",
            "Los controles solo reducen presión cuando fueron declarados; su ausencia permanece no evaluada.",
        ],
    }


def _empty_model() -> dict[str, Any]:
    horizons = _horizons(0.0, 0.0)
    return {
        "model_version": MODEL_VERSION,
        "model_type": "prospective_signal_pressure",
        "status": "insufficient_evidence",
        "prediction_is_calibrated": False,
        "attack_probability": {
            "value": None,
            "status": "not_calibrated",
            "defined_outcome": "confirmed cyber attack within the selected horizon",
            "calibration_metrics": None,
            "model_version": MODEL_VERSION,
            "reason": "No hay evidencia directa o validada suficiente para estimar presión prospectiva.",
        },
        "pressure_index_30d": None,
        "daily_signal_rate": None,
        "evidence_confidence": 0.0,
        "trend": {
            "direction": "insufficient_evidence",
            "change_ratio": None,
            "current_7d_daily_weight": 0.0,
            "previous_23d_daily_weight": 0.0,
            "meaning": "Sin evidencia suficiente para comparar periodos.",
        },
        "horizons": horizons,
        "drivers": [],
        "scenarios": [],
        "limitations": ["No se convierte ausencia de datos en cero observado ni en ausencia de riesgo."],
    }


def _horizons(daily_rate: float, confidence: float) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    sensitivity = 0.18 + 0.22 * (1 - confidence)
    for days in (7, 14, 30, 90):
        pressure = 1 - math.exp(-max(0.0, daily_rate) * days)
        output[str(days)] = {
            "signal_pressure_index": round(pressure, 4) if daily_rate > 0 else None,
            "lower_sensitivity": round(max(0.0, pressure * (1 - sensitivity)), 4) if daily_rate > 0 else None,
            "base_sensitivity": round(pressure, 4) if daily_rate > 0 else None,
            "upper_sensitivity": round(min(1.0, pressure * (1 + sensitivity)), 4) if daily_rate > 0 else None,
            "prediction_is_calibrated": False,
            "target": "relative pressure of validated public signals",
            "band_semantics": "sensitivity_not_confidence_interval",
            "language": "Índice relativo de presión; no es probabilidad de ataque ni intervalo de confianza.",
        }
    return output


def _scenario_rows(
    events: list[ThreatEvent],
    findings: list[RiskFinding],
    overall_pressure: float | None,
) -> list[dict[str, Any]]:
    groups: dict[str, list[ThreatEvent]] = defaultdict(list)
    for event in events:
        groups[_scenario_key(event)].append(event)
    finding_by_category: dict[str, list[RiskFinding]] = defaultdict(list)
    for finding in findings:
        finding_by_category[finding.category].append(finding)
    rows = []
    for key, group in groups.items():
        sources = {event.source for event in group}
        evidence_weight = sum(_event_weight(event) for event in group)
        support = _clip(0.55 * (1 - math.exp(-0.24 * evidence_weight)) + 0.25 * min(1.0, len(sources) / 3))
        related_findings = [
            finding
            for category, category_findings in finding_by_category.items()
            if category == key or any(event.category == category for event in group)
            for finding in category_findings
        ]
        residual = max((finding.residual_risk for finding in related_findings), default=None)
        rows.append(
            {
                "id": f"prospective-{key}",
                "modality": _scenario_label(key),
                "support_score": round(support, 4),
                "pressure_index": round((overall_pressure or 0.0) * support, 4),
                "evidence_count": len(group),
                "source_count": len(sources),
                "max_residual_risk": residual,
                "evidence_ids": [event.canonical_id or event.id for event in group[:20]],
                "evidence_urls": list(dict.fromkeys(event.evidence_url for event in group if event.evidence_url))[:10],
                "status": "supported" if len(sources) >= 2 or any(event.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED} for event in group) else "candidate",
                "decision": _scenario_decision(key),
            }
        )
    return sorted(rows, key=lambda row: (float(row["support_score"]), int(row["evidence_count"])), reverse=True)[:8]


def _event_weight(event: ThreatEvent) -> float:
    return (
        max(0.0, min(1.0, event.source_weight))
        * max(0.0, min(1.0, event.confidence_score))
        * decay(max(0, event.age_days), 14)
        * (1.15 if event.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED} else 1.0)
    )


def _declared_control_effect(controls: Mapping[str, float]) -> float | None:
    values = [
        max(0.0, min(1.0, float(value)))
        for value in controls.values()
        if isinstance(value, (int, float))
    ]
    return sum(values) / len(values) if values else None


def _matches(event: ThreatEvent, *terms: str) -> bool:
    text = " ".join(
        [
            event.category,
            event.source,
            event.title,
            event.evidence_url or "",
            " ".join(event.tags),
        ]
    ).lower()
    return any(term in text for term in terms)


def _scenario_key(event: ThreatEvent) -> str:
    if event.vulnerability_status in APPLICABLE_VULNERABILITY_STATES:
        return "vulnerability_exploitation"
    if _matches(event, "ransomware", "darkweb", "dark_web"):
        return "ransomware_darkweb"
    if _matches(event, "phishing", "fraud", "lookalike", "brand"):
        return "fraud_brand"
    if event.category.startswith("attack_surface"):
        return "external_surface"
    if _matches(event, "disinformation", "narrative", "socmint", "social"):
        return "influence_social"
    if event.technique or (event.actor and event.actor.lower() not in {"unknown", "unattributed"}):
        return "adversary_activity"
    return "other_validated_signal"


def _scenario_label(key: str) -> str:
    return {
        "vulnerability_exploitation": "Explotación de vulnerabilidades aplicables",
        "ransomware_darkweb": "Ransomware y exposición en dark web",
        "fraud_brand": "Fraude, phishing y suplantación de marca",
        "external_surface": "Exposición de superficie externa",
        "influence_social": "Narrativas e inteligencia social",
        "adversary_activity": "Actividad adversaria atribuible",
        "other_validated_signal": "Otras señales validadas",
    }[key]


def _scenario_decision(key: str) -> str:
    return {
        "vulnerability_exploitation": "Priorizar validación de versión, exposición y remediación basada en KEV/EPSS.",
        "ransomware_darkweb": "Correlacionar activos, identidad y continuidad antes de escalar respuesta.",
        "fraud_brand": "Validar dominio, canal y suplantación; activar protección de marca según evidencia.",
        "external_surface": "Confirmar exposición y propietario del activo antes de ordenar cierre.",
        "influence_social": "Revisar propagación, fuente y alcance antes de comunicar o responder.",
        "adversary_activity": "Validar atribución y TTP con fuentes independientes antes de activar escenarios.",
        "other_validated_signal": "Mantener observación y solicitar validación analítica adicional.",
    }[key]


def _driver(name: str, value: float, evidence_count: int, explanation: str) -> dict[str, Any]:
    return {
        "name": name,
        "value": round(_clip(value) * 100, 1),
        "evidence_count": evidence_count,
        "explanation": explanation,
    }


def _clip(value: float) -> float:
    return max(0.0, min(1.0, float(value)))
