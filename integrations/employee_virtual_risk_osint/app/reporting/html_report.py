from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import EmployeeRiskSummary
from app.privacy import mask_email
from .charts import (
    QUERY_TYPE_LABELS,
    confidence_distribution_chart,
    domain_signal_chart,
    evidence_review_chart,
    executive_risk_gauge,
    field_source_bar_chart,
    keyword_bar_chart,
    probability_impact_chart,
    query_basis_heatmap,
    radar_chart,
    risk_bar_chart,
    risk_contribution_donut,
)


def _decision_for_level(decision_matrix: Dict[str, Any], level: str) -> List[Dict[str, str]]:
    rows = decision_matrix.get("decision_rows", [])
    return [row for row in rows if row.get("risk_level") == level]


def _slug(value: str) -> str:
    import re
    value = (value or "").lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "empleado"


def _input_field_rows(summary: EmployeeRiskSummary) -> List[Dict[str, str]]:
    e = summary.employee
    evidence = summary.evidence
    source_counts = Counter(QUERY_TYPE_LABELS.get(ev.query_type, ev.query_type) for ev in evidence)
    rows = [
        {
            "field": "Nombre completo",
            "status": "Disponible" if e.full_name else "No informado",
            "used": "Sí" if e.full_name else "No",
            "mode": "Búsqueda exacta y combinada con organización/dominio",
            "findings": str(
                source_counts.get("Nombre exacto", 0)
                + source_counts.get("Nombre + sitio social/técnico", 0)
                + source_counts.get("Nombre + keyword", 0)
                + source_counts.get("Nombre + organización", 0)
                + source_counts.get("Nombre + organización + keyword", 0)
                + source_counts.get("Nombre + dominio", 0)
                + source_counts.get("Nombre + dominio + keyword", 0)
            ),
        },
        {
            "field": "Correo corporativo",
            "status": "Disponible" if e.corporate_email else "No informado",
            "used": "Sí" if e.corporate_email else "No",
            "mode": "Búsqueda exacta por correo corporativo",
            "findings": str(source_counts.get("Correo corporativo exacto", 0) + source_counts.get("Correo corporativo + keyword", 0)),
        },
        {
            "field": "Correo personal",
            "status": "Disponible" if e.personal_email else "No informado",
            "used": "Sí" if (e.personal_email and e.authorized_personal_email) else "No",
            "mode": "Solo con autorización explícita",
            "findings": str(source_counts.get("Correo personal autorizado", 0) + source_counts.get("Correo personal autorizado + keyword", 0)),
        },
        {
            "field": "Documento de identificación",
            "status": "Hash disponible" if e.identification_document_hash else "No informado",
            "used": "No",
            "mode": "No se utiliza por minimización y privacidad",
            "findings": "0",
        },
    ]
    return rows


def _query_source_summary(summary: EmployeeRiskSummary) -> Dict[str, int]:
    counts = Counter(QUERY_TYPE_LABELS.get(ev.query_type, ev.query_type) for ev in summary.evidence)
    ordered = [
        "Nombre exacto",
        "Nombre + sitio social/técnico",
        "Nombre + keyword",
        "Nombre + organización",
        "Nombre + organización + keyword",
        "Correo corporativo exacto",
        "Correo corporativo + keyword",
        "Nombre + dominio",
        "Nombre + dominio + keyword",
        "Resultado manual/importado",
        "Correo personal autorizado",
        "Correo personal autorizado + keyword",
    ]
    return {label: counts.get(label, 0) for label in ordered if counts.get(label, 0) > 0} or {"Sin hallazgos": 0}


def _portfolio_employee_rows(summaries: List[EmployeeRiskSummary]) -> List[Dict[str, Any]]:
    rows = []
    for summary in summaries:
        e = summary.employee
        filename = f"{e.employee_id}_{_slug(e.full_name)}.html"
        rows.append({
            "employee_id": e.employee_id,
            "full_name": e.full_name,
            "role": e.role,
            "department": e.department,
            "organization": e.organization,
            "access_level": e.access_level,
            "access_category": e.access_category,
            "risk": summary.total_risk,
            "risk_level": summary.risk_level,
            "evidence_count": len(summary.evidence),
            "skipped": summary.skipped,
            "skip_reason": summary.skip_reason,
            "report_rel_path": f"employees/{filename}",
        })
    return sorted(rows, key=lambda r: (-float(r["risk"]), r["full_name"]))


def render_html_reports(
    summaries: List[EmployeeRiskSummary],
    decision_matrix: Dict[str, Any],
    output_dir: str | Path,
    title: str = "Informe de Ciberinteligencia de Exposición y Riesgo Digital",
) -> Dict[str, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    employee_dir = output_dir / "employees"
    employee_dir.mkdir(parents=True, exist_ok=True)

    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["mask_email"] = mask_email
    employee_template = env.get_template("employee_report.html.j2")
    portfolio_template = env.get_template("portfolio_report.html.j2")

    generated_at = datetime.now(timezone.utc).isoformat()
    generated_files: Dict[str, Path] = {}

    for summary in summaries:
        charts = {}
        if not summary.skipped:
            evidence_rows = [e.as_dict() for e in summary.evidence]
            charts = {
                "risk_gauge": executive_risk_gauge(summary.total_risk, summary.risk_level),
                "risk_bar": risk_bar_chart(summary.dimension_risks, summary.dimension_labels),
                "risk_donut": risk_contribution_donut(summary.dimension_risks, summary.dimension_labels),
                "keyword_bar": keyword_bar_chart(summary.top_keywords),
                "probability_impact": probability_impact_chart(summary.dimension_probability_impact),
                "radar": radar_chart(summary.dimension_risks, summary.dimension_labels),
                "query_heatmap": query_basis_heatmap(evidence_rows, summary.dimension_labels),
                "source_bar": field_source_bar_chart(_query_source_summary(summary)),
                "confidence_distribution": confidence_distribution_chart(evidence_rows),
                "evidence_review": evidence_review_chart(evidence_rows),
                "domain_signal": domain_signal_chart(evidence_rows),
            }
        employee = summary.employee
        file_name = f"{employee.employee_id}_{_slug(employee.full_name)}.html"
        out_path = employee_dir / file_name
        html = employee_template.render(
            title=title,
            generated_at=generated_at,
            summary=summary,
            employee=employee,
            charts=charts,
            decision_rows=_decision_for_level(decision_matrix, summary.risk_level),
            input_field_rows=_input_field_rows(summary),
            query_source_summary=_query_source_summary(summary),
            methodology_steps=[
                "Ingesta y validación de datos autorizados.",
                "Construcción de consultas OSINT con trazabilidad por tipo de dato.",
                "Consulta a fuentes públicas mediante buscadores permitidos.",
                "Filtrado, deduplicación y evaluación de falsos positivos.",
                "Scoring de confianza, severidad, probabilidad e impacto.",
                "Generación de hallazgos, gráficos, matriz de decisión y recomendaciones.",
            ],
            author_label="Proceso de análisis diseñado por Edwin Peñuela",
            query_type_labels=QUERY_TYPE_LABELS,
        )
        out_path.write_text(html, encoding="utf-8")
        generated_files[employee.employee_id] = out_path

    portfolio = {
        "employees_total": len(summaries),
        "employees_analyzed": len([s for s in summaries if not s.skipped]),
        "employees_skipped": len([s for s in summaries if s.skipped]),
        "max_risk": max([s.total_risk for s in summaries], default=0),
        "avg_risk": round(sum(s.total_risk for s in summaries) / len(summaries), 2) if summaries else 0,
        "critical_count": len([s for s in summaries if s.risk_level in {"Crítico", "Extremo"}]),
        "high_count": len([s for s in summaries if s.risk_level == "Alto"]),
    }
    employee_rows = _portfolio_employee_rows(summaries)
    index_path = output_dir / "cyberintelligence_report.html"
    portfolio_html = portfolio_template.render(
        title=title,
        generated_at=generated_at,
        portfolio=portfolio,
        employee_rows=employee_rows,
        author_label="Proceso de análisis diseñado por Edwin Peñuela",
    )
    index_path.write_text(portfolio_html, encoding="utf-8")
    generated_files["portfolio"] = index_path
    return generated_files
