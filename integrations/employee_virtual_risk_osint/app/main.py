from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from .audit import write_audit_log
from .catalogs import load_catalogs
from .config import load_settings
from .ingestion import create_template, read_employees, validate_employee_records
from .models import EmployeeRiskSummary, ScoredEvidence
from .manual_results import load_manual_results
from .privacy import has_valid_consent
from .query_builder import build_queries
from .reporting.html_report import render_html_reports
from .scoring import aggregate_employee_risk, dedupe_results, score_result
from .search_clients import make_search_client
from .search_clients.base import SearchClientError


def cmd_generate_template(args: argparse.Namespace) -> int:
    path = create_template(args.output)
    print(f"Plantilla creada: {path}")
    return 0


def cmd_validate_consent(args: argparse.Namespace) -> int:
    settings = load_settings()
    employees = read_employees(args.input, settings.hash_salt)
    errors, warnings = validate_employee_records(employees)
    print(f"Registros leídos: {len(employees)}")
    if errors:
        print("Errores:")
        for item in errors:
            print(f"  - {item}")
    if warnings:
        print("Advertencias:")
        for item in warnings:
            print(f"  - {item}")
    approved = sum(1 for e in employees if has_valid_consent(e.consent_status))
    print(f"Con consentimiento aprobado: {approved}")
    print(f"Sin consentimiento aprobado: {len(employees) - approved}")
    return 1 if errors else 0


def _empty_skipped_summary(employee, reason: str, risk_config: Dict[str, Any]) -> EmployeeRiskSummary:
    dimensions_cfg = risk_config.get("dimensions", {})
    dimension_risks = {k: 0.0 for k, v in dimensions_cfg.items() if not v.get("mitigating", False)}
    dimension_labels = {k: v.get("label", k) for k, v in dimensions_cfg.items() if not v.get("mitigating", False)}
    return EmployeeRiskSummary(
        employee=employee,
        total_risk=0.0,
        risk_level="Bajo",
        mitigation_score=0.0,
        dimension_risks=dimension_risks,
        dimension_labels=dimension_labels,
        dimension_probability_impact={k: {"probability": 0.0, "impact": 0.0, "label": label} for k, label in dimension_labels.items()},
        top_keywords=[],
        social_surfaces=[],
        evidence=[],
        skipped=True,
        skip_reason=reason,
    )


def _write_outputs(output_dir: Path, summaries: List[EmployeeRiskSummary], formats: List[str]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    serializable = [s.as_dict() for s in summaries]

    if "json" in formats:
        (output_dir / "analysis_results.json").write_text(json.dumps(serializable, ensure_ascii=False, indent=2), encoding="utf-8")

    evidence_rows = []
    summary_rows = []
    for summary in summaries:
        summary_rows.append({
            "employee_id": summary.employee.employee_id,
            "full_name": summary.employee.full_name,
            "department": summary.employee.department,
            "role": summary.employee.role,
            "access_level": summary.employee.access_level,
            "access_category": summary.employee.access_category,
            "total_risk": summary.total_risk,
            "risk_level": summary.risk_level,
            "mitigation_score": summary.mitigation_score,
            "skipped": summary.skipped,
            "skip_reason": summary.skip_reason,
        })
        for ev in summary.evidence:
            evidence_rows.append(ev.as_dict())

    if "csv" in formats:
        pd.DataFrame(summary_rows).to_csv(output_dir / "employee_risk_summary.csv", index=False)
        pd.DataFrame(evidence_rows).to_csv(output_dir / "evidence.csv", index=False)


def cmd_analyze(args: argparse.Namespace) -> int:
    settings = load_settings()
    if args.search_client:
        settings.search_client = args.search_client
    settings.max_queries_per_employee = args.max_queries_per_employee or settings.max_queries_per_employee
    settings.min_confidence = args.min_confidence if args.min_confidence is not None else settings.min_confidence

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    catalogs = load_catalogs(args.catalogs_dir)
    keywords_catalog = catalogs["keywords"]
    risk_config = catalogs["risk_weights"]
    decision_matrix = catalogs["decision_matrix"]

    employees = read_employees(args.input, settings.hash_salt)
    errors, warnings = validate_employee_records(employees)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 2
    for warning in warnings:
        print(f"ADVERTENCIA: {warning}", file=sys.stderr)

    client = None
    if not args.skip_web_search:
        try:
            client = make_search_client(settings.search_client, settings)
        except (SearchClientError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    manual_results_by_employee = {}
    if args.manual_results:
        try:
            manual_results_by_employee = load_manual_results(args.manual_results)
        except Exception as exc:
            print(f"ERROR cargando resultados manuales: {exc}", file=sys.stderr)
            return 2

    formats = [item.strip().lower() for item in args.formats.split(",") if item.strip()]
    summaries: List[EmployeeRiskSummary] = []
    audit_records: List[Dict[str, Any]] = []

    for employee in employees:
        if not has_valid_consent(employee.consent_status):
            summaries.append(_empty_skipped_summary(employee, "Consentimiento no aprobado o no documentado.", risk_config))
            audit_records.append({"event": "employee_skipped", "employee_id": employee.employee_id, "reason": "missing_consent"})
            continue

        query_specs = build_queries(
            employee=employee,
            keyword_catalog=keywords_catalog,
            allow_personal_email=args.allow_personal_email,
            max_keywords_per_dimension=args.max_keywords_per_dimension,
            max_queries_per_employee=settings.max_queries_per_employee,
            include_identity_discovery=not args.no_identity_discovery,
        )

        if args.dry_run_queries:
            for spec in query_specs:
                print(f"{employee.employee_id}\t{spec.dimension_label}\t{spec.keyword}\t{spec.query}")
            summaries.append(_empty_skipped_summary(employee, "Dry run de queries; no se ejecutó búsqueda.", risk_config))
            continue

        raw_results = []
        web_search_attempts = 0
        web_search_success = 0
        web_search_errors = 0

        # Resultados manuales/importados: útiles cuando Google muestra resultados en navegador,
        # pero bloquea automatización o el entorno no tiene conectividad.
        raw_results.extend(manual_results_by_employee.get(employee.employee_id, []))
        if manual_results_by_employee.get(employee.employee_id):
            audit_records.append({
                "event": "manual_results_loaded",
                "employee_id": employee.employee_id,
                "results_count": len(manual_results_by_employee.get(employee.employee_id, [])),
            })

        if not args.skip_web_search:
            for spec in query_specs:
                web_search_attempts += 1
                try:
                    assert client is not None
                    results = client.search(spec.query, count=args.results_per_query)
                except SearchClientError as exc:
                    web_search_errors += 1
                    print(f"ADVERTENCIA: búsqueda fallida para {employee.employee_id}: {exc}", file=sys.stderr)
                    audit_records.append({"event": "search_error", "employee_id": employee.employee_id, "query": spec.query, "error": str(exc)})
                    continue
                web_search_success += 1
                for result in results:
                    raw_results.append((spec, result))
                audit_records.append({
                    "event": "search_executed",
                    "employee_id": employee.employee_id,
                    "dimension": spec.dimension_key,
                    "keyword": spec.keyword,
                    "query_type": spec.query_type,
                    "query": spec.query,
                    "results_count": len(results),
                    "search_client": client.name if client else "none",
                })

        # Si todas las búsquedas fallaron por conectividad/bloqueo y no había datos manuales,
        # no lo presentamos como “sin hallazgos”: lo marcamos como búsqueda no completada.
        if not raw_results and web_search_attempts > 0 and web_search_success == 0 and web_search_errors > 0:
            reason = f"Búsqueda no completada: {web_search_errors}/{web_search_attempts} consultas fallaron por conectividad, DNS, bloqueo del buscador o captcha. Reintenta en red local o usa --manual-results."
            summaries.append(_empty_skipped_summary(employee, reason, risk_config))
            audit_records.append({"event": "employee_search_not_completed", "employee_id": employee.employee_id, "reason": reason})
            print(f"No completado {employee.employee_id}: {reason}")
            continue

        deduped = dedupe_results(raw_results)
        scored: List[ScoredEvidence] = [
            score_result(employee, spec, result, risk_config, settings.min_confidence)
            for spec, result in deduped
        ]
        summary = aggregate_employee_risk(employee, scored, risk_config)
        summaries.append(summary)
        print(f"Analizado {employee.employee_id}: riesgo={summary.total_risk} nivel={summary.risk_level} evidencias={len(scored)}")

    if "html" in formats:
        report_paths = render_html_reports(
            summaries=summaries,
            decision_matrix=decision_matrix,
            output_dir=output_dir,
        )
        print(f"Informe HTML maestro generado: {report_paths['portfolio']}")
        print(f"Informes individuales generados en: {output_dir / 'employees'}")

    _write_outputs(output_dir, summaries, formats)
    write_audit_log(output_dir, audit_records)
    print(f"Resultados guardados en: {output_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="employee_virtual_risk_osint",
        description="Análisis OSINT/ciberinteligencia autorizado de exposición pública y riesgo digital de empleados.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    tpl = sub.add_parser("generate-template", help="Genera plantilla XLSX de entrada")
    tpl.add_argument("--output", required=True, help="Ruta de salida .xlsx")
    tpl.set_defaults(func=cmd_generate_template)

    val = sub.add_parser("validate-consent", help="Valida estructura y consentimiento")
    val.add_argument("--input", required=True, help="CSV/XLSX de empleados")
    val.set_defaults(func=cmd_validate_consent)

    ana = sub.add_parser("analyze", help="Ejecuta análisis y genera reporte")
    ana.add_argument("--input", required=True, help="CSV/XLSX de empleados")
    ana.add_argument("--output", required=True, help="Directorio de salida")
    ana.add_argument("--catalogs-dir", default="catalogs", help="Directorio de catálogos YAML")
    ana.add_argument("--search-client", default="", choices=["", "mock", "duckduckgo_lite", "ddg", "bing_html", "multi_noapi", "noapi", "bing", "google_cse"], help="Cliente de búsqueda")
    ana.add_argument("--formats", default="html,json,csv", help="Formatos: html,json,csv")
    ana.add_argument("--results-per-query", type=int, default=5, help="Resultados por query")
    ana.add_argument("--max-keywords-per-dimension", type=int, default=20, help="Máximo de keywords por dimensión")
    ana.add_argument("--max-queries-per-employee", type=int, default=None, help="Límite de queries por empleado")
    ana.add_argument("--min-confidence", type=float, default=None, help="Umbral mínimo de confianza")
    ana.add_argument("--allow-personal-email", action="store_true", help="Permite usar correo personal si la fila lo autoriza")
    ana.add_argument("--no-identity-discovery", action="store_true", help="Desactiva consultas amplias iniciales: nombre exacto, nombre+organización, perfiles y correos exactos")
    ana.add_argument("--manual-results", default="", help="CSV/XLSX con resultados recolectados manualmente desde Google u otro buscador: employee_id,url,title,snippet,query")
    ana.add_argument("--skip-web-search", action="store_true", help="No consulta buscadores; analiza solo --manual-results")
    ana.add_argument("--dry-run-queries", action="store_true", help="Imprime queries sin consultar buscador")
    ana.set_defaults(func=cmd_analyze)
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
