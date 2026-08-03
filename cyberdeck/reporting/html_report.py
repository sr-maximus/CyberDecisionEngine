from __future__ import annotations

import html
import json
import re
import unicodedata
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cyberdeck.analysis.cyber_radar import build_cyber_risk_radar
from cyberdeck.analysis.fraud import fraud_pressure_index
from cyberdeck.analysis.mitre_mapping import build_atlas_profile, build_d3fend_profile, build_mitre_profile
from cyberdeck.analysis.narratives import build_narrative_intelligence
from cyberdeck.analysis.public_entities import build_public_entity_intelligence
from cyberdeck.analysis.pivot_intelligence import build_pivot_intelligence
from cyberdeck.analysis.prospective_risk import build_prospective_attack_risk
from cyberdeck.analysis.sector_intelligence import build_sector_intelligence
from cyberdeck.analysis.strategic_news import build_strategic_intelligence, export_strategic_scores
from cyberdeck.analysis.framework_evidence import build_framework_evidence_mapping
from cyberdeck.analysis.geographic_intelligence import build_geographic_intelligence
from cyberdeck.analysis.threat_news import build_threat_news
from cyberdeck.analysis.source_intel import build_actor_profile, build_pattern_profile, build_source_coverage
from cyberdeck.analysis.strategy import build_strategic_action_plan
from cyberdeck.analysis.trend_detection import summarize_trends
from cyberdeck.analysis.vulnerability import build_vulnerability_intelligence
from cyberdeck.analysis.layered_scenario_risk import calculate_layered_scenario_risk
from cyberdeck.enrichment.evidence_pipeline import process_evidence_records
from cyberdeck.enrichment.vulnerability_correlation import correlate_vulnerabilities
from cyberdeck.decision_intelligence import build_decision_snapshot
from cyberdeck.knowledge.migrations import remove_legacy_optional_collector
from cyberdeck.methodology import load_methodology_registry
from cyberdeck.reporting.data_export import export_evidence
from cyberdeck.reporting.validator import validate_report_bundle
from cyberdeck.schemas import EvidenceStatus, RunContext
from cyberdeck.semantics import CLAIM_EVIDENCE_MODEL_VERSION, build_claim_evidence_bundle, get_term_registry
from cyberdeck.settings import PROJECT_ROOT, resolve_path


REFERENCES = [
    {"name": "NIST CSF 2.0", "url": "https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final"},
    {"name": "NIST SP 800-30 Rev. 1", "url": "https://csrc.nist.gov/pubs/sp/800/30/r1/final"},
    {"name": "NIST SP 800-53 Rev. 5", "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
    {"name": "NIST SP 800-63-4 Digital Identity", "url": "https://csrc.nist.gov/pubs/sp/800/63/4/final"},
    {"name": "CISA KEV Catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
    {"name": "FIRST EPSS", "url": "https://www.first.org/epss/"},
    {"name": "Google News RSS Search", "url": "https://news.google.com/rss/search"},
    {"name": "Reddit public search RSS", "url": "https://www.reddit.com/search.rss"},
    {"name": "Authorized ransomware/dark-web public index", "url": "https://api.ransomware.live/apidocs/"},
    {"name": "Ahmia Tor Search Terms", "url": "https://ahmia.fi/terms/"},
    {"name": "MITRE ATT&CK v19.1", "url": "https://attack.mitre.org/resources/versions/"},
    {"name": "MITRE D3FEND v1.4.0", "url": "https://d3fend.mitre.org/version/"},
    {"name": "MITRE ATLAS data v5.6.0", "url": "https://github.com/mitre-atlas/atlas-data/releases/tag/v5.6.0"},
    {"name": "DISARM Foundation", "url": "https://github.com/disarmfoundation"},
    {"name": "FBI IC3 Annual Reports", "url": "https://www.ic3.gov/annualreport/reports"},
    {"name": "ENISA Threat Landscape Finance Sector", "url": "https://www.enisa.europa.eu/publications/enisa-threat-landscape-finance-sector"},
    {"name": "ACFE Report to the Nations", "url": "https://legacy.acfe.com/report-to-the-nations/2024/"},
    {"name": "Bolton and Hand, Statistical Fraud Detection", "url": "https://projecteuclid.org/journals/statistical-science/volume-17/issue-3/Statistical-Fraud-Detection-A-Review/10.1214/ss/1042727940.pdf"},
    {"name": "Richards Heuer, Psychology of Intelligence Analysis", "url": "https://www.ialeia.org/docs/Psychology_of_Intelligence_Analysis.pdf"},
    {"name": "Sherman Kent and Strategic Warning", "url": "https://tnsr.org/2018/08/beacon-and-warning-sherman-kent-scientific-hubris-and-the-cias-office-of-national-estimates/"},
]

SECTOR_LABELS_ES = {
    "All sectors": "Todos los sectores",
    "Agriculture, forestry and fishing": "Agricultura, silvicultura y pesca",
    "Mining and quarrying": "Explotación de minas y canteras",
    "Manufacturing": "Industrias manufactureras",
    "Electricity, gas, steam and air conditioning supply": "Suministro de electricidad, gas, vapor y aire acondicionado",
    "Water supply, sewerage, waste management and remediation": "Agua, saneamiento, residuos y remediación",
    "Construction": "Construcción",
    "Wholesale and retail trade; repair of motor vehicles and motorcycles": "Comercio y reparación de vehículos y motocicletas",
    "Transportation and storage": "Transporte y almacenamiento",
    "Accommodation and food service activities": "Alojamiento y servicios de comida",
    "Information and communication": "Información y comunicaciones",
    "Financial and insurance activities": "Actividades financieras y de seguros",
    "Real estate activities": "Actividades inmobiliarias",
    "Professional, scientific and technical activities": "Actividades profesionales, científicas y técnicas",
    "Administrative and support service activities": "Servicios administrativos y de apoyo",
    "Public administration and defence; compulsory social security": "Administración pública, defensa y seguridad social",
    "Education": "Educación",
    "Human health and social work activities": "Salud humana y asistencia social",
    "Arts, entertainment and recreation": "Artes, entretenimiento y recreación",
    "Other service activities": "Otras actividades de servicios",
    "Activities of households as employers": "Actividades de los hogares como empleadores",
    "Activities of extraterritorial organizations and bodies": "Organizaciones y organismos extraterritoriales",
}

TOOL_NAME_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"Kali Surface Tools:?",
        r"Kali Surface Sidecar",
        r"SpiderFoot Passive Sidecar",
        r"SpiderFoot(?: UI)?",
        r"OSINT Tools Sidecar",
        r"urlscan\.io Public Search",
        r"Dark Web Ransomware\.live",
        r"Ransomware\.live",
        r"Kali sidecar unavailable:[^.]+\.?",
        r"SpiderFoot sidecar unavailable:[^.]+\.?",
        r"OSINT tools sidecar unavailable:[^.]+\.?",
        r"Google CSE omitted:[^.]+\.?",
        r"Brave Search omitted:[^.]+\.?",
        r"Search provider ignored:[^.]+\.?",
        r"subfinder/amass/dnsrecon",
        r"sfp_[a-z0-9_]+",
        r"\b(?:sslscan|wafw00f|whatweb|nuclei|amass|subfinder|dnsrecon)\b",
        r"\b(?:kali_surface|osint_tools|spiderfoot|duckduckgo_lite|internet_search|open_web_signal)\b",
        r"\btool:[a-z0-9_.-]+\b",
        r"Internet Search:\s*",
    )
]


def render_report(context: RunContext, output_path: str, *, prepared: bool = False) -> Path:
    out = resolve_path(output_path)
    run_id = out.stem.split("-", 1)[0]
    if not prepared:
        context = prepare_context_for_report(context, run_id=run_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(PROJECT_ROOT / "cyberdeck" / "reporting" / "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("executive_report.html.j2")
    technical_template = env.get_template("technical_report.html.j2")
    css = (PROJECT_ROOT / "cyberdeck" / "reporting" / "assets" / "style.css").read_text(encoding="utf-8")
    payload = _model_dump(context)
    payload["decision_snapshot"] = context.decision_snapshot
    report_lang = _report_language(payload)
    payload = _localize_payload(payload, report_lang)
    payload["format_strategic_percent"] = lambda value: _format_strategic_percent(value, report_lang)
    payload["display_sector"] = _localized_sector(payload.get("organization", {}).get("sector"), report_lang)
    payload["display_country"] = _localized_country(payload.get("organization", {}).get("country"), report_lang)
    payload["display_mode"] = _localized_mode(payload.get("mode"), report_lang)
    term_registry = get_term_registry()
    payload["terms"] = term_registry.labels(language=report_lang, audience="executive")
    payload["technical_terms"] = term_registry.labels(language=report_lang, audience="technical")
    payload["term_registry_version"] = term_registry.version
    payload["claim_evidence_rows"] = _claim_evidence_rows(payload, report_lang)
    payload["technical_report_name"] = f"{out.stem}-technical{out.suffix}"
    payload["risk_findings"] = _display_risk_findings(payload.get("risk_findings", []), report_lang)
    payload["metrics"] = _display_metrics_sources(payload.get("metrics", {}), report_lang)
    payload["metrics"]["vulnerability_intelligence"] = _display_vulnerability_intelligence(
        payload["metrics"].get("vulnerability_intelligence", {}),
        report_lang,
    )
    payload["references"] = context.references or REFERENCES
    payload["css"] = css
    payload["report_display"] = _report_display(payload, report_lang)
    payload["top_findings"] = sorted(payload["risk_findings"], key=lambda item: item["residual_risk"], reverse=True)[:10]
    payload["heatmap"] = _heatmap(payload["risk_findings"])
    payload["export_files"] = export_evidence(context, out)
    payload["export_files"].update(export_strategic_scores(context.metrics.get("strategic_news", {}), out))
    payload["report_scope"] = _report_scope(payload, report_lang)
    payload["scope_events"] = _scope_filtered_events(payload, report_lang)
    payload["evidence_rows"] = _evidence_rows(payload["scope_events"], report_lang)
    payload["executive_evidence_rows"] = _executive_evidence_sample(payload["evidence_rows"])
    payload["evidence_type_summary"] = _evidence_type_summary(payload["evidence_rows"], report_lang)
    payload["search_groups"] = _search_groups(payload["scope_events"], report_lang)
    payload["risk_digest"] = _risk_digest(payload, report_lang)
    payload["domain_comparison_rows"] = _domain_comparison_rows(payload, report_lang)
    payload["decision_layers"] = _decision_layers(payload, report_lang)
    payload["framework_summary"] = _framework_summary(payload, report_lang)
    payload["f3_summary"] = _f3_summary(payload, report_lang)
    payload["scenario_cards"] = _scenario_cards(payload, report_lang)
    payload["scenario_library"] = _scenario_library_digest(payload, report_lang)
    payload["domain_reading_rows"] = _domain_reading_rows(payload, report_lang)
    payload["attack_surface_inventory"] = _attack_surface_inventory(payload, report_lang)
    payload["executive_alerts"] = _executive_alert_rows(payload, report_lang)
    payload["evidence_preview_gallery"] = _evidence_preview_gallery(payload["scope_events"], report_lang)
    payload["disinformation_summary"] = _disinformation_summary(payload, report_lang)
    payload["intelligence_modules"] = _intelligence_modules(payload, report_lang)
    payload["brand_fraud_summary"] = _brand_fraud_summary(payload, report_lang)
    payload["model_summary"] = _model_summary(payload, report_lang)
    payload["recommendation_catalog"] = _recommendation_catalog(payload, report_lang)
    payload["work_plan"] = _work_plan(payload, report_lang)
    payload["methodology_summary"] = _methodology_summary(payload, report_lang)
    payload["source_statuses"] = _display_source_statuses(payload.get("source_statuses", []), report_lang)
    payload["radars"] = {
        "pestel": _radar_svg("Cyber-PESTEL · SignalScore", payload["metrics"]["pestel"].get("dimensions", [])),
        "porter": _radar_svg("Cyber-Porter · SignalScore", payload["metrics"]["porter"].get("dimensions", [])),
        "risk_heat": _risk_heat_svg(payload["metrics"]["risk_heat_radar"].get("rows", [])),
    }
    html = template.render(**payload)
    out.write_text(html, encoding="utf-8")
    technical_path = out.with_name(f"{out.stem}-technical{out.suffix}")
    technical_html = technical_template.render(**payload)
    technical_path.write_text(technical_html, encoding="utf-8")
    validate_report_bundle(context, out, technical_path)
    return out


def _report_file_slug(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", "_", normalized).strip("_") or "multi_domain"


def prepare_context_for_report(context: RunContext, run_id: str = "") -> RunContext:
    prepared = context.model_copy(deep=True)
    _remove_legacy_assumed_profile_data(prepared)
    remove_legacy_optional_collector(prepared)
    scope_terms = [*prepared.organization.primary_domains, prepared.organization.name]
    existing_summary = dict(prepared.processing_summary)
    already_processed = bool(existing_summary) and int(existing_summary.get("unique_records", -1)) == len(prepared.raw_events)
    if already_processed:
        processed_records = prepared.raw_events
        processed_summary = existing_summary
    else:
        processed = process_evidence_records(
            prepared.raw_events,
            scope_terms,
            raw_count=int(existing_summary.get("raw_records_collected", len(prepared.raw_events))),
        )
        processed_records = processed.records
        processed_summary = processed.summary
    prepared.raw_events = processed_records
    _ensure_claim_evidence_chain(prepared)
    validated_findings = [
        finding
        for finding in prepared.risk_findings
        if finding.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    raw_count = int(processed_summary.get("raw_records_collected", len(prepared.raw_events)))
    unique_count = int(processed_summary.get("unique_records", len(prepared.raw_events)))
    discarded_count = int(processed_summary.get("discarded_records", 0))
    derived_duplicates = max(0, raw_count - unique_count - discarded_count)
    prepared.processing_summary = {
        **existing_summary,
        **processed_summary,
        "normalized_records": max(
            int(existing_summary.get("normalized_records", 0)),
            unique_count + derived_duplicates,
        ),
        "duplicates_removed": max(
            int(existing_summary.get("duplicates_removed", 0)),
            derived_duplicates,
        ),
        "validated_findings": len(validated_findings),
        "confirmed_findings": sum(
            1 for finding in prepared.risk_findings if finding.evidence_status == EvidenceStatus.CONFIRMED
        ),
        "calculated_risks": len(prepared.risk_findings),
        "confirmed_incidents": sum(1 for finding in prepared.risk_findings if finding.incident_confirmed),
    }
    coverage = build_source_coverage(prepared.source_statuses, prepared.raw_events)
    prepared.connector_coverage = coverage
    prepared.metrics["source_coverage"] = coverage
    prepared.metrics["evidence_summary"] = prepared.processing_summary
    _rebuild_report_metrics(prepared, coverage)
    prepared.decision_snapshot = build_decision_snapshot(prepared, run_id=run_id).model_dump(mode="json")
    prepared.incidents_confirmed = int(prepared.processing_summary["confirmed_incidents"])
    prepared.false_positive_count = int(prepared.processing_summary.get("false_positives", 0))
    return prepared


def _ensure_claim_evidence_chain(context: RunContext) -> None:
    requires_rebuild = context.claim_evidence_model_version != CLAIM_EVIDENCE_MODEL_VERSION
    if not requires_rebuild and all(
        (
            context.claims,
            context.evidence_items,
            context.claim_evidence_links,
            context.interpretations,
            context.decisions,
        )
    ):
        return
    subject_entity_ids = list(
        dict.fromkeys(
            item.strip()
            for item in [context.organization.name, *context.organization.primary_domains]
            if item and item.strip()
        )
    )
    if not subject_entity_ids:
        subject_entity_ids = ["authorized-subject"]
    scope = "subjects:" + "|".join(subject_entity_ids)
    bundle = build_claim_evidence_bundle(
        context.raw_events,
        context.risk_findings,
        subject_entity_ids,
        scope,
    )
    if requires_rebuild or not context.claims:
        context.claims = [item.model_dump(mode="json") for item in bundle.claims]
    if requires_rebuild or not context.evidence_items:
        context.evidence_items = [item.model_dump(mode="json") for item in bundle.evidence]
    if requires_rebuild or not context.claim_evidence_links:
        context.claim_evidence_links = [item.model_dump(mode="json") for item in bundle.links]
    if requires_rebuild or not context.contradicting_evidence:
        context.contradicting_evidence = [item.model_dump(mode="json") for item in bundle.contradictions]
    if requires_rebuild or not context.interpretations:
        context.interpretations = [item.model_dump(mode="json") for item in bundle.interpretations]
    if requires_rebuild or not context.decisions:
        context.decisions = [item.model_dump(mode="json") for item in bundle.decisions]
    context.claim_evidence_model_version = CLAIM_EVIDENCE_MODEL_VERSION


def _remove_legacy_assumed_profile_data(context: RunContext) -> None:
    legacy_controls = {
        "iso27001_score": 0.6,
        "nist_csf_score": 0.62,
        "soc2_score": 0.54,
        "d3fend_coverage": 0.55,
        "attack_detection_coverage": 0.5,
        "incident_response_maturity": 0.62,
    }
    legacy_fraud = {
        "identity_proofing": 0.55,
        "transaction_monitoring": 0.6,
        "device_intelligence": 0.52,
        "mule_detection": 0.48,
        "case_management": 0.58,
        "customer_awareness": 0.54,
    }
    legacy_technologies = {"dns", "email", "waf", "cloud", "api_gateway", "siem", "edr"}
    if context.organization.control_maturity == legacy_controls:
        context.organization.control_maturity = {}
    if context.organization.fraud_maturity == legacy_fraud:
        context.organization.fraud_maturity = {}
    if set(context.organization.technologies) == legacy_technologies:
        context.organization.technologies = []
    defaults = {"dns", "email_security", "brand", "web_presence", "apis", "identity"}
    context.organization.crown_jewels = [item for item in context.organization.crown_jewels if item not in defaults]


def _rebuild_report_metrics(context: RunContext, coverage: Dict[str, Any]) -> None:
    events = correlate_vulnerabilities(
        [
            event
            for event in context.raw_events
            if event.evidence_status not in {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}
        ]
    )
    findings = context.risk_findings
    assured = [
        event
        for event in events
        if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    fraud_pressure = fraud_pressure_index(assured)
    evidence_assurance = len(assured) / max(1, len(events))
    source_health = float(coverage.get("source_health_score", 0.0) or 0.0)
    max_residual = max((finding.residual_risk for finding in findings), default=0.0)
    external_posture = (
        100 * (0.4 * source_health + 0.35 * evidence_assurance + 0.25 * max(0.0, 1 - max_residual / 100))
        if events
        else 0.0
    )
    key_labels = {
        "nist_csf_score": "NIST CSF 2.0",
        "iso27001_score": "ISO 27001:2022",
        "soc2_score": "SOC 2",
        "d3fend_coverage": "D3FEND",
        "attack_detection_coverage": "ATT&CK Detection",
        "incident_response_maturity": "Incident Response",
    }
    control_scores = {
        label: context.organization.control_maturity[key]
        for key, label in key_labels.items()
        if key in context.organization.control_maturity
    }
    strategic_news = build_strategic_intelligence(events, context.organization, created_at=context.generated_at)
    prospective_attack_risk = build_prospective_attack_risk(
        assured,
        findings,
        sector=context.organization.sector,
        controls=context.organization.control_maturity,
        source_coverage=coverage,
    )
    context.metrics.update(
        {
            "posture_index": round(external_posture, 2),
            "external_cyber_intelligence_posture_index": round(external_posture, 2),
            "posture_index_type": "external_cyber_intelligence_posture_index",
            "posture_index_limitations": "No mide cumplimiento ni madurez interna; resume salud de fuentes, aseguramiento de evidencia y riesgo externo calculado.",
            "control_scores": control_scores,
            "control_assessment": {
                "status": "self_declared_unverified" if control_scores else "unassessed",
                "is_compliance_assessment": False,
                "note": "Los controles no declarados se mantienen como desconocidos y no reducen el riesgo.",
            },
            "fraud_pressure": round(fraud_pressure, 3),
            "trends": summarize_trends(events),
            "actors": build_actor_profile(events),
            "patterns": build_pattern_profile(events),
            "mitre": build_mitre_profile(events),
            "d3fend": build_d3fend_profile(events),
            "atlas": build_atlas_profile(events),
            "vulnerability_intelligence": build_vulnerability_intelligence(events, findings),
            "layered_scenario_risk": calculate_layered_scenario_risk(context.organization.scenario_risk_inputs),
            "risk_heat_radar": build_cyber_risk_radar(events, findings),
            "strategy": build_strategic_action_plan(findings, events, context.organization, coverage),
            "strategic_news": strategic_news,
            "threat_news": build_threat_news(events),
            "framework_mapping": build_framework_evidence_mapping(events, findings, context.organization),
            "geographic_intelligence": build_geographic_intelligence(events, context.organization),
            "sector_intelligence": build_sector_intelligence(events, context.organization),
            "public_entity_intelligence": build_public_entity_intelligence(events, context.organization),
            "pivot_intelligence": build_pivot_intelligence(events),
            "pestel": strategic_news["pestel"],
            "porter": strategic_news["porter"],
            "narrative_intelligence": build_narrative_intelligence(events, context.organization),
            "prospective_attack_risk": prospective_attack_risk,
            "forecast": prospective_attack_risk["horizons"],
            "risk_methodology": {
                "purpose": "El modelo separa evidencia, plausibilidad contextual, impacto, controles declarados, riesgo inherente y riesgo residual; no confirma incidentes ni estima probabilidad calibrada de ataque.",
                "likelihood": "La plausibilidad contextual es un puntaje acotado basado en evidencia directa o validada. Las limitaciones y fuentes ausentes no incrementan el riesgo.",
                "impact": "El impacto pondera dimensiones financieras, operacionales, reputacionales, legales y de continuidad únicamente cuando aplican al hallazgo.",
                "control_effectiveness": "Solo los controles declarados reducen el riesgo; un control desconocido permanece sin evaluar.",
                "matrix": "La matriz 4x4 cruza plausibilidad contextual e impacto para ordenar tratamiento; no representa certeza de ataque.",
                "monte_carlo": "Las bandas de sensibilidad muestran variación del riesgo calculado y no constituyen intervalos de predicción de incidentes.",
            },
            "model_version": "evidence-pipeline-v2",
        }
    )


def _model_dump(context: RunContext) -> Dict[str, Any]:
    if hasattr(context, "model_dump"):
        return context.model_dump(mode="json")
    return context.dict()


def _claim_evidence_rows(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    evidence_by_id = {item.get("evidence_id"): item for item in payload.get("evidence_items", []) if item.get("evidence_id")}
    interpretation_by_claim = {
        item.get("claim_id"): item for item in payload.get("interpretations", []) if item.get("claim_id")
    }
    decision_by_claim = {item.get("claim_id"): item for item in payload.get("decisions", []) if item.get("claim_id")}
    contradictions_by_claim: Dict[str, list[Dict[str, Any]]] = {}
    for item in payload.get("contradicting_evidence", []):
        contradictions_by_claim.setdefault(str(item.get("claim_id") or ""), []).append(item)

    rows: list[Dict[str, Any]] = []
    for claim in payload.get("claims", []):
        claim_id = str(claim.get("claim_id") or "")
        if not claim_id:
            continue
        interpretation = interpretation_by_claim.get(claim_id, {})
        decision = decision_by_claim.get(claim_id, {})
        evidence = [
            evidence_by_id[evidence_id]
            for evidence_id in claim.get("evidence_ids", [])
            if evidence_id in evidence_by_id
        ]
        status = str(claim.get("claim_status") or "supported")
        if language == "en":
            demonstrates = (
                "Supports a reproducible condition linked to the analyzed scope."
                if status in {"validated", "confirmed"}
                else "Supports an analytical possibility that still requires reproducible validation."
            )
            not_demonstrates = "It does not by itself prove exploitation, compromise, attribution or a confirmed incident."
            fallback_decision = "Review treatment with the risk owner."
            fallback_owner = "Cyber intelligence analyst"
            fallback_closure = "Revalidate with reproducible evidence or document the discard decision."
        else:
            demonstrates = str(interpretation.get("what_demonstrates") or "Respalda una posibilidad analítica que aún requiere validación reproducible.")
            not_demonstrates = str(interpretation.get("what_not_demonstrates") or "No demuestra por sí sola explotación, compromiso, atribución ni incidente confirmado.")
            fallback_decision = "Revisar tratamiento con el responsable del riesgo."
            fallback_owner = "Analista de ciberinteligencia"
            fallback_closure = "Revalidar con evidencia reproducible o documentar el descarte."
        rows.append(
            {
                "claim_id": claim_id,
                "statement": claim.get("statement") or "",
                "status": status,
                "what_found": interpretation.get("what_found") or claim.get("statement") or "",
                "what_demonstrates": demonstrates,
                "what_not_demonstrates": not_demonstrates,
                "how_validated": interpretation.get("validation_summary") or claim.get("validation_method") or ("Not validated" if language == "en" else "No validado"),
                "evidence": evidence,
                "evidence_count": len(evidence),
                "confidence": round(float(claim.get("confidence") or 0.0) * 100),
                "limitations": claim.get("limitations") or [],
                "contradictions": contradictions_by_claim.get(claim_id, []),
                "decision": decision.get("decision") or fallback_decision,
                "recommended_action": decision.get("recommended_action") or fallback_decision,
                "owner": decision.get("owner") or fallback_owner,
                "closure_criteria": decision.get("closure_criteria") or fallback_closure,
            }
        )
    return rows


def _report_language(payload: Dict[str, Any]) -> str:
    language = str(payload.get("organization", {}).get("language", "es")).lower()
    normalized = "en" if language.startswith("en") else "es"
    payload.setdefault("organization", {})["language"] = normalized
    return normalized


def _localized_sector(value: Any, language: str) -> str:
    label = str(value or "").strip()
    if not label:
        return "Not declared" if language == "en" else "No declarado"
    if language == "es":
        return SECTOR_LABELS_ES.get(label, label)
    reverse = {spanish.casefold(): english for english, spanish in SECTOR_LABELS_ES.items()}
    return reverse.get(label.casefold(), label)


@lru_cache(maxsize=1)
def _country_label_index() -> dict[str, dict[str, str]]:
    path = PROJECT_ROOT / "config" / "catalogs" / "countries.json"
    if not path.exists():
        return {}
    rows = json.loads(path.read_text(encoding="utf-8"))
    index: dict[str, dict[str, str]] = {}
    for row in rows:
        normalized = {"en": str(row.get("en") or ""), "es": str(row.get("es") or row.get("en") or "")}
        for alias in (row.get("code"), row.get("en"), row.get("es")):
            if alias:
                index[str(alias).casefold()] = normalized
    return index


def _localized_country(value: Any, language: str) -> str:
    label = str(value or "").strip()
    if not label:
        return "Not declared" if language == "en" else "No declarado"
    row = _country_label_index().get(label.casefold())
    return row.get(language, label) if row else label


def _localized_mode(value: Any, language: str) -> str:
    mode = str(value or "snapshot").strip().lower()
    labels = {
        "snapshot": {"es": "Instantánea", "en": "Snapshot"},
        "deep": {"es": "Profundo", "en": "Deep"},
    }
    return labels.get(mode, {}).get(language, str(value or mode))


def _report_display(payload: Dict[str, Any], language: str) -> Dict[str, str]:
    raw_value = str(payload.get("report_display_at") or payload.get("generated_at") or "").strip()
    if not raw_value:
        raw_value = datetime.now().isoformat(timespec="minutes")
    try:
        parsed = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
        date_value = parsed.date().isoformat()
        time_value = parsed.strftime("%H:%M")
    except ValueError:
        date_value = raw_value[:10]
        time_value = raw_value[11:16] if len(raw_value) >= 16 else ""
    datetime_value = date_value
    return {
        "label": "Report date" if language == "en" else "Fecha del informe",
        "date": date_value,
        "time": time_value,
        "datetime": datetime_value,
    }


def _display_source_name(source: str | None, language: str) -> str:
    value = (source or "").strip()
    if not value:
        return "Public evidence" if language == "en" else "Evidencia publica"
    if re.search(r"kali|subfinder|amass|dnsrecon|sslscan|wafw00f|whatweb|nuclei", value, re.IGNORECASE):
        return "External surface" if language == "en" else "Superficie externa"
    if re.search(r"spiderfoot|sfp_", value, re.IGNORECASE):
        return "Passive inventory" if language == "en" else "Inventario pasivo"
    if re.search(r"internet search|google|duckduckgo|gdelt|news|rss", value, re.IGNORECASE):
        return "Public search" if language == "en" else "Busqueda publica"
    if re.search(r"common crawl|osint public|osint tools|osint sidecar|sidecar|urlscan", value, re.IGNORECASE):
        return "Public index" if language == "en" else "Indice publico"
    if re.search(r"ransomware|dark web|tor|onion|leak", value, re.IGNORECASE):
        return "Authorized dark web index" if language == "en" else "Indice dark web autorizado"
    if re.search(r"misp|stix|taxii", value, re.IGNORECASE):
        return "Configured CTI platform" if language == "en" else "Plataforma CTI configurada"
    if re.search(r"shodan|censys", value, re.IGNORECASE):
        return "Passive surface index" if language == "en" else "Indice pasivo de superficie"
    if re.search(r"cisa|kev|nvd|epss|github", value, re.IGNORECASE):
        return "Vulnerability intelligence" if language == "en" else "Inteligencia de vulnerabilidades"
    if re.search(r"socmint|reddit|facebook|instagram|tiktok|twitter|\bx\b|linkedin", value, re.IGNORECASE):
        return "SOCMINT"
    return re.sub(r"\s+", " ", value)


def _clean_evidence_text(value: str | None, language: str = "es") -> str:
    text = (value or "").strip()
    source_label = _internal_source_label(text, language)
    if source_label:
        count_match = re.search(r":\s*(\d+)\s*$", text)
        return f"{source_label}: {count_match.group(1)}" if count_match else f"{source_label} {'validated' if language == 'en' else 'validada'}"
    for pattern in TOOL_NAME_PATTERNS:
        text = pattern.sub("", text)
    text = re.sub(r"\bobservo\b", "detecto", text, flags=re.IGNORECASE)
    text = re.sub(r"\bobserv[oó]\b", "detecto", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+\|\s*query:", " | busqueda:", text, flags=re.IGNORECASE)
    text = re.sub(r"\(\s*real\s*\)", "", text, flags=re.IGNORECASE)
    text = re.sub(r"GOOGLE_CSE_API_KEY|GOOGLE_CSE_CX|BRAVE_SEARCH_API_KEY", "credencial opcional", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*,\s*,", ",", text)
    text = re.sub(r"\s{2,}", " ", text)
    text = text.lstrip(":-,; ").strip()
    if text:
        return text
    return "Validated public evidence" if language == "en" else "Evidencia publica validada"


def _internal_source_label(value: str, language: str) -> str | None:
    if not re.search(
        r"kali surface tools|kali surface sidecar|spiderfoot|osint tools sidecar|urlscan\.io public search|internet search:|dark web ransomware\.live|ransomware\.live",
        value,
        re.IGNORECASE,
    ):
        return None
    return _display_source_name(value, language)


def _display_risk_findings(findings: list[Dict[str, Any]], language: str) -> list[Dict[str, Any]]:
    output = []
    for finding in findings or []:
        row = dict(finding)
        row["title"] = _clean_evidence_text(str(row.get("title") or ""), language)
        row["evidence"] = [
            _clean_evidence_text(str(item or ""), language)
            for item in (row.get("evidence") or [])
            if str(item or "").strip()
        ]
        row["recommendations"] = [
            _clean_evidence_text(str(item or ""), language)
            for item in (row.get("recommendations") or [])
            if str(item or "").strip()
        ]
        output.append(row)
    return output


def _work_plan(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    scoped_events = payload.get("scope_events") or _scope_filtered_events(payload, language)
    events = [
        event
        for event in scoped_events
        if str(event.get("evidence_status", "raw")) in {"direct", "validated", "confirmed"}
    ]
    findings = sorted(
        [
            item
            for item in payload.get("risk_findings", []) or []
            if str(item.get("evidence_status", "validated")) in {"validated", "confirmed"}
        ],
        key=lambda item: item.get("residual_risk", 0) or 0,
        reverse=True,
    )
    scenario_matches = payload.get("scenario_library", {}).get("matches", []) or []
    event_by_id: dict[str, Dict[str, Any]] = {}
    for event in events:
        for value in (event.get("canonical_id"), event.get("id")):
            if value:
                event_by_id[str(value)] = event

    items: list[Dict[str, Any]] = []
    for match in scenario_matches:
        evidence_ids = [str(value) for value in match.get("evidence_ids", []) if value]
        matched_events = [event_by_id[value] for value in evidence_ids if value in event_by_id]
        evidence_count = int(match.get("evidence_count", 0) or 0)
        if not match.get("id") or evidence_count <= 0:
            continue
        actions = _unique_text_values([match.get("recommendation"), match.get("decision")])
        if not actions:
            continue
        confidence = float(match.get("confidence", 0) or 0)
        score = min(25.0, confidence / 5.0 + min(evidence_count, 5))
        owners = _scenario_action_owners(match, language)
        control_mappings = _scenario_control_mappings(payload, match, language)
        basis = (
            f"Escenario {match.get('id')} · {evidence_count} evidencias relacionadas · confianza {confidence:.0f}%."
            if language == "es"
            else f"Scenario {match.get('id')} · {evidence_count} related evidence records · {confidence:.0f}% confidence."
        )
        item = {
            "id": match.get("id"),
            "title": match.get("title"),
            "timeframe": _work_plan_timeframe(score, str(match.get("primary_framework") or ""), language),
            "priority": _work_plan_priority_label(score, language),
            "tone": _work_plan_tone(score),
            "owners": owners,
            "objective": match.get("question"),
            "actions": actions,
            "validation": match.get("criteria"),
            "argument": match.get("reasons_label"),
            "basis": basis,
            "evidence_urls": _work_plan_evidence_urls(matched_events),
            "evidence_ids": evidence_ids,
            "scenarios": [match.get("id")],
            "control_mappings": control_mappings,
        }
        items.append(item)

    items = sorted(items, key=lambda item: _work_plan_sort_key(item, language))[:8]
    has_supported_plan = bool(items)
    if language == "es":
        summary = (
            f"Plan sustentado en {len(items)} escenarios respaldados por evidencia, "
            f"{len(findings)} hallazgos validados y {len(events)} evidencias directas o validadas."
            if has_supported_plan
            else (
                "No se publica un plan de mitigación: esta corrida no contiene escenarios respaldados "
                "por evidencia suficientes para justificar acciones."
            )
        )
        decision_gate = (
            "Cada acción debe conservar el escenario, el argumento, la evidencia y el criterio de cierre que la sustentan."
            if has_supported_plan
            else (
                "Los registros recolectados permanecen como contexto. El plan se habilita únicamente cuando "
                "la validación activa un escenario del marco analítico."
            )
        )
    else:
        summary = (
            f"Plan supported by {len(items)} evidence-backed scenarios, "
            f"{len(findings)} validated findings and {len(events)} direct or validated evidence records."
            if has_supported_plan
            else (
                "No mitigation plan is published: this run does not contain evidence-backed scenarios "
                "sufficient to justify actions."
            )
        )
        decision_gate = (
            "Every action must retain its supporting scenario, rationale, evidence and closure criterion."
            if has_supported_plan
            else (
                "Collected records remain context. A plan is enabled only when validation activates "
                "a scenario from the analytical framework."
            )
        )
    return {
        "status": "supported" if has_supported_plan else "not_supported",
        "summary": summary,
        "decision_gate": decision_gate,
        "items": items,
    }


def _unique_text_values(values: list[Any]) -> list[str]:
    unique: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in unique:
            unique.append(text)
    return unique


def _scenario_action_owners(match: Dict[str, Any], language: str) -> list[str]:
    framework = str(match.get("primary_framework") or "").lower()
    if language == "en":
        return {
            "f3": ["Fraud", "Digital channels", "Cybersecurity", "Legal"],
            "disarm": ["Communications", "Reputation risk", "Cyber intelligence", "Legal"],
            "atlas": ["AI security", "Application security", "Technology risk"],
            "attack": ["Cybersecurity", "SOC / CTI", "Asset owner"],
        }.get(framework, ["Cybersecurity", "Risk owner"])
    return {
        "f3": ["Fraude", "Canales digitales", "Ciberseguridad", "Legal"],
        "disarm": ["Comunicaciones", "Riesgo reputacional", "Ciberinteligencia", "Legal"],
        "atlas": ["Seguridad de IA", "Seguridad de aplicaciones", "Riesgo tecnológico"],
        "attack": ["Ciberseguridad", "SOC / CTI", "Dueño del activo"],
    }.get(framework, ["Ciberseguridad", "Dueño del riesgo"])


def _scenario_control_mappings(
    payload: Dict[str, Any],
    match: Dict[str, Any],
    language: str,
) -> list[Dict[str, Any]]:
    evidence_ids = {str(value) for value in match.get("evidence_ids", []) if value}
    if not evidence_ids:
        return []
    framework_summary = payload.get("framework_summary") or _framework_summary(payload, language)
    decision_frameworks = {
        "NIST CSF",
        "ISO 27001",
        "PCI DSS",
        "SOC 2",
        "GDPR",
        "CIS Controls",
        "COBIT 2019",
    }
    mappings: list[Dict[str, Any]] = []
    for row in framework_summary.get("mappings", []) or []:
        if row.get("framework") not in decision_frameworks:
            continue
        row_evidence_ids = {
            str(item.get("evidence_id"))
            for item in row.get("evidence", []) or []
            if item.get("evidence_id")
        }
        linked_count = len(evidence_ids.intersection(row_evidence_ids))
        if linked_count <= 0:
            continue
        mappings.append(
            {
                "framework": row.get("framework"),
                "aspect": row.get("axis"),
                "controls": list(row.get("controls") or []),
                "evidence_count": linked_count,
            }
        )
    mappings.sort(key=lambda item: (-item["evidence_count"], str(item["framework"]), str(item["aspect"])))
    return mappings[:8]


def _work_plan_catalog(language: str) -> list[Dict[str, Any]]:
    if language == "en":
        return [
            {
                "key": "triage",
                "id": "WP-01",
                "title": "Executive triage and risk acceptance",
                "keywords": ("critical", "high", "residual", "ransomware", "kev", "fraud", "phishing", "credential", "cve", "exploit"),
                "owners": ["CISO", "Risk", "SOC/CTI", "Business owner"],
                "objective": "Confirm the decision threshold for {scope} and separate urgent mitigation, accepted risk and evidence to validate.",
                "actions": [
                    "Review top residual risks and confirm appetite, urgency and escalation path.",
                    "Define which findings require mitigation, exception, monitoring or formal acceptance.",
                    "Set the next evidence threshold before changing business controls.",
                ],
                "validation": "Approved risk register update, owner-by-role and evidence threshold for each critical scenario.",
            },
            {
                "key": "surface",
                "id": "WP-02",
                "title": "External surface reduction",
                "keywords": ("surface", "domain", "subdomain", "dns", "tls", "certificate", "whois", "port", "service", "api", "exposed", "vulnerab", "cve", "kev", "headers"),
                "owners": ["Infrastructure", "EASM", "AppSec", "SOC"],
                "objective": "Reduce externally visible exposure for {scope} with verifiable closure evidence.",
                "actions": [
                    "Validate DNS, TLS/certificates, exposed services, web headers, APIs and passive subdomain inventory.",
                    "Close or justify exposures by asset criticality and owner.",
                    "Retest public evidence after remediation and keep before/after traceability.",
                ],
                "validation": "Retest evidence shows exposure closed, accepted or monitored with compensating control.",
            },
            {
                "key": "brand_fraud",
                "id": "WP-03",
                "title": "Brand, fraud and public-social response",
                "keywords": ("brand", "fraud", "phishing", "smishing", "imperson", "lookalike", "socmint", "facebook", "instagram", "linkedin", "tiktok", "twitter", "x.com", "complaint", "reputation"),
                "owners": ["Fraud", "Digital Channels", "Legal", "Communications", "SOC"],
                "objective": "Treat public brand and fraud signals for {scope} without overstating unvalidated mentions.",
                "actions": [
                    "Classify mentions, similar domains and impersonation indicators as evidence, false positive or monitoring item.",
                    "Prepare takedown/legal/customer-communication paths only for validated cases.",
                    "Correlate public-social signals with fraud telemetry and customer-impact thresholds.",
                ],
                "validation": "Each public signal has status, URL evidence, decision and follow-up owner by role.",
            },
            {
                "key": "darkweb_identity",
                "id": "WP-04",
                "title": "Authorized dark-web and identity validation",
                "keywords": ("dark", "tor", "onion", "leak", "credential", "password", "account", "identity", "mfa", "ato", "ransomware"),
                "owners": ["CTI", "IAM", "SOC", "Legal/Privacy"],
                "objective": "Validate authorized deep/dark-web or credential signals for {scope} with privacy and chain-of-custody controls.",
                "actions": [
                    "Use only authorized/redacted metadata and register source, scope, TLP and evidence URL when available.",
                    "Trigger account validation, hunting or preventive rotation only when the signal crosses evidence threshold.",
                    "Document false positives and residual monitoring needs.",
                ],
                "validation": "Identity/dark-web signals are triaged with legal/privacy review and response record.",
            },
            {
                "key": "framework",
                "id": "WP-05",
                "title": "Framework mapping and declared control evidence",
                "keywords": ("nist", "iso", "pci", "soc", "gdpr", "cobit", "cis", "d3fend", "control", "compliance", "privacy", "governance"),
                "owners": ["GRC", "Compliance", "Legal/Privacy", "Control owners"],
                "objective": "Map {scope} evidence to frameworks and convert gaps into control evidence or treatment actions.",
                "actions": [
                    "Link each risk to the affected framework aspect and expected control evidence.",
                    "Separate quick control evidence from real remediation needs.",
                    "Update audit artifacts, exception register and risk treatment plan.",
                ],
                "validation": "Framework mapping shows affected aspect, owner role, evidence artifact and next review date.",
            },
            {
                "key": "scenario",
                "id": "WP-06",
                "title": "Scenario review and executive tabletop",
                "keywords": ("scenario", "attack", "mitre", "atlas", "disarm", "d3fend", "forecast", "prediction", "influence", "continuity", "ransomware"),
                "owners": ["CISO", "Operational Risk", "Continuity", "Executive committee"],
                "objective": "Review the active scenarios for {scope} and translate them into decision options, not certainty claims.",
                "actions": [
                    "Select the scenarios that crossed evidence threshold and assign a decision path.",
                    "Run a short tabletop for the highest-impact modality.",
                    "Define early-warning indicators, stop conditions and next intelligence collection.",
                ],
                "validation": "Scenario record includes trigger, decision option, owner role, metrics and next validation window.",
            },
            {
                "key": "sources",
                "id": "WP-07",
                "title": "Source health and collection continuity",
                "keywords": ("source", "connector", "timeout", "partial", "skipped", "api", "osint", "socmint"),
                "owners": ["Threat Intelligence", "Platform admin", "Data engineering"],
                "objective": "Stabilize collection for {scope} so future analysis does not confuse source gaps with absence of risk.",
                "actions": [
                    "Review partial, skipped or timed-out sources and decide whether to add API keys, schedule scans or reduce scope.",
                    "Tune backoff, cache and collection windows for multi-domain runs.",
                    "Record source limitations in the next report.",
                ],
                "validation": "Source health improves or the limitation remains explicitly documented in the report.",
            },
        ]
    return [
        {
            "key": "triage",
            "id": "PT-01",
            "title": "Triage ejecutivo y aceptación de riesgo",
            "keywords": ("critico", "crítico", "alto", "residual", "ransomware", "kev", "fraude", "phishing", "credencial", "cve", "exploit"),
            "owners": ["CISO", "Riesgo", "SOC/CTI", "Dueño de negocio"],
            "objective": "Confirmar el umbral de decisión para {scope} y separar mitigación urgente, riesgo aceptado y evidencia por validar.",
            "actions": [
                "Revisar los riesgos residuales principales y confirmar apetito, urgencia y ruta de escalamiento.",
                "Definir qué hallazgos requieren mitigación, excepción, monitoreo o aceptación formal.",
                "Fijar el siguiente umbral de evidencia antes de cambiar controles de negocio.",
            ],
            "validation": "Registro de riesgo actualizado, responsable por rol y umbral de evidencia para cada escenario crítico.",
        },
        {
            "key": "surface",
            "id": "PT-02",
            "title": "Reducción de superficie externa",
            "keywords": ("superficie", "surface", "dominio", "domain", "subdomain", "subdominio", "dns", "tls", "certificado", "whois", "puerto", "servicio", "api", "expuesto", "vulnerab", "cve", "kev", "headers"),
            "owners": ["Infraestructura", "EASM", "AppSec", "SOC"],
            "objective": "Reducir exposición visible en Internet para {scope} con evidencia verificable de cierre.",
            "actions": [
                "Validar DNS, TLS/certificados, servicios expuestos, headers web, APIs e inventario pasivo de subdominios.",
                "Cerrar o justificar exposiciones por criticidad de activo y dueño responsable.",
                "Reprobar evidencia pública después de remediar y conservar trazabilidad antes/después.",
            ],
            "validation": "La reprueba evidencia exposición cerrada, aceptada o monitoreada con control compensatorio.",
        },
        {
            "key": "brand_fraud",
            "id": "PT-03",
            "title": "Respuesta de marca, fraude y redes públicas",
            "keywords": ("marca", "brand", "fraude", "fraud", "phishing", "smishing", "suplant", "imperson", "lookalike", "socmint", "facebook", "instagram", "linkedin", "tiktok", "twitter", "x.com", "queja", "reputacion", "reputación"),
            "owners": ["Fraude", "Canales digitales", "Legal", "Comunicaciones", "SOC"],
            "objective": "Tratar señales públicas de marca y fraude para {scope} sin sobredimensionar menciones no validadas.",
            "actions": [
                "Clasificar menciones, dominios parecidos e indicadores de suplantación como evidencia, falso positivo o monitoreo.",
                "Preparar rutas de takedown/legal/comunicación a clientes solo para casos validados.",
                "Correlacionar señales públicas con telemetría antifraude y umbrales de impacto a clientes.",
            ],
            "validation": "Cada señal pública queda con estado, URL de evidencia, decisión y seguimiento por rol.",
        },
        {
            "key": "darkweb_identity",
            "id": "PT-04",
            "title": "Validación autorizada de dark web e identidad",
            "keywords": ("dark", "tor", "onion", "fuga", "leak", "credencial", "password", "cuenta", "identity", "identidad", "mfa", "ato", "ransomware"),
            "owners": ["CTI", "IAM", "SOC", "Legal/Privacidad"],
            "objective": "Validar señales autorizadas deep/dark-web o de credenciales para {scope} con privacidad y cadena de custodia.",
            "actions": [
                "Usar solo metadatos autorizados/redactados y registrar fuente, alcance, TLP y URL cuando esté disponible.",
                "Activar validación de cuentas, hunting o rotación preventiva solo si la señal cruza el umbral de evidencia.",
                "Documentar falsos positivos y necesidades de monitoreo residual.",
            ],
            "validation": "Señales de identidad/dark web triadas con revisión legal/privacidad y registro de respuesta.",
        },
        {
            "key": "framework",
            "id": "PT-05",
            "title": "Mapeo de frameworks y evidencia de control declarada",
            "keywords": ("nist", "iso", "pci", "soc", "gdpr", "cobit", "cis", "d3fend", "control", "cumplimiento", "privacy", "privacidad", "gobierno"),
            "owners": ["GRC", "Cumplimiento", "Legal/Privacidad", "Dueños de control"],
            "objective": "Mapear la evidencia de {scope} a frameworks y convertir brechas en evidencia de control o acciones de tratamiento.",
            "actions": [
                "Relacionar cada riesgo con el aspecto de framework afectado y la evidencia de control esperada.",
                "Separar evidencia rápida de control de necesidades reales de remediación.",
                "Actualizar artefactos de auditoría, registro de excepciones y plan de tratamiento.",
            ],
            "validation": "El mapeo muestra aspecto afectado, rol responsable, artefacto de evidencia y próxima revisión.",
        },
        {
            "key": "scenario",
            "id": "PT-06",
            "title": "Revisión de escenarios y ejercicio directivo",
            "keywords": ("escenario", "scenario", "attack", "mitre", "atlas", "disarm", "d3fend", "forecast", "predic", "influencia", "continuidad", "ransomware"),
            "owners": ["CISO", "Riesgo operacional", "Continuidad", "Comité ejecutivo"],
            "objective": "Revisar los escenarios activos para {scope} y traducirlos en opciones de decisión, no en afirmaciones de certeza.",
            "actions": [
                "Seleccionar los escenarios que cruzaron umbral de evidencia y asignar una ruta de decisión.",
                "Ejecutar un ejercicio corto de mesa sobre la modalidad de mayor impacto.",
                "Definir alertas tempranas, condiciones de cierre y próxima recolección de inteligencia.",
            ],
            "validation": "Registro de escenario con gatillo, opción de decisión, rol responsable, métricas y próxima ventana de validación.",
        },
        {
            "key": "sources",
            "id": "PT-07",
            "title": "Cobertura operativa de conectores y continuidad de recolección",
            "keywords": ("fuente", "source", "connector", "timeout", "partial", "parcial", "omitida", "skipped", "api", "osint", "socmint"),
            "owners": ["Threat Intelligence", "Administrador de plataforma", "Ingeniería de datos"],
            "objective": "Estabilizar la recolección de {scope} para que futuros análisis no confundan brechas de fuente con ausencia de riesgo.",
            "actions": [
                "Revisar fuentes parciales, omitidas o con timeout y decidir si se agregan API keys, programación o reducción de alcance.",
                "Ajustar backoff, cache y ventanas de recolección para corridas multi-dominio.",
                "Registrar las limitaciones de fuente en el siguiente informe.",
            ],
            "validation": "La salud de fuentes mejora o la limitación queda explícitamente documentada en el informe.",
        },
    ]


def _work_plan_matching_events(events: list[Dict[str, Any]], keywords: tuple[str, ...]) -> list[Dict[str, Any]]:
    return [event for event in events if _text_has_any(_event_text(event), keywords)]


def _finding_text(finding: Dict[str, Any]) -> str:
    return " ".join(
        [
            str(finding.get("title", "")),
            str(finding.get("category", "")),
            str(finding.get("matrix_label", "")),
            " ".join(finding.get("evidence", []) or []),
            " ".join(finding.get("recommendations", []) or []),
            str(finding.get("owner", "")),
        ]
    )


def _work_plan_matching_findings(findings: list[Dict[str, Any]], keywords: tuple[str, ...]) -> list[Dict[str, Any]]:
    return [finding for finding in findings if _text_has_any(_finding_text(finding), keywords)]


def _work_plan_matching_scenarios(matches: list[Dict[str, Any]], keywords: tuple[str, ...]) -> list[Dict[str, Any]]:
    matched = []
    for match in matches:
        text = " ".join(
            [
                str(match.get("id", "")),
                str(match.get("title", "")),
                str(match.get("primary_framework", "")),
                str(match.get("criteria", "")),
                str(match.get("question", "")),
                str(match.get("decision", "")),
                " ".join(match.get("reasons", []) or []),
                " ".join(match.get("domains", []) or []),
            ]
        )
        if _text_has_any(text, keywords):
            matched.append(match)
    return matched


def _work_plan_priority_score(
    findings: list[Dict[str, Any]],
    events: list[Dict[str, Any]],
    scenarios: list[Dict[str, Any]],
    config: Dict[str, Any],
    source_gaps: list[Dict[str, Any]],
) -> float:
    residual = max((float(item.get("residual_risk", 0) or 0) for item in findings), default=0.0)
    event_severity = max((float(item.get("severity", 0) or 0) * 30 for item in events), default=0.0)
    scenario_confidence = max((float(item.get("confidence", 0) or 0) / 4 for item in scenarios), default=0.0)
    source_gap_boost = 4 if config["key"] == "sources" and source_gaps else 0
    always_floor = 8 if config.get("always") else 0
    return max(residual, event_severity, scenario_confidence, always_floor) + min(6, len(events) / 15) + min(4, len(scenarios)) + source_gap_boost


def _work_plan_timeframe(score: float, key: str, language: str) -> str:
    if key == "sources":
        return "0-14 days" if language == "en" else "0-14 días"
    if score >= 22:
        return "0-7 days" if language == "en" else "0-7 días"
    if score >= 14:
        return "8-30 days" if language == "en" else "8-30 días"
    if score >= 8:
        return "31-60 days" if language == "en" else "31-60 días"
    return "60-90 days" if language == "en" else "60-90 días"


def _work_plan_priority_label(score: float, language: str) -> str:
    if score >= 22:
        return "Critical" if language == "en" else "Crítica"
    if score >= 14:
        return "High" if language == "en" else "Alta"
    if score >= 8:
        return "Medium" if language == "en" else "Media"
    return "Preventive" if language == "en" else "Preventiva"


def _work_plan_tone(score: float) -> str:
    if score >= 22:
        return "critical"
    if score >= 14:
        return "high"
    if score >= 8:
        return "medium"
    return "planned"


def _work_plan_internal_provider_label(language: str) -> str:
    return "Internal operational execution" if language == "en" else "Ejecución operativa interna"


def _work_plan_provider(key: str, has_signal: bool, has_source_gap: bool, language: str) -> str:
    internal = _work_plan_internal_provider_label(language)
    if not has_signal and not has_source_gap:
        return internal
    providers = {
        "en": {
            "surface": "Additional capability: EASM, testing or exposure remediation when internal capacity is limited.",
            "brand_fraud": "Additional capability: brand protection, takedown and anti-fraud correlation when validated.",
            "darkweb_identity": "Additional capability: CTI, MDR or IAM triage for authorized credential and dark-web signals.",
            "framework": "Additional capability: control evidence, audit readiness and remediation tracking.",
            "scenario": "Additional capability: tabletop facilitation, validation exercise or resilience review if approved.",
            "sources": "Additional capability: connector enablement, API configuration and collection reliability.",
        },
        "es": {
            "surface": "Capacidad adicional: EASM, pruebas o remediación de exposición si la capacidad interna es limitada.",
            "brand_fraud": "Capacidad adicional: protección de marca, takedown y correlación antifraude cuando esté validado.",
            "darkweb_identity": "Capacidad adicional: CTI, MDR o IAM para triage autorizado de credenciales y dark web.",
            "framework": "Capacidad adicional: evidencia de controles, preparación de auditoría y seguimiento de remediación.",
            "scenario": "Capacidad adicional: ejercicio de mesa, validación controlada o revisión de resiliencia si se aprueba.",
            "sources": "Capacidad adicional: habilitación de conectores, APIs y confiabilidad de recolección.",
        },
    }
    return providers[language].get(key, internal)


def _work_plan_basis(findings: int, events: int, scenarios: int, language: str) -> str:
    if language == "en":
        return f"{findings} findings · {events} evidence records · {scenarios} scenarios"
    return f"{findings} hallazgos · {events} evidencias · {scenarios} escenarios"


def _work_plan_evidence_urls(events: list[Dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for event in events:
        url = str(event.get("evidence_url") or "").strip()
        if url and url not in urls:
            urls.append(url)
        if len(urls) >= 3:
            break
    return urls


def _work_plan_sort_key(item: Dict[str, Any], language: str) -> tuple[int, str]:
    order = {
        "Crítica": 0,
        "Critical": 0,
        "Alta": 1,
        "High": 1,
        "Media": 2,
        "Medium": 2,
        "Preventiva": 3,
        "Preventive": 3,
    }
    return (order.get(item.get("priority"), 9), item.get("id", ""))


def _work_plan_empty_item(scope_label: str, language: str) -> Dict[str, Any]:
    if language == "en":
        return {
            "id": "WP-00",
            "title": "Validate scope and collection readiness",
            "timeframe": "0-7 days",
            "priority": "Preventive",
            "tone": "planned",
            "owners": ["Platform admin", "Threat Intelligence", "Risk"],
            "provider": _work_plan_internal_provider_label(language),
            "objective": f"Confirm authorized scope and source readiness for {scope_label} before making risk decisions.",
            "actions": ["Validate domains, brands, countries and allowed sources.", "Run collection again once missing sources are configured."],
            "validation": "The next report contains evidence records or explicitly documented source limitations.",
            "basis": "0 findings · 0 evidence records · 0 scenarios",
            "evidence_urls": [],
            "scenarios": [],
        }
    return {
        "id": "PT-00",
        "title": "Validar alcance y preparación de recolección",
        "timeframe": "0-7 días",
        "priority": "Preventiva",
        "tone": "planned",
        "owners": ["Administrador de plataforma", "Threat Intelligence", "Riesgo"],
        "provider": _work_plan_internal_provider_label(language),
        "objective": f"Confirmar alcance autorizado y preparación de fuentes para {scope_label} antes de tomar decisiones de riesgo.",
        "actions": ["Validar dominios, marcas, países y fuentes permitidas.", "Reejecutar recolección cuando las fuentes faltantes estén configuradas."],
        "validation": "El siguiente informe contiene evidencias o limitaciones de fuente explícitamente documentadas.",
        "basis": "0 hallazgos · 0 evidencias · 0 escenarios",
        "evidence_urls": [],
        "scenarios": [],
    }


def _methodology_summary(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    metrics = payload.get("metrics", {}) or {}
    risk = metrics.get("risk_methodology", {}) or {}
    processing = payload.get("processing_summary", {}) or {}
    source_count = len(payload.get("source_statuses", []) or [])
    evidence_count = len(payload.get("scope_events") or payload.get("raw_events", []) or [])
    finding_count = len(payload.get("risk_findings", []) or [])
    direct_count = int(processing.get("direct_evidence", 0) or 0)
    validated_count = int(processing.get("validated_evidence", 0) or 0)
    validated_finding_count = int(processing.get("validated_findings", finding_count) or 0)
    confirmed_finding_count = int(processing.get("confirmed_findings", 0) or 0)
    if language == "en":
        steps = [
            {
                "name": "Scope",
                "detail": "Authorized domains, brand/group terms, analysis window, country and sector are fixed before collection.",
            },
            {
                "name": "Collection",
                "detail": "The process uses public search, passive indexes, external-surface checks, vulnerability intelligence, SOCMINT public signals and authorized dark-web metadata.",
            },
            {
                "name": "Validation",
                "detail": "Evidence is deduplicated, time-windowed, linked to domain/asset/query when possible and marked as direct, potential or contextual before decision use.",
            },
            {
                "name": "Calculation",
                "detail": "Each percentage has its own disclosed basis: source health, evidence assurance, supported residual risk or contextual evidence intensity. Framework values are mappings, not compliance scores. Missing inputs remain unassessed.",
            },
            {
                "name": "Decision",
                "detail": "The executive view summarizes priority and work plan; the technical view preserves URL-level evidence, validation notes and scenario traceability.",
            },
        ]
        percent_note = (
            f"Decision indicators use {direct_count} direct evidence records, {validated_count} validated evidence records, {validated_finding_count} validated findings and {confirmed_finding_count} confirmed findings. CVSS/EPSS/KEV and declared controls are used only when linked to an applicable asset or finding; absent data never becomes favorable evidence."
        )
    else:
        steps = [
            {
                "name": "Alcance",
                "detail": "Se fijan dominios autorizados, términos de marca/grupo, ventana de análisis, país y sector antes de recolectar.",
            },
            {
                "name": "Recolección",
                "detail": "El proceso usa búsqueda pública, índices pasivos, superficie externa, inteligencia de vulnerabilidades, señales SOCMINT públicas y metadatos dark web autorizados.",
            },
            {
                "name": "Validación",
                "detail": "La evidencia se deduplica, se filtra por tiempo, se relaciona con dominio/activo/query cuando es posible y se marca como directa, potencial o contextual antes de usarla para decisión.",
            },
            {
                "name": "Cálculo",
                "detail": "Cada porcentaje declara su propia base: salud de fuentes, aseguramiento de evidencia, riesgo residual sustentado o intensidad de evidencia contextual. Los valores de frameworks son mapeos, no puntajes de cumplimiento. Lo ausente queda sin evaluar.",
            },
            {
                "name": "Decisión",
                "detail": "La vista ejecutiva resume prioridad y plan de trabajo; la técnica conserva evidencia URL por URL, notas de validación y trazabilidad de escenarios.",
            },
        ]
        percent_note = (
            f"Los indicadores usan {direct_count} evidencias directas, {validated_count} evidencias validadas, {validated_finding_count} hallazgos validados y {confirmed_finding_count} hallazgos confirmados. CVSS/EPSS/KEV y controles declarados solo se incorporan cuando están vinculados a un activo o hallazgo aplicable; la ausencia de datos nunca cuenta como evidencia favorable."
        )
    return {
        "evidence_count": evidence_count,
        "source_count": source_count,
        "finding_count": finding_count,
        "steps": steps,
        "percent_note": percent_note,
        "risk_note": risk.get("purpose", ""),
        "calculation_basis": [
            risk.get("likelihood", ""),
            risk.get("impact", ""),
            risk.get("control_effectiveness", ""),
            risk.get("matrix", ""),
        ],
    }


def _display_status_label(status: str | None, language: str) -> str:
    normalized = str(status or "").strip().lower()
    labels = {
        "es": {
            "ok": "OK",
            "healthy": "OK",
            "active": "Activa",
            "completed": "Completa",
            "partial": "Parcial",
            "timeout": "Limitada",
            "warning": "Revisar",
            "searched": "Consultada",
            "configured": "Configurada",
            "skipped": "Sin datos",
            "disabled": "No habilitada",
            "missing": "No disponible",
            "failed": "Falla",
            "error": "Falla",
        },
        "en": {
            "ok": "OK",
            "healthy": "OK",
            "active": "Active",
            "completed": "Complete",
            "partial": "Partial",
            "timeout": "Limited",
            "warning": "Review",
            "searched": "Searched",
            "configured": "Configured",
            "skipped": "No data",
            "disabled": "Disabled",
            "missing": "Unavailable",
            "failed": "Failed",
            "error": "Failed",
        },
    }
    return labels["en" if language == "en" else "es"].get(normalized, normalized or ("Sin datos" if language == "es" else "No data"))


def _display_source_statuses(source_statuses: list[Dict[str, Any]], language: str) -> list[Dict[str, Any]]:
    rows = []
    seen = set()
    for status in source_statuses:
        row = dict(status)
        row["name"] = _display_source_name(str(status.get("name") or ""), language)
        if status.get("warning"):
            row["warning"] = _clean_evidence_text(str(status.get("warning") or ""), language)
        row["status_label"] = _display_status_label(str(status.get("status") or ""), language)
        key = (row.get("name"), row.get("status"), row.get("records"), row.get("warning"))
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows


def _display_metrics_sources(metrics: Dict[str, Any], language: str) -> Dict[str, Any]:
    output = dict(metrics or {})
    mitre = dict(output.get("mitre", {}) or {})
    tactics = []
    for tactic in mitre.get("tactics", []) or []:
        tactic_row = dict(tactic)
        techniques = []
        for technique in tactic_row.get("techniques", []) or []:
            technique_row = dict(technique)
            technique_row["sources"] = sorted({
                _display_source_name(source, language)
                for source in technique_row.get("sources", []) or []
                if source
            })
            examples = []
            for example in technique_row.get("examples", []) or []:
                example_row = dict(example)
                example_row["title"] = _clean_evidence_text(str(example_row.get("title") or ""))
                examples.append(example_row)
            technique_row["examples"] = examples
            techniques.append(technique_row)
        tactic_row["techniques"] = techniques
        tactics.append(tactic_row)
    if mitre:
        mitre["tactics"] = tactics
        output["mitre"] = mitre
    return output


def _display_vulnerability_intelligence(value: Dict[str, Any], language: str = "es") -> Dict[str, Any]:
    output = dict(value or {})
    rows = []
    for row in output.get("rows", []) or []:
        row_data = dict(row or {})
        row_data["evidence_url"] = _public_evidence_url(str(row_data.get("evidence_url") or ""))
        row_data["preview_url"] = _event_preview_url(row) if isinstance(row, dict) else ""
        row_type = str(row_data.get("type") or "potential")
        type_labels = {
            "confirmed": ("Aplicabilidad sustentada", "Supported applicability"),
            "candidate": ("Coincidencia por validar", "Match to validate"),
            "potential": ("Tecnología por validar", "Technology to validate"),
        }
        row_data["type_label"] = type_labels.get(row_type, type_labels["potential"])[
            1 if language == "en" else 0
        ]
        if language == "en":
            row_data["status"] = REPORT_TRANSLATIONS_EN.get(str(row_data.get("status") or ""), row_data.get("status") or "")
            row_data["decision"] = REPORT_TRANSLATIONS_EN.get(
                str(row_data.get("decision") or ""),
                row_data.get("decision") or "",
            )
            row_data["what_it_demonstrates"] = REPORT_TRANSLATIONS_EN.get(
                str(row_data.get("what_it_demonstrates") or ""),
                row_data.get("what_it_demonstrates") or "",
            )
            row_data["what_it_does_not_demonstrate"] = REPORT_TRANSLATIONS_EN.get(
                str(row_data.get("what_it_does_not_demonstrate") or ""),
                row_data.get("what_it_does_not_demonstrate") or "",
            )
        rows.append(row_data)
    output["rows"] = rows
    return output


def _localize_payload(value: Any, language: str) -> Any:
    if language != "en":
        return value
    if isinstance(value, dict):
        return {key: _localize_payload(item, language) for key, item in value.items()}
    if isinstance(value, list):
        return [_localize_payload(item, language) for item in value]
    if isinstance(value, str):
        for source, target in REPORT_PREFIX_TRANSLATIONS_EN.items():
            if value.startswith(source):
                return value.replace(source, target, 1)
        return REPORT_TRANSLATIONS_EN.get(value, value)
    return value


REPORT_PREFIX_TRANSLATIONS_EN = {
    "Senales reales de fuentes publicas gratuitas: ": "Real signals from free public sources: ",
}


REPORT_TRANSLATIONS_EN = {
    "Tecnología observada sin versión exacta": "Technology observed without an exact version",
    "Confirmar versión o SBOM antes de asociar una CVE.": "Confirm the version or SBOM before associating a CVE.",
    "Tecnología observada pasivamente en un activo del alcance.": "Technology was passively observed on an in-scope asset.",
    "No demuestra versión afectada, vulnerabilidad aplicable ni compromiso.": "It does not demonstrate an affected version, an applicable vulnerability, or compromise.",
    "Producto coincidente; versión pendiente de confirmación": "Product match; version pending confirmation",
    "Confirmar producto, versión, activo y exposición antes de priorizar parche.": "Confirm product, version, asset, and exposure before prioritizing a patch.",
    "Existe coincidencia de producto entre el activo observado y la configuración publicada por NVD.": "A product match exists between the observed asset and the configuration published by NVD.",
    "No demuestra aplicabilidad hasta confirmar la versión; tampoco demuestra explotación ni compromiso.": "It does not demonstrate applicability until the version is confirmed, nor exploitation or compromise.",
    "KEV aplicable": "Applicable KEV",
    "CVE aplicable": "Applicable CVE",
    "Priorizar validación de exposición, vector CVSS y ventana de parche.": "Prioritize validation of exposure, CVSS vector, and patch window.",
    "La tecnología y versión observadas coinciden con una configuración afectada publicada por NVD.": "The observed technology and version match an affected configuration published by NVD.",
    "No demuestra explotación ni compromiso.": "It does not demonstrate exploitation or compromise.",
    "PESTEL explica por que el riesgo cyber cambia por fuerzas externas, no solo por vulnerabilidades. Para la marca, grupo o conglomerado analizado, la lectura debe cubrir unidades de negocio, canales digitales, terceros, clientes, regulacion, continuidad y exposiciones sectoriales declaradas en la solicitud.": "PESTEL explains why cyber risk changes because of external forces, not only vulnerabilities. For the analyzed brand, group or conglomerate, the reading should cover business units, digital channels, third parties, customers, regulation, continuity and sector exposures declared in the request.",
    "Politico": "Political",
    "Economico/Fraude": "Economic/Fraud",
    "Social/Ing. social": "Social/Social engineering",
    "Tecnologico": "Technological",
    "Ambiental/Continuidad": "Environmental/Continuity",
    "Legal/Regulatorio": "Legal/Regulatory",
    "La estabilidad institucional, geolitica regional y prioridades de seguridad nacional pueden aumentar targeting o controles regulatorios.": "Institutional stability, regional geopolitics and national-security priorities can increase targeting or regulatory controls.",
    "Mantener escenarios de crisis y relacion con CSIRT/regulador.": "Maintain crisis scenarios and relationships with the CSIRT/regulator.",
    "Presion economica y monetizacion criminal elevan phishing, BEC, fraude transaccional y cuentas mula.": "Economic pressure and criminal monetization increase phishing, BEC, transactional fraud and mule accounts.",
    "Refuerzo de fraude digital, monitoreo de pagos y comunicacion a clientes.": "Strengthen digital fraud controls, payment monitoring and customer communications.",
    "La adopcion digital y confianza del usuario afectan exito de smishing, vishing y suplantacion.": "Digital adoption and user trust affect the success of smishing, vishing and impersonation.",
    "Campanas segmentadas y autenticacion resistente a phishing.": "Segmented campaigns and phishing-resistant authentication.",
    "Banca digital, pagos, pensiones, fiduciaria, APIs, cloud, proveedores y operaciones no financieras amplian superficie y dependencias.": "Digital banking, payments, pensions, fiduciary services, APIs, cloud, suppliers and non-financial operations expand attack surface and dependencies.",
    "Priorizar EASM, API security, hardening cloud, terceros criticos y DevSecOps.": "Prioritize EASM, API security, cloud hardening, critical third parties and DevSecOps.",
    "Infraestructura, energia/gas, hoteles y agroindustria agregan continuidad fisica-operacional, OT/IoT y dependencia de proveedores.": "Infrastructure, energy/gas, hotels and agribusiness add physical-operational continuity, OT/IoT and supplier dependency.",
    "Validar BCP/DRP, continuidad operacional multisector y segregacion IT/OT cuando aplique.": "Validate BCP/DRP, multisector operational continuity and IT/OT segregation where applicable.",
    "Privacidad, regulacion financiera, fiduciaria, pensional, mercado de valores, terceros e infraestructura exigen evidencia y gobierno transversal.": "Privacy, financial regulation, fiduciary/pension duties, capital markets, third parties and infrastructure require evidence and cross-functional governance.",
    "Preparar evidencias, playbooks legales, reporting ejecutivo y trazabilidad por filial/sector.": "Prepare evidence, legal playbooks, executive reporting and traceability by subsidiary/sector.",
    "Porter Cyber explica como la estructura competitiva modifica el riesgo. Para la marca, grupo o conglomerado analizado no basta mirar un solo dominio: deben revisarse clientes, filiales, proveedores tecnologicos, sustitutos digitales, presion sectorial y dependencias de continuidad.": "Porter Cyber explains how competitive structure changes risk. For the analyzed brand, group or conglomerate, one domain is not enough: customers, subsidiaries, technology providers, digital substitutes, sector pressure and continuity dependencies should be reviewed.",
    "Rivalidad": "Rivalry",
    "Proveedores": "Suppliers",
    "Clientes": "Customers",
    "Sustitutos": "Substitutes",
    "Nuevos entrantes": "New entrants",
    "Competencia financiera acelera canales digitales y aumenta exposicion de marca, apps y APIs.": "Financial competition accelerates digital channels and increases exposure across brand, apps and APIs.",
    "Proteger disponibilidad, reputacion y monitoreo de suplantacion.": "Protect availability, reputation and impersonation monitoring.",
    "Cloud, core bancario, pagos, SaaS, custodios, infraestructura, energia/gas, hoteles y agro agregan cadena de suministro heterogenea.": "Cloud, banking core, payments, SaaS, custodians, infrastructure, energy/gas, hotels and agribusiness create a heterogeneous supply chain.",
    "KRIs de terceros, SBOM/SCA, continuidad, clausulas de seguridad y pruebas de resiliencia.": "Third-party KRIs, SBOM/SCA, continuity, security clauses and resilience testing.",
    "Clientes bancarios, pensionados, inversionistas, empresas y usuarios digitales amplian phishing, ATO, fraude y soporte social.": "Banking customers, pensioners, investors, companies and digital users expand phishing, ATO, fraud and social-support exposure.",
    "Friccion adaptativa, awareness segmentado, deteccion transaccional y proteccion de identidad.": "Adaptive friction, segmented awareness, transactional detection and identity protection.",
    "Wallets, fintech, cripto y nuevos rieles de pago cambian fraude y superficie tecnologica.": "Wallets, fintech, crypto and new payment rails change fraud and technology exposure.",
    "Monitorear nuevos canales y adaptar controles antifraude.": "Monitor new channels and adapt anti-fraud controls.",
    "Open banking, fintech, insuretech, wealthtech y plataformas de pagos incrementan integraciones y presion de velocidad.": "Open banking, fintech, insuretech, wealthtech and payment platforms increase integrations and speed pressure.",
    "API security, OAuth governance, rate limits y monitoreo de integraciones.": "API security, OAuth governance, rate limits and integration monitoring.",
    "extraido de fuente": "extracted from source",
    "no atribuido por la fuente publica": "not attributed by the public source",
    "La vista de actores separa atribucion real de eventos no atribuidos. Si la fuente publica no nombra actor, el informe conserva 'unattributed' en vez de inventar grupos.": "The actor view separates real attribution from unattributed events. If the public source does not name an actor, the report keeps 'unattributed' instead of inventing groups.",
    "Explotacion y vulnerabilidades priorizadas": "Exploitation and prioritized vulnerabilities",
    "Alta relacion con KEV, EPSS, NVD y advisories de software; prioriza patching y exposicion externa.": "Strong relationship with KEV, EPSS, NVD and software advisories; prioritize patching and external exposure.",
    "Fraude, phishing o suplantacion": "Fraud, phishing or impersonation",
    "Afecta canales digitales, identidad, clientes y monitoreo transaccional.": "Affects digital channels, identity, customers and transactional monitoring.",
    "Senal asociada a ransomware": "Ransomware-associated signal",
    "CISA KEV marca uso conocido en campanas ransomware; refuerza backups, segmentacion y respuesta.": "CISA KEV marks known use in ransomware campaigns; reinforce backups, segmentation and response.",
    "Los patrones resumen concentraciones repetidas por tipo de amenaza, fuente y tecnica; sirven para decidir donde invertir primero.": "Patterns summarize repeated concentrations by threat type, source and technique; they help decide where to invest first.",
    "OSINT consolida fuentes abiertas y gratuitas: busquedas web/noticias, advisories, RSS tecnicos, CISA KEV, NVD, EPSS y GitHub Security Advisories. Sirve para cibervigilancia temprana sin intrusividad.": "OSINT consolidates free open sources: web/news searches, advisories, technical RSS, CISA KEV, NVD, EPSS and GitHub Security Advisories. It supports early cyber monitoring without intrusiveness.",
    "SOCMINT aporta senales publicas de marca, fraude, phishing y conversacion agregada. En modo real-only no se hace scraping social; solo APIs/RSS publicos autorizados.": "SOCMINT contributes public brand, fraud, phishing and aggregated conversation signals. In real-only mode it does not perform social scraping; only authorized public APIs/RSS are used.",
    "Dark Web usa metadatos autorizados e indices publicos de inteligencia ransomware/darkweb. Tor directo, foros privados, credenciales y datos robados quedan fuera de alcance salvo habilitacion explicita y archivo redacted autorizado.": "Dark Web uses authorized metadata and public ransomware/darkweb intelligence indexes. Direct Tor browsing, private forums, credentials and stolen data remain out of scope unless explicitly enabled with an authorized redacted file.",
    "Dark Web usa metadatos autorizados y fuentes publicas de inteligencia ransomware/darkweb como ransomware.live. Tor directo, foros privados, credenciales y datos robados quedan fuera de alcance salvo habilitacion explicita y archivo redacted autorizado.": "Dark Web uses authorized metadata and public ransomware/darkweb intelligence indexes. Direct Tor browsing, private forums, credentials and stolen data remain out of scope unless explicitly enabled with an authorized redacted file.",
    "Radar-calor propio para decision ejecutiva: combina intensidad de evidencia, riesgo residual y tendencia por tipo de ciberriesgo. Sirve para ver donde anticiparse, donde invertir y que area debe actuar primero.": "CyberDecisionEngine heat radar for executive decision-making: combines evidence intensity, residual risk and trend by cyber-risk type. It shows where to anticipate, where to invest and which area should act first.",
    "Cada sector numerado representa un tipo de ciberriesgo. El color va de verde a rojo segun calor; el radio representa intensidad. La tabla explica la decision recomendada y las senales que originaron el puntaje.": "Each numbered sector represents a cyber-risk type. Color moves from green to red by heat; radius represents intensity. The table explains the recommended decision and the signals behind the score.",
    "Vulnerabilidades explotables": "Exploitable vulnerabilities",
    "Fraude e ingenieria social": "Fraud and social engineering",
    "Identidad y accesos": "Identity and access",
    "Ransomware y continuidad": "Ransomware and continuity",
    "Cloud, APIs y DevSecOps": "Cloud, APIs and DevSecOps",
    "Terceros y cadena de suministro": "Third parties and supply chain",
    "Datos, privacidad y regulacion": "Data, privacy and regulation",
    "IA, agentes y automatizacion": "AI, agents and automation",
    "Priorizar KEV/EPSS, exposicion externa y activos criticos.": "Prioritize KEV/EPSS, external exposure and critical assets.",
    "Ajustar controles de identidad, monitoreo transaccional y takedown.": "Tune identity controls, transactional monitoring and takedown.",
    "Reforzar MFA resistente a phishing, PAM, deteccion de valid accounts.": "Reinforce phishing-resistant MFA, PAM and valid-account detection.",
    "Validar backups, segmentacion, EDR/NDR y ejercicios de crisis.": "Validate backups, segmentation, EDR/NDR and crisis exercises.",
    "Revisar API security, secretos, SCA/SBOM, CI/CD y CSPM.": "Review API security, secrets, SCA/SBOM, CI/CD and CSPM.",
    "Monitorear proveedores, contratos, SBOM y resiliencia operacional.": "Monitor suppliers, contracts, SBOM and operational resilience.",
    "Reducir exposicion de datos, trazabilidad legal y respuesta regulatoria.": "Reduce data exposure, legal traceability and regulatory response.",
    "Gobernar prompts, agentes, herramientas, logs y decisiones automatizadas.": "Govern prompts, agents, tools, logs and automated decisions.",
    "Probabilidad relativa estimada; no implica certeza de ataque.": "Estimated relative probability; it does not imply certainty of attack.",
    "La estructura de riesgo convierte evidencia trazable en una estimacion contextual de plausibilidad, impacto de negocio, riesgo inherente, riesgo residual y matriz 4x4; no confirma incidentes.": "The risk structure converts traceable evidence into contextual plausibility, business impact, inherent risk, residual risk and a 4x4 matrix; it does not confirm incidents.",
    "L usa funcion logistica con activo, exposicion, CVSS, EPSS, KEV, actividad de amenaza, targeting sectorial, presion geopolitica/regulatoria y resta madurez de controles, deteccion y resiliencia.": "L uses a logistic function with asset, exposure, CVSS, EPSS, KEV, threat activity, sector targeting, geopolitical/regulatory pressure and subtracts control, detection and resilience maturity.",
    "El modelo separa evidencia, plausibilidad contextual, impacto, controles declarados, riesgo inherente y riesgo residual; no confirma incidentes ni estima probabilidad calibrada de ataque.": "The model separates evidence, contextual plausibility, impact, declared controls, inherent risk and residual risk; it does not confirm incidents or estimate calibrated attack probability.",
    "La plausibilidad contextual es un puntaje acotado basado en evidencia directa o validada. Las limitaciones y fuentes ausentes no incrementan el riesgo.": "Contextual plausibility is a bounded score based on direct or validated evidence. Limitations and unavailable sources do not increase risk.",
    "El impacto pondera dimensiones financieras, operacionales, reputacionales, legales y de continuidad únicamente cuando aplican al hallazgo.": "Impact weights financial, operational, reputational, legal and continuity dimensions only when they apply to the finding.",
    "Solo los controles declarados reducen el riesgo; un control desconocido permanece sin evaluar.": "Only declared controls reduce risk; an unknown control remains unassessed.",
    "La matriz 4x4 cruza plausibilidad contextual e impacto para ordenar tratamiento; no representa certeza de ataque.": "The 4x4 matrix crosses contextual plausibility and impact to prioritize treatment; it does not represent attack certainty.",
    "Las bandas de sensibilidad muestran variación del riesgo calculado y no constituyen intervalos de predicción de incidentes.": "Sensitivity bands show variation in calculated risk and are not incident prediction intervals.",
    "I pondera impacto financiero, operacional, confidencialidad, integridad, disponibilidad, legal y reputacional.": "I weights financial, operational, confidentiality, integrity, availability, legal and reputational impact.",
    "CE combina ISO, NIST, SOC2, D3FEND, cobertura ATT&CK y respuesta a incidentes, con tope de reduccion de 0.85 para evitar riesgo cero.": "CE combines ISO, NIST, SOC2, D3FEND, ATT&CK coverage and incident response, capped at 0.85 to avoid zero risk.",
    "La matriz 4x4 usa ceil(4*L) y ceil(4*I). 1-3 Bajo, 4-7 Medio, 8-11 Alto, 12-16 Critico.": "The 4x4 matrix uses ceil(4*L) and ceil(4*I). 1-3 Low, 4-7 Medium, 8-11 High, 12-16 Critical.",
    "Esta capa convierte inteligencia tecnica en decisiones por rol. Sirve para anticipar, asignar accountability y coordinar CISO, directores y areas de negocio antes de que el riesgo se materialice.": "This layer turns technical intelligence into role-based decisions. It supports anticipation, accountability assignment and coordination among the CISO, directors and business areas before risk materializes.",
    "Junta / CEO": "Board / CEO",
    "Director de Fraude": "Fraud Director",
    "Infraestructura / Vulnerabilidades": "Infrastructure / Vulnerabilities",
    "Riesgo Operacional / GRC": "Operational Risk / GRC",
    "Legal / Cumplimiento / Comunicaciones": "Legal / Compliance / Communications",
    "Aprobar apetito de riesgo cyber-fraude y umbrales de escalamiento ejecutivo.": "Approve cyber-fraud risk appetite and executive escalation thresholds.",
    "Exigir tablero mensual con KEV, EPSS, fraude, cobertura ATT&CK y excepciones de patching.": "Require a monthly dashboard with KEV, EPSS, fraud, ATT&CK coverage and patching exceptions.",
    "Activar comite ejecutivo si riesgo residual critico supera el umbral o hay exposicion KEV sin remediar.": "Activate the executive committee if critical residual risk exceeds threshold or KEV exposure remains unremediated.",
    "Usar forecast 7/14/30 dias para decidir refuerzo temporal de presupuesto, comunicacion y capacidad SOC.": "Use the 7/14/30-day forecast to decide temporary budget, communications and SOC capacity reinforcement.",
    "Indicadores: KEV abiertos, EPSS alto, T1190/T1566, incidentes por canal digital, MTTR y cobertura D3FEND.": "Indicators: open KEV, high EPSS, T1190/T1566, incidents by digital channel, MTTR and D3FEND coverage.",
    "Orquestar el portafolio de controles que reduzca maxima perdida esperada por unidad de esfuerzo.": "Orchestrate the control portfolio that reduces maximum expected loss per unit of effort.",
    "Priorizar controles D3FEND asociados a las tecnicas ATT&CK observadas y cerrar brechas de deteccion.": "Prioritize D3FEND controls associated with observed ATT&CK techniques and close detection gaps.",
    "Convertir los top riesgos en backlog con owner, fecha, evidencia y criterio de aceptacion.": "Convert top risks into a backlog with owner, date, evidence and acceptance criteria.",
    "Vigilar aceleracion de KEV/EPSS, concentracion por tecnica y senales SOCMINT/Dark Web autorizada.": "Monitor KEV/EPSS acceleration, concentration by technique and authorized SOCMINT/Dark Web signals.",
    "Acciones: patching por riesgo, detecciones SIEM/NDR/EDR, hardening IAM, pruebas de respuesta y reglas antifraude.": "Actions: risk-based patching, SIEM/NDR/EDR detections, IAM hardening, response testing and anti-fraud rules.",
    "Alinear detecciones a TTP reales en vez de alertas genericas.": "Align detections to real TTPs instead of generic alerts.",
    "Crear casos de uso para T1190, T1566, T1078 y ransomware_signal cuando aparezcan en fuentes reales.": "Create use cases for T1190, T1566, T1078 and ransomware_signal when they appear in real sources.",
    "Medir cobertura de logs, falsos positivos, tiempo de triage y gaps de telemetria por tecnica.": "Measure log coverage, false positives, triage time and telemetry gaps by technique.",
    "Elevar vigilancia cuando suban eventos KEV, advisories o patrones repetidos por fuente.": "Raise monitoring when KEV events, advisories or repeated patterns by source increase.",
    "Herramientas: SIEM, EDR/XDR, NDR, SOAR, detecciones Sigma/YARA cuando aplique, enrichment CVE/EPSS.": "Tools: SIEM, EDR/XDR, NDR, SOAR, Sigma/YARA detections where applicable, CVE/EPSS enrichment.",
    "Integrar fraude digital con inteligencia cyber y no tratarlo como silo transaccional.": "Integrate digital fraud with cyber intelligence instead of treating it as a transactional silo.",
    "Fortalecer monitoreo de phishing, smishing, device intelligence, velocity rules y graph analytics.": "Strengthen phishing and smishing monitoring, device intelligence, velocity rules and graph analytics.",
    "Retroalimentar reglas/modelos con casos confirmados y patrones de beneficiarios, dispositivos y sesiones.": "Feed rules/models with confirmed cases and beneficiary, device and session patterns.",
    "Usar senales publicas de suplantacion y picos de phishing para anticipar refuerzo de monitoreo por canal.": "Use public impersonation signals and phishing spikes to anticipate monitoring reinforcement by channel.",
    "Controles: FIDO2/step-up, scoring transaccional, deteccion de cuentas mula, takedown, case management.": "Controls: FIDO2/step-up, transactional scoring, mule-account detection, takedown, case management.",
    "Mover patching de calendario fijo a priorizacion por explotacion real y criticidad de activo.": "Move patching from a fixed calendar to prioritization by real exploitation and asset criticality.",
    "Cruzar CISA KEV, EPSS, NVD y exposicion externa con CMDB y crown jewels.": "Cross CISA KEV, EPSS, NVD and external exposure with CMDB and crown jewels.",
    "Remediar o compensar CVEs con KEV/EPSS alto; documentar excepciones aceptadas por riesgo.": "Remediate or compensate CVEs with high KEV/EPSS; document risk-accepted exceptions.",
    "Anticipar ventanas de cambio si crece la tasa de KEV o advisories de proveedores clave.": "Anticipate change windows if KEV rate or key-provider advisories increase.",
    "Herramientas: VM, EASM, CMDB, WAF, patch orchestration, SCA/SBOM para dependencias open source.": "Tools: VM, EASM, CMDB, WAF, patch orchestration, SCA/SBOM for open-source dependencies.",
    "Reducir exposicion de APIs, secretos, pipelines y dependencias antes de explotacion.": "Reduce API, secret, pipeline and dependency exposure before exploitation.",
    "Integrar GitHub advisories, SCA, IaC scanning, secret scanning y proteccion de ramas.": "Integrate GitHub advisories, SCA, IaC scanning, secret scanning and branch protection.",
    "Bloquear despliegues con vulnerabilidades explotables o secretos detectados.": "Block deployments with exploitable vulnerabilities or detected secrets.",
    "Usar tendencias de advisories open source para anticipar actualizaciones de imagenes base y librerias.": "Use open-source advisory trends to anticipate base-image and library updates.",
    "Controles: SAST/SCA/DAST, SBOM, admission control, CSPM/CWPP, API gateway, least privilege.": "Controls: SAST/SCA/DAST, SBOM, admission control, CSPM/CWPP, API gateway, least privilege.",
    "Traducir hallazgos tecnicos a riesgo residual, KRIs y apetito de riesgo.": "Translate technical findings into residual risk, KRIs and risk appetite.",
    "Mantener trazabilidad NIST/ISO/SOC2/D3FEND para auditoria y priorizacion de controles.": "Maintain NIST/ISO/SOC2/D3FEND traceability for audit and control prioritization.",
    "Registrar aceptaciones temporales con impacto, compensatorios y fecha de cierre.": "Record temporary acceptances with impact, compensating controls and closure date.",
    "Usar PESTEL/Porter y forecast para escenarios trimestrales y pruebas de estres.": "Use PESTEL/Porter and forecast for quarterly scenarios and stress testing.",
    "KRIs: residual risk, CE, matrix score, excepciones KEV, cobertura ATT&CK, MTTR, fraude por canal.": "KRIs: residual risk, CE, matrix score, KEV exceptions, ATT&CK coverage, MTTR, fraud by channel.",
    "Preparar respuesta regulatoria, contractual y reputacional antes del incidente.": "Prepare regulatory, contractual and reputational response before the incident.",
    "Validar obligaciones de notificacion, evidencia, privacidad y terceros criticos.": "Validate notification obligations, evidence, privacy and critical third parties.",
    "Coordinar comunicaciones, preservacion de evidencia y notificaciones si hay impacto material.": "Coordinate communications, evidence preservation and notifications if there is material impact.",
    "Monitorear presion regulatoria, fraude de marca y campanas de suplantacion que requieran comunicacion preventiva.": "Monitor regulatory pressure, brand fraud and impersonation campaigns that require preventive communication.",
    "Insumos: fuentes, timestamps, decisiones, owners, datos redacted, TLP y cadena de custodia.": "Inputs: sources, timestamps, decisions, owners, redacted data, TLP and chain of custody.",
    "KEV activos en tecnologias propias": "Active KEV in owned technologies",
    "Concentracion ATT&CK": "ATT&CK concentration",
    "Senales fraude/phishing": "Fraud/phishing signals",
    "Dark Web autorizada": "Authorized Dark Web",
    "Riesgo residual maximo": "Maximum residual risk",
    "Cualquier KEV en activo expuesto o crown jewel exige decision CISO en 24-72h.": "Any KEV on an exposed asset or crown jewel requires a CISO decision within 24-72h.",
    "Reservar ventana de cambio y controles compensatorios antes de explotacion masiva.": "Reserve a change window and compensating controls before mass exploitation.",
    "Una tecnica domina la corrida o aparece en varias fuentes independientes.": "One technique dominates the run or appears in multiple independent sources.",
    "Aumentar detecciones, telemetria y playbooks sobre esa tecnica.": "Increase detections, telemetry and playbooks for that technique.",
    "Aumento de phishing/fraude en fuentes publicas o SOCMINT autorizado.": "Increase in phishing/fraud across public sources or authorized SOCMINT.",
    "Refuerzo de monitoreo transaccional, customer comms y takedown.": "Reinforce transactional monitoring, customer communications and takedown.",
    "Metadatos redacted con marca, proveedor, credenciales o sector financiero.": "Redacted metadata with brand, provider, credential or financial-sector references.",
    "Forzar rotacion preventiva, hunting de accesos y revision de terceros.": "Force preventive rotation, access hunting and third-party review.",
    "Riesgo residual critico o creciente despues de controles.": "Critical or increasing residual risk after controls.",
    "Elevar a comite de riesgo y ajustar capacidad defensiva temporal.": "Escalate to the risk committee and adjust temporary defensive capacity.",
    "sin datos": "no data",
    "Phishing, smishing y suplantacion de marca contra clientes": "Phishing, smishing and brand impersonation against customers",
    "Account takeover con credenciales filtradas o session hijacking": "Account takeover with leaked credentials or session hijacking",
    "Mule accounts y dispersion transaccional anomala": "Mule accounts and anomalous transactional dispersion",
    "BEC y pagos no autorizados por ingenieria social": "BEC and unauthorized payments through social engineering",
    "DMARC, SPF, DKIM y monitoreo de dominios lookalike": "DMARC, SPF, DKIM and lookalike-domain monitoring",
    "Campanas de awareness por segmentos": "Segmented awareness campaigns",
    "Takedown coordinado con legal y proveedores": "Takedown coordinated with legal and providers",
    "Autenticacion resistente a phishing": "Phishing-resistant authentication",
    "Analitica de device fingerprint y impossible travel": "Device fingerprint and impossible-travel analytics",
    "Step-up authentication por riesgo": "Risk-based step-up authentication",
    "Graph analytics de beneficiarios": "Beneficiary graph analytics",
    "Velocity rules por canal y dispositivo": "Velocity rules by channel and device",
    "Orquestacion de casos con retroalimentacion del SOC": "Case orchestration with SOC feedback",
    "Verificacion fuera de banda de cambios de cuenta": "Out-of-band verification of account changes",
    "Controles duales para pagos criticos": "Dual controls for critical payments",
    "Monitoreo de reglas sospechosas de correo": "Monitoring of suspicious email rules",
    "Fraude": "Fraud",
    "Tesoreria/Fraude": "Treasury/Fraud",
    "Fuentes metodologicas: FBI IC3, ENISA Finance Threat Landscape, ACFE y NIST SP 800-63-4.": "Methodological sources: FBI IC3, ENISA Finance Threat Landscape, ACFE and NIST SP 800-63-4.",
    "deteccion -> respuesta -> hardening -> menor exposicion": "detection -> response -> hardening -> lower exposure",
    "patching reduce vulnerabilidad explotable": "patching reduces exploitable vulnerability",
    "telemetria mejora deteccion y reduce dwell time": "telemetry improves detection and reduces dwell time",
    "fraud case feedback recalibra reglas y modelos": "fraud case feedback recalibrates rules and models",
    "awareness reduce tasa de exito de ingenieria social": "awareness reduces social-engineering success rate",
    "hardening": "hardening",
    "monitoring": "monitoring",
    "training": "training",
}


RECOMMENDATION_LIBRARY = [
    {
        "area": "strategic",
        "triggers": ["critical", "critico", "crítico", "residual", "kev", "ransomware", "fraude", "fraud"],
        "title_es": "Umbrales ejecutivos de escalamiento",
        "title_en": "Executive escalation thresholds",
        "action_es": "Definir umbrales por riesgo residual, KEV expuesto, fraude y continuidad para activar comité ejecutivo en 24-72 horas.",
        "action_en": "Define thresholds for residual risk, exposed KEV, fraud and continuity to activate the executive committee within 24-72 hours.",
        "owner_es": "Junta / CEO / CISO",
        "owner_en": "Board / CEO / CISO",
    },
    {
        "area": "strategic",
        "triggers": ["porter", "pestel", "competidor", "competitor", "benchmark", "sector"],
        "title_es": "Benchmark competitivo controlado",
        "title_en": "Controlled competitive benchmark",
        "action_es": "Comparar menciones, superficie visible y presión de fraude contra dominios benchmark declarados, separando contexto sectorial de afectación propia.",
        "action_en": "Compare mentions, visible surface and fraud pressure against declared benchmark domains, separating sector context from direct exposure.",
        "owner_es": "Estrategia / Riesgo / CTI",
        "owner_en": "Strategy / Risk / CTI",
    },
    {
        "area": "strategic",
        "triggers": ["scenario", "escenario", "forecast", "predic", "anticip"],
        "title_es": "Mesa de escenarios trimestral",
        "title_en": "Quarterly scenario table-top",
        "action_es": "Ejecutar escenarios por fraude, ransomware, terceros, datos y disponibilidad usando señales tempranas y forecast 7/14/30 días.",
        "action_en": "Run fraud, ransomware, third-party, data and availability scenarios using early signals and 7/14/30-day forecasts.",
        "owner_es": "CISO / Riesgo Operacional",
        "owner_en": "CISO / Operational Risk",
    },
    {
        "area": "risk",
        "triggers": ["kev", "epss", "cve", "vulnerab", "exploit", "patch"],
        "title_es": "Patching basado en explotación real",
        "title_en": "Exploitation-based patching",
        "action_es": "Priorizar CVE por KEV, EPSS, exposición externa y criticidad del activo; documentar excepciones con compensatorios.",
        "action_en": "Prioritize CVEs by KEV, EPSS, external exposure and asset criticality; document exceptions with compensating controls.",
        "owner_es": "Infraestructura / Vulnerabilidades",
        "owner_en": "Infrastructure / Vulnerability Management",
    },
    {
        "area": "risk",
        "triggers": ["ransomware", "continuidad", "backup", "edr", "ndr"],
        "title_es": "Resiliencia contra ransomware",
        "title_en": "Ransomware resilience",
        "action_es": "Validar backups inmutables, segmentación, EDR/NDR, restauración y simulacro de crisis con tiempos de recuperación medibles.",
        "action_en": "Validate immutable backups, segmentation, EDR/NDR, restoration and crisis drills with measurable recovery times.",
        "owner_es": "Continuidad / SOC / Infraestructura",
        "owner_en": "Continuity / SOC / Infrastructure",
    },
    {
        "area": "risk",
        "triggers": ["fraude", "fraud", "phishing", "smishing", "suplantacion", "impersonation"],
        "title_es": "Ciclo integrado cyber-fraude",
        "title_en": "Integrated cyber-fraud cycle",
        "action_es": "Cruzar phishing, suplantación, ATO, device intelligence, reglas de velocidad y casos confirmados para recalibrar controles.",
        "action_en": "Cross phishing, impersonation, ATO, device intelligence, velocity rules and confirmed cases to recalibrate controls.",
        "owner_es": "Fraude / SOC / Canales Digitales",
        "owner_en": "Fraud / SOC / Digital Channels",
    },
    {
        "area": "risk",
        "triggers": ["tercer", "supplier", "supply", "cadena", "proveedor"],
        "title_es": "Riesgo de terceros con evidencia técnica",
        "title_en": "Third-party risk with technical evidence",
        "action_es": "Mapear proveedores críticos, SBOM/SCA, continuidad contractual, exposición pública y cláusulas de notificación.",
        "action_en": "Map critical suppliers, SBOM/SCA, contractual continuity, public exposure and notification clauses.",
        "owner_es": "Compras / GRC / Legal",
        "owner_en": "Procurement / GRC / Legal",
    },
    {
        "area": "compliance",
        "triggers": ["nist", "iso", "soc2", "pci", "gdpr", "cumplimiento", "compliance", "privacy", "privacidad"],
        "title_es": "Repositorio de evidencia regulatoria",
        "title_en": "Regulatory evidence repository",
        "action_es": "Mantener evidencias por NIST, ISO 27001, SOC 2, PCI DSS y GDPR con owner, fecha, control, fuente y decisión.",
        "action_en": "Maintain evidence for NIST, ISO 27001, SOC 2, PCI DSS and GDPR with owner, date, control, source and decision.",
        "owner_es": "GRC / Legal / Auditoría",
        "owner_en": "GRC / Legal / Audit",
    },
    {
        "area": "compliance",
        "triggers": ["gdpr", "datos", "data", "privacy", "privacidad", "regulatorio"],
        "title_es": "Preparación de privacidad y notificación",
        "title_en": "Privacy and notification readiness",
        "action_es": "Validar clasificación de datos, retención, cadena de custodia, umbrales de notificación y mensajes regulatorios.",
        "action_en": "Validate data classification, retention, chain of custody, notification thresholds and regulatory messaging.",
        "owner_es": "Legal / Privacidad / Comunicaciones",
        "owner_en": "Legal / Privacy / Communications",
    },
    {
        "area": "compliance",
        "triggers": ["pci", "card", "tarjeta", "pagos", "payments"],
        "title_es": "Alcance PCI y monitoreo de pagos",
        "title_en": "PCI scope and payment monitoring",
        "action_es": "Separar ambiente de datos de tarjeta, validar segmentación, logs, cifrado, acceso privilegiado y monitoreo antifraude.",
        "action_en": "Separate cardholder-data environments and validate segmentation, logs, encryption, privileged access and anti-fraud monitoring.",
        "owner_es": "Pagos / GRC / Infraestructura",
        "owner_en": "Payments / GRC / Infrastructure",
    },
    {
        "area": "technical",
        "triggers": ["domain", "dominio", "whois", "tls", "cert", "surface", "easm", "api"],
        "title_es": "Superficie de ataque verificable",
        "title_en": "Verifiable attack surface",
        "action_es": "Consolidar WHOIS, DNS, TLS/certificados, headers, servicios expuestos, APIs y dominios lookalike para priorizar cierre.",
        "action_en": "Consolidate WHOIS, DNS, TLS/certificates, headers, exposed services, APIs and lookalike domains for closure prioritization.",
        "owner_es": "EASM / Infraestructura / SOC",
        "owner_en": "EASM / Infrastructure / SOC",
    },
    {
        "area": "technical",
        "triggers": ["dmarc", "spf", "dkim", "bimi", "phishing", "email"],
        "title_es": "Protección de correo y marca",
        "title_en": "Email and brand protection",
        "action_es": "Endurecer DMARC/SPF/DKIM, monitorear lookalikes, activar takedown y correlacionar campañas con SOCMINT público.",
        "action_en": "Harden DMARC/SPF/DKIM, monitor lookalikes, activate takedown and correlate campaigns with public SOCMINT.",
        "owner_es": "Canales Digitales / SOC / Legal",
        "owner_en": "Digital Channels / SOC / Legal",
    },
    {
        "area": "technical",
        "triggers": ["attack", "mitre", "ttp", "t1190", "t1566", "t1078", "d3fend"],
        "title_es": "Detecciones alineadas a ATT&CK/D3FEND",
        "title_en": "ATT&CK/D3FEND-aligned detections",
        "action_es": "Crear casos de uso por técnica observada, definir logs mínimos, reglas, pruebas de detección y contramedidas D3FEND.",
        "action_en": "Create use cases per observed technique, define minimum logs, rules, detection tests and D3FEND countermeasures.",
        "owner_es": "SOC / CTI / Ingeniería de Detección",
        "owner_en": "SOC / CTI / Detection Engineering",
    },
    {
        "area": "technical",
        "triggers": ["iam", "identity", "identidad", "mfa", "ato", "valid accounts", "credencial"],
        "title_es": "Identidad resistente a phishing",
        "title_en": "Phishing-resistant identity",
        "action_es": "Priorizar FIDO2/passkeys, PAM, conditional access, impossible travel, rotación preventiva y hunting de cuentas válidas.",
        "action_en": "Prioritize FIDO2/passkeys, PAM, conditional access, impossible travel, preventive rotation and valid-account hunting.",
        "owner_es": "IAM / SOC",
        "owner_en": "IAM / SOC",
    },
    {
        "area": "technical",
        "triggers": ["cloud", "api", "secret", "sbom", "sca", "devsecops", "pipeline"],
        "title_es": "DevSecOps y APIs bajo control",
        "title_en": "Controlled DevSecOps and APIs",
        "action_es": "Bloquear secretos, SCA/SBOM, IaC scanning, API gateway, OAuth governance, rate limits y pruebas DAST.",
        "action_en": "Block secrets, SCA/SBOM, IaC scanning, API gateway, OAuth governance, rate limits and DAST testing.",
        "owner_es": "DevSecOps / Arquitectura",
        "owner_en": "DevSecOps / Architecture",
    },
    {
        "area": "prediction",
        "triggers": ["forecast", "predic", "early", "tempran", "warning", "anticip"],
        "title_es": "Reglas de activación predictiva",
        "title_en": "Predictive activation rules",
        "action_es": "Definir gatillos por bandas de presión, aumento de KEV aplicable, concentración ATT&CK, fraude, SOCMINT y dark web autorizada.",
        "action_en": "Define triggers using pressure bands, applicable KEV growth, ATT&CK concentration, fraud, SOCMINT and authorized dark-web signals.",
        "owner_es": "CISO / SOC / Fraude",
        "owner_en": "CISO / SOC / Fraud",
    },
    {
        "area": "prediction",
        "triggers": ["dark", "tor", "ransomware", "credential", "credencial"],
        "title_es": "Triage autorizado de dark web",
        "title_en": "Authorized dark-web triage",
        "action_es": "Usar solo metadatos autorizados/redacted, registrar fuente, TLP, alcance, hallazgo y acción de rotación/hunting.",
        "action_en": "Use only authorized/redacted metadata and register source, TLP, scope, finding and rotation/hunting action.",
        "owner_es": "CTI / Legal / SOC",
        "owner_en": "CTI / Legal / SOC",
    },
    {
        "area": "prediction",
        "triggers": ["fraud", "fraude", "phishing", "brand", "marca", "socmint"],
        "title_es": "Vigilancia anticipada de fraude de marca",
        "title_en": "Forward-looking brand-fraud watch",
        "action_es": "Monitorear menciones públicas, dominios similares, campañas de phishing y patrones de reclamo para activar comunicación preventiva.",
        "action_en": "Monitor public mentions, similar domains, phishing campaigns and complaint patterns to activate preventive communications.",
        "owner_es": "Fraude / Marca / Comunicaciones",
        "owner_en": "Fraud / Brand / Communications",
    },
]


FRAMEWORK_ASPECTS = [
    {
        "framework": "NIST CSF 2.0",
        "aspect_es": "Gobierno, identificación, protección, detección, respuesta y recuperación.",
        "aspect_en": "Govern, identify, protect, detect, respond and recover.",
    },
    {
        "framework": "ISO 27001",
        "aspect_es": "Sistema de gestión, tratamiento de riesgos, controles Anexo A, evidencia y mejora continua.",
        "aspect_en": "Management system, risk treatment, Annex A controls, evidence and continual improvement.",
    },
    {
        "framework": "SOC 2",
        "aspect_es": "Seguridad, disponibilidad, confidencialidad, integridad de procesamiento y privacidad.",
        "aspect_en": "Security, availability, confidentiality, processing integrity and privacy.",
    },
    {
        "framework": "PCI DSS",
        "aspect_es": "Ambiente de datos de tarjeta, segmentación, cifrado, monitoreo, acceso y pruebas.",
        "aspect_en": "Cardholder-data environment, segmentation, encryption, monitoring, access and testing.",
    },
    {
        "framework": "GDPR / Privacidad",
        "aspect_es": "Datos personales, base legal, minimización, derechos, notificación y transferencias.",
        "aspect_en": "Personal data, lawful basis, minimization, rights, notification and transfers.",
    },
    {
        "framework": "MITRE ATT&CK / D3FEND",
        "aspect_es": "TTP observadas, detecciones, contramedidas, cobertura y pruebas de control.",
        "aspect_en": "Observed TTPs, detections, countermeasures, coverage and control testing.",
    },
    {
        "framework": "MITRE F3 v1.1",
        "aspect_es": "Conductas de fraude, abuso de identidad y pagos, suplantación, posicionamiento y monetización sustentadas por evidencia.",
        "aspect_en": "Evidence-backed fraud behavior, identity and payment abuse, impersonation, positioning and monetization.",
    },
]


def _report_scope(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    org = payload.get("organization", {})
    primary_domains = _clean_domain_list(org.get("primary_domains") or [])
    if not primary_domains:
        primary_domains = _clean_domain_list([item for item in org.get("crown_jewels", []) if _looks_like_domain(item)])
    comparison_domains = _clean_domain_list(org.get("comparison_domains") or [])
    source_statuses = payload.get("source_statuses", [])
    source_names = [_display_source_name(status.get("name", ""), language) for status in source_statuses if status.get("name")]
    if comparison_domains:
        comparison_basis = (
            "Comparación contra dominios benchmark declarados por el usuario; los conteos reflejan menciones/resultados recolectados, no una afirmación de compromiso."
            if language == "es"
            else "Comparison against benchmark domains declared by the user; counts reflect collected mentions/results, not a compromise claim."
        )
    else:
        comparison_basis = (
            "Sin dominios benchmark declarados; la comparación se limita a sector, país, frameworks, fuentes públicas y señales de contexto."
            if language == "es"
            else "No benchmark domains were declared; comparison is limited to sector, country, frameworks, public sources and context signals."
        )
    return {
        "primary_domains": primary_domains,
        "comparison_domains": comparison_domains,
        "comparison_basis": comparison_basis,
        "analysis_window": f"{org.get('analysis_window', payload.get('analysis_window', '30d'))} / {org.get('lookback_hours', payload.get('lookback_hours', 720))}h",
        "event_count": len(payload.get("raw_events", [])),
        "risk_count": len(payload.get("risk_findings", [])),
        "source_count": len(source_statuses),
        "source_names": source_names[:10],
        "data_basis": (
            "Fuentes abiertas, conectores autorizados, métricas internas del motor y evidencias exportables JSON/CSV."
            if language == "es"
            else "Open sources, authorized connectors, engine metrics and exportable JSON/CSV evidence."
        ),
    }


def _risk_digest(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    findings = payload.get("risk_findings", [])
    heat_rows = payload.get("metrics", {}).get("risk_heat_radar", {}).get("rows", [])
    top_finding = max(findings, key=lambda item: item.get("residual_risk", 0), default={})
    top_heat = max(heat_rows, key=lambda item: item.get("score", 0), default={})
    critical_count = sum(1 for item in findings if str(item.get("matrix_label", "")).lower() in {"critico", "crítico", "critical"} or item.get("matrix_score", 0) >= 12)
    healthy_sources = sum(1 for status in payload.get("source_statuses", []) if _status_is_healthy(status))
    total_sources = len(payload.get("source_statuses", []))
    forecast = _forecast_snapshot(payload.get("metrics", {}))
    max_residual = float(top_finding.get("residual_risk", 0) or 0) if top_finding else None
    return {
        "top_title": top_finding.get("title") or ("Sin hallazgos priorizados" if language == "es" else "No prioritized findings"),
        "max_residual": max_residual,
        "max_label": top_finding.get("matrix_label") or ("Sin datos" if language == "es" else "No data"),
        "top_heat": top_heat.get("name") or ("sin datos" if language == "es" else "no data"),
        "top_heat_score": float(top_heat.get("score", 0) or 0) if top_heat else None,
        "critical_count": critical_count,
        "source_health": f"{healthy_sources}/{total_sources}",
        "forecast": forecast,
    }


def _domain_comparison_rows(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    scope = payload.get("report_scope") or _report_scope(payload, language)
    rows = []
    for role, domains in (("own", scope.get("primary_domains", [])), ("benchmark", scope.get("comparison_domains", []))):
        for domain in domains:
            matches = [event for event in payload.get("raw_events", []) if _event_matches_domain(event, domain)]
            rows.append(
                {
                    "role": "Propio" if role == "own" and language == "es" else "Own" if role == "own" else "Benchmark",
                    "domain": domain,
                    "events": len(matches),
                    "sources": ", ".join(sorted({_display_source_name(event.get("source", ""), language) for event in matches if event.get("source")})[:4]) or ("sin evidencia directa" if language == "es" else "no direct evidence"),
                    "categories": ", ".join(
                        sorted(
                            {
                                _search_category_label(event.get("category"), language)
                                for event in matches
                                if event.get("category")
                            }
                        )[:5]
                    )
                    or ("sin categoría" if language == "es" else "no category"),
                }
            )
    return rows


def _decision_layers(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    scope = payload.get("report_scope") or _report_scope(payload, language)
    digest = payload.get("risk_digest") or _risk_digest(payload, language)
    processing = payload.get("processing_summary", {}) or {}
    unique = int(processing.get("unique_records", scope.get("event_count", 0)) or 0)
    direct = int(processing.get("direct_evidence", 0) or 0)
    validated = int(processing.get("validated_evidence", 0) or 0)
    contextual = sum(
        int(processing.get(key, 0) or 0)
        for key in ("contextual_evidence", "potential_evidence", "related_evidence")
    )
    incidents = int(processing.get("confirmed_incidents", 0) or 0)
    max_residual = digest.get("max_residual")
    if language == "en":
        return [
            {
                "area": "Exposure",
                "question": "How exposed is the organization?",
                "signal": f"{unique} unique records; {direct + validated} direct or validated",
                "decision": "Use the external posture index and asset inventory to prioritize verifiable exposure.",
                "evidence": f"Scope: {', '.join(scope.get('primary_domains', [])) or 'not declared'}; window {scope['analysis_window']}.",
            },
            {
                "area": "Risk",
                "question": "What risk is calculated?",
                "signal": (
                    f"Max residual risk {max_residual:.1f} ({digest['max_label']})"
                    if max_residual is not None
                    else "Residual risk not calculated: no validated risk finding"
                ),
                "decision": f"Review {digest['top_title']} first, subject to its linked evidence and assumptions.",
                "evidence": f"{scope['risk_count']} calculated risks; {incidents} confirmed incidents.",
            },
            {
                "area": "Evidence",
                "question": "What is direct or validated?",
                "signal": f"{direct} direct; {validated} technically validated",
                "decision": "Base remediation and escalation on these records and their complete URLs.",
                "evidence": "Validation state, confidence and relationship to scope are retained per record.",
            },
            {
                "area": "Context",
                "question": "What is only contextual or potential?",
                "signal": f"{contextual} contextual, potential or related records",
                "decision": "Use these records for orientation and follow-up, not as proof of compromise.",
                "evidence": "Missing data and unavailable connectors are limitations, not zero risk.",
            },
            {
                "area": "Decision",
                "question": "What requires an executive decision?",
                "signal": f"{digest['critical_count']} critical rows; source health {digest['source_health']}",
                "decision": "Assign validation, mitigation and monitoring priorities with owners and closure evidence.",
                "evidence": "The work plan lists options; it does not assign unnamed people or claim implementation.",
            },
            {
                "area": "Limits",
                "question": "What must not be concluded?",
                "signal": f"{incidents} confirmed incidents",
                "decision": "Do not infer compromise, compliance, control maturity, campaign attribution or attack probability without the required evidence.",
                "evidence": "Framework mappings are preventive unless direct or validated evidence activates them.",
            },
        ]
    return [
        {
            "area": "Exposición",
            "question": "¿Qué tan expuesta está la organización?",
            "signal": f"{unique} registros únicos; {direct + validated} directos o validados",
            "decision": "Usar el índice de postura externa y el inventario de activos para priorizar exposición verificable.",
            "evidence": f"Alcance: {', '.join(scope.get('primary_domains', [])) or 'no declarado'}; ventana {scope['analysis_window']}.",
        },
        {
            "area": "Riesgo",
            "question": "¿Qué riesgo está calculado?",
            "signal": (
                f"Riesgo residual máximo {max_residual:.1f} ({digest['max_label']})"
                if max_residual is not None
                else "Riesgo residual no calculado: no existe un hallazgo de riesgo validado"
            ),
            "decision": f"Revisar primero {digest['top_title']}, sujeto a su evidencia enlazada y supuestos.",
            "evidence": f"{scope['risk_count']} riesgos calculados; {incidents} incidentes confirmados.",
        },
        {
            "area": "Evidencia",
            "question": "¿Qué es evidencia directa o validada?",
            "signal": f"{direct} directa; {validated} validada técnicamente",
            "decision": "Basar remediación y escalamiento en estos registros y sus URL completas.",
            "evidence": "Cada registro conserva validación, confianza y relación con el alcance.",
        },
        {
            "area": "Contexto",
            "question": "¿Qué es solo contextual o potencial?",
            "signal": f"{contextual} registros contextuales, potenciales o relacionados",
            "decision": "Usarlos para orientación y seguimiento, no como prueba de compromiso.",
            "evidence": "La falta de datos o de conectores es una limitación, no riesgo cero.",
        },
        {
            "area": "Decisión",
            "question": "¿Qué requiere decisión ejecutiva?",
            "signal": f"{digest['critical_count']} filas críticas; salud de fuentes {digest['source_health']}",
            "decision": "Priorizar validación, mitigación y monitoreo con responsables y evidencia de cierre.",
            "evidence": "El plan presenta opciones; no asigna personas no declaradas ni afirma implementación.",
        },
        {
            "area": "Límites",
            "question": "¿Qué no debe concluirse?",
            "signal": f"{incidents} incidentes confirmados",
            "decision": "No inferir compromiso, cumplimiento, madurez, atribución de campaña ni probabilidad de ataque sin evidencia suficiente.",
            "evidence": "Los mapeos son preventivos salvo activación por evidencia directa o validada.",
        },
    ]


def _framework_summary(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    scores = []
    control_scores = payload.get("metrics", {}).get("control_scores", {})
    for name, value in sorted(control_scores.items(), key=lambda item: item[1]):
        scores.append(
            {
                "name": name,
                "score": float(value or 0),
                "score_label": f"{float(value or 0) * 100:.0f}%",
                "status": _control_status(float(value or 0), language),
            }
        )
    aspects = []
    for item in FRAMEWORK_ASPECTS:
        aspects.append(
            {
                "framework": item["framework"],
                "aspect": item["aspect_en"] if language == "en" else item["aspect_es"],
            }
        )
    axis_labels = {
        "governance": ("Gobierno", "Governance"),
        "identity": ("Identidad y acceso", "Identity and access"),
        "protect": ("Protección", "Protection"),
        "detect": ("Detección", "Detection"),
        "response": ("Respuesta y recuperación", "Response and recovery"),
        "privacy": ("Datos y privacidad", "Data and privacy"),
        "vulnerability": ("Vulnerabilidades y exposición", "Vulnerabilities and exposure"),
        "fraud": ("Fraude, suplantación y marca", "Fraud, impersonation and brand"),
        "ai": ("Riesgo de IA", "AI risk"),
        "adversary": ("Comportamiento adversario", "Adversary behavior"),
    }
    evidence_mapping = payload.get("metrics", {}).get("framework_mapping", {}) or {}
    mappings = []
    for row in evidence_mapping.get("mappings", []) or []:
        axis = str(row.get("axis") or "unmapped")
        evidence_rows = []
        for evidence in row.get("evidence", []) or []:
            evidence_rows.append(
                {
                    "evidence_id": evidence.get("evidence_id"),
                    "title": evidence.get("title") or evidence.get("url") or "Evidence",
                    "url": evidence.get("url"),
                    "status": evidence.get("evidence_status") or "raw",
                    "relationship": evidence.get("relationship") or "unassessed",
                    "domain": evidence.get("domain") or "",
                    "source": evidence.get("source") or "",
                }
            )
        mappings.append(
            {
                "framework": row.get("framework") or "Framework",
                "axis": axis_labels.get(axis, (axis, axis))[1 if language == "en" else 0],
                "record_count": int(row.get("record_count") or len(evidence_rows)),
                "validated_count": int(row.get("validated_count") or 0),
                "direct_count": int(row.get("direct_count") or 0),
                "related_count": int(row.get("related_count") or 0),
                "finding_count": int(row.get("finding_count") or 0),
                "controls": list(row.get("controls") or []),
                "domains": list(row.get("domains") or []),
                "evidence_ids": [
                    str(value)
                    for value in row.get("evidence_ids", [])
                    if value
                ],
                "validated_evidence_ids": [
                    str(value)
                    for value in row.get("validated_evidence_ids", [])
                    if value
                ],
                "direct_relationship_evidence_ids": [
                    str(value)
                    for value in row.get("direct_relationship_evidence_ids", [])
                    if value
                ],
                "evidence": evidence_rows,
            }
        )
    affected_axes: list[Dict[str, Any]] = []
    axes: dict[str, Dict[str, Any]] = {}
    for mapping in mappings:
        axis = str(mapping.get("axis") or "")
        group = axes.setdefault(
            axis,
            {
                "axis": axis,
                "frameworks": set(),
                "controls": {},
                "evidence": {},
                "evidence_ids": set(),
                "validated_evidence_ids": set(),
                "direct_relationship_evidence_ids": set(),
                "fallback_record_count": 0,
                "fallback_validated_count": 0,
                "fallback_direct_count": 0,
            },
        )
        framework = str(mapping.get("framework") or "")
        if framework:
            group["frameworks"].add(framework)
            group["controls"][framework] = list(mapping.get("controls") or [])
        group["evidence_ids"].update(mapping.get("evidence_ids") or [])
        group["validated_evidence_ids"].update(
            mapping.get("validated_evidence_ids") or []
        )
        group["direct_relationship_evidence_ids"].update(
            mapping.get("direct_relationship_evidence_ids") or []
        )
        group["fallback_record_count"] = max(
            group["fallback_record_count"],
            int(mapping.get("record_count") or 0),
        )
        group["fallback_validated_count"] = max(
            group["fallback_validated_count"],
            int(mapping.get("validated_count") or 0),
        )
        group["fallback_direct_count"] = max(
            group["fallback_direct_count"],
            int(mapping.get("direct_count") or 0),
        )
        for evidence in mapping.get("evidence", []) or []:
            evidence_id = str(evidence.get("evidence_id") or evidence.get("url") or "")
            if evidence_id:
                group["evidence"][evidence_id] = evidence
    for axis, group in sorted(axes.items()):
        evidence_rows = list(group["evidence"].values())
        record_count = (
            len(group["evidence_ids"])
            if group["evidence_ids"]
            else max(len(evidence_rows), group["fallback_record_count"])
        )
        validated_count = (
            len(group["validated_evidence_ids"])
            if group["evidence_ids"]
            else max(
                sum(
                    1
                    for evidence in evidence_rows
                    if str(evidence.get("status") or "").lower()
                    in {"validated", "confirmed"}
                ),
                group["fallback_validated_count"],
            )
        )
        direct_count = (
            len(group["direct_relationship_evidence_ids"])
            if group["evidence_ids"]
            else max(
                sum(
                    1
                    for evidence in evidence_rows
                    if str(evidence.get("relationship") or "").lower() == "direct"
                ),
                group["fallback_direct_count"],
            )
        )
        affected_axes.append(
            {
                "axis": axis,
                "frameworks": sorted(group["frameworks"]),
                "control_lines": [
                    {
                        "framework": framework,
                        "controls": controls,
                    }
                    for framework, controls in sorted(group["controls"].items())
                ],
                "record_count": record_count,
                "validated_count": validated_count,
                "direct_count": direct_count,
                "evidence": evidence_rows[:3],
            }
        )
    related_frameworks = sorted(
        {
            str(mapping.get("framework"))
            for mapping in mappings
            if mapping.get("framework")
        }
    )
    return {
        "scores": scores,
        "aspects": aspects,
        "mappings": mappings,
        "affected_axes": affected_axes,
        "related_frameworks": related_frameworks,
        "mapping_status": evidence_mapping.get("status") or "no_data",
        "mapped_records": int(evidence_mapping.get("record_count") or 0),
        "validated_records": int(evidence_mapping.get("validated_count") or 0),
        "mapped_cells": int(evidence_mapping.get("cell_count") or len(mappings)),
        "mapping_limitations": list(evidence_mapping.get("limitations") or []),
        "gap_summary": (
            (
                "Priorice las coberturas declaradas más bajas y vincule cada acción a evidencia, responsable y fecha de cierre."
                if language == "es"
                else "Prioritize the lowest declared coverage and link each action to evidence, owner and closure date."
            )
            if scores
            else (
                "No se declararon controles internos; el mapeo es preventivo y no representa cumplimiento ni madurez."
                if language == "es"
                else "No internal controls were declared; mapping is preventive and does not represent compliance or maturity."
            )
        ),
    }


def _f3_summary(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    profile = payload.get("metrics", {}).get("f3", {}) or {}
    technique_rows = []
    for technique in profile.get("techniques", []) or []:
        evidence_rows = [
            {
                "evidence_id": evidence.get("evidence_id") or "",
                "title": evidence.get("title") or "",
                "url": evidence.get("url") or "",
                "status": evidence.get("status") or "raw",
            }
            for evidence in technique.get("evidence", []) or []
        ]
        technique_rows.append(
            {
                "id": technique.get("id") or "",
                "name": technique.get("official_name") or "",
                "tactics": list(technique.get("tactics") or []),
                "record_count": int(technique.get("record_count") or len(evidence_rows)),
                "validated_count": int(technique.get("validated_count") or 0),
                "mapping_status": technique.get("mapping_status") or "evidence_supported_candidate",
                "evidence": evidence_rows,
            }
        )
    active_tactics = [
        tactic
        for tactic in profile.get("tactics", []) or []
        if int(tactic.get("record_count") or 0) > 0
    ]
    return {
        "framework": profile.get("framework") or "MITRE Fight Fraud Framework",
        "version": profile.get("framework_version") or "1.1",
        "source_url": profile.get("source_url") or "https://ctid.mitre.org/fraud",
        "status": profile.get("status") or "no_data",
        "mapped_record_count": int(profile.get("mapped_record_count") or 0),
        "mapped_technique_count": int(profile.get("mapped_technique_count") or len(technique_rows)),
        "active_tactics": active_tactics,
        "techniques": technique_rows,
        "limitations": list(profile.get("limitations") or []),
        "interpretation": (
            (
                "La corrida contiene registros asegurados compatibles con técnicas F3. "
                "El mapeo orienta validación y controles; no confirma fraude ni incidente."
            )
            if language == "es"
            else (
                "The run contains assured records compatible with F3 techniques. "
                "The mapping guides validation and controls; it does not confirm fraud or an incident."
            )
        ),
    }


def _scenario_cards(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    metrics = payload.get("metrics", {})
    heat_rows = sorted(metrics.get("risk_heat_radar", {}).get("rows", []), key=lambda item: item.get("score", 0), reverse=True)
    forecast = _forecast_snapshot(metrics)
    cards = []
    for row in heat_rows[:5]:
        name = row.get("name", "sin datos" if language == "es" else "no data")
        cards.append(
            {
                "title": name,
                "modality": _scenario_modality(name, language),
                "heat": row.get("heat", "medium"),
                "score_label": f"{float(row.get('score', 0) or 0) * 100:.0f}%",
                "evidence": row.get("evidence_count", 0),
                "signals": [_clean_evidence_text(str(signal), language) for signal in (row.get("signals", []) or [])[:3]],
                "trigger": row.get("decision") or ("Revisar señales y asignar owner." if language == "es" else "Review signals and assign an owner."),
                "forecast": f"{forecast.get('horizon', 'n/a')}d base {forecast.get('base_label', 'n/a')} / sensibilidad superior {forecast.get('upper_label', 'n/a')}",
                "confidence": _scenario_confidence(row, language),
            }
        )
    if not cards:
        for finding in payload.get("top_findings", [])[:3]:
            cards.append(
                {
                    "title": finding.get("category", "risk"),
                    "modality": finding.get("title", ""),
                    "heat": "high" if finding.get("residual_risk", 0) >= 20 else "medium",
                    "score_label": f"{float(finding.get('residual_risk', 0) or 0):.1f}",
                    "evidence": len(finding.get("evidence", [])),
                    "signals": finding.get("evidence", [])[:3],
                    "trigger": "; ".join(finding.get("recommendations", [])[:2]),
                    "forecast": f"{forecast.get('horizon', 'n/a')}d base {forecast.get('base_label', 'n/a')}",
                    "confidence": "Media" if language == "es" else "Medium",
                }
            )
    return cards


def _scenario_library_digest(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    library = _local_scenario_library()
    scenarios = library.get("scenarios", []) or []
    matches = _build_report_scenario_matches(scenarios, payload, language)
    framework_counts = _framework_coverage_from_matches(matches)
    math_model = library.get("math_model", {}) or {}
    model_text = math_model.get(language) or math_model.get("es") or math_model.get("en") or ""
    formula = math_model.get("formula") or "ResidualRisk=100*sigmoid(z)*Impact*(1-ControlEffectiveness)"
    return {
        "reference_template_count": sum(1 for item in scenarios if item.get("status") == "preventive_template"),
        "defined_count": 0,
        "executable_count": 0,
        "tested_count": 0,
        "active_count": len(matches),
        "sources": library.get("sources", []) or [],
        "math_model": model_text,
        "formula": formula,
        "framework_counts": framework_counts,
        "matches": matches[:12],
        "status": (
            "Las plantillas son referencias preventivas. Solo se muestran posibilidades soportadas cuando la evidencia de la corrida satisface criterios explícitos."
            if language == "es"
            else "Templates are preventive references. Supported possibilities appear only when run evidence meets explicit criteria."
        ),
    }


def _domain_reading_rows(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    scope = payload.get("report_scope") or _report_scope(payload, language)
    domains = scope.get("primary_domains") or []
    rows = []
    scenario_matches = payload.get("scenario_library", {}).get("matches", [])
    for domain in domains:
        events = [event for event in payload.get("raw_events", []) if _event_matches_domain(event, domain)]
        findings = [finding for finding in payload.get("risk_findings", []) if _finding_matches_domain(finding, domain)]
        top_finding = max(findings, key=lambda item: item.get("residual_risk", 0), default={})
        domain_matches = [match for match in scenario_matches if domain in match.get("domains", [])]
        top_event = max(events, key=lambda item: item.get("severity", 0), default={})
        rows.append(
            {
                "domain": domain,
                "events": len(events),
                "scenarios": len(domain_matches),
                "risk": f"{float(top_finding.get('residual_risk', 0) or 0):.1f}" if top_finding else ("sin evidencia directa" if language == "es" else "no direct evidence"),
                "signal": _clean_evidence_text(top_event.get("title")) or ("sin señal directa" if language == "es" else "no direct signal"),
                "sources": ", ".join(sorted({_display_source_name(event.get("source", ""), language) for event in events if event.get("source")})[:4]) or ("sin fuente directa" if language == "es" else "no direct source"),
            }
        )
    if not rows:
        digest = _risk_digest(payload, language)
        max_residual = digest.get("max_residual")
        rows.append(
            {
                "domain": "grupo general" if language == "es" else "overall group",
                "events": len(payload.get("raw_events", [])),
                "scenarios": len(scenario_matches),
                "risk": (
                    f"{max_residual:.1f}"
                    if max_residual is not None
                    else ("sin cálculo" if language == "es" else "not calculated")
                ),
                "signal": _clean_evidence_text(digest.get("top_title")),
                "sources": ", ".join(scope.get("source_names", [])[:4]) or ("sin fuentes" if language == "es" else "no sources"),
            }
        )
    return rows


def _attack_surface_inventory(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    scope = payload.get("report_scope") or _report_scope(payload, language)
    domains = scope.get("primary_domains") or []
    rows: list[Dict[str, Any]] = []
    events = payload.get("scope_events") or _scope_filtered_events(payload, language)
    for domain in domains:
        domain_events = [event for event in events if _event_matches_domain(event, domain)]
        subdomains = []
        web_assets = []
        controls = []
        for event in domain_events:
            category = str(event.get("category") or "")
            tags = event.get("tags") or []
            host = _tag_value(tags, "host") or _tag_value(tags, "asset") or _host_from_url(str(event.get("evidence_url") or ""))
            if category == "attack_surface_dns":
                subdomains.append(
                    {
                        "host": host or _clean_evidence_text(event.get("title", ""), language),
                        "severity": _event_severity_label(event, language),
                        "status": "Inventario DNS; validar servicio activo" if language == "es" else "DNS inventory; validate active service",
                        "note": _surface_note(event, language),
                    }
                )
            elif category == "attack_surface_web":
                web_assets.append(
                    {
                        "url": _public_evidence_url(str(event.get("evidence_url") or "")),
                        "host": host,
                        "severity": _event_severity_label(event, language),
                        "title": _clean_evidence_text(event.get("title", ""), language),
                    }
                )
            elif category == "attack_surface":
                controls.append(
                    {
                        "asset": host or _tag_value(tags, "asset") or domain,
                        "finding": _clean_evidence_text(event.get("title", ""), language),
                        "severity": _event_severity_label(event, language),
                        "validation": _event_validation_state(event, language),
                        "url": _public_evidence_url(str(event.get("evidence_url") or "")),
                    }
                )
        rows.append(
            {
                "domain": domain,
                "subdomain_count": len(subdomains),
                "web_asset_count": len(web_assets),
                "control_count": len(controls),
                "subdomains": sorted(subdomains, key=lambda item: item["host"])[:80],
                "web_assets": sorted(web_assets, key=lambda item: item["url"] or item["host"])[:60],
                "controls": sorted(controls, key=lambda item: item["severity"], reverse=True)[:40],
            }
        )
    return {
        "summary": (
            "Inventario técnico de dominios, subdominios, activos web y controles observados. Un subdominio DNS-only no se trata como vulnerabilidad hasta confirmar servicio, exposición sensible o control débil."
            if language == "es"
            else "Technical inventory of domains, subdomains, web assets and observed controls. A DNS-only subdomain is not treated as a vulnerability until an active service, sensitive exposure or weak control is confirmed."
        ),
        "rows": rows,
    }


def _executive_alert_rows(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    alerts = []
    for finding in payload.get("top_findings", [])[:8]:
        evidence = [str(item) for item in finding.get("evidence", []) or []]
        urls = [_public_evidence_url(item) for item in evidence if item.startswith("http")]
        rationale = next((item for item in evidence if "Base de criticidad" in item or "Criticality basis" in item), "")
        residual = float(finding.get("residual_risk", 0) or 0)
        alerts.append(
            {
                "title": finding.get("title", ""),
                "priority": _priority_from_score(residual, language),
                "residual": f"{residual:.1f}",
                "validation": _finding_validation_label(finding, urls, rationale, language),
                "basis": rationale or _fallback_alert_basis(finding, language),
                "urls": urls[:3],
            }
        )
    return alerts


def _evidence_preview_gallery(events: list[Dict[str, Any]], language: str) -> list[Dict[str, Any]]:
    gallery = []
    for event in events:
        raw_url = str(event.get("evidence_url") or "")
        for capture in event.get("captures", []) or []:
            if not isinstance(capture, dict):
                continue
            preview = _capture_preview_url(capture)
            if not preview:
                continue
            gallery.append(
                {
                    "title": _clean_evidence_text(event.get("title", ""), language),
                    "url": _public_evidence_url(raw_url),
                    "preview_url": preview,
                    "relationship": _evidence_relationship(event, language),
                    "validation": _evidence_validation(event, raw_url, _public_evidence_url(raw_url), language),
                    "capture_timestamp": capture.get("capture_timestamp") or capture.get("captureTimestamp"),
                    "screenshot_id": capture.get("screenshot_id") or capture.get("screenshotId"),
                    "run_id": capture.get("run_id") or capture.get("runId"),
                    "evidence_id": capture.get("evidence_id") or capture.get("evidenceId"),
                    "source_id": capture.get("source_id") or capture.get("sourceId"),
                    "image_hash": capture.get("image_hash") or capture.get("imageHash"),
                    "image_size_bytes": capture.get("image_size_bytes") or capture.get("imageSizeBytes"),
                    "capture_type": capture.get("capture_type") or capture.get("captureType"),
                    "dimensions": capture.get("dimensions") or {},
                    "browser_engine": capture.get("browser_engine") or capture.get("browserEngine"),
                    "browser_engine_version": capture.get("browser_engine_version") or capture.get("browserEngineVersion"),
                    "validation_status": capture.get("validation_status") or capture.get("validationStatus"),
                    "redaction_applied": bool(capture.get("redaction_applied") or capture.get("redactionApplied")),
                }
            )
            if len(gallery) >= 12:
                return gallery
    return gallery


def _disinformation_summary(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    framework = _local_disarm_framework()
    intelligence = (payload.get("metrics", {}) or {}).get("narrative_intelligence", {}) or {}
    claims = intelligence.get("claims", []) or []
    candidate_rows = [
        {
            "source": claim.get("source") or "N/D",
            "category": claim.get("contentType") or "unverified_claim",
            "title": claim.get("claimText") or claim.get("title") or "N/D",
            "tags": f"{claim.get('truthStatus', 'unverified')} · {claim.get('coordinationStatus', 'insufficient_data')} · {claim.get('status', 'under_review')}",
            "evidence_url": claim.get("url"),
            "confidence": claim.get("confidence"),
            "review_reason": claim.get("reviewReason"),
        }
        for claim in claims
    ]
    active_rows = [row for row, claim in zip(candidate_rows, claims) if claim.get("disarmEligible")]
    activated = bool(active_rows)
    tactic_counts = _active_disarm_tactic_counts(active_rows, language)
    active_count = len(active_rows)
    if active_count:
        risk_statement = (
            f"Hay {active_count} señales públicas compatibles con narrativa, influencia o confianza digital; revisar fuente, canal, alcance y amplificación antes de activar respuesta."
            if language == "es"
            else f"{active_count} public signals are compatible with narrative, influence or digital-trust risk; validate source, channel, reach and amplification before response."
        )
    else:
        risk_statement = (
            "No se activaron señales de desinformación en la evidencia de esta corrida. El framework queda disponible como referencia preventiva."
            if language == "es"
            else "No disinformation signals were activated by this run evidence. The framework remains available as a preventive reference."
        )
    return {
        "source": framework.get("source") or "DISARM Foundation",
        "source_url": framework.get("source_url"),
        "tactics_count": len(framework.get("tactics", []) or []),
        "techniques_count": len(framework.get("techniques", []) or []),
        "tactic_counts": tactic_counts,
        "active_evidence": active_count,
        "candidate_evidence": len(candidate_rows),
        "review_evidence": sum(1 for claim in claims if claim.get("status") in {"candidate", "under_review"}),
        "supported_evidence": sum(1 for claim in claims if claim.get("status") in {"supported", "validated", "confirmed"}),
        "activation_status": "activated" if activated else "preventive_reference",
        "active_rows": active_rows[:10],
        "all_rows": candidate_rows[:30],
        "risk_statement": risk_statement,
    }


def _active_disarm_tactic_counts(rows: list[Dict[str, Any]], language: str) -> list[Dict[str, Any]]:
    labels = {
        "narrative": "Narrative trust pressure" if language == "en" else "Presion sobre confianza narrativa",
        "amplification": "Coordinated amplification" if language == "en" else "Amplificacion coordinada",
        "manipulation": "Influence manipulation" if language == "en" else "Manipulacion de influencia",
        "reputation": "Brand deception signal" if language == "en" else "Senal de engano de marca",
    }
    counts = {key: 0 for key in labels}
    for row in rows:
        text = _normalize(" ".join([str(row.get("title", "")), str(row.get("tags", "")), str(row.get("category", ""))]))
        if _text_has_any(text, ("desinform", "disinform", "misinform", "fake", "rumor", "narrative", "narrativa")):
            counts["narrative"] += 1
        if _text_has_any(text, ("bot", "coordin", "viral", "meme", "amplif")):
            counts["amplification"] += 1
        if _text_has_any(text, ("propaganda", "influenc", "manipul")):
            counts["manipulation"] += 1
        if _text_has_any(text, ("farsa", "fraud", "scam", "phish", "suplant", "imperson")):
            counts["reputation"] += 1
    return [{"name": labels[key], "value": value} for key, value in counts.items() if value > 0][:6]


def _intelligence_modules(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    metrics = payload.get("metrics", {})
    source_coverage = metrics.get("source_coverage", {}) or {}
    scope_events = payload.get("scope_events") or _scope_filtered_events(payload, language)
    osint_records = _source_record_count(source_coverage, "osint")
    socmint_records = _source_record_count(source_coverage, "socmint")
    socmint_related = int((source_coverage.get("socmint", {}) or {}).get("related_public_records", 0) or 0)
    darkweb_records = _source_record_count(source_coverage, "darkweb")
    disinfo = payload.get("disinformation_summary") or _disinformation_summary(payload, language)
    scenario_library = payload.get("scenario_library") or _scenario_library_digest(payload, language)
    surface_count = _count_events_by_keywords(
        scope_events,
        ("whois", "rdap", "dns", "tls", "ssl", "certificate", "certificado", "dmarc", "spf", "dkim", "easm", "surface", "subdomain", "dominio"),
    )
    brand_fraud_count = _count_events_by_keywords(
        scope_events,
        ("fraud", "fraude", "phishing", "smishing", "suplant", "imperson", "brand", "marca", "bec", "payment", "pago"),
    )
    framework_count = len((payload.get("framework_summary") or _framework_summary(payload, language)).get("scores", []))
    labels = {
        "active": "Con evidencia" if language == "es" else "Evidence found",
        "quiet": "Sin evidencia activa" if language == "es" else "No active evidence",
        "reference": "Referencia de modelo" if language == "es" else "Model reference",
    }

    def card(title: str, value: int | float | str, unit: str, decision: str, detail: str, tone: str = "active") -> Dict[str, Any]:
        return {
            "title": title,
            "value": value,
            "unit": unit,
            "status": labels[tone],
            "decision": decision,
            "detail": detail,
            "tone": tone,
        }

    if language == "en":
        return [
            card("OSINT", osint_records, "records", "Use collected URLs, news, advisories and public indexes as the first evidence layer.", "Open-source collection is passive and traceable.", "active" if osint_records else "quiet"),
            card("SOCMINT", socmint_records + socmint_related, "public signals", "Escalate only aggregated, authorized public mentions tied to fraud, brand or trust.", "No private social collection is assumed.", "active" if socmint_records + socmint_related else "quiet"),
            card("Dark Web", darkweb_records, "records", "Treat as authorized metadata; rotate or hunt only when evidence is redacted, attributable and in scope.", "No direct private-market assertion is made.", "active" if darkweb_records else "quiet"),
            card("Disinformation", disinfo["active_evidence"], "signals", "Separate narrative, channel, audience and amplification before response.", f"DISARM reference loaded: {disinfo['techniques_count']} techniques.", "active" if disinfo["active_evidence"] else "quiet"),
            card("Attack Surface", surface_count, "signals", "Use WHOIS/DNS/TLS/email-control evidence to prioritize verifiable closure.", "Domain evidence is kept separate from benchmark domains.", "active" if surface_count else "quiet"),
            card("Brand and Fraud", f"{metrics.get('fraud_pressure', 0):.2f}", "pressure", "Connect phishing, impersonation, complaints and transaction monitoring.", f"{brand_fraud_count} brand/fraud-related signals.", "active" if brand_fraud_count or metrics.get("fraud_pressure", 0) else "quiet"),
            card("Framework Mapping", framework_count, "frameworks", "Map actions to NIST, ISO, SOC 2, PCI, GDPR, ATT&CK and D3FEND evidence.", "Only declared coverage can become an auditable remediation item; this is not a compliance assessment.", "reference"),
            card("Supported possibilities", scenario_library["active_count"], "current run", "Use supported possibilities as decision options, not as confirmed incidents.", "Only evidence-supported scenarios from the current run are presented.", "active" if scenario_library["active_count"] else "reference"),
        ]
    return [
        card("OSINT", osint_records, "registros", "Usar URLs, noticias, advisories e índices públicos como primera capa de evidencia.", "Recolección abierta, pasiva y trazable.", "active" if osint_records else "quiet"),
        card("SOCMINT", socmint_records + socmint_related, "señales públicas", "Escalar solo menciones públicas agregadas y autorizadas ligadas a fraude, marca o confianza.", "No se asume recolección social privada.", "active" if socmint_records + socmint_related else "quiet"),
        card("Dark Web", darkweb_records, "registros", "Tratar como metadatos autorizados; rotar o hacer hunting solo con evidencia redacted, atribuible y en alcance.", "No afirma presencia en mercados privados.", "active" if darkweb_records else "quiet"),
        card("Desinformación", disinfo["active_evidence"], "señales", "Separar narrativa, canal, audiencia y amplificación antes de responder.", f"Referencia DISARM cargada: {disinfo['techniques_count']} técnicas.", "active" if disinfo["active_evidence"] else "quiet"),
        card("Superficie de ataque", surface_count, "señales", "Usar WHOIS/DNS/TLS/correo para priorizar cierres verificables.", "La evidencia propia se separa de dominios benchmark.", "active" if surface_count else "quiet"),
        card("Marca y fraude", f"{metrics.get('fraud_pressure', 0):.2f}", "presión", "Conectar phishing, suplantación, reclamos y monitoreo transaccional.", f"{brand_fraud_count} señales asociadas a marca/fraude.", "active" if brand_fraud_count or metrics.get("fraud_pressure", 0) else "quiet"),
        card("Mapeo de frameworks", framework_count, "marcos", "Mapear acciones a NIST, ISO, SOC 2, PCI, GDPR, ATT&CK y D3FEND.", "Solo la cobertura declarada puede pasar a remediación auditable; no es una evaluación de cumplimiento.", "reference"),
        card("Posibilidades soportadas", scenario_library["active_count"], "corrida actual", "Usar posibilidades soportadas como opciones de decisión, no como incidentes confirmados.", "Solo se presentan escenarios de la corrida actual respaldados por evidencia.", "active" if scenario_library["active_count"] else "reference"),
    ]


def _model_summary(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    metrics = payload.get("metrics", {})
    registry = load_methodology_registry()
    selected_ids = {
        "risk.contextual_likelihood",
        "risk.business_impact",
        "risk.control_effectiveness",
        "risk.residual",
        "strategy.pestel_porter_pressure",
    }
    brief_models = []
    for method in registry.methods:
        if method.status != "active" or method.methodId not in selected_ids:
            continue
        localized_name = method.name.en if language == "en" else method.name.es
        localized_interpretation = method.interpretation.en if language == "en" else method.interpretation.es
        brief_models.append(
            {
                "method_id": method.methodId,
                "version": method.version,
                "title": localized_name,
                "summary": localized_interpretation,
            }
        )
    return {
        "purpose": metrics.get("risk_methodology", {}).get("purpose", "Risk model" if language == "en" else "Modelo de riesgo"),
        "registry_version": registry.registryVersion,
        "brief_models": brief_models,
        # Formulas remain available only through the admin methodology registry, not reports.
        "formulas": [],
        "assumptions": [
            "No unavailable source is filled with invented evidence." if language == "en" else "Las fuentes no disponibles no se rellenan con evidencia inventada.",
            "Benchmark domains are context, not proof of compromise." if language == "en" else "Los dominios comparativos son contexto, no prueba de compromiso.",
            "Findings preserve evidence references in the technical report and exports." if language == "en" else "Los hallazgos conservan referencias de evidencia en el informe técnico y los exportes.",
        ],
    }


def _recommendation_catalog(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    areas = {
        "strategic": {"label": "Estratégica" if language == "es" else "Strategic", "items": []},
        "risk": {"label": "Riesgos" if language == "es" else "Risk", "items": []},
        "compliance": {"label": "Cumplimiento" if language == "es" else "Compliance", "items": []},
        "technical": {"label": "Técnica" if language == "es" else "Technical", "items": []},
        "prediction": {"label": "Índice de presión de señales" if language == "es" else "Signal pressure index", "items": []},
    }
    area_by_framework = {
        "attack": "technical",
        "d3fend": "technical",
        "atlas": "risk",
        "disarm": "strategic",
        "f3": "risk",
    }
    seen: set[tuple[str, str]] = set()
    for match in (payload.get("scenario_library", {}).get("matches", []) or [])[:12]:
        scenario_id = str(match.get("id") or "").strip()
        action = str(match.get("recommendation") or match.get("decision") or "").strip()
        evidence_count = int(match.get("evidence_count", 0) or 0)
        if not scenario_id or not action or evidence_count <= 0:
            continue
        key = (scenario_id, action)
        if key in seen:
            continue
        framework = str(match.get("primary_framework") or "").lower()
        area_key = area_by_framework.get(framework, "strategic")
        confidence = float(match.get("confidence", 0) or 0)
        score = min(25.0, confidence / 5.0 + min(evidence_count, 5))
        basis = (
            f"Sustentada por {scenario_id}, {evidence_count} evidencias relacionadas y confianza {confidence:.0f}%."
            if language == "es"
            else f"Supported by {scenario_id}, {evidence_count} related evidence records and {confidence:.0f}% confidence."
        )
        areas[area_key]["items"].append(
            {
                "title": match.get("title") or scenario_id,
                "action": action,
                "owner": " · ".join(_scenario_action_owners(match, language)),
                "basis": basis,
                "priority": _work_plan_priority_label(score, language),
                "tone": _work_plan_tone(score),
                "scenario_id": scenario_id,
            }
        )
        seen.add(key)
    for area in areas.values():
        area["items"] = area["items"][:6]
    return areas


def _append_library_recommendation(areas: Dict[str, Any], item: Dict[str, Any], matches: list[str], language: str, seen: set) -> None:
    key = (item["area"], item["title_en"])
    if key in seen or item["area"] not in areas:
        return
    basis = (
        f"Seleccionada por señales: {', '.join(matches[:4])}." if matches and language == "es" else
        f"Selected by signals: {', '.join(matches[:4])}." if matches else
        "Opción preventiva del catálogo interno; validar pertinencia con el owner." if language == "es" else
        "Preventive option from the internal catalog; validate relevance with the owner."
    )
    areas[item["area"]]["items"].append(
        {
            "title": item["title_en"] if language == "en" else item["title_es"],
            "action": item["action_en"] if language == "en" else item["action_es"],
            "owner": item["owner_en"] if language == "en" else item["owner_es"],
            "basis": basis,
            "priority": ("Alta" if language == "es" else "High") if matches else ("Media" if language == "es" else "Medium"),
        }
    )
    seen.add(key)


@lru_cache(maxsize=1)
def _local_scenario_library() -> Dict[str, Any]:
    path = PROJECT_ROOT / "data" / "scenarios" / "cyber_scenario_library.json"
    if not path.exists():
        return {"scenario_count": 0, "sources": [], "math_model": {}, "scenarios": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"scenario_count": 0, "sources": [], "math_model": {}, "scenarios": []}
    payload.setdefault("scenarios", [])
    payload.setdefault("scenario_count", len(payload["scenarios"]))
    payload.setdefault("sources", [])
    payload.setdefault("math_model", {})
    return payload


@lru_cache(maxsize=1)
def _local_disarm_framework() -> Dict[str, Any]:
    path = PROJECT_ROOT / "data" / "frameworks" / "disarm_observable.json"
    if not path.exists():
        return {"source": "DISARM Foundation", "source_url": None, "tactics": [], "techniques": [], "tactic_counts": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"source": "DISARM Foundation", "source_url": None, "tactics": [], "techniques": [], "tactic_counts": []}
    tactic_counts: Dict[str, int] = {}
    for technique in payload.get("techniques", []) or []:
        tactic = technique.get("tactic") or "Unmapped"
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    payload["tactic_counts"] = [{"name": name, "value": value} for name, value in sorted(tactic_counts.items(), key=lambda item: item[1], reverse=True)]
    return payload


def _build_report_scenario_matches(scenarios: list[Dict[str, Any]], payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    evidence = _scenario_evidence_signals(payload)
    if not scenarios or not evidence:
        return []
    scope = payload.get("report_scope") or _report_scope(payload, language)
    domains = scope.get("primary_domains", [])
    sector = _normalize(payload.get("organization", {}).get("sector", ""))
    matches = []
    for scenario in scenarios:
        match = _score_report_scenario(scenario, evidence, domains, sector, language)
        if match:
            matches.append(match)
    matches.sort(key=lambda item: item.get("score", 0), reverse=True)
    seen = set()
    unique = []
    for match in matches:
        scenario = match.get("scenario", {})
        frameworks = scenario.get("frameworks", {}) or {}
        key = (
            (frameworks.get("attack", {}) or {}).get("id"),
            (frameworks.get("disarm", {}) or {}).get("id"),
            (frameworks.get("d3fend", {}) or {}).get("id"),
            (frameworks.get("atlas", {}) or {}).get("id"),
            (frameworks.get("f3", {}) or {}).get("id"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(_scenario_match_view(match, language))
        if len(unique) >= 60:
            break
    return unique


def _scenario_evidence_signals(payload: Dict[str, Any]) -> list[Dict[str, Any]]:
    language = _report_language(payload)
    domains = (payload.get("report_scope") or _report_scope(payload, language)).get("primary_domains", [])
    signals = []
    events = payload.get("scope_events") or _scope_filtered_events(payload, language)
    for event in events[:160]:
        evidence_status = str(event.get("evidence_status", "raw"))
        if evidence_status not in {"direct", "validated", "confirmed"}:
            continue
        text = _event_text(event)
        tags = {str(tag).lower() for tag in event.get("tags", []) or []}
        validation = event.get("technical_validation", {}) or {}
        f3_ids = {
            str(item.get("id", "")).upper()
            for item in validation.get("f3_mappings", []) or []
            if isinstance(item, dict) and item.get("id")
        }
        signals.append(
            {
                "id": event.get("canonical_id") or event.get("id"),
                "title": _clean_evidence_text(event.get("title", "")),
                "category": event.get("category", ""),
                "source": _display_source_name(event.get("source", ""), language),
                "source_refs": event.get("source_refs", []) or [event.get("source", "")],
                "technique": event.get("technique") or _extract_technique(text),
                "domains": _domains_in_text(text, domains),
                "tokens": _tokenize(text),
                "evidence_status": evidence_status,
                "confidence_score": float(event.get("confidence_score", event.get("confidence", 0)) or 0),
                "attack_mapping_status": event.get("attack_mapping_status", "potentially_relevant_technique"),
                "disarm_signal": bool(
                    tags.intersection({"disarm_signal", "narrative_manipulation", "coordinated_amplification", "influence_operation"})
                    or event.get("category") in {"disinformation", "narrative_manipulation"}
                ),
                "atlas_signal": bool(
                    tags.intersection({"atlas_signal", "ai_asset", "ai_model", "ai_agent", "prompt_injection", "model_supply_chain"})
                    or event.get("category") in {"ai_security", "ai_model_exposure"}
                ),
                "f3_signal": bool(f3_ids),
                "framework_ids": _scenario_framework_ids(text, tags).union(f3_ids),
                "tags": tags,
            }
        )
    return [signal for signal in signals if signal["tokens"]][:180]


def _score_report_scenario(
    scenario: Dict[str, Any],
    evidence: list[Dict[str, Any]],
    domains: list[str],
    sector: str,
    language: str,
) -> Dict[str, Any] | None:
    frameworks = scenario.get("frameworks", {}) or {}
    attack = frameworks.get("attack", {}) or {}
    disarm = frameworks.get("disarm", {}) or {}
    atlas = frameworks.get("atlas", {}) or {}
    f3 = frameworks.get("f3", {}) or {}
    reasons = set()
    matched_domains = set()
    attack_matches = [
        signal
        for signal in evidence
        if attack.get("id")
        and signal.get("technique") == attack.get("id")
        and signal.get("attack_mapping_status") == "observed_adversary_behavior"
    ]
    disarm_matches = [
        signal
        for signal in evidence
        if disarm.get("id")
        and signal.get("disarm_signal")
        and str(disarm.get("id")).upper() in signal.get("framework_ids", set())
    ]
    atlas_matches = [
        signal
        for signal in evidence
        if atlas.get("id")
        and signal.get("atlas_signal")
        and str(atlas.get("id")).upper() in signal.get("framework_ids", set())
    ]
    f3_matches = [
        signal
        for signal in evidence
        if f3.get("id")
        and signal.get("f3_signal")
        and str(f3.get("id")).upper() in signal.get("framework_ids", set())
    ]

    primary_framework = ""
    matched = []
    if f3_matches:
        primary_framework = "f3"
        matched = f3_matches
        reasons.add(f"F3 {f3.get('id')}")
    elif attack_matches:
        primary_framework = "attack"
        matched = attack_matches
        reasons.add(f"ATT&CK {attack.get('id')}")
    elif len(disarm_matches) >= 2 and len(
        {
            source
            for signal in disarm_matches
            for source in (signal.get("source_refs", []) or [signal.get("source")])
            if source
        }
    ) >= 2:
        primary_framework = "disarm"
        matched = disarm_matches
        reasons.add(f"DISARM {disarm.get('id')}")
    elif atlas_matches and any(float(signal.get("confidence_score", 0)) >= 0.65 for signal in atlas_matches):
        primary_framework = "atlas"
        matched = atlas_matches
        reasons.add(f"ATLAS {atlas.get('id')}")
    if not matched:
        return None
    for signal in matched:
        for domain in signal.get("domains", []):
            matched_domains.add(domain)
    if not matched_domains:
        if len(domains) == 1:
            matched_domains.add(domains[0])
        else:
            matched_domains.add("__group__")
    evidence_count = len(matched)
    mean_confidence = sum(float(signal.get("confidence_score", 0)) for signal in matched) / evidence_count
    score = evidence_count * 5 + mean_confidence * 100
    confidence = min(95, round(mean_confidence * 100))
    fallback = (
        f"F3 {f3.get('id')}"
        if f3.get("id")
        else f"ATT&CK {attack.get('id')}"
        if attack.get("id")
        else str(disarm.get("tactic", "DISARM"))
    )
    return {
        "scenario": scenario,
        "score": score,
        "confidence": confidence,
        "reasons": list(reasons)[:4] or [fallback],
        "domains": sorted(matched_domains),
        "evidence_count": evidence_count,
        "primary_framework": primary_framework,
        "status": "evidence_supported",
        "evidence_ids": [signal.get("id") for signal in matched[:12]],
    }


def _scenario_framework_ids(text: str, tags: set[str]) -> set[str]:
    identifiers: set[str] = set()
    for tag in tags:
        match = re.match(
            r"^(?:atlas|disarm|f3|framework_id):\s*(AML\.TA\d{4}|T\d{4}(?:\.\d{3})?|F\d{4}(?:\.\d{3})?|FA\d{4})$",
            tag,
            re.IGNORECASE,
        )
        if match:
            identifiers.add(match.group(1).upper())
    identifiers.update(match.group(0).upper() for match in re.finditer(r"\bAML\.TA\d{4}\b", text, re.IGNORECASE))
    identifiers.update(match.group(1).upper() for match in re.finditer(r"\bDISARM\s*[:#-]?\s*(T\d{4}(?:\.\d{3})?)\b", text, re.IGNORECASE))
    identifiers.update(match.group(1).upper() for match in re.finditer(r"\bF3\s*[:#-]?\s*(F\d{4}(?:\.\d{3})?|FA\d{4}|T\d{4}(?:\.\d{3})?)\b", text, re.IGNORECASE))
    return identifiers


def _scenario_match_view(match: Dict[str, Any], language: str) -> Dict[str, Any]:
    scenario = match.get("scenario", {})
    lens = _scenario_decision_lens(match, language)
    frameworks = scenario.get("frameworks", {}) or {}
    recommendation = scenario.get("recommendation_en" if language == "en" else "recommendation_es") or ""
    evidence_count = int(match.get("evidence_count", 0) or 0)
    reasons = match.get("reasons", []) or []
    return {
        "id": scenario.get("id", ""),
        "title": _scenario_display_title(match, language),
        "score": float(match.get("score", 0) or 0),
        "confidence": int(match.get("confidence", 0) or 0),
        "evidence_count": evidence_count,
        "evidence_label": _scenario_evidence_label(evidence_count, reasons, language),
        "domains": match.get("domains", []),
        "domains_label": _format_match_domains(match.get("domains", []), "grupo general" if language == "es" else "overall group"),
        "reasons": reasons,
        "reasons_label": ", ".join(reasons[:4]) if reasons else ("sin criterio visible" if language == "es" else "no visible criterion"),
        "primary_framework": match.get("primary_framework", "attack"),
        "frameworks": {
            "attack": _framework_label(frameworks.get("attack", {}) or {}),
            "d3fend": _framework_label(frameworks.get("d3fend", {}) or {}),
            "atlas": _framework_label(frameworks.get("atlas", {}) or {}),
            "disarm": _framework_label(frameworks.get("disarm", {}) or {}),
            "f3": _framework_label(frameworks.get("f3", {}) or {}),
        },
        "criteria": lens["criteria"],
        "question": lens["question"],
        "decision": lens["decision"],
        "recommendation": recommendation,
        "support": _format_scenario_risk(float(match.get("confidence", 0) or 0), language),
        "evidence_ids": [str(value) for value in match.get("evidence_ids", []) if value],
        "scenario": scenario,
    }


def _scenario_evidence_label(evidence_count: int, reasons: list[str], language: str) -> str:
    visible = min(len(reasons), 4)
    if language == "en":
        if visible:
            return f"{evidence_count} matching signals; {visible} visible criteria"
        return f"{evidence_count} matching signals"
    if visible:
        return f"{evidence_count} señales coincidentes; {visible} criterios visibles"
    return f"{evidence_count} señales coincidentes"


def _framework_coverage_from_matches(matches: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    sets = {"attack": set(), "d3fend": set(), "atlas": set(), "disarm": set(), "f3": set()}
    labels = {"attack": "ATT&CK", "d3fend": "D3FEND", "atlas": "ATLAS", "disarm": "DISARM", "f3": "F3"}
    for match in matches:
        frameworks = match.get("scenario", {}).get("frameworks", {}) or {}
        for key in sets:
            item = frameworks.get(key, {}) or {}
            if item.get("id"):
                sets[key].add(item["id"])
    return [{"name": labels[key], "value": len(value)} for key, value in sets.items()]


def _scenario_display_title(match: Dict[str, Any], language: str) -> str:
    family = _scenario_family(match)
    titles = {
        "es": {
            "exploit": "Explotación y exposición técnica",
            "identity": "Identidad y acceso bajo presión",
            "fraud": "Fraude digital y abuso de confianza",
            "influence": "Influencia pública y narrativa de riesgo",
            "ai": "Abuso de IA y automatización",
            "continuity": "Continuidad y extorsión operacional",
            "general": "Escenario multi-framework priorizado",
        },
        "en": {
            "exploit": "Exploitation and technical exposure",
            "identity": "Identity and access pressure",
            "fraud": "Digital fraud and trust abuse",
            "influence": "Public influence and narrative risk",
            "ai": "AI abuse and automation",
            "continuity": "Operational continuity and extortion",
            "general": "Prioritized multi-framework scenario",
        },
    }
    scenario = match.get("scenario", {})
    return f"{scenario.get('id', 'CDE-SCN')} · {titles[language][family]}"


def _scenario_family(match: Dict[str, Any]) -> str:
    scenario = match.get("scenario", {})
    frameworks = scenario.get("frameworks", {}) or {}
    attack = frameworks.get("attack", {}) or {}
    disarm = frameworks.get("disarm", {}) or {}
    d3fend = frameworks.get("d3fend", {}) or {}
    atlas = frameworks.get("atlas", {}) or {}
    f3 = frameworks.get("f3", {}) or {}
    text = _normalize(
        " ".join(
            [
                str(scenario.get("title_es", "")),
                str(scenario.get("title_en", "")),
                str(scenario.get("sector", "")),
                str(attack.get("name", "")),
                " ".join(attack.get("tactics", []) or []),
                str(disarm.get("name", "")),
                str(disarm.get("tactic", "")),
                str(d3fend.get("name", "")),
                str(atlas.get("name", "")),
                str(f3.get("name", "")),
                " ".join(match.get("reasons", []) or []),
            ]
        )
    )
    if re.search(r"ransom|extortion|backup|continuity|destruct|wipe|availability|impact", text):
        return "continuity"
    if re.search(r"fraud|payment|bec|imperson|brand|correo|email|trust|pago|marca", text):
        return "fraud"
    if re.search(r"narrative|publication|content|influence|propaganda|disinform|fake|viral", text):
        return "influence"
    if re.search(r"\bai\b|atlas|model|prompt|machine|automation", text):
        return "ai"
    if re.search(r"exploit|vulnerab|cve|kev|rce|bypass|injection|exposure|access", text):
        return "exploit"
    if re.search(r"credential|account|identity|mfa|session|login|valid account|phishing", text):
        return "identity"
    return "general"


def _scenario_decision_lens(match: Dict[str, Any], language: str) -> Dict[str, str]:
    family = _scenario_family(match)
    scenario = match.get("scenario", {})
    frameworks = scenario.get("frameworks", {}) or {}
    primary_domain = _format_match_domains(match.get("domains", []), "grupo general" if language == "es" else "overall group")
    attack = _framework_label(frameworks.get("attack", {}) or {})
    control = _framework_label(frameworks.get("d3fend", {}) or {})
    atlas = _framework_label(frameworks.get("atlas", {}) or {})
    disarm = _framework_label(frameworks.get("disarm", {}) or {})
    f3 = _framework_label(frameworks.get("f3", {}) or {})
    support = _format_scenario_risk(float(match.get("confidence", 0) or 0), language)
    if language == "en":
        catalog = {
            "exploit": {
                "criteria": "CISM/CyBOK/ISO/COBIT: risk appetite, vulnerability management, control evidence, KRI and treatment owner.",
                "question": f"For {primary_domain}, does evidence support {support} justify comparing {attack}, {disarm} and {atlas} against the defined appetite for exposed services?",
                "decision": f"Evaluate risk treatment for {attack}: mitigate with {control}, document a temporary exception or formally accept if evidence remains below threshold.",
            },
            "identity": {
                "criteria": "CISM/CIPM/CyBOK: identity governance, human factor, privacy, privileged access and monitoring evidence.",
                "question": f"For {primary_domain}, does {attack} with {disarm} and evidence support {support} indicate credential, session or privilege exposure?",
                "decision": f"Consider a scoped identity review for {control}: phishing-resistant MFA/PAM, exposed-account validation and privacy-aware monitoring.",
            },
            "fraud": {
                "criteria": "CISM/CISA/COBIT/CIPM: fraud accountability, evidence quality, customer impact, third parties and escalation controls.",
                "question": f"For {primary_domain}, can {f3} with {attack} plus {disarm} enable impersonation, payment abuse or trust degradation?",
                "decision": f"Evaluate the F3 fraud behavior {f3}: channel validation, identity/payment controls, takedown/legal coordination and transaction monitoring thresholds.",
            },
            "influence": {
                "criteria": "Threat Intelligence/CISM/CyBOK: intelligence requirement, source confidence, narrative reach, reputation and risk communication.",
                "question": f"For {primary_domain}, does {disarm} represent narrative or influence risk with enough source confidence and reach?",
                "decision": f"For {disarm}, consider monitoring, communications or takedown only after separating source, channel, audience and amplification.",
            },
            "ai": {
                "criteria": "CISM/CyBOK/ATLAS: AI governance, human oversight, traceability, automated decisions and control testing.",
                "question": f"For {primary_domain}, can {atlas} amplify {attack} and {disarm} through automation or content generation?",
                "decision": f"Evaluate AI governance controls for {atlas}: human approval points, prompt/log traceability, abuse monitoring and integration limits.",
            },
            "continuity": {
                "criteria": "CISM/CyBOK/ISO: BIA, RTO/RPO, incident roles, recovery testing, crisis communication and resilience metrics.",
                "question": f"For {primary_domain}, does evidence support {support} justify evaluating whether {attack} and {disarm} can affect continuity thresholds or crisis activation?",
                "decision": f"Consider continuity preparation for {attack}: restore validation, segmentation, EDR/NDR coverage and supplier dependency review.",
            },
            "general": {
                "criteria": "CISM/CISA/CyBOK: governance, risk ownership, evidence sufficiency, control gap and decision traceability.",
                "question": f"For {primary_domain}, what decision is justified by {match.get('evidence_count', 0)} evidence signals and confidence {match.get('confidence', 0)}%?",
                "decision": "Assign a risk owner, minimum evidence threshold and next validation source before turning this scenario into action or investment.",
            },
        }
        return catalog[family]
    catalog = {
        "exploit": {
            "criteria": "CISM/CyBOK/ISO/COBIT: apetito de riesgo, gestión de vulnerabilidades, evidencia de control, KRI y dueño de tratamiento.",
            "question": f"Para {primary_domain}, ¿el soporte de evidencia {support} justifica contrastar {attack}, {disarm} y {atlas} con el apetito definido para servicios expuestos?",
            "decision": f"Evaluar tratamiento del riesgo para {attack}: mitigar con {control}, documentar excepción temporal o aceptar formalmente si la evidencia queda bajo umbral.",
        },
        "identity": {
            "criteria": "CISM/CIPM/CyBOK: gobierno de identidad, factor humano, privacidad, acceso privilegiado y evidencia de monitoreo.",
            "question": f"Para {primary_domain}, ¿{attack} con {disarm} y soporte {support} indica exposición de credenciales, sesión o privilegios?",
            "decision": f"Considerar revisión acotada de identidad para {control}: MFA resistente a phishing/PAM, validación de cuentas expuestas y monitoreo con criterio de privacidad.",
        },
        "fraud": {
            "criteria": "CISM/CISA/COBIT/CIPM: responsabilidad antifraude, calidad de evidencia, impacto a clientes, terceros y controles de escalamiento.",
            "question": f"Para {primary_domain}, ¿{f3} junto con {attack} y {disarm} puede habilitar suplantación, abuso de pagos o deterioro de confianza?",
            "decision": f"Evaluar la conducta antifraude F3 {f3}: validación de canales, controles de identidad/pago, coordinación legal/takedown y umbrales de monitoreo transaccional.",
        },
        "influence": {
            "criteria": "Threat Intelligence/CISM/CyBOK: requerimiento de inteligencia, confianza de fuente, alcance narrativo, reputación y comunicación de riesgo.",
            "question": f"Para {primary_domain}, ¿{disarm} representa riesgo narrativo o de influencia con suficiente confianza de fuente y alcance?",
            "decision": f"Para {disarm}, considerar monitoreo, comunicación o takedown solo tras separar fuente, canal, audiencia y amplificación.",
        },
        "ai": {
            "criteria": "CISM/CyBOK/ATLAS: gobierno de IA, supervisión humana, trazabilidad, decisiones automatizadas y prueba de controles.",
            "question": f"Para {primary_domain}, ¿{atlas} puede amplificar {attack} y {disarm} mediante automatización o generación de contenido?",
            "decision": f"Evaluar controles de gobierno de IA para {atlas}: aprobación humana, trazabilidad de prompts/logs, monitoreo de abuso y límites de integración.",
        },
        "continuity": {
            "criteria": "CISM/CyBOK/ISO: BIA, RTO/RPO, roles de incidente, pruebas de recuperación, comunicación de crisis y métricas de resiliencia.",
            "question": f"Para {primary_domain}, ¿el soporte de evidencia {support} justifica evaluar si {attack} y {disarm} pueden afectar continuidad o criterios de crisis?",
            "decision": f"Considerar preparación de continuidad para {attack}: restauración, segmentación, cobertura EDR/NDR y revisión de proveedores críticos.",
        },
        "general": {
            "criteria": "CISM/CISA/CyBOK: gobierno, dueño de riesgo, suficiencia de evidencia, brecha de control y trazabilidad de decisión.",
            "question": f"Para {primary_domain}, ¿qué decisión justifican {match.get('evidence_count', 0)} señales y confianza {match.get('confidence', 0)}%?",
            "decision": "Asignar dueño de riesgo, umbral mínimo de evidencia y próxima fuente de validación antes de convertir el escenario en acción o inversión.",
        },
    }
    return catalog[family]


def _framework_label(item: Dict[str, Any]) -> str:
    return " ".join(str(part) for part in [item.get("id"), item.get("name")] if part).strip() or "n/a"


def _format_scenario_risk(value: Any, language: str) -> str:
    try:
        raw = float(value or 0)
    except (TypeError, ValueError):
        raw = 0.0
    percent = raw * 100 if 0 < raw <= 1 else raw
    suffix = " %" if language == "es" else "%"
    return f"{round(percent)}{suffix}"


def _format_strategic_percent(value: Any, language: str) -> str:
    try:
        percent = max(0.0, float(value or 0.0))
    except (TypeError, ValueError):
        percent = 0.0
    rendered = f"{percent:.2f}"
    return f"{rendered.replace('.', ',') if language == 'es' else rendered}%"


def _format_match_domains(domains: list[str], fallback: str) -> str:
    visible = [domain for domain in domains if domain != "__group__"]
    return ", ".join(visible) if visible else fallback


def _category_terms(category: str, title: str) -> list[str]:
    text = _normalize(f"{category} {title}")
    terms = set()
    if re.search(r"vulnerab|cve|kev|exploit|rce|bypass|traversal|upload|injection|access", text):
        terms.update(["exploit", "vulnerability", "access", "defense", "detect"])
    if re.search(r"credential|account|takeover|password|session|login", text):
        terms.update(["credential", "account", "mfa", "phishing", "detect"])
    if re.search(r"bec|email|correo|payment|pago|fraud|fraude|social", text):
        terms.update(["phishing", "email", "fraud", "account", "control"])
    if re.search(r"disinformation|desinform|narrative|propaganda|influence|fake|viral", text):
        terms.update(["narrative", "publication", "content", "influence"])
    if re.search(r"\bai\b|model|atlas|machine|prompt", text):
        terms.update(["ai", "model", "atlas"])
    return list(terms)


def _tokenize(text: str) -> set[str]:
    return {_stem_token(token) for token in re.split(r"[^a-z0-9]+", _normalize(text)) if len(token) > 2}


def _stem_token(token: str) -> str:
    if token.startswith("exploit"):
        return "exploit"
    if token.startswith("vulnerab"):
        return "vulnerability"
    if token.startswith("credential"):
        return "credential"
    if token.startswith("phish"):
        return "phishing"
    if token.startswith("detect"):
        return "detect"
    if token.startswith("narrativ"):
        return "narrative"
    if token.startswith("publicat"):
        return "publication"
    if token.startswith("influenc"):
        return "influence"
    if token.startswith("control"):
        return "control"
    return token


def _normalize(text: str) -> str:
    return "".join(
        char
        for char in unicodedata.normalize("NFD", str(text).lower())
        if unicodedata.category(char) != "Mn"
    )


def _extract_technique(text: str) -> str | None:
    match = re.search(r"T\d{4}(?:\.\d{3})?", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def _domains_in_text(text: str, domains: list[str]) -> list[str]:
    normalized = _normalize(text)
    return [domain for domain in domains if _normalize(domain) in normalized]


def _event_text(event: Dict[str, Any]) -> str:
    return " ".join(
        [
            str(event.get("title", "")),
            str(event.get("category", "")),
            str(event.get("source", "")),
            str(event.get("technique", "")),
            str(event.get("evidence_url", "")),
            " ".join(event.get("tags", []) or []),
        ]
    )


def _finding_matches_domain(finding: Dict[str, Any], domain: str) -> bool:
    text = " ".join(
        [
            str(finding.get("title", "")),
            str(finding.get("category", "")),
            " ".join(finding.get("evidence", []) or []),
            " ".join(finding.get("recommendations", []) or []),
        ]
    ).lower()
    return domain.lower() in text


def _source_record_count(source_coverage: Dict[str, Any], key: str) -> int:
    try:
        return int((source_coverage.get(key, {}) or {}).get("records", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _count_events_by_keywords(events: list[Dict[str, Any]], keywords: tuple[str, ...]) -> int:
    return sum(1 for event in events if _text_has_any(_event_text(event), keywords))


def _text_has_any(text: str, keywords: tuple[str, ...]) -> bool:
    normalized = _normalize(text)
    return any(keyword in normalized for keyword in keywords)


def _clean_domain_list(values: list[Any]) -> list[str]:
    domains = []
    for value in values:
        if not isinstance(value, str):
            continue
        domain = value.strip().lower().removeprefix("https://").removeprefix("http://").strip("/")
        domain = domain.split("/")[0].split(":")[0]
        if _looks_like_domain(domain) and domain not in domains:
            domains.append(domain)
    return domains


def _looks_like_domain(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    item = value.strip().lower()
    return "." in item and " " not in item and len(item) <= 253 and not item.startswith(".")


def _event_matches_domain(event: Dict[str, Any], domain: str) -> bool:
    haystack = " ".join(
        [
            str(event.get("title", "")),
            str(event.get("evidence_url", "")),
            str(event.get("source", "")),
            " ".join(event.get("tags", []) or []),
        ]
    ).lower()
    return domain.lower() in haystack


def _tag_value(tags: list[Any], prefix: str) -> str:
    marker = f"{prefix}:"
    for tag in tags or []:
        value = str(tag)
        if value.startswith(marker):
            return value.split(":", 1)[1]
    return ""


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.removeprefix("www.")
    except Exception:
        return ""


def _event_severity_label(event: Dict[str, Any], language: str) -> str:
    try:
        severity = float(event.get("severity", 0) or 0)
    except (TypeError, ValueError):
        severity = 0.0
    if severity >= 0.75:
        return "Crítica" if language == "es" else "Critical"
    if severity >= 0.60:
        return "Alta" if language == "es" else "High"
    if severity >= 0.40:
        return "Media" if language == "es" else "Medium"
    return "Baja / inventario" if language == "es" else "Low / inventory"


def _surface_note(event: Dict[str, Any], language: str) -> str:
    tags = set(str(tag) for tag in event.get("tags", []) or [])
    if "dns_inventory_only" in tags:
        return (
            "No se eleva criticidad por sí solo; requiere confirmar servicio activo, datos expuestos o control débil."
            if language == "es"
            else "It does not raise criticality by itself; confirm active service, exposed data or weak control."
        )
    if "validation_required" in tags:
        return "Requiere validación manual/técnica antes de acción." if language == "es" else "Requires manual/technical validation before action."
    return "Evidencia técnica observada." if language == "es" else "Observed technical evidence."


def _event_validation_state(event: Dict[str, Any], language: str) -> str:
    tags = set(str(tag) for tag in event.get("tags", []) or [])
    if tags.intersection({"validation_required", "reputation_checker", "dns_inventory_only"}):
        return "Validación requerida" if language == "es" else "Validation required"
    if event.get("evidence_url") or float(event.get("severity", 0) or 0) >= 0.55:
        return "Validada por evidencia técnica" if language == "es" else "Validated by technical evidence"
    return "Contextual" if language == "es" else "Contextual"


def _finding_validation_label(finding: Dict[str, Any], urls: list[str], rationale: str, language: str) -> str:
    evidence_text = " ".join(str(item) for item in finding.get("evidence", []) or []).lower()
    if "validation_required" in evidence_text or "reputation_checker" in evidence_text:
        return "Requiere validación" if language == "es" else "Requires validation"
    if urls and rationale:
        return "Validada con URL y base técnica" if language == "es" else "Validated with URL and technical basis"
    if rationale:
        return "Validada por base técnica" if language == "es" else "Validated by technical basis"
    if urls:
        return "URL pendiente de verificación" if language == "es" else "URL pending verification"
    return "Sin URL directa; revisar fuente" if language == "es" else "No direct URL; review source"


def _fallback_alert_basis(finding: Dict[str, Any], language: str) -> str:
    recommendations = finding.get("recommendations", []) or []
    if recommendations:
        return (
            "Prioridad inferida por riesgo residual y recomendaciones asociadas: " + "; ".join(str(item) for item in recommendations[:2])
            if language == "es"
            else "Priority inferred from residual risk and associated recommendations: " + "; ".join(str(item) for item in recommendations[:2])
        )
    return "Prioridad inferida por matriz de riesgo residual." if language == "es" else "Priority inferred from residual-risk matrix."


def _scope_filtered_events(payload: Dict[str, Any], language: str) -> list[Dict[str, Any]]:
    terms = _scope_terms_for_payload(payload, language)
    events = payload.get("raw_events", []) or []
    if not terms:
        return events
    filtered = [event for event in events if _event_matches_scope_terms(event, terms)]
    return filtered


def _scope_terms_for_payload(payload: Dict[str, Any], language: str) -> list[str]:
    scope = payload.get("report_scope") or _report_scope(payload, language)
    terms: list[str] = []

    def add_term(value: Any, *, minimum: int = 4) -> None:
        cleaned = str(value or "").strip().lower()
        if len(cleaned) < minimum:
            return
        terms.append(cleaned)
        compact = cleaned.replace(" ", "")
        if len(compact) >= 4:
            terms.append(compact)

    for domain in scope.get("primary_domains", []) or []:
        cleaned = str(domain).strip().lower()
        if not cleaned:
            continue
        terms.append(cleaned)
        label = cleaned.split(".", 1)[0].replace("-", " ").replace("_", " ").strip()
        add_term(label)
    organization = payload.get("organization", {}) or {}
    org_name = str(organization.get("name", "") or "").strip().lower()
    if org_name and not org_name.startswith("domain intelligence:") and len(org_name) >= 4:
        add_term(org_name)
        legal_suffixes = {"ag", "corp", "corporation", "inc", "incorporated", "ltd", "limited", "llc", "plc", "sa", "sas"}
        without_suffix = " ".join(part for part in org_name.replace(",", " ").split() if part not in legal_suffixes)
        if without_suffix != org_name:
            add_term(without_suffix)
    for field in (
        "legal_name",
        "brands",
        "subsidiaries",
        "parent_organizations",
        "entity_aliases",
        "subject_aliases",
        "strategic_assets",
    ):
        values = organization.get(field, []) or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            add_term(value, minimum=3)
    deduped: list[str] = []
    seen = set()
    for term in terms:
        if len(term) < 4 or term in seen:
            continue
        seen.add(term)
        deduped.append(term)
    return deduped


def _event_matches_scope_terms(event: Dict[str, Any], terms: list[str]) -> bool:
    haystack = " ".join(
        [
            str(event.get("title", "")),
            str(event.get("category", "")),
            str(event.get("source", "")),
            str(event.get("actor", "")),
            str(event.get("technique", "")),
            str(event.get("evidence_url", "")),
            " ".join(event.get("tags", []) or []),
        ]
    ).lower()
    return any(term in haystack for term in terms)


def _payload_signal_text(payload: Dict[str, Any]) -> str:
    parts = []
    for event in payload.get("raw_events", []):
        parts.extend([event.get("title", ""), event.get("category", ""), event.get("source", ""), " ".join(event.get("tags", []) or [])])
    for finding in payload.get("risk_findings", []):
        parts.extend([finding.get("title", ""), finding.get("category", ""), finding.get("matrix_label", ""), " ".join(finding.get("evidence", []) or [])])
    metrics = payload.get("metrics", {})
    for row in metrics.get("risk_heat_radar", {}).get("rows", []):
        parts.extend([row.get("name", ""), row.get("heat", ""), " ".join(row.get("signals", []) or [])])
    return " ".join(str(part).lower() for part in parts if part)


def _forecast_snapshot(metrics: Dict[str, Any]) -> Dict[str, Any]:
    forecast = metrics.get("forecast", {}) or {}
    if not forecast:
        return {"horizon": "n/a", "lower_label": "n/a", "base_label": "n/a", "upper_label": "n/a", "calibrated": False}
    key = sorted(forecast.keys(), key=lambda item: int(item) if str(item).isdigit() else 0)[-1]
    item = forecast.get(key, {})
    return {
        "horizon": key,
        "lower_label": _index_label(item.get("lower_sensitivity", item.get("p10"))),
        "base_label": _index_label(item.get("signal_pressure_index", item.get("p50"))),
        "upper_label": _index_label(item.get("upper_sensitivity", item.get("p90"))),
        "p10_label": _index_label(item.get("lower_sensitivity", item.get("p10"))),
        "p50_label": _index_label(item.get("signal_pressure_index", item.get("p50"))),
        "p90_label": _index_label(item.get("upper_sensitivity", item.get("p90"))),
        "calibrated": bool(item.get("prediction_is_calibrated", False)),
        "note": item.get("language", ""),
    }


def _index_label(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}/100"
    except (TypeError, ValueError):
        return "n/a"


def _pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "n/a"


def _status_is_healthy(status: Dict[str, Any]) -> bool:
    status_text = str(status.get("status", "")).lower()
    return status_text in {"ok", "healthy", "active", "completed", "searched", "configured"} or (status.get("records", 0) or 0) > 0


def _control_status(value: float, language: str) -> str:
    if value >= 0.75:
        return "Fuerte" if language == "es" else "Strong"
    if value >= 0.55:
        return "Intermedio" if language == "es" else "Intermediate"
    return "Brecha prioritaria" if language == "es" else "Priority gap"


def _priority_from_score(score: float, language: str) -> str:
    if score >= 24:
        return "Crítica" if language == "es" else "Critical"
    if score >= 16:
        return "Alta" if language == "es" else "High"
    return "Media" if language == "es" else "Medium"


def _scenario_modality(name: str, language: str) -> str:
    lowered = name.lower()
    if any(token in lowered for token in ["fraud", "fraude", "phishing", "suplant"]):
        return "Phishing, suplantación, ATO o fraude transaccional" if language == "es" else "Phishing, impersonation, ATO or transactional fraud"
    if any(token in lowered for token in ["ransomware", "continu"]):
        return "Extorsión, cifrado, interrupción o presión reputacional" if language == "es" else "Extortion, encryption, disruption or reputation pressure"
    if any(token in lowered for token in ["vulner", "exploit", "kev", "cve"]):
        return "Explotación de vulnerabilidad o servicio expuesto" if language == "es" else "Vulnerability or exposed-service exploitation"
    if any(token in lowered for token in ["cloud", "api", "devsecops"]):
        return "Abuso de API, secretos, nube o pipeline" if language == "es" else "API, secret, cloud or pipeline abuse"
    if any(token in lowered for token in ["tercer", "supplier", "supply"]):
        return "Compromiso de proveedor o dependencia crítica" if language == "es" else "Supplier or critical-dependency compromise"
    if any(token in lowered for token in ["datos", "privacy", "privacidad", "data"]):
        return "Exposición de datos, privacidad o obligación regulatoria" if language == "es" else "Data exposure, privacy or regulatory obligation"
    return "Escenario de presión cyber a validar con evidencia" if language == "es" else "Cyber-pressure scenario to validate with evidence"


def _scenario_confidence(row: Dict[str, Any], language: str) -> str:
    evidence_count = int(row.get("evidence_count", 0) or 0)
    if evidence_count >= 5:
        return "Alta" if language == "es" else "High"
    if evidence_count >= 1:
        return "Media" if language == "es" else "Medium"
    return "Preventiva" if language == "es" else "Preventive"


def _heatmap(findings: list[Dict[str, Any]]) -> list[list[Dict[str, Any]]]:
    cells = []
    for likelihood in range(4, 0, -1):
        row = []
        for impact in range(1, 5):
            count = sum(
                1
                for finding in findings
                if _index(finding["likelihood"]) == likelihood and _index(finding["impact"]) == impact
            )
            score = likelihood * impact
            if score <= 3:
                label = "low"
            elif score <= 7:
                label = "medium"
            elif score <= 11:
                label = "high"
            else:
                label = "critical"
            row.append({"score": score, "count": count, "class": label})
        cells.append(row)
    return cells


def _index(value: float) -> int:
    import math

    return max(1, min(4, math.ceil(4 * max(0.0, min(1.0, value)))))


def _evidence_rows(events: list[Dict[str, Any]], language: str) -> list[Dict[str, Any]]:
    rows = sorted(events, key=lambda item: (item.get("source") or "", item.get("category") or "", item.get("title") or ""))
    return [_search_row(row, language) | {
        "technique": row.get("technique") or "",
        "cve": row.get("cve") or "",
    } for row in rows]


def _evidence_type_summary(rows: list[Dict[str, Any]], language: str) -> list[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for row in rows:
        key = str(row.get("evidence_type") or "other")
        counts[key] = counts.get(key, 0) + 1
    labels = {
        "document": ("Documentos y archivos", "Documents and files"),
        "web_page": ("Páginas web", "Web pages"),
        "news": ("Noticias y comunicados", "News and releases"),
        "social_media": ("Redes sociales", "Social media"),
        "technology_infrastructure": ("Tecnología e infraestructura", "Technology and infrastructure"),
        "official_record": ("Registros oficiales", "Official records"),
        "authorized_dark_web": ("Dark web autorizada", "Authorized dark web"),
        "other": ("Otros registros", "Other records"),
    }
    label_index = 1 if language == "en" else 0
    return [
        {"key": key, "label": labels.get(key, labels["other"])[label_index], "count": count}
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _executive_evidence_sample(rows: list[Dict[str, Any]], limit: int = 40) -> list[Dict[str, Any]]:
    buckets: Dict[str, list[Dict[str, Any]]] = {}
    for row in rows:
        buckets.setdefault(str(row.get("evidence_type") or "other"), []).append(row)
    keys = sorted(buckets)
    offsets = {key: 0 for key in keys}
    sample: list[Dict[str, Any]] = []
    while len(sample) < min(limit, len(rows)):
        advanced = False
        for key in keys:
            offset = offsets[key]
            if offset >= len(buckets[key]):
                continue
            sample.append(buckets[key][offset])
            offsets[key] += 1
            advanced = True
            if len(sample) >= limit:
                break
        if not advanced:
            break
    return sample


def _search_groups(events: list[Dict[str, Any]], language: str = "es") -> Dict[str, Any]:
    groups = {
        "internet": {"title": "Resultados de busquedas en internet", "title_en": "Internet search results", "rows": []},
        "socmint": {"title": "Resultados de busquedas en redes sociales publicas", "title_en": "Public social media search results", "rows": []},
        "darkweb": {"title": "Resultados dark web / TOR autorizados", "title_en": "Authorized dark web / TOR results", "rows": []},
    }
    for event in events:
        tags = set(event.get("tags") or [])
        source = event.get("source") or ""
        if "darkweb_index" in tags or "darkweb_authorized" in tags or "Dark Web" in source:
            groups["darkweb"]["rows"].append(_search_row(event, language))
        elif "socmint_public" in tags or "SOCMINT" in source:
            groups["socmint"]["rows"].append(_search_row(event, language))
        elif "internet_search" in tags or "osint_public" in tags or "common_crawl" in tags or "Internet Search" in source or "OSINT" in source or "Common Crawl" in source:
            groups["internet"]["rows"].append(_search_row(event, language))
    for group in groups.values():
        group["rows"] = sorted(
            group["rows"],
            key=lambda item: (
                item["age_days"] if item["age_days"] is not None else 10**9,
                item["source"],
                item["title"],
            ),
        )[:16]
        group["count"] = len(group["rows"])
    groups["total"] = sum(group["count"] for group in groups.values())
    return groups


def _search_row(event: Dict[str, Any], language: str = "es") -> Dict[str, Any]:
    tags = event.get("tags") or []
    raw_url = str(event.get("evidence_url") or "").strip()
    review_url = _public_evidence_url(raw_url)
    age_value = event.get("age_days")
    try:
        age_days = max(0, int(age_value)) if age_value is not None else None
    except (TypeError, ValueError):
        age_days = None
    observed_at = (
        event.get("observed_at")
        or event.get("published_at")
        or event.get("collected_at")
        or event.get("timestamp")
    )
    return {
        "source": _display_source_name(event.get("source", ""), language),
        "category": event.get("category") or "",
        "category_label": _search_category_label(event.get("category"), language),
        "evidence_type": event.get("evidence_type") or "other",
        "evidence_type_label": _evidence_type_label(event.get("evidence_type"), language),
        "title": _search_result_title(event, review_url, language),
        "actor": event.get("actor") or "",
        "age_days": age_days,
        "observed_date": _observation_date_label(observed_at, language),
        "recency_label": _recency_label(age_days, language),
        "tags": _clean_tag_list(tags, language),
        "evidence_url": review_url,
        "evidence_url_label": _host_from_url(review_url) or ("fuente" if language == "es" else "source"),
        "raw_evidence_url": raw_url,
        "preview_url": _event_preview_url(event),
        "relationship": _evidence_relationship(event, language),
        "validation": _evidence_validation(event, raw_url, review_url, language),
    }


def _search_category_label(value: Any, language: str) -> str:
    labels = {
        "osint_public_index": ("Índice web público", "Public web index"),
        "social_signal": ("Mención social pública", "Public social mention"),
        "brand_reputation": ("Marca y reputación", "Brand and reputation"),
        "fake_recruitment": ("Suplantación en ofertas de empleo", "Recruitment impersonation"),
        "phishing": ("Suplantación y phishing", "Impersonation and phishing"),
        "attack_surface": ("Superficie externa", "External surface"),
        "attack_surface_web": ("Servicio web observado", "Observed web service"),
        "attack_surface_dns": ("Registro DNS observado", "Observed DNS record"),
        "exploit_context": ("Contexto público de explotación", "Public exploit context"),
        "darkweb": ("Índice autorizado de dark web", "Authorized dark web index"),
    }
    raw = str(value or "").strip()
    if raw in labels:
        return labels[raw][1 if language == "en" else 0]
    if not raw:
        return "Sin clasificar" if language == "es" else "Unclassified"
    return raw.replace("_", " ").strip().capitalize()


def _search_result_title(event: Dict[str, Any], evidence_url: str, language: str) -> str:
    title = _clean_evidence_text(event.get("title") or "", language)
    normalized = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii").lower()
    if normalized.startswith("url publica indexada para"):
        host = str(event.get("domain") or "").strip()
        if not host and evidence_url:
            host = (urlparse(evidence_url).hostname or "").removeprefix("www.")
        if host:
            return (
                f"Public page indexed on {host}"
                if language == "en"
                else f"Página pública indexada en {host}"
            )
    return title


def _observation_date_label(value: Any, language: str) -> str:
    if not value:
        return "Not reported" if language == "en" else "No informada"
    parsed: datetime | None = value if isinstance(value, datetime) else None
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return "Not reported" if language == "en" else "No informada"
    if language == "en":
        months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        return f"{months[parsed.month - 1]} {parsed.day}, {parsed.year}"
    months = ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")
    return f"{parsed.day} {months[parsed.month - 1]} {parsed.year}"


def _recency_label(age_days: int | None, language: str) -> str:
    if age_days is None:
        return "Recency unavailable" if language == "en" else "Recencia no disponible"
    if age_days == 0:
        return "Observed today" if language == "en" else "Observado hoy"
    if age_days == 1:
        return "Observed 1 day ago" if language == "en" else "Observado hace 1 día"
    return (
        f"Observed {age_days} days ago"
        if language == "en"
        else f"Observado hace {age_days} días"
    )


def _evidence_type_label(value: Any, language: str) -> str:
    labels = {
        "document": ("Documentos y archivos", "Documents and files"),
        "web_page": ("Páginas web", "Web pages"),
        "news": ("Noticias y comunicados", "News and releases"),
        "social_media": ("Redes sociales", "Social media"),
        "technology_infrastructure": ("Tecnología e infraestructura", "Technology and infrastructure"),
        "official_record": ("Registros oficiales", "Official records"),
        "authorized_dark_web": ("Dark web autorizada", "Authorized dark web"),
        "other": ("Otros registros", "Other records"),
    }
    pair = labels.get(str(value or "other"), labels["other"])
    return pair[1 if language == "en" else 0]


def _public_evidence_url(url: str) -> str:
    if not url:
        return ""
    match = _urlscan_uuid(url)
    if match:
        return f"https://urlscan.io/result/{match}/"
    return url


def _capture_preview_url(capture: Dict[str, Any]) -> str:
    status = str(capture.get("validation_status") or capture.get("validationStatus") or "")
    if status not in {"captured", "verified"}:
        return ""
    path = str(capture.get("image_path") or capture.get("imagePath") or "").strip()
    if ".." not in path and re.fullmatch(r"(?:\./)?assets/[A-Za-z0-9_.\-/]+\.(?:png|jpe?g|webp)", path, re.IGNORECASE):
        return path
    return ""


def _event_preview_url(event: Dict[str, Any]) -> str:
    for capture in event.get("captures", []) or []:
        if isinstance(capture, dict):
            preview = _capture_preview_url(capture)
            if preview:
                return preview
    return ""


def _urlscan_uuid(url: str) -> str:
    match = re.search(r"urlscan\.io/(?:api/v1/)?result/([0-9a-f-]{32,36})/?", url or "", re.IGNORECASE)
    return match.group(1) if match else ""


def _evidence_relationship(event: Dict[str, Any], language: str) -> str:
    tags = [str(tag) for tag in event.get("tags", []) or []]
    tagged_assets = []
    for tag in tags:
        if tag.startswith(("domain:", "host:", "asset:", "query:")):
            tagged_assets.append(tag.split(":", 1)[1])
    url_host = urlparse(str(event.get("evidence_url") or "")).netloc.removeprefix("www.")
    if url_host and "urlscan.io" not in url_host:
        tagged_assets.append(url_host)
    unique_assets = []
    for asset in tagged_assets:
        cleaned = asset.strip().lower()
        if cleaned and cleaned not in unique_assets:
            unique_assets.append(cleaned)
    if unique_assets:
        label = ", ".join(unique_assets[:3])
        return (
            f"Relacionada por dominio, host, query o activo observado: {label}."
            if language == "es"
            else f"Related by observed domain, host, query or asset: {label}."
        )
    if event.get("technique"):
        return (
            f"Relacionada por técnica mapeada {event.get('technique')} y contexto de fuente."
            if language == "es"
            else f"Related by mapped technique {event.get('technique')} and source context."
        )
    return (
        "Relación inferida por título, fuente y contexto de la corrida; validar con la URL antes de ejecutar acciones."
        if language == "es"
        else "Relationship inferred from title, source and run context; validate the URL before action."
    )


def _evidence_validation(event: Dict[str, Any], raw_url: str, review_url: str, language: str) -> str:
    if _urlscan_uuid(raw_url):
        return (
            "La fuente entregó un resultado indexado. La URL pública se conserva; una captura solo se muestra si fue generada y verificada por el navegador interno."
            if language == "es"
            else "The source returned an indexed result. The public URL is preserved; a capture appears only when generated and verified by the internal browser."
        )
    if review_url:
        return (
            "Evidencia con URL directa. Debe revisarse contenido, fecha, dominio y contexto antes de clasificarla como accionable."
            if language == "es"
            else "Direct-URL evidence. Review content, date, domain and context before marking it actionable."
        )
    return (
        "Sin URL directa; la trazabilidad queda en el exporte JSON/CSV y estado de la fuente."
        if language == "es"
        else "No direct URL; traceability remains in the JSON/CSV export and source status."
    )


def _clean_tag_list(tags: list[Any], language: str) -> str:
    labels = {
        "attack_surface": "superficie_ataque" if language == "es" else "attack_surface",
        "email_security": "seguridad_email" if language == "es" else "email_security",
        "darkweb_index": "indice_darkweb" if language == "es" else "darkweb_index",
        "darkweb_authorized": "darkweb_autorizada" if language == "es" else "authorized_darkweb",
        "ransomware": "ransomware",
        "tor_onion_metadata": "metadata_onion" if language == "es" else "onion_metadata",
        "clearweb_index": "indice_publico" if language == "es" else "public_index",
        "socmint_public": "socmint_publico" if language == "es" else "public_socmint",
        "common_crawl": "indice_publico" if language == "es" else "public_index",
    }
    internal = re.compile(
        r"^(tool:|query:|country:|kali_surface|osint_tools|spiderfoot|duckduckgo_lite|internet_search|open_web_signal|sfp_)",
        re.IGNORECASE,
    )
    output = []
    seen = set()
    for tag in tags or []:
        raw = str(tag or "").strip()
        if not raw or internal.search(raw):
            continue
        value = labels.get(raw, _clean_evidence_text(raw, language))
        if value and value not in seen:
            output.append(value)
            seen.add(value)
        if len(output) >= 5:
            break
    return ", ".join(output)


def _brand_fraud_summary(payload: Dict[str, Any], language: str) -> Dict[str, Any]:
    events = payload.get("raw_events", []) or []
    domains = _clean_domain_list(payload.get("organization", {}).get("primary_domains", []) or [])
    organization_name = str(payload.get("organization", {}).get("name") or "").strip()
    terms = _brand_terms_for_report(domains, organization_name)
    mentions = []
    for event in events:
        text = _normalize(_event_text(event))
        if terms and not any(term in text for term in terms):
            continue
        sentiment = _brand_sentiment(text)
        domain = _brand_domain_for_event(event, domains, terms)
        mentions.append(
            {
                "domain": domain,
                "phrase": _short_phrase(_clean_evidence_text(str(event.get("title") or ""))),
                "sentiment": sentiment,
                "tone": _brand_tone(text),
                "source": _display_source_name(event.get("source", ""), language),
                "category": event.get("category") or "",
                "url": event.get("evidence_url") or "",
            }
        )
    negative = sum(1 for item in mentions if item["sentiment"] == "negative")
    positive = sum(1 for item in mentions if item["sentiment"] == "positive")
    darkweb = sum(1 for item in mentions if _text_has_any(f"{item['source']} {item['category']}", ("dark", "onion", "ransom", "leak")))
    socmint = sum(1 for item in mentions if _text_has_any(item["source"], ("socmint", "reddit", "facebook", "instagram", "tiktok", "linkedin", "x.com")))
    reputation_impact = _brand_reputation_impact(mentions, darkweb, socmint)
    domain_rows = _brand_domain_rows(domains, mentions)
    lookalikes = _brand_lookalikes(events, domains, language)
    if language == "en":
        narrative = (
            "No active brand/fraud evidence was collected for this run."
            if not mentions
            else f"{len(mentions)} brand/domain mentions were collected; {negative} are negative and {len(lookalikes)} URL-domain similarities require validation."
        )
    else:
        narrative = (
            "No se recolectó evidencia activa de marca/fraude en esta corrida."
            if not mentions
            else f"Se recolectaron {len(mentions)} menciones de marca/dominio; {negative} son negativas y {len(lookalikes)} similitudes de dominio requieren validación."
        )
    return {
        "total_mentions": len(mentions),
        "positive": positive,
        "neutral": sum(1 for item in mentions if item["sentiment"] == "neutral"),
        "negative": negative,
        "fraud_pressure": float(payload.get("metrics", {}).get("fraud_pressure") or 0),
        "fraud_pressure_label": f"{float(payload.get('metrics', {}).get('fraud_pressure') or 0) * 100:.0f}%",
        "reputation_impact": reputation_impact,
        "darkweb": darkweb,
        "socmint": socmint,
        "domain_rows": domain_rows,
        "lookalikes": lookalikes[:12],
        "mentions": mentions[:16],
        "narrative": narrative,
    }


def _brand_terms_for_report(domains: list[str], organization_name: str) -> list[str]:
    values = []
    if organization_name and not organization_name.lower().startswith("domain intelligence:"):
        values.append(organization_name)
    values.extend(domains)
    values.extend(domain.split(".", 1)[0].replace("-", " ") for domain in domains)
    output = []
    for value in values:
        normalized = _normalize(value).strip()
        if len(normalized) >= 4 and normalized not in output:
            output.append(normalized)
    return output


def _brand_sentiment(text: str) -> str:
    negative = (
        "fraud",
        "fraude",
        "phishing",
        "smishing",
        "vishing",
        "suplant",
        "imperson",
        "scam",
        "estafa",
        "farsa",
        "queja",
        "reclamo",
        "denuncia",
        "fake",
        "falso",
        "leak",
        "filtracion",
        "breach",
        "ransomware",
        "dark web",
        "credential",
        "password",
        "malware",
        "ciberataque",
        "hack",
    )
    positive = ("seguridad", "security", "certificacion", "reconocimiento", "alianza", "award", "innovation", "innovacion")
    if any(term in text for term in negative):
        return "negative"
    if any(term in text for term in positive):
        return "positive"
    return "neutral"


def _brand_tone(text: str) -> str:
    if any(term in text for term in ("ransom", "dark web", "onion", "leak", "filtracion", "credential", "password", "breach")):
        return "critical"
    if any(term in text for term in ("fraud", "fraude", "phishing", "suplant", "scam", "estafa", "farsa", "fake")):
        return "high"
    if any(term in text for term in ("queja", "reclamo", "denuncia", "support", "login", "verificacion", "security")):
        return "medium"
    return "low"


def _brand_domain_for_event(event: Dict[str, Any], domains: list[str], terms: list[str]) -> str:
    text = _normalize(_event_text(event))
    host = _host_from_url(str(event.get("evidence_url") or ""))
    for domain in domains:
        if domain in text or host == domain or host.endswith(f".{domain}"):
            return domain
    for domain in domains:
        label = _normalize(domain.split(".", 1)[0].replace("-", " "))
        if label and label in text:
            return domain
    return terms[0] if terms else "brand"


def _brand_reputation_impact(mentions: list[Dict[str, Any]], darkweb: int, socmint: int) -> int:
    if not mentions:
        return 0
    negative = sum(1 for item in mentions if item["sentiment"] == "negative")
    high = sum(1 for item in mentions if item["tone"] == "high")
    critical = sum(1 for item in mentions if item["tone"] == "critical")
    return max(0, min(100, round((negative / len(mentions)) * 58 + high * 6 + critical * 10 + darkweb * 8 + socmint * 3)))


def _brand_domain_rows(domains: list[str], mentions: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    rows = []
    visible_domains = domains or sorted({str(item.get("domain")) for item in mentions if item.get("domain")})
    for domain in visible_domains:
        scoped = [item for item in mentions if item.get("domain") == domain]
        total = len(scoped)
        positive = sum(1 for item in scoped if item["sentiment"] == "positive")
        neutral = sum(1 for item in scoped if item["sentiment"] == "neutral")
        negative = sum(1 for item in scoped if item["sentiment"] == "negative")
        impact = max(0, min(100, round((negative / max(1, total)) * 65 + sum(1 for item in scoped if item["tone"] in {"high", "critical"}) * 7)))
        rows.append(
            {
                "domain": domain,
                "total": total,
                "positive": positive,
                "neutral": neutral,
                "negative": negative,
                "positive_pct": _bar_pct(positive, total),
                "neutral_pct": _bar_pct(neutral, total),
                "negative_pct": _bar_pct(negative, total),
                "impact": impact,
            }
        )
    return rows


def _bar_pct(value: int, total: int) -> int:
    if total <= 0 or value <= 0:
        return 0
    return max(8, round((value / total) * 100))


def _brand_lookalikes(events: list[Dict[str, Any]], domains: list[str], language: str) -> list[Dict[str, Any]]:
    rows = []
    seen = set()
    for event in events:
        url = str(event.get("evidence_url") or "")
        observed = _host_from_url(url)
        if not observed:
            continue
        for target in domains:
            analysis = _lookalike_reason(target, observed, language)
            if not analysis:
                continue
            key = (target, observed, url)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "target": target,
                    "observed": observed,
                    "url": url,
                    "source": _display_source_name(event.get("source", ""), language),
                    "reason": analysis["reason"],
                    "similarity": analysis["similarity"],
                    "tone": "critical" if analysis["similarity"] >= 90 else "high" if analysis["similarity"] >= 82 else "medium",
                }
            )
    return sorted(rows, key=lambda item: item["similarity"], reverse=True)


def _lookalike_reason(target_domain: str, observed_domain: str, language: str) -> Dict[str, Any] | None:
    target = target_domain.lower().removeprefix("www.")
    observed = observed_domain.lower().removeprefix("www.")
    if observed == target or observed.endswith(f".{target}"):
        return None
    target_label = target.split(".", 1)[0]
    observed_label = observed.split(".", 1)[0]
    if len(target_label) < 4 or len(observed_label) < 4:
        return None
    compact_target = re.sub(r"[-_.]+", "", target_label)
    compact_observed = re.sub(r"[-_.]+", "", observed_label)
    conf_target = _normalize_confusables(compact_target)
    conf_observed = _normalize_confusables(compact_observed)
    if compact_target == compact_observed:
        return {"reason": "Same brand label with different domain/TLD" if language == "en" else "Misma marca con dominio/TLD diferente", "similarity": 96}
    if conf_target == conf_observed and compact_target != compact_observed:
        return {"reason": "Possible visual substitution such as 0/o or 1/l" if language == "en" else "Sustitución visual posible tipo 0/o, 1/l", "similarity": 94}
    if compact_target in compact_observed and len(compact_observed) <= len(compact_target) + 8:
        return {"reason": "Observed domain contains the protected brand label" if language == "en" else "El dominio observado contiene la marca protegida", "similarity": 88}
    distance = _levenshtein(conf_target, conf_observed)
    similarity = round((1 - distance / max(len(conf_target), len(conf_observed), 1)) * 100)
    if similarity >= 82 or (distance <= 2 and min(len(conf_target), len(conf_observed)) >= 5):
        return {"reason": "High lexical similarity to protected domain" if language == "en" else "Alta similitud léxica con el dominio protegido", "similarity": similarity}
    return None


def _normalize_confusables(value: str) -> str:
    return (
        value.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
        .replace("8", "b")
    )


def _levenshtein(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current.append(min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1] if previous else len(left)


def _host_from_url(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlparse(value if value.startswith(("http://", "https://")) else f"https://{value}")
        return (parsed.hostname or "").lower().removeprefix("www.")
    except ValueError:
        match = re.search(r"(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})(?:/|$)", value.lower())
        return match.group(1).removeprefix("www.") if match else ""


def _short_phrase(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.split(" | query: ", 1)[0]).strip()
    return cleaned if len(cleaned) <= 150 else f"{cleaned[:147]}..."


def _radar_svg(title: str, dimensions: list[Dict[str, Any]]) -> str:
    import math

    if not dimensions:
        return "<p class=\"small\">Informacion insuficiente para construir una visualizacion cuantitativa.</p>"
    center = 150
    radius = 88
    labels = []
    scored_points = []
    markers = []
    rings = []
    axes = []
    legend = []
    count = len(dimensions)
    for ring in (0.25, 0.5, 0.75, 1.0):
        ring_points = []
        for idx in range(count):
            angle = -math.pi / 2 + 2 * math.pi * idx / count
            ring_points.append(f"{center + radius * ring * math.cos(angle):.1f},{center + radius * ring * math.sin(angle):.1f}")
        rings.append(f"<polygon points=\"{' '.join(ring_points)}\" fill=\"none\" stroke=\"#d8e1ea\" stroke-width=\"1\" />")
    for idx, dimension in enumerate(dimensions):
        raw_score = dimension.get("signalScore", dimension.get("signal_score"))
        angle = -math.pi / 2 + 2 * math.pi * idx / count
        ax = center + radius * math.cos(angle)
        ay = center + radius * math.sin(angle)
        lx = center + (radius + 18) * math.cos(angle)
        ly = center + (radius + 18) * math.sin(angle)
        short_name = html.escape(str(dimension.get("shortName") or dimension.get("name") or f"Dimension {idx + 1}"))
        value_label = "N/D" if raw_score is None else f"{float(raw_score):.1f}"
        axis_style = "stroke-dasharray=\"3 3\"" if raw_score is None else ""
        axes.append(f"<line x1=\"{center}\" y1=\"{center}\" x2=\"{ax:.1f}\" y2=\"{ay:.1f}\" stroke=\"#d8e1ea\" stroke-width=\"1\" {axis_style} />")
        labels.append(f"<g><title>{short_name}: {value_label}</title><circle cx=\"{lx:.1f}\" cy=\"{ly:.1f}\" r=\"9\" fill=\"#edf3f8\" stroke=\"#c8d6e2\" /><text x=\"{lx:.1f}\" y=\"{ly + 0.5:.1f}\" text-anchor=\"middle\" dominant-baseline=\"middle\" font-size=\"9\" font-weight=\"800\" fill=\"#18324d\">{idx + 1}</text></g>")
        legend.append(f"<li><b>{idx + 1}</b><span>{short_name}</span><strong>{value_label}</strong></li>")
        if raw_score is not None:
            score = max(0.0, min(1.0, float(raw_score) / 100.0))
            x = center + radius * score * math.cos(angle)
            y = center + radius * score * math.sin(angle)
            scored_points.append(f"{x:.1f},{y:.1f}")
            markers.append(f"<line x1=\"{center}\" y1=\"{center}\" x2=\"{x:.1f}\" y2=\"{y:.1f}\" stroke=\"#087f8c\" stroke-width=\"2\" opacity=\".72\" /><circle cx=\"{x:.1f}\" cy=\"{y:.1f}\" r=\"4\" fill=\"#087f8c\"><title>{short_name}: {value_label}</title></circle>")
    polygon = (
        f"<polygon points=\"{' '.join(scored_points)}\" fill=\"rgba(8,127,140,.28)\" stroke=\"#087f8c\" stroke-width=\"2\" />"
        if len(scored_points) == count
        else "".join(markers)
    )
    escaped_title = html.escape(title)
    return (
        f"<figure class=\"radar\"><figcaption>{escaped_title}</figcaption><svg viewBox=\"0 0 300 300\" role=\"img\" aria-label=\"{escaped_title} radar\">"
        + "".join(rings)
        + "".join(axes)
        + polygon
        + "".join(labels)
        + "</svg><ol class=\"radar-dimension-legend\">"
        + "".join(legend)
        + "</ol></figure>"
    )


def _risk_heat_svg(rows: list[Dict[str, Any]]) -> str:
    import math

    if not rows:
        return "<p class=\"small\">Sin datos suficientes para radar-calor.</p>"
    center = 150
    max_radius = 108
    count = len(rows)
    rings = []
    for ring in (0.25, 0.5, 0.75, 1.0):
        rings.append(f"<circle cx=\"{center}\" cy=\"{center}\" r=\"{max_radius * ring:.1f}\" fill=\"none\" stroke=\"#d8e1ea\" stroke-width=\"1\" />")
    wedges = []
    for idx, row in enumerate(rows):
        start = -math.pi / 2 + 2 * math.pi * idx / count
        end = -math.pi / 2 + 2 * math.pi * (idx + 1) / count
        mid = (start + end) / 2
        score = max(0.05, min(1.0, float(row.get("score", 0))))
        radius = max_radius * score
        color = {"critical": "#b42318", "high": "#e47f22", "medium": "#d6a10d", "low": "#2e7d32"}.get(row.get("heat"), "#087f8c")
        x1 = center + radius * math.cos(start)
        y1 = center + radius * math.sin(start)
        x2 = center + radius * math.cos(end)
        y2 = center + radius * math.sin(end)
        lx = center + (max_radius + 17) * math.cos(mid)
        ly = center + (max_radius + 17) * math.sin(mid)
        large_arc = 1 if (end - start) > math.pi else 0
        path = f"M {center},{center} L {x1:.1f},{y1:.1f} A {radius:.1f},{radius:.1f} 0 {large_arc} 1 {x2:.1f},{y2:.1f} Z"
        wedges.append(f"<path d=\"{path}\" fill=\"{color}\" fill-opacity=\"0.70\" stroke=\"#ffffff\" stroke-width=\"2\" />")
        wedges.append(f"<text x=\"{lx:.1f}\" y=\"{ly:.1f}\" text-anchor=\"middle\" dominant-baseline=\"middle\" font-size=\"11\" font-weight=\"700\" fill=\"#172033\">{row.get('index')}</text>")
    return (
        "<figure class=\"risk-heat\"><figcaption>Radar-calor de ciberriesgos</figcaption>"
        "<svg viewBox=\"0 0 300 300\" role=\"img\" aria-label=\"Radar calor de ciberriesgos por categoria\">"
        + "".join(rings)
        + "".join(wedges)
        + "<text x=\"150\" y=\"154\" text-anchor=\"middle\" font-size=\"12\" font-weight=\"800\" fill=\"#18324d\">CDE</text>"
        + "</svg></figure>"
    )
