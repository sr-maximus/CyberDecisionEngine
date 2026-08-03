from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List

from cyberdeck.schemas import EvidenceStatus, SourceStatus, ThreatEvent


def build_actor_profile(events: Iterable[ThreatEvent]) -> Dict[str, object]:
    counter = Counter((event.actor or "unattributed") for event in events)
    rows = []
    for actor, count in counter.most_common(12):
        actor_events = [event for event in events if (event.actor or "unattributed") == actor]
        rows.append(
            {
                "actor": actor,
                "count": count,
                "confidence": "extraido de fuente" if actor not in {"unknown", "unattributed"} else "no atribuido por la fuente publica",
                "sources": sorted({event.source for event in actor_events})[:5],
                "patterns": sorted({event.category for event in actor_events})[:5],
            }
        )
    return {
        "rows": rows,
        "purpose": "La vista de actores separa atribucion real de eventos no atribuidos. Si la fuente publica no nombra actor, el informe conserva 'unattributed' en vez de inventar grupos.",
    }


def build_pattern_profile(events: Iterable[ThreatEvent]) -> Dict[str, object]:
    event_list = list(events)
    categories = Counter(event.category for event in event_list)
    sources = Counter(event.source for event in event_list)
    techniques = Counter(event.technique or "unmapped" for event in event_list)
    tags = Counter(tag for event in event_list for tag in event.tags)
    patterns: List[Dict[str, object]] = []
    if categories.get("vulnerability", 0):
        patterns.append({"name": "Explotacion y vulnerabilidades priorizadas", "count": categories["vulnerability"], "meaning": "Alta relacion con KEV, EPSS, NVD y advisories de software; prioriza patching y exposicion externa."})
    if categories.get("phishing", 0) or tags.get("fraud", 0):
        patterns.append({"name": "Fraude, phishing o suplantacion", "count": categories.get("phishing", 0) + tags.get("fraud", 0), "meaning": "Afecta canales digitales, identidad, clientes y monitoreo transaccional."})
    if tags.get("ransomware_signal", 0):
        patterns.append({"name": "Senal asociada a ransomware", "count": tags["ransomware_signal"], "meaning": "CISA KEV marca uso conocido en campanas ransomware; refuerza backups, segmentacion y respuesta."})
    return {
        "patterns": patterns,
        "top_sources": [{"name": key, "count": value} for key, value in sources.most_common(8)],
        "top_techniques": [{"name": key, "count": value} for key, value in techniques.most_common(8)],
        "purpose": "Los patrones resumen concentraciones repetidas por tipo de amenaza, fuente y tecnica; sirven para decidir donde invertir primero.",
    }


def build_source_coverage(statuses: Iterable[SourceStatus], events: Iterable[ThreatEvent]) -> Dict[str, object]:
    status_list = list(statuses)
    event_list = list(events)
    socmint_status = [_status_dict(status) for status in status_list if "SOCMINT" in status.name]
    darkweb_status = [
        _status_dict(status)
        for status in status_list
        if "dark web" in status.name.lower()
        or "tor" in status.name.lower()
        or status.name in {"MISP", "STIX/TAXII"}
    ]
    osint_status = [
        _status_dict(status)
        for status in status_list
        if status.name in {"CISA KEV", "RSS CTI", "GitHub Security Advisories", "FIRST EPSS", "NVD"}
        or "busqueda publica" in status.name.lower()
        or "indice publico" in status.name.lower()
        or "OTX" in status.name
        or "OSINT" in status.name
    ]
    web_layers = _web_layer_map(status_list, event_list)
    relevant_statuses = [status for status in status_list if status.eligible]
    coverage_score = _average(relevant_statuses, "coverage_score")
    source_health_score = _average(relevant_statuses, "source_health_score")
    source_completeness_score = _average(relevant_statuses, "source_completeness_score")
    socmint_events = [event for event in event_list if _is_socmint_record(event)]
    darkweb_events = [event for event in event_list if _is_darkweb_record(event)]
    osint_events = [event for event in event_list if not _is_darkweb_record(event)]
    unique_records = len({event.canonical_id or event.id for event in event_list})
    return {
        "unique_records": unique_records,
        "coverage_score": coverage_score,
        "source_health_score": source_health_score,
        "source_completeness_score": source_completeness_score,
        "interpretation": "Cobertura usa solo conectores elegibles; salud mide ejecucion tecnica y productividad indica conectores que aportaron registros normalizados. Sin datos no equivale a ausencia de riesgo.",
        "source_lifecycle": _source_lifecycle(status_list),
        "connector_diagnostics": _connector_diagnostics(status_list),
        "scraping_assessment": _scraping_assessment(event_list, status_list),
        "connectors": [_status_dict(status) for status in status_list],
        "osint": {
            "records": len(osint_events),
            "records_queried": sum(int(status.get("records", 0)) for status in osint_status),
            "records_retrieved": len(osint_events),
            "unique_records": len({event.canonical_id or event.id for event in osint_events}),
            "statuses": osint_status,
            "purpose": "OSINT consolida fuentes abiertas y gratuitas: busquedas web/noticias, advisories, RSS tecnicos, CISA KEV, NVD, EPSS y GitHub Security Advisories. Sirve para cibervigilancia temprana sin intrusividad.",
        },
        "socmint": {
            "records": len(socmint_events),
            "records_queried": sum(int(status.get("records", 0)) for status in socmint_status),
            "records_retrieved": len(socmint_events),
            "unique_records": len({event.canonical_id or event.id for event in socmint_events}),
            "statuses": socmint_status,
            "related_public_records": sum(
                1
                for event in socmint_events
                if event.evidence_status in {EvidenceStatus.RELATED, EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
            ),
            "direct_or_validated_records": sum(
                1
                for event in socmint_events
                if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
            ),
            "purpose": "SOCMINT aporta senales publicas de marca, fraude, phishing y conversacion agregada. En modo real-only no se hace scraping social; solo APIs/RSS publicos autorizados.",
        },
        "darkweb": {
            "records": len(darkweb_events),
            "records_queried": sum(int(status.get("records", 0)) for status in darkweb_status),
            "records_retrieved": len(darkweb_events),
            "unique_records": len({event.canonical_id or event.id for event in darkweb_events}),
            "related_records": sum(1 for event in darkweb_events if event.evidence_status == EvidenceStatus.RELATED),
            "direct_or_validated_records": sum(
                1
                for event in darkweb_events
                if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
            ),
            "confirmed_incidents": sum(1 for event in darkweb_events if event.incident_confirmed),
            "statuses": darkweb_status,
            "purpose": "Dark Web usa metadatos autorizados e indices publicos de inteligencia ransomware/darkweb. Tor directo, foros privados, credenciales y datos robados quedan fuera de alcance salvo habilitacion explicita y archivo redacted autorizado.",
        },
        "web_layers": web_layers,
    }


def _status_dict(status: SourceStatus) -> Dict[str, object]:
    if hasattr(status, "model_dump"):
        return status.model_dump()
    return status.dict()


def _average(statuses: List[SourceStatus], field: str) -> float:
    if not statuses:
        return 0.0
    return round(sum(float(getattr(status, field, 0.0)) for status in statuses) / len(statuses), 4)


def _source_lifecycle(statuses: List[SourceStatus]) -> Dict[str, object]:
    eligible = sum(1 for status in statuses if status.eligible)
    attempted = sum(1 for status in statuses if status.attempted)
    productive = sum(1 for status in statuses if status.productive)
    succeeded = sum(1 for status in statuses if status.succeeded)
    return {
        "registered": len(statuses),
        "configured": sum(1 for status in statuses if status.configured),
        "enabled": sum(1 for status in statuses if status.enabled),
        "eligible": eligible,
        "attempted": attempted,
        "succeeded": succeeded,
        "productive": productive,
        "empty": sum(1 for status in statuses if status.empty),
        "degraded": sum(1 for status in statuses if status.degraded),
        "failed": sum(1 for status in statuses if status.failed),
        "skipped": sum(1 for status in statuses if status.skipped),
        "disabled": sum(1 for status in statuses if status.disabled),
        "unconfigured": sum(1 for status in statuses if status.unconfigured),
        "attempted_ratio": round(attempted / eligible, 4) if eligible else None,
        "success_ratio": round(succeeded / attempted, 4) if attempted else None,
        "productive_ratio": round(productive / attempted, 4) if attempted else None,
        "denominator": "eligible",
    }


def _connector_diagnostics(statuses: List[SourceStatus]) -> Dict[str, object]:
    rows: List[Dict[str, object]] = []
    causes = Counter()
    for status in statuses:
        if status.rate_limited:
            issue = "rate_limited"
            action = "Reanudar con backoff desde el último checkpoint."
            retryable = True
        elif status.timed_out:
            issue = "timed_out"
            action = "Reanudar el conector sin descartar los registros ya persistidos."
            retryable = True
        elif status.failed:
            issue = "failed"
            action = "Revisar el error del conector antes del siguiente ciclo."
            retryable = True
        elif status.unconfigured:
            issue = "unconfigured"
            action = "Configurar credenciales solo si la fuente aporta cobertura adicional."
            retryable = False
        elif status.empty and status.attempted:
            issue = "empty"
            action = "Mantener como consulta exitosa sin datos; no convertirla en cero de riesgo."
            retryable = False
        elif status.degraded:
            issue = "degraded"
            action = "Conservar resultados parciales y reanudar en el siguiente ciclo."
            retryable = True
        else:
            continue
        causes[issue] += 1
        rows.append(
            {
                "connector": status.name,
                "issue": issue,
                "records": status.records,
                "retryable": retryable,
                "action": action,
                "warning": status.warning,
            }
        )
    return {
        "issue_count": len(rows),
        "retryable_count": sum(1 for row in rows if row["retryable"]),
        "by_cause": dict(sorted(causes.items())),
        "rows": rows,
        "risk_effect": "none",
        "interpretation": (
            "Los fallos operativos reducen cobertura y confianza; nunca incrementan riesgo ni se interpretan "
            "como ausencia de señales."
        ),
    }


def _scraping_assessment(events: List[ThreatEvent], statuses: List[SourceStatus]) -> Dict[str, object]:
    scraping_tokens = {
        "busqueda publica",
        "common crawl",
        "indice publico",
        "evidencia web",
        "inventario pasivo",
        "spiderfoot",
        "socmint",
    }
    records = [
        event
        for event in events
        if any(token in f"{event.source} {event.category} {' '.join(event.tags)}".lower() for token in scraping_tokens)
    ]
    unique_urls = {event.evidence_url for event in records if event.evidence_url}
    validated = [
        event
        for event in records
        if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    related = [
        event
        for event in records
        if event.evidence_status in {EvidenceStatus.RELATED, EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    connector_names = {
        status.name
        for status in statuses
        if any(token in status.name.lower() for token in scraping_tokens)
    }
    return {
        "records": len(records),
        "unique_urls": len(unique_urls),
        "related_records": len(related),
        "direct_or_validated_records": len(validated),
        "connector_count": len(connector_names),
        "validation_yield": round(len(validated) / len(records), 4) if records else None,
        "contribution": [
            "descubrimiento de activos y entidades",
            "corroboración entre fuentes",
            "contexto temporal y reputacional",
        ],
        "risk_effect": (
            "supports_risk_only_when_validated_and_scope_related"
            if validated
            else "coverage_only"
        ),
        "interpretation": (
            "El scraping amplía cobertura. Solo registros relacionados con el alcance y validados pueden sustentar "
            "un hallazgo o un factor de riesgo."
        ),
    }


def _is_socmint_record(event: ThreatEvent) -> bool:
    tags = {tag.lower() for tag in event.tags}
    return event.category == "social_signal" or "socmint_public" in tags or "social_profile" in tags


def _is_darkweb_record(event: ThreatEvent) -> bool:
    tags = {tag.lower() for tag in event.tags}
    source = event.source.lower()
    url = (event.evidence_url or "").lower()
    return (
        any(token in source for token in ("dark web", "darkweb", "onion", "ransomware index"))
        or any(token in tags for token in ("darkweb", "dark_web", "onion", "tor_result", "ransomware_victim"))
        or ".onion" in url
    )


def _web_layer_map(statuses: Iterable[SourceStatus], events: Iterable[ThreatEvent]) -> Dict[str, Dict[str, object]]:
    status_list = list(statuses)
    event_list = list(events)
    layers = {
        "surface": {"label": "Surface Web", "records": 0, "sources": set(), "status_records": 0},
        "deep": {"label": "Deep Web", "records": 0, "sources": set(), "status_records": 0},
        "dark": {"label": "Dark Web", "records": 0, "sources": set(), "status_records": 0},
    }
    for status in status_list:
        layer_key = _web_layer_for_text(status.name, "")
        layers[layer_key]["status_records"] = int(layers[layer_key]["status_records"]) + int(status.records or 0)
        layers[layer_key]["sources"].add(status.name)
    for event in event_list:
        layer_key = _web_layer_for_text(event.source, f"{event.category} {' '.join(event.tags)}")
        layers[layer_key]["records"] = int(layers[layer_key]["records"]) + 1
        layers[layer_key]["sources"].add(event.source)
    descriptions = {
        "surface": "Fuentes indexadas publicamente: noticias, buscadores, advisories, RSS, CTI publica y superficie externa pasiva.",
        "deep": "Indices publicos no siempre visibles en una busqueda comun: Common Crawl, documentos indexados y registros pasivos.",
        "dark": "Indices autorizados de dark web, ransomware, TOR runtime y plataformas CTI configuradas; no implica acceso a foros privados.",
    }
    return {
        key: {
            "label": value["label"],
            "records": int(value["records"]),
            "status_records": int(value["status_records"]),
            "sources": sorted(value["sources"])[:10],
            "description": descriptions[key],
        }
        for key, value in layers.items()
    }


def _web_layer_for_text(source: str, evidence: str) -> str:
    text = f"{source} {evidence}".lower()
    if any(token in text for token in ("dark web", "darkweb", "ransomware index", "tor_result", ".onion")):
        return "dark"
    if any(token in text for token in ("common crawl", "document", "archivo", "pdf", "indexed_file", "public_document", "document_index")):
        return "deep"
    return "surface"
