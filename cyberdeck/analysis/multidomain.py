from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Mapping, Sequence
from urllib.parse import urlparse

from cyberdeck.schemas import (
    AnalysisDomain,
    EvidenceStatus,
    EvidenceType,
    OrganizationProfile,
    PublicAttributionStatus,
    RiskFinding,
    RunContext,
    TechnologyDomain,
    ThreatEvent,
)


MULTIDOMAIN_MODEL_VERSION = "cde-public-footprint-v1.0.0"
PUBLIC_FOOTPRINT_DISCLAIMER_ES = (
    "Este análisis se basa en evidencia pública y observaciones externas consolidadas por "
    "CyberDecisionEngine. No constituye un inventario interno, auditoría, prueba de compromiso, "
    "confirmación de firmware instalado ni certificación de cumplimiento."
)
PUBLIC_FOOTPRINT_DISCLAIMER_EN = (
    "This analysis is based on public evidence and external observations consolidated by "
    "CyberDecisionEngine. It is not an internal inventory, audit, proof of compromise, installed "
    "firmware confirmation, or compliance certification."
)

PUBLIC_CAPABILITIES: Dict[str, Dict[str, str]] = {
    "public_web": {
        "id": "public_web_intelligence",
        "label": "CyberDecisionEngine — Inteligencia web pública",
    },
    "technology": {
        "id": "public_technology_exposure",
        "label": "CyberDecisionEngine — Exposición tecnológica pública",
    },
    "vulnerability": {
        "id": "vulnerability_intelligence",
        "label": "CyberDecisionEngine — Inteligencia de vulnerabilidades",
    },
    "threat": {
        "id": "threat_intelligence",
        "label": "CyberDecisionEngine — Inteligencia de amenazas",
    },
    "cyber_physical": {
        "id": "cyber_physical_intelligence",
        "label": "CyberDecisionEngine — Inteligencia ciberfísica",
    },
    "fraud": {
        "id": "fraud_intelligence",
        "label": "CyberDecisionEngine — Inteligencia de fraude",
    },
    "historical": {
        "id": "historical_intelligence",
        "label": "CyberDecisionEngine — Inteligencia histórica",
    },
    "corroborated": {
        "id": "corroborated_public_evidence",
        "label": "CyberDecisionEngine — Evidencia pública corroborada",
    },
}

INTERNAL_PROVIDER_PATTERNS = (
    "spiderfoot",
    "shodan",
    "censys",
    "urlscan",
    "urlscan.io",
    "kali surface",
    "sidecar",
    "onionsearch",
    "ahmia",
    "duckduckgo",
    "duckduckgo_lite",
    "brave search",
    "google cse",
    "google news rss search",
    "google_news_rss",
    "reddit public search rss",
    "reddit_rss",
    "openclaw",
    "ollama",
    "opencti",
    "alienvault",
    "virustotal",
    "greynoise",
    "abuseipdb",
    "subfinder",
    "dnsrecon",
    "sslscan",
    "wafw00f",
    "whatweb",
    "nuclei",
    "osint tools",
)

PUBLIC_TEXT_REPLACEMENTS = {
    "google news rss search": "fuente pública de noticias",
    "reddit public search rss": "fuente social pública",
    "authorized ransomware/dark-web public index": "fuente pública autorizada de amenazas",
    "ahmia tor search terms": "consulta autorizada de índices públicos",
    "urlscan.io public search": "exposición tecnológica pública",
    "spiderfoot passive sidecar": "inteligencia web pública",
    "kali surface sidecar": "exposición tecnológica pública",
    "osint tools sidecar": "inteligencia web pública",
    "openclaw": "capa de análisis",
    "ollama": "motor local de análisis",
}
_NORMALIZED_INTERNAL_PROVIDER_PATTERNS = tuple(
    re.sub(r"[^a-z0-9]+", " ", pattern.lower()).strip()
    for pattern in INTERNAL_PROVIDER_PATTERNS
)
_PUBLIC_TEXT_PATTERN = re.compile(
    "|".join(
        re.escape(pattern)
        for pattern in sorted(
            {*INTERNAL_PROVIDER_PATTERNS, *PUBLIC_TEXT_REPLACEMENTS},
            key=len,
            reverse=True,
        )
    ),
    flags=re.IGNORECASE,
)

INTERNAL_COLLECTION_HOSTS = {
    "urlscan.io",
    "api.urlscan.io",
    "search.brave.com",
    "html.duckduckgo.com",
    "ahmia.fi",
}

TECHNOLOGY_KEYWORDS: Dict[TechnologyDomain, Dict[str, Sequence[str]]] = {
    TechnologyDomain.OT: {
        "asset": ("scada", "plc", "hmi", "dcs", "rtu", "ics", "historian", "safety system", "sis"),
        "protocol": (
            "modbus",
            "dnp3",
            "opc ua",
            "opc-ua",
            "bacnet",
            "profinet",
            "ethernet/ip",
            "iec 60870",
            "iec 61850",
            "s7comm",
        ),
    },
    TechnologyDomain.IIOT: {
        "asset": (
            "iiot",
            "industrial iot",
            "industrial gateway",
            "edge gateway",
            "condition monitoring",
            "industrial sensor",
        ),
        "protocol": ("mqtt", "amqp", "coap", "lwm2m", "sparkplug"),
    },
    TechnologyDomain.IOT: {
        "asset": (
            "iot",
            "smart device",
            "camera",
            "cctv",
            "nvr",
            "dvr",
            "bms",
            "building management",
            "access control",
            "sensor",
            "kiosk",
            "pos terminal",
            "firmware",
        ),
        "protocol": ("zigbee", "z-wave", "bluetooth", "ble", "matter", "thread", "coap", "upnp"),
    },
    TechnologyDomain.IT: {
        "asset": (
            "domain",
            "dns",
            "email",
            "web",
            "server",
            "cloud",
            "api",
            "database",
            "vpn",
            "firewall",
            "identity",
            "certificate",
            "operating system",
        ),
        "protocol": (
            "http",
            "https",
            "tls",
            "ssh",
            "smtp",
            "imap",
            "ldap",
            "rdp",
            "snmp",
            "ftp",
            "smb",
        ),
    },
}

FRAUD_TYPES: Dict[str, Sequence[str]] = {
    "identity_fraud": ("identity fraud", "fraude de identidad", "identity theft", "document fraud"),
    "account_takeover": ("account takeover", "ato", "credential stuffing", "secuestro de cuenta"),
    "transaction_fraud": ("transaction fraud", "fraude transaccional", "unauthorized transaction"),
    "payment_fraud": ("payment fraud", "fraude de pago", "card fraud", "qr fraud"),
    "digital_asset_fraud": (
        "digital asset fraud",
        "crypto fraud",
        "cryptocurrency fraud",
        "wallet theft",
        "blockchain scam",
        "fraude de criptoactivos",
    ),
    "supplier_procurement_fraud": (
        "supplier fraud",
        "vendor fraud",
        "procurement fraud",
        "fraude de proveedor",
    ),
    "business_email_compromise": (
        "business email compromise",
        "bec",
        "invoice fraud",
        "fraude de factura",
    ),
    "brand_impersonation": (
        "brand impersonation",
        "suplantación de marca",
        "impersonation",
        "phishing",
    ),
    "fake_domain": ("lookalike", "typosquat", "fake domain", "dominio falso"),
    "fake_app": ("fake app", "aplicación falsa", "aplicacion falsa"),
    "fake_support": ("fake support", "soporte falso", "tech support scam"),
    "recruitment_fraud": ("recruitment fraud", "fake job", "falso empleo", "oferta laboral falsa"),
    "mule_recruitment": ("money mule", "mula de dinero", "mule recruitment"),
    "synthetic_identity": ("synthetic identity", "identidad sintética"),
    "deepfake_social_engineering": ("deepfake", "voice clone", "clonación de voz"),
    "cyber_enabled_fraud": ("cyber-enabled fraud", "scam", "estafa", "fraud"),
    "occupational_internal_fraud": ("occupational fraud", "internal fraud", "fraude interno"),
    "aml_linkage": ("money laundering", "lavado de activos", "aml", "illicit finance"),
}

SCENARIO_TEMPLATES: Sequence[Dict[str, Any]] = (
    {
        "id": "CDE-MD-001",
        "title_es": "Servicio tecnológico públicamente observado",
        "title_en": "Publicly observed technology service",
        "technology": ("it",),
        "frameworks": ("MITRE ATT&CK Enterprise", "CWE", "CAPEC"),
    },
    {
        "id": "CDE-MD-002",
        "title_es": "Dispositivo IoT públicamente observado",
        "title_en": "Publicly observed IoT device",
        "technology": ("iot",),
        "frameworks": ("MITRE EMB3D", "CWE", "CAPEC"),
    },
    {
        "id": "CDE-MD-003",
        "title_es": "Servicio industrial u OT públicamente observado",
        "title_en": "Publicly observed industrial or OT service",
        "technology": ("iiot", "ot"),
        "frameworks": ("MITRE ATT&CK ICS", "MITRE EMB3D"),
    },
    {
        "id": "CDE-MD-004",
        "title_es": "Interfaz de administración remota expuesta",
        "title_en": "Exposed remote administration interface",
        "keywords": ("admin", "remote", "rdp", "vpn", "management"),
        "frameworks": ("MITRE ATT&CK Enterprise", "MITRE D3FEND"),
    },
    {
        "id": "CDE-MD-005",
        "title_es": "Producto observado con advisory relacionado",
        "title_en": "Observed product with related advisory",
        "keywords": ("advisory", "security bulletin", "boletín"),
        "frameworks": ("CWE", "CAPEC"),
    },
    {
        "id": "CDE-MD-006",
        "title_es": "Producto y versión con vulnerabilidad aplicable",
        "title_en": "Product and version with applicable vulnerability",
        "requires_cve": True,
        "frameworks": ("CVE", "CWE", "CAPEC"),
    },
    {
        "id": "CDE-MD-007",
        "title_es": "Producto observado presente en KEV",
        "title_en": "Observed product present in KEV",
        "keywords": ("kev", "known exploited"),
        "frameworks": ("CISA KEV", "MITRE ATT&CK"),
    },
    {
        "id": "CDE-MD-008",
        "title_es": "Tecnología obsoleta o sin soporte",
        "title_en": "Obsolete or unsupported technology",
        "keywords": ("end of life", "eol", "unsupported", "obsoleto"),
        "frameworks": ("NIST CSF 2.0", "CIS Controls"),
    },
    {
        "id": "CDE-MD-009",
        "title_es": "Proveedor comprometido relacionado",
        "title_en": "Related compromised supplier",
        "keywords": ("supplier", "vendor", "supply chain", "proveedor"),
        "frameworks": ("MITRE ATT&CK Enterprise", "NIST CSF 2.0"),
    },
    {
        "id": "CDE-MD-010",
        "title_es": "IoT como posible punto de entrada a IT",
        "title_en": "IoT as a possible entry point to IT",
        "technology": ("iot", "it"),
        "cross_domain": True,
        "frameworks": ("MITRE EMB3D", "MITRE ATT&CK Enterprise"),
    },
    {
        "id": "CDE-MD-011",
        "title_es": "Transición potencial IT hacia OT",
        "title_en": "Potential IT-to-OT transition",
        "technology": ("it", "ot"),
        "cross_domain": True,
        "frameworks": ("MITRE ATT&CK Enterprise", "MITRE ATT&CK ICS"),
    },
    {
        "id": "CDE-MD-012",
        "title_es": "Campaña ATT&CK ICS relevante por sector",
        "title_en": "Sector-relevant ATT&CK ICS campaign",
        "technology": ("ot",),
        "keywords": ("campaign", "actor", "ransomware", "campaña"),
        "frameworks": ("MITRE ATT&CK ICS",),
    },
    {
        "id": "CDE-MD-013",
        "title_es": "Amenaza EMB3D relevante",
        "title_en": "Relevant EMB3D threat",
        "technology": ("iot", "iiot", "ot"),
        "frameworks": ("MITRE EMB3D",),
    },
    {
        "id": "CDE-MD-014",
        "title_es": "Exposición de BMS, CCTV o control de acceso",
        "title_en": "BMS, CCTV, or access-control exposure",
        "keywords": ("bms", "cctv", "access control", "nvr", "dvr"),
        "frameworks": ("MITRE EMB3D", "MITRE ATT&CK ICS"),
    },
    {
        "id": "CDE-MD-015",
        "title_es": "Pérdida potencial de vista o control",
        "title_en": "Potential loss of view or control",
        "technology": ("ot",),
        "keywords": ("hmi", "scada", "loss of view", "loss of control"),
        "frameworks": ("MITRE ATT&CK ICS", "MITRE D3FEND"),
    },
    {
        "id": "CDE-MD-016",
        "title_es": "Suplantación de marca",
        "title_en": "Brand impersonation",
        "fraud": ("brand_impersonation",),
        "frameworks": ("MITRE F3", "DISARM"),
    },
    {
        "id": "CDE-MD-017",
        "title_es": "Dominio o aplicación falsa",
        "title_en": "Fake domain or application",
        "fraud": ("fake_domain", "fake_app"),
        "frameworks": ("MITRE F3", "MITRE ATT&CK Enterprise"),
    },
    {
        "id": "CDE-MD-018",
        "title_es": "BEC o suplantación de proveedor",
        "title_en": "BEC or supplier impersonation",
        "fraud": ("business_email_compromise", "supplier_procurement_fraud"),
        "frameworks": ("MITRE F3", "MITRE ATT&CK Enterprise"),
    },
    {
        "id": "CDE-MD-019",
        "title_es": "Reclutamiento falso o captación de mulas",
        "title_en": "Recruitment fraud or money-mule recruitment",
        "fraud": ("recruitment_fraud", "mule_recruitment"),
        "frameworks": ("MITRE F3",),
    },
    {
        "id": "CDE-MD-020",
        "title_es": "Deepfake o suplantación ejecutiva",
        "title_en": "Deepfake or executive impersonation",
        "fraud": ("deepfake_social_engineering",),
        "frameworks": ("MITRE F3", "MITRE ATLAS"),
    },
    {
        "id": "CDE-MD-021",
        "title_es": "Fraude vinculado con kiosco, PoS, QR o canal conectado",
        "title_en": "Fraud linked to kiosk, PoS, QR, or connected channel",
        "fraud": ("payment_fraud", "transaction_fraud"),
        "technology": ("iot",),
        "frameworks": ("MITRE F3", "MITRE EMB3D"),
    },
    {
        "id": "CDE-MD-022",
        "title_es": "Cadena ciber, identidad, fraude y monetización",
        "title_en": "Cyber, identity, fraud, and monetization chain",
        "analysis": ("cyber", "fraud"),
        "cross_domain": True,
        "frameworks": ("MITRE ATT&CK Enterprise", "MITRE F3"),
    },
    {
        "id": "CDE-MD-023",
        "title_es": "Abuso de pagos o activos digitales",
        "title_en": "Digital-asset or payment-technology abuse",
        "fraud": ("digital_asset_fraud",),
        "frameworks": ("MITRE AADAPT", "MITRE F3"),
    },
    {
        "id": "CDE-MD-024",
        "title_es": "Brecha de preparación threat-informed",
        "title_en": "Threat-informed readiness gap",
        "keywords": (
            "threat-informed",
            "threat informed",
            "maturity gap",
            "coverage gap",
            "brecha de madurez",
            "brecha de cobertura",
        ),
        "frameworks": ("MITRE INFORM", "MITRE D3FEND"),
    },
    {
        "id": "CDE-MD-025",
        "title_es": "Aplicación o servicio móvil expuesto",
        "title_en": "Exposed mobile application or service",
        "keywords": ("android", "ios", "mobile app", "aplicación móvil", "aplicacion movil"),
        "frameworks": ("MITRE ATT&CK Mobile",),
    },
)


def enrich_multidomain_intelligence(
    events: Sequence[ThreatEvent],
    organization: OrganizationProfile,
) -> Dict[str, Any]:
    for event in events:
        _enrich_event(event, organization)
    relationships = _build_relationships(events)
    scenarios = _activate_scenarios(events, relationships)
    scenario_refs: Dict[str, List[str]] = defaultdict(list)
    for scenario in scenarios:
        for evidence_id in scenario["evidence_ids"]:
            scenario_refs[evidence_id].append(scenario["scenario_id"])
    for event in events:
        event.scenario_refs = sorted(set([*event.scenario_refs, *scenario_refs.get(event.id, [])]))
    return _build_summary(events, relationships, scenarios, organization)


def enrich_multidomain_findings(
    findings: Sequence[RiskFinding], events: Sequence[ThreatEvent]
) -> None:
    by_id = {event.id: event for event in events}
    by_canonical = {event.canonical_id: event for event in events if event.canonical_id}
    for finding in findings:
        linked = [by_id.get(item) or by_canonical.get(item) for item in finding.linked_evidence_ids]
        linked = [item for item in linked if item is not None]
        if not linked:
            title = finding.title.lower()
            linked = [event for event in events if event.host and event.host.lower() in title]
        domains = sorted(
            {domain for event in linked for domain in event.technology_domains},
            key=lambda item: item.value,
        )
        analyses = sorted(
            {domain for event in linked for domain in event.analysis_domains},
            key=lambda item: item.value,
        )
        frameworks = sorted({ref for event in linked for ref in event.framework_refs})
        scenarios = sorted({ref for event in linked for ref in event.scenario_refs})
        fraud_refs = sorted({ref for event in linked for ref in event.fraud_refs})
        if domains:
            finding.technology_domains = domains
            finding.primary_technology_domain = _primary_domain_from_events(linked)
            finding.technology_domain_confidence = round(
                sum(event.technology_domain_confidence for event in linked) / len(linked), 3
            )
            finding.technology_domain_basis = sorted(
                {basis for event in linked for basis in event.technology_domain_basis}
            )[:8]
        finding.analysis_domains = analyses
        finding.framework_refs = frameworks
        finding.scenario_refs = scenarios
        finding.fraud_refs = fraud_refs
        if linked:
            finding.asset_class = next(
                (event.asset_class for event in linked if event.asset_class), None
            )
        if not finding.control_inputs:
            finding.residual_risk_status = "insufficient_control_evidence"
            if (
                "No se observaron controles internos; el riesgo residual no puede confirmarse."
                not in finding.limitations
            ):
                finding.limitations.append(
                    "No se observaron controles internos; el riesgo residual no puede confirmarse."
                )


def sanitize_public_payload(
    value: Any,
    _evidence_identity_map: Mapping[str, str] | None = None,
) -> Any:
    if _evidence_identity_map is None:
        _evidence_identity_map = _collect_public_evidence_ids(value)
    if isinstance(value, Mapping):
        source_label = str(value.get("public_capability_label") or "")
        is_evidence_record = bool(
            (
                value.get("id")
                or value.get("canonical_id")
                or value.get("content_hash")
                or value.get("public_evidence_id")
            )
            and ("evidence_status" in value or "record_kind" in value)
        )
        public_evidence_id = str(value.get("public_evidence_id") or "").strip()
        if is_evidence_record and not public_evidence_id:
            seed = str(value.get("canonical_id") or value.get("content_hash") or value.get("id") or "")
            if seed:
                public_evidence_id = _public_reference_id(seed)
        result: Dict[str, Any] = {}
        for key, item in value.items():
            if str(key).startswith("internal_"):
                continue
            if is_evidence_record and key in {"canonical_id", "external_id"}:
                continue
            if is_evidence_record and key == "id" and public_evidence_id:
                result[key] = public_evidence_id
                continue
            if key == "public_evidence_id" and public_evidence_id:
                result[key] = public_evidence_id
                continue
            if isinstance(item, str) and (key == "evidence_id" or key.endswith("_evidence_id")):
                result[key] = _evidence_identity_map.get(item, _public_reference_id(item))
                continue
            if isinstance(item, (list, tuple)) and (
                key in {"evidence_ids", "event_ids"} or key.endswith("_evidence_ids")
            ):
                result[key] = [
                    _evidence_identity_map.get(str(identifier), _public_reference_id(str(identifier)))
                    for identifier in item
                    if identifier
                ]
                continue
            if key == "technical_validation" and isinstance(item, Mapping):
                item = {
                    sub_key: sub_value
                    for sub_key, sub_value in item.items()
                    if not str(sub_key).startswith("internal_")
                    and str(sub_key).lower()
                    not in {
                        "provider",
                        "connector",
                        "collector",
                        "engine",
                        "source_record_id",
                        "collection_url",
                        "raw_metadata",
                    }
                }
            if key == "tags" and isinstance(item, (list, tuple)):
                result[key] = [
                    sanitize_public_payload(tag, _evidence_identity_map)
                    for tag in item
                    if not _looks_internal_provider(str(tag))
                ]
                continue
            if key == "source" and source_label:
                result[key] = source_label
                continue
            if key == "source_refs" and source_label:
                publisher = str(value.get("original_publisher") or "").strip()
                result[key] = [publisher] if publisher else [source_label]
                continue
            if key == "evidence_url" and source_label:
                result[key] = _sanitize_public_artifact_url(
                    value.get("original_artifact_url") or item,
                    allow_collection_reference=True,
                )
                continue
            if isinstance(item, (list, tuple)) and (
                key == "urls" or key.endswith("_urls")
            ):
                result[key] = [
                    url
                    for candidate in item
                    if (
                        url := _sanitize_public_artifact_url(
                            candidate,
                            allow_collection_reference=True,
                        )
                    )
                ]
                continue
            if key in {"evidence_url", "canonical_url", "raw_reference", "original_artifact_url"}:
                replacement = value.get("original_artifact_url") if key == "evidence_url" else item
                result[key] = _sanitize_public_artifact_url(
                    replacement or item,
                    allow_collection_reference=True,
                )
                continue
            if key == "path" and isinstance(item, str) and item.startswith(("/app/", "/Users/")):
                result[key] = value.get("url") or ""
                continue
            if key == "technical_path" and isinstance(item, str) and item.startswith(("/app/", "/Users/")):
                result[key] = value.get("technical_url")
                continue
            if key == "validation_path" and isinstance(item, str) and item.startswith(("/app/", "/Users/")):
                result[key] = None
                continue
            if key == "name" and _looks_internal_provider(str(item)):
                result[key] = _public_status_label(value)
                continue
            result[key] = sanitize_public_payload(item, _evidence_identity_map)
        return result
    if isinstance(value, list):
        return [sanitize_public_payload(item, _evidence_identity_map) for item in value]
    if isinstance(value, tuple):
        return [sanitize_public_payload(item, _evidence_identity_map) for item in value]
    if isinstance(value, str):
        return _sanitize_public_text(value)
    return value


def _collect_public_evidence_ids(value: Any) -> Dict[str, str]:
    identities: Dict[str, str] = {}

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            is_evidence_record = bool(
                (item.get("id") or item.get("canonical_id") or item.get("content_hash"))
                and ("evidence_status" in item or "record_kind" in item)
            )
            if is_evidence_record:
                seed = str(item.get("canonical_id") or item.get("content_hash") or item.get("id"))
                public_id = str(item.get("public_evidence_id") or "").strip()
                if not public_id.startswith("CDE-EV-"):
                    public_id = _public_reference_id(seed)
                for key in ("id", "canonical_id", "content_hash", "external_id", "public_evidence_id"):
                    identifier = str(item.get(key) or "").strip()
                    if identifier:
                        identities[identifier] = public_id
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)

    visit(value)
    return identities


def _public_reference_id(value: str) -> str:
    if value.startswith("CDE-EV-"):
        return value
    return "CDE-EV-" + hashlib.sha256(
        value.encode("utf-8", errors="ignore")
    ).hexdigest()[:16].upper()


def _sanitize_public_artifact_url(
    value: Any,
    *,
    allow_collection_reference: bool = False,
) -> str | None:
    candidate = str(value or "").strip()
    if not candidate or any(character.isspace() for character in candidate):
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    host = parsed.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith((".local", ".internal")):
        return None
    if not allow_collection_reference and (
        _is_internal_collection_url(candidate) or _looks_internal_provider(candidate)
    ):
        return None
    return candidate


def public_source_status(status: Mapping[str, Any]) -> Dict[str, Any]:
    payload = dict(status)
    payload["name"] = _public_status_label(payload)
    payload.pop("warning", None)
    return sanitize_public_payload(payload)


def project_context_by_intelligence_filters(
    context: RunContext,
    technology_domains: Sequence[str] | None = None,
    analysis_domains: Sequence[str] | None = None,
) -> RunContext:
    """Return a report/export projection without mutating the persisted run."""
    selected_technology = _normalized_filter_values(
        technology_domains,
        {domain.value for domain in TechnologyDomain},
    )
    selected_analysis = _normalized_filter_values(
        analysis_domains,
        {domain.value for domain in AnalysisDomain},
    )
    projected = context.model_copy(deep=True)
    if not selected_technology and not selected_analysis:
        return projected

    enrich_multidomain_intelligence(projected.raw_events, projected.organization)
    enrich_multidomain_findings(projected.risk_findings, projected.raw_events)
    source_event_count = len(projected.raw_events)
    source_finding_count = len(projected.risk_findings)
    projected.raw_events = [
        event
        for event in projected.raw_events
        if _matches_filter_projection(event, selected_technology, selected_analysis)
    ]
    selected_ids = {
        identifier
        for event in projected.raw_events
        for identifier in (event.id, event.canonical_id, event.public_evidence_id)
        if identifier
    }
    projected.risk_findings = [
        finding
        for finding in projected.risk_findings
        if _finding_matches_filter_projection(
            finding, selected_ids, selected_technology, selected_analysis
        )
    ]
    projected.multidomain_intelligence = enrich_multidomain_intelligence(
        projected.raw_events,
        projected.organization,
    )
    enrich_multidomain_findings(projected.risk_findings, projected.raw_events)
    projection = {
        "technology_domains": sorted(selected_technology),
        "analysis_domains": sorted(selected_analysis),
        "source_event_count": source_event_count,
        "projected_event_count": len(projected.raw_events),
        "source_finding_count": source_finding_count,
        "projected_finding_count": len(projected.risk_findings),
        "source_snapshot_hash": context.decision_snapshot.get("snapshot_hash"),
        "mutates_source_run": False,
    }
    projected.processing_summary = {
        **projected.processing_summary,
        "raw_records_collected": len(projected.raw_events),
        "unique_records": len(projected.raw_events),
        "filtered_projection": projection,
    }
    projected.metrics = {
        **projected.metrics,
        "intelligence_filter_projection": projection,
        "multidomain_intelligence": projected.multidomain_intelligence,
        "public_technology_footprint": projected.multidomain_intelligence.get(
            "technology_footprint", {}
        ),
    }
    projected.decision_snapshot = {}
    projected.claims = []
    projected.evidence_items = []
    projected.claim_evidence_links = []
    projected.contradicting_evidence = []
    projected.interpretations = []
    projected.decisions = []
    projected.claim_evidence_model_version = ""
    return projected


def _enrich_event(event: ThreatEvent, organization: OrganizationProfile) -> None:
    source = event.source or ""
    event.internal_provider_id = event.internal_provider_id or _slug(source)
    event.internal_connector_id = event.internal_connector_id or _slug(source)
    event.internal_source_record_id = (
        event.internal_source_record_id or event.external_id or event.id
    )
    event.internal_collection_url = event.internal_collection_url or event.evidence_url
    if not event.internal_raw_metadata:
        event.internal_raw_metadata = {
            "source_refs": list(event.source_refs),
            "original_category": event.category,
        }
    capability_class = _capability_class(event)
    capability = PUBLIC_CAPABILITIES[capability_class]
    event.public_capability_id = capability["id"]
    event.public_capability_label = capability["label"]
    event.public_source_class = capability_class
    event.public_evidence_id = public_evidence_reference(event)
    event.original_publisher = event.original_publisher or _original_publisher(event)
    event.original_artifact_url = event.original_artifact_url or _public_artifact_url(
        event.evidence_url,
        event.indicator,
        event.asset,
        *(
            str(event.technical_validation.get(key) or "")
            for key in ("original_url", "target_url", "canonical_url", "url")
        ),
    )

    text = _event_text(event)
    scores: Dict[TechnologyDomain, float] = {domain: 0.0 for domain in TechnologyDomain}
    basis: Dict[TechnologyDomain, List[str]] = defaultdict(list)
    protocols: set[str] = set(event.protocols)
    for domain, groups in TECHNOLOGY_KEYWORDS.items():
        for keyword in groups["asset"]:
            if _contains(text, keyword):
                scores[domain] += 1.0
                basis[domain].append(f"asset:{keyword}")
        for protocol in groups["protocol"]:
            if _contains(text, protocol):
                scores[domain] += 1.35
                basis[domain].append(f"protocol:{protocol}")
                protocols.add(protocol.upper() if len(protocol) <= 5 else protocol)
    if event.evidence_type == EvidenceType.TECHNOLOGY_INFRASTRUCTURE:
        scores[TechnologyDomain.IT] += 0.8
        basis[TechnologyDomain.IT].append("observation:technology_infrastructure")
    if event.cve or event.cpe:
        scores[TechnologyDomain.IT] += 0.5
        basis[TechnologyDomain.IT].append("observation:vulnerability_reference")
    if max(scores.values()) <= 0 and event.host:
        scores[TechnologyDomain.IT] = 0.45
        basis[TechnologyDomain.IT].append("observation:public_host")
    ranked = sorted(
        (
            (domain, score)
            for domain, score in scores.items()
            if domain != TechnologyDomain.UNKNOWN and score > 0
        ),
        key=lambda item: (-item[1], item[0].value),
    )
    event.technology_domains = (
        [domain for domain, score in ranked if score >= max(0.45, ranked[0][1] * 0.45)]
        if ranked
        else []
    )
    event.primary_technology_domain = ranked[0][0] if ranked else TechnologyDomain.UNKNOWN
    event.technology_domain_confidence = (
        round(min(0.95, ranked[0][1] / (ranked[0][1] + 1.5)), 3) if ranked else 0.0
    )
    event.technology_domain_basis = sorted(set(basis.get(event.primary_technology_domain, [])))[:10]
    event.protocols = sorted(protocols)
    event.asset_class = event.asset_class or _asset_class(text, event)
    _copy_product_fields(event)

    analysis_domains = {AnalysisDomain.CYBER}
    fraud_refs = sorted(
        {
            fraud_type
            for fraud_type, keywords in FRAUD_TYPES.items()
            if any(_contains(text, keyword) for keyword in keywords)
        }
    )
    if fraud_refs:
        analysis_domains.add(AnalysisDomain.FRAUD)
    if any(
        _contains(text, keyword)
        for keyword in ("brand", "marca", "reputation", "reputación", "impersonation", "lookalike")
    ):
        analysis_domains.add(AnalysisDomain.BRAND)
    if any(
        _contains(text, keyword)
        for keyword in ("disinformation", "desinformación", "false narrative", "narrativa falsa")
    ):
        analysis_domains.add(AnalysisDomain.DISINFORMATION)
    if any(
        _contains(text, keyword)
        for keyword in (
            "llm",
            "prompt injection",
            "machine learning",
            "deepfake",
            "ai model",
            "modelo de ia",
        )
    ):
        analysis_domains.add(AnalysisDomain.AI_SECURITY)
    event.analysis_domains = sorted(analysis_domains, key=lambda item: item.value)
    event.fraud_refs = fraud_refs
    event.public_observation_type = _observation_type(event)
    _apply_attribution(event, organization)
    event.first_seen = event.first_seen or event.observed_at
    event.last_seen = event.last_seen or event.observed_at
    event.freshness_status = (
        "current" if event.age_days <= 30 else "recent" if event.age_days <= 90 else "historical"
    )
    event.framework_refs = _framework_refs(event)
    event.technique_refs = sorted(
        set([*event.technique_refs, *([event.technique] if event.technique else [])])
    )
    event.attack_mapping_status = _mapping_status(event)


def _copy_product_fields(event: ThreatEvent) -> None:
    technical = event.technical_validation if isinstance(event.technical_validation, dict) else {}
    for name in ("vendor", "product", "model", "firmware", "version", "cpe"):
        if getattr(event, name):
            continue
        value = technical.get(name)
        if isinstance(value, str) and value.strip():
            setattr(event, name, value.strip())


def _apply_attribution(event: ThreatEvent, organization: OrganizationProfile) -> None:
    if event.evidence_status == EvidenceStatus.FALSE_POSITIVE:
        event.public_attribution_status = PublicAttributionStatus.FALSE_POSITIVE
        event.attribution_score = 0.0
        event.attribution_basis = ["human_review:false_positive"]
        return
    scope = {item.lower().strip(".") for item in organization.primary_domains if item}
    observed = " ".join(
        filter(None, (event.host, event.asset, event.indicator, event.evidence_url))
    ).lower()
    exact_scope = any(
        domain and (domain in observed or observed.endswith(domain)) for domain in scope
    )
    relationship = (event.relationship_to_scope or "").lower()
    basis: List[str] = []
    score = 0.0
    if exact_scope:
        score += 0.45
        basis.append("scope:domain_or_asset_match")
    if relationship in {"direct", "direct_relationship", "related_to_scope", "validated"}:
        score += 0.25
        basis.append(f"relationship:{relationship}")
    elif relationship not in {"", "unassessed", "unrelated"}:
        score += 0.1
        basis.append(f"relationship:{relationship}")
    if event.evidence_status in {
        EvidenceStatus.DIRECT,
        EvidenceStatus.VALIDATED,
        EvidenceStatus.CONFIRMED,
    }:
        score += 0.2
        basis.append(f"evidence:{event.evidence_status.value}")
    independent_sources = len({item for item in event.source_refs if item})
    if independent_sources >= 2:
        score += 0.1
        basis.append("corroboration:multiple_public_records")
    if event.evidence_status in {
        EvidenceStatus.RAW,
        EvidenceStatus.CONTEXTUAL,
        EvidenceStatus.POTENTIAL,
    }:
        score = min(score, 0.34)
        basis.append("gate:evidence_not_direct")
    elif event.evidence_status == EvidenceStatus.RELATED:
        score = min(score, 0.59)
        basis.append("gate:evidence_related_only")
    event.attribution_score = round(min(0.95, score), 3)
    event.attribution_basis = basis or ["scope:unattributed"]
    if score >= 0.85 and independent_sources >= 2:
        event.public_attribution_status = PublicAttributionStatus.CORROBORATED_PUBLIC
    elif score >= 0.6:
        event.public_attribution_status = PublicAttributionStatus.OBSERVED_PUBLIC
    elif score >= 0.35:
        event.public_attribution_status = PublicAttributionStatus.RELATED
    elif score > 0:
        event.public_attribution_status = PublicAttributionStatus.POSSIBLE
    else:
        event.public_attribution_status = PublicAttributionStatus.UNATTRIBUTED
    if event.public_attribution_status in {
        PublicAttributionStatus.UNATTRIBUTED,
        PublicAttributionStatus.POSSIBLE,
    }:
        event.limitations = sorted(
            set([*event.limitations, "La relación con el alcance requiere validación adicional."])
        )


def _framework_refs(event: ThreatEvent) -> List[str]:
    refs: set[str] = {"NIST CSF 2.0", "CIS Controls", "COBIT", "ISO/IEC 27001"}
    domains = set(event.technology_domains)
    if TechnologyDomain.IT in domains:
        refs.update(("MITRE ATT&CK Enterprise", "MITRE D3FEND", "CWE", "CAPEC"))
    if domains & {TechnologyDomain.IOT, TechnologyDomain.IIOT, TechnologyDomain.OT}:
        refs.update(("MITRE EMB3D 2.0.2", "CWE", "CAPEC"))
    if domains & {TechnologyDomain.IIOT, TechnologyDomain.OT}:
        refs.update(("MITRE ATT&CK ICS", "MITRE D3FEND"))
    if event.fraud_refs:
        refs.add("MITRE Fight Fraud Framework (F3) 1.1")
    if AnalysisDomain.DISINFORMATION in event.analysis_domains:
        refs.add("DISARM")
    if AnalysisDomain.AI_SECURITY in event.analysis_domains:
        refs.add("MITRE ATLAS")
    return sorted(refs)


def _mapping_status(event: ThreatEvent) -> str:
    if not event.framework_refs:
        return "not_applicable"
    if event.evidence_status == EvidenceStatus.CONFIRMED and event.incident_confirmed:
        return "validated"
    if (
        event.evidence_status in {EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        and event.technique
    ):
        return "observed_behavior"
    if event.evidence_status in {
        EvidenceStatus.DIRECT,
        EvidenceStatus.VALIDATED,
        EvidenceStatus.CONFIRMED,
    }:
        return "evidence_supported_candidate"
    if event.public_attribution_status in {
        PublicAttributionStatus.RELATED,
        PublicAttributionStatus.OBSERVED_PUBLIC,
    }:
        return "potentially_relevant"
    return "preventive_reference"


def _build_relationships(events: Sequence[ThreatEvent]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[ThreatEvent]] = defaultdict(list)
    for event in events:
        key = (event.host or event.asset or event.indicator or "").strip().lower()
        if key:
            grouped[key].append(event)
    relationships: List[Dict[str, Any]] = []
    for entity, rows in grouped.items():
        technology = sorted({domain.value for row in rows for domain in row.technology_domains})
        analysis = sorted({domain.value for row in rows for domain in row.analysis_domains})
        if len(rows) < 2 and len(technology) < 2 and len(analysis) < 2:
            continue
        evidence_ids = sorted({row.id for row in rows})
        relationships.append(
            {
                "relationship_id": "REL-"
                + hashlib.sha256(f"{entity}|{'|'.join(evidence_ids)}".encode()).hexdigest()[:12],
                "entity": entity,
                "technology_domains": technology,
                "analysis_domains": analysis,
                "evidence_ids": evidence_ids,
                "confidence": round(sum(row.attribution_score for row in rows) / len(rows), 3),
                "basis": "shared_observed_entity",
                "limitations": []
                if len(evidence_ids) >= 2
                else ["Relación sustentada por una sola observación pública."],
            }
        )
    return sorted(relationships, key=lambda item: (-item["confidence"], item["entity"]))


def _activate_scenarios(
    events: Sequence[ThreatEvent], relationships: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    assured = [
        event
        for event in events
        if event.evidence_status
        in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
        and event.public_attribution_status
        not in {PublicAttributionStatus.UNATTRIBUTED, PublicAttributionStatus.FALSE_POSITIVE}
    ]
    cross_domain_entities = {
        row["entity"]
        for row in relationships
        if len(row.get("technology_domains", [])) > 1 or len(row.get("analysis_domains", [])) > 1
    }
    matches: List[Dict[str, Any]] = []
    for template in SCENARIO_TEMPLATES:
        evidence: List[ThreatEvent] = []
        for event in assured:
            text = _event_text(event)
            technology = {domain.value for domain in event.technology_domains}
            analysis = {domain.value for domain in event.analysis_domains}
            if template.get("technology") and not technology.intersection(template["technology"]):
                continue
            if template.get("analysis") and not set(template["analysis"]).issubset(analysis):
                continue
            if template.get("fraud") and not set(event.fraud_refs).intersection(template["fraud"]):
                continue
            if template.get("keywords") and not any(
                _contains(text, keyword) for keyword in template["keywords"]
            ):
                continue
            if template.get("requires_cve") and not (event.cve and (event.version or event.cpe)):
                continue
            if template.get("cross_domain"):
                entity = (event.host or event.asset or event.indicator or "").lower()
                if entity not in cross_domain_entities and not (
                    len(technology) > 1 or len(analysis) > 1
                ):
                    continue
            evidence.append(event)
        if not evidence:
            continue
        evidence_ids = sorted({event.id for event in evidence})
        confidence = round(
            min(0.95, sum(event.attribution_score for event in evidence) / len(evidence)), 3
        )
        matches.append(
            {
                "scenario_id": template["id"],
                "title_es": template["title_es"],
                "title_en": template["title_en"],
                "status": "evidence_supported_candidate",
                "technology_domains": sorted(
                    {domain.value for event in evidence for domain in event.technology_domains}
                ),
                "analysis_domains": sorted(
                    {domain.value for event in evidence for domain in event.analysis_domains}
                ),
                "framework_refs": list(template["frameworks"]),
                "evidence_ids": evidence_ids,
                "confidence": confidence,
                "decision_question_es": "¿La evidencia atribuida justifica validar el activo, el contexto operativo y los controles antes de decidir tratamiento?",
                "decision_question_en": "Does attributed evidence justify validating the asset, operational context, and controls before deciding treatment?",
                "limitations": [
                    "Escenario candidato; no confirma incidente, compromiso ni explotación."
                ],
            }
        )
    return matches


def _build_summary(
    events: Sequence[ThreatEvent],
    relationships: Sequence[Dict[str, Any]],
    scenarios: Sequence[Dict[str, Any]],
    organization: OrganizationProfile,
) -> Dict[str, Any]:
    relevant = [
        event for event in events if event.primary_technology_domain != TechnologyDomain.UNKNOWN
    ]
    assured = [
        event
        for event in relevant
        if event.evidence_status
        in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    attributed = [
        event
        for event in relevant
        if event.public_attribution_status
        in {
            PublicAttributionStatus.RELATED,
            PublicAttributionStatus.OBSERVED_PUBLIC,
            PublicAttributionStatus.CORROBORATED_PUBLIC,
        }
    ]
    source_classes = {event.public_source_class for event in relevant}
    counts = Counter(event.primary_technology_domain.value for event in relevant)
    analysis_counts = Counter(domain.value for event in events for domain in event.analysis_domains)
    independent_factor = min(1.0, len(source_classes) / 4)
    coverage = min(
        1.0,
        len({event.host or event.asset for event in relevant if event.host or event.asset})
        / max(1, len(organization.primary_domains)),
    )
    assurance = len(assured) / len(relevant) if relevant else 0.0
    attribution = len(attributed) / len(relevant) if relevant else 0.0
    presence_score = (
        round(100 * (0.45 * coverage + 0.35 * assurance + 0.20 * independent_factor), 2)
        if relevant
        else None
    )
    attribution_score = (
        round(100 * sum(event.attribution_score for event in relevant) / len(relevant), 2)
        if relevant
        else None
    )
    exposure_index = (
        round(100 * (0.45 * assurance + 0.35 * attribution + 0.20 * independent_factor), 2)
        if relevant
        else None
    )
    domain_sufficiency = (
        round(100 * (0.5 * assurance + 0.3 * attribution + 0.2 * independent_factor), 2)
        if relevant
        else None
    )
    ot_rows = [
        event
        for event in assured
        if set(event.technology_domains)
        & {TechnologyDomain.OT, TechnologyDomain.IIOT, TechnologyDomain.IOT}
    ]
    fraud_rows = [
        event
        for event in events
        if event.fraud_refs
        and event.evidence_status
        in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    ot_pressure = _bounded_pressure(ot_rows)
    fraud_pressure = _bounded_pressure(fraud_rows)
    technology_rows = []
    for domain in (
        TechnologyDomain.IT,
        TechnologyDomain.IOT,
        TechnologyDomain.IIOT,
        TechnologyDomain.OT,
        TechnologyDomain.UNKNOWN,
    ):
        rows = [event for event in events if event.primary_technology_domain == domain]
        if not rows:
            continue
        technology_rows.append(
            {
                "domain": domain.value,
                "records": len(rows),
                "assured_records": sum(
                    event.evidence_status
                    in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
                    for event in rows
                ),
                "attributed_records": sum(
                    event.public_attribution_status
                    in {
                        PublicAttributionStatus.RELATED,
                        PublicAttributionStatus.OBSERVED_PUBLIC,
                        PublicAttributionStatus.CORROBORATED_PUBLIC,
                    }
                    for event in rows
                ),
                "assets": sorted(
                    {event.host or event.asset for event in rows if event.host or event.asset}
                )[:50],
                "protocols": sorted({protocol for event in rows for protocol in event.protocols}),
                "vendors": sorted({event.vendor for event in rows if event.vendor}),
                "products": sorted({event.product for event in rows if event.product}),
                "framework_refs": sorted({ref for event in rows for ref in event.framework_refs}),
                "evidence_ids": [event.id for event in rows],
            }
        )
    return {
        "model_version": MULTIDOMAIN_MODEL_VERSION,
        "taxonomy": {
            "technology_domains": [domain.value for domain in TechnologyDomain],
            "analysis_domains": [domain.value for domain in AnalysisDomain],
            "fraud_types": sorted(FRAUD_TYPES),
            "attribution_states": [status.value for status in PublicAttributionStatus],
        },
        "technology_footprint": {
            "status": "calculated" if relevant else "no_data",
            "total_records": len(relevant),
            "assured_records": len(assured),
            "attributed_records": len(attributed),
            "domain_counts": dict(counts),
            "rows": technology_rows,
        },
        "analysis_dimensions": dict(analysis_counts),
        "relationships": list(relationships),
        "scenario_templates": len(SCENARIO_TEMPLATES),
        "scenario_candidates": list(scenarios),
        "method_scores": {
            "public_technology_presence": _metric(presence_score, "public_technology_presence_v1"),
            "public_attribution": _metric(attribution_score, "public_attribution_v1"),
            "public_exposure_intelligence": _metric(
                exposure_index, "public_exposure_intelligence_v1"
            ),
            "domain_evidence_sufficiency": _metric(
                domain_sufficiency, "domain_evidence_sufficiency_v1"
            ),
            "ot_iot_signal_pressure": _metric(ot_pressure, "ot_iot_signal_pressure_v1"),
            "fraud_signal_pressure": _metric(fraud_pressure, "fraud_signal_pressure_v1"),
            "cross_domain_scenario_relevance": _metric(
                round(100 * len(scenarios) / max(1, len(SCENARIO_TEMPLATES)), 2)
                if scenarios
                else (0.0 if assured else None),
                "cross_domain_scenario_relevance_v1",
            ),
        },
        "disclaimer_es": PUBLIC_FOOTPRINT_DISCLAIMER_ES,
        "disclaimer_en": PUBLIC_FOOTPRINT_DISCLAIMER_EN,
    }


def _metric(value: float | None, version: str) -> Dict[str, Any]:
    return {
        "value": value,
        "value_status": "valid_value"
        if value is not None and value > 0
        else "observed_zero"
        if value == 0
        else "no_data",
        "unit": "index_points",
        "range": [0, 100],
        "model_version": version,
        "calibrated_probability": False,
    }


def _bounded_pressure(events: Sequence[ThreatEvent]) -> float | None:
    if not events:
        return None
    signal = sum(
        max(0.05, event.confidence_score) * math.exp(-math.log(2) * max(0, event.age_days) / 30)
        for event in events
    )
    return round(100 * (1 - math.exp(-0.28 * signal)), 2)


def _primary_domain_from_events(events: Sequence[ThreatEvent]) -> TechnologyDomain:
    counts = Counter(event.primary_technology_domain for event in events)
    return counts.most_common(1)[0][0] if counts else TechnologyDomain.UNKNOWN


def _event_text(event: ThreatEvent) -> str:
    technical = event.technical_validation if isinstance(event.technical_validation, dict) else {}
    safe_technical = " ".join(
        str(technical.get(key) or "")
        for key in (
            "vendor",
            "product",
            "model",
            "firmware",
            "version",
            "cpe",
            "protocol",
            "service",
            "technology",
        )
    )
    return " ".join(
        filter(
            None,
            (
                event.title,
                event.category,
                " ".join(event.tags),
                event.asset or "",
                event.host or "",
                event.indicator or "",
                event.technique or "",
                event.cve or "",
                safe_technical,
            ),
        )
    ).lower()


def _contains(text: str, keyword: str) -> bool:
    if len(keyword) <= 3 and keyword.isalnum():
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(keyword.lower())}(?![a-z0-9])", text))
    return keyword.lower() in text


def _capability_class(event: ThreatEvent) -> str:
    if event.evidence_type == EvidenceType.AUTHORIZED_DARK_WEB:
        return "threat"
    if (
        event.cve
        or event.evidence_type == EvidenceType.OFFICIAL_RECORD
        and "vulner" in event.category.lower()
    ):
        return "vulnerability"
    if event.evidence_type == EvidenceType.TECHNOLOGY_INFRASTRUCTURE:
        return "technology"
    if any(
        token in event.category.lower() for token in ("fraud", "brand", "phishing", "lookalike")
    ):
        return "fraud"
    if any(token in event.category.lower() for token in ("threat", "actor", "campaign", "malware")):
        return "threat"
    return "public_web"


def _original_publisher(event: ThreatEvent) -> str | None:
    source = (event.source or "").strip()
    if source and not _looks_internal_provider(source):
        return source
    hostname = (urlparse(event.evidence_url or "").hostname or "").lower()
    if (
        hostname
        and hostname not in INTERNAL_COLLECTION_HOSTS
        and not any(hostname.endswith(f".{host}") for host in INTERNAL_COLLECTION_HOSTS)
    ):
        return hostname.removeprefix("www.")
    return None


def _public_artifact_url(*values: str | None) -> str | None:
    for value in values:
        if not value or not re.match(r"^https?://", value, flags=re.IGNORECASE):
            continue
        hostname = (urlparse(value).hostname or "").lower()
        if hostname in INTERNAL_COLLECTION_HOSTS or any(
            hostname.endswith(f".{host}") for host in INTERNAL_COLLECTION_HOSTS
        ):
            continue
        return value
    return None


def _observation_type(event: ThreatEvent) -> str:
    if event.cve:
        return "vulnerability_reference"
    if event.evidence_type == EvidenceType.TECHNOLOGY_INFRASTRUCTURE:
        return "public_technology_observation"
    if event.evidence_type == EvidenceType.SOCIAL_MEDIA:
        return "public_social_mention"
    if event.evidence_type == EvidenceType.NEWS:
        return "public_news_record"
    if event.evidence_type == EvidenceType.DOCUMENT:
        return "public_document"
    return "public_record"


def _asset_class(text: str, event: ThreatEvent) -> str:
    for label, keywords in (
        ("industrial_control", ("scada", "plc", "hmi", "dcs", "rtu")),
        ("building_or_physical_security", ("bms", "cctv", "access control", "nvr", "dvr")),
        ("connected_device", ("iot", "sensor", "camera", "firmware")),
        ("network_service", ("dns", "vpn", "ssh", "rdp", "smtp", "tls")),
        ("web_application", ("web", "http", "api", "application")),
    ):
        if any(_contains(text, keyword) for keyword in keywords):
            return label
    return "public_entity" if event.host or event.asset else "context_record"


def public_evidence_reference(event: ThreatEvent) -> str:
    """Return the stable public identifier for one normalized evidence record."""
    seed = event.canonical_id or event.content_hash or event.id
    return _public_reference_id(seed)


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug or "internal_collector"


def _looks_internal_provider(value: str) -> bool:
    lowered = value.lower()
    normalized = re.sub(r"[^a-z0-9]+", " ", lowered).strip()
    return any(
        pattern in lowered or normalized_pattern in normalized
        for pattern, normalized_pattern in zip(
            INTERNAL_PROVIDER_PATTERNS,
            _NORMALIZED_INTERNAL_PROVIDER_PATTERNS,
        )
    )


def _is_internal_collection_url(value: str) -> bool:
    if not value:
        return False
    try:
        host = (urlparse(value).hostname or "").lower()
    except ValueError:
        return False
    return host in INTERNAL_COLLECTION_HOSTS or _looks_internal_provider(host)


def _public_status_label(status: Mapping[str, Any]) -> str:
    text = " ".join(str(status.get(key) or "") for key in ("name", "mode", "status")).lower()
    if any(token in text for token in ("vulner", "nvd", "epss", "kev", "cve")):
        return PUBLIC_CAPABILITIES["vulnerability"]["label"]
    if any(token in text for token in ("dark", "tor", "onion", "ransomware")):
        return PUBLIC_CAPABILITIES["threat"]["label"]
    if any(
        token in text
        for token in (
            "surface",
            "dns",
            "certificate",
            "technology",
            "spider",
            "shodan",
            "censys",
            "urlscan",
        )
    ):
        return PUBLIC_CAPABILITIES["technology"]["label"]
    if any(token in text for token in ("fraud", "brand", "socmint")):
        return PUBLIC_CAPABILITIES["fraud"]["label"]
    if any(token in text for token in ("cache", "histor")):
        return PUBLIC_CAPABILITIES["historical"]["label"]
    return PUBLIC_CAPABILITIES["public_web"]["label"]


def _sanitize_public_text(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return PUBLIC_TEXT_REPLACEMENTS.get(
            match.group(0).lower(),
            "capacidad de inteligencia pública",
        )

    return _PUBLIC_TEXT_PATTERN.sub(replace, value)


def _normalized_filter_values(values: Sequence[str] | None, allowed: set[str]) -> set[str]:
    if not values:
        return set()
    normalized = {str(value).strip().lower() for value in values if str(value).strip()}
    if "all" in normalized or "todos" in normalized:
        return set()
    return normalized.intersection(allowed)


def _matches_filter_projection(
    event: ThreatEvent,
    technology_domains: set[str],
    analysis_domains: set[str],
) -> bool:
    event_technology = {domain.value for domain in event.technology_domains}
    if not event_technology:
        event_technology = {event.primary_technology_domain.value}
    event_analysis = {domain.value for domain in event.analysis_domains} or {
        AnalysisDomain.CYBER.value
    }
    return (not technology_domains or bool(event_technology.intersection(technology_domains))) and (
        not analysis_domains or bool(event_analysis.intersection(analysis_domains))
    )


def _finding_matches_filter_projection(
    finding: RiskFinding,
    selected_ids: set[str],
    technology_domains: set[str],
    analysis_domains: set[str],
) -> bool:
    linked = set(finding.linked_evidence_ids)
    if linked and not linked.intersection(selected_ids):
        return False
    finding_technology = {domain.value for domain in finding.technology_domains}
    if not finding_technology:
        finding_technology = {finding.primary_technology_domain.value}
    finding_analysis = {domain.value for domain in finding.analysis_domains} or {
        AnalysisDomain.CYBER.value
    }
    return (
        not technology_domains or bool(finding_technology.intersection(technology_domains))
    ) and (not analysis_domains or bool(finding_analysis.intersection(analysis_domains)))
