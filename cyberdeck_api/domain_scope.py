from __future__ import annotations

import copy
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import urlsplit

from cyberdeck_api.models import DomainAnalysisRequest


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    if not candidate:
        raise ValueError("Domain cannot be empty.")
    if "://" in candidate:
        candidate = urlsplit(candidate).netloc
    else:
        candidate = candidate.split("/", 1)[0]
    candidate = candidate.split("?", 1)[0].split("#", 1)[0]
    candidate = candidate.lstrip("@").removeprefix("www.").removeprefix("*.")
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain: {value}") from exc
    if not DOMAIN_RE.match(candidate):
        raise ValueError(f"Invalid domain: {value}")
    return candidate


def normalize_domains(values: Iterable[str]) -> List[str]:
    seen = set()
    domains = []
    for raw in values:
        domain = normalize_domain(raw)
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    if not domains:
        raise ValueError("At least one valid domain is required.")
    return domains


def build_domain_queries(
    domains: Iterable[str],
    subject_name: str | None = None,
    country: str | None = None,
    sector: str | None = None,
    subject_type: str = "organization",
    subject_aliases: Iterable[str] | None = None,
    strategic_context: Dict[str, Any] | None = None,
) -> List[str]:
    domain_list = list(domains)
    queries = []
    domain_priority_templates = [
        '"{domain}"',
        '"{domain}" -site:{domain}',
        '"{domain}" phishing',
        '"{domain}" fraude',
        '"{domain}" scam OR estafa OR suplantacion',
        '"{domain}" facebook OR instagram OR linkedin OR tiktok OR "x.com"',
        '"{domain}" leak OR filtracion OR credenciales',
        '"{domain}" dark web OR "breach forum" OR ".onion"',
    ]
    domain_deep_templates = [
        '"{domain}" ransomware',
        '"{domain}" "data breach"',
        '"{domain}" ciberataque',
        '"{domain}" malware',
        'site:{domain} filetype:pdf OR filetype:xls OR filetype:doc',
        'site:{domain} intitle:"index of"',
        '"{domain}" password OR token OR credential OR secret',
        '"{domain}" support OR ayuda OR login OR verificacion',
        '"{domain}" "dominio falso" OR "soporte falso" OR "login falso"',
    ]
    brand_priority_templates = [
        '"{term}"',
        '"{term}" instagram',
        '"{term}" facebook',
        '"{term}" tiktok',
        '"{term}" x.com',
        '"{term}" linkedin',
        '"{term}" farsa',
        '"{term}" estafa',
        '"{term}" queja OR reclamo OR denuncia',
        '"{term}" fraude OR phishing OR suplantacion',
    ]
    strategic_evidence_templates = [
        '"{term}" regulator OR regulacion OR regulation OR gobierno',
        '"{term}" resultados financieros OR financial results OR inversion',
        '"{term}" mercado OR competidor OR adquisicion OR merger',
        '"{term}" proveedor tecnologico OR technology supplier OR cloud provider',
        '"{term}" clientes OR customer complaints OR interrupcion del servicio',
        '"{term}" transformacion digital OR digital transformation OR fintech',
        '"{term}" sostenibilidad OR sustainability report OR transicion energetica',
        '"{term}" sancion OR litigio OR privacy investigation',
        '"{term}" comunicado OR informe anual OR annual report',
    ]
    brand_deep_templates = [
        '"{term}" farsa OR estafa OR scam OR fraude',
        '"{term}" reputacion OR reclamo OR queja',
        '"{term}" ciberataque OR seguridad OR incidente',
        '"{term}" filtracion OR fuga OR datos',
        '"{term}" dark web OR ransomware OR leak',
        '"{term}" site:linkedin.com OR site:instagram.com OR site:facebook.com OR site:x.com OR site:tiktok.com OR site:youtube.com',
        '"{term}" youtube',
        '"{term}" hashtag OR "#"',
    ]
    person_priority_templates = [
        '"{term}"',
        '"{term}" site:linkedin.com OR site:instagram.com OR site:facebook.com OR site:x.com OR site:tiktok.com',
        '"{term}" perfil OR profile OR biografia OR biography',
        '"{term}" noticias OR entrevista OR conferencia OR publicacion',
        '"{term}" suplantacion OR impersonation OR cuenta falsa',
    ]
    person_deep_templates = [
        '"{term}" username OR usuario OR alias',
        '"{term}" correo OR email OR contacto',
        '"{term}" filtracion OR breach OR leak',
        '"{term}" foro OR forum OR comentario OR mention',
        '"{term}" foto OR image OR video',
    ]
    colombia_templates = [
        '"{term}" site:colcert.gov.co',
        '"{term}" site:cc-csirt.policia.gov.co',
        '"{term}" site:csirtsalud.gov.co',
        '"{term}" site:datos.gov.co',
        '"{term}" site:rues.org.co',
        '"{term}" site:sic.gov.co',
        '"{term}" site:superfinanciera.gov.co',
        '"{term}" site:supersociedades.gov.co',
        '"{term}" Colombia ciberataque OR incidente OR filtracion',
        '"{term}" Colombia phishing OR fraude OR suplantacion',
    ]
    strategic_context = strategic_context or {}
    declared_context_terms = _unique_ordered(
        str(value)
        for key in ("brands", "subsidiaries", "parent_organizations", "products", "strategic_assets")
        for value in strategic_context.get(key, [])
        if str(value).strip()
    )
    subject_terms = _unique_ordered([*_scoped_brand_terms(domain_list, subject_name, subject_aliases), *declared_context_terms])
    if subject_type != "person":
        strategic_terms = _unique_ordered([subject_name.strip()] if subject_name and subject_name.strip() else subject_terms[:1])
        for template in strategic_evidence_templates:
            queries.extend(template.format(term=term) for term in strategic_terms)
        queries.extend(_strategic_market_queries(strategic_terms, domain_list, country, sector, strategic_context))
    for template in domain_priority_templates:
        queries.extend(template.format(domain=domain) for domain in domain_list)
    priority_templates = person_priority_templates if subject_type == "person" else brand_priority_templates
    deep_templates = person_deep_templates if subject_type == "person" else brand_deep_templates
    for template in priority_templates:
        queries.extend(template.format(term=term) for term in subject_terms)
    for template in domain_deep_templates:
        queries.extend(template.format(domain=domain) for domain in domain_list)
    for template in deep_templates:
        queries.extend(template.format(term=term) for term in subject_terms)
    has_colombia_scope = _is_colombia(country)
    if has_colombia_scope and subject_type != "person":
        regional_terms = _unique_ordered([*domain_list, *subject_terms])
        for template in colombia_templates:
            queries.extend(template.format(term=term) for term in regional_terms)
    if sector and country and subject_type != "person":
        queries.extend(
            [
                f'"{sector}" "{country}" regulacion OR politica publica',
                f'"{sector}" "{country}" tecnologia OR proveedor OR continuidad',
                f'"{sector}" "{country}" competidor OR adquisicion OR sustituto',
            ]
        )
    return _unique_ordered(queries)


def build_source_config(
    base_sources: Dict[str, object],
    domains: List[str],
    organization_name: str | None = None,
    competitor_domains: List[str] | None = None,
    country: str | None = None,
    mode: str = "deep",
    scan_time_budget_minutes: int = 0,
    sector: str | None = None,
    subject_type: str = "organization",
    subject_aliases: Iterable[str] | None = None,
    strategic_context: Dict[str, Any] | None = None,
) -> Dict[str, object]:
    config = copy.deepcopy(base_sources)
    competitor_domains = competitor_domains or []
    search_domains = [*domains, *competitor_domains]
    brand_terms = _scoped_brand_terms(search_domains, organization_name, subject_aliases)
    budget_seconds = _scan_budget_seconds(scan_time_budget_minutes)
    budget_multiplier = _budget_multiplier(budget_seconds)
    web_search = config.setdefault("web_search", {})
    web_search["enabled"] = True
    web_search["queries"] = build_domain_queries(
        search_domains,
        organization_name,
        country,
        sector,
        subject_type,
        subject_aliases,
        strategic_context,
    )
    web_search.setdefault("provider", "aggregated_public_search")
    web_search.setdefault("providers", ["duckduckgo_lite", "google_news_rss", "gdelt", "hacker_news", "google_cse", "brave"])
    is_deep = mode == "deep"
    query_volume = max(1, len(search_domains) + len(brand_terms))
    web_search["request_delay_seconds"] = max(float(web_search.get("request_delay_seconds", 0.35) or 0.35), 0.45 if is_deep else 0.30)
    web_search["timeout_seconds"] = max(float(web_search.get("timeout_seconds", 8.0) or 8.0), 9.0 if is_deep else 7.0)
    requested_collection_timeout = float(web_search.get("collection_timeout_seconds", 90.0) or 90.0)
    adaptive_collection_timeout = (115 if is_deep else 65) + query_volume * (14 if is_deep else 8)
    if budget_seconds:
        adaptive_collection_timeout = max(adaptive_collection_timeout, min(900.0, budget_seconds * 0.38))
    web_search["collection_timeout_seconds"] = min(900.0 if budget_seconds else 420.0 if is_deep else 210.0, max(requested_collection_timeout, adaptive_collection_timeout))
    provider_budget = min(42 if budget_seconds else 28 if is_deep else 16, max(8, int((len(search_domains) * 4 + len(brand_terms) * 2) * budget_multiplier)))
    current_limits = web_search.get("provider_query_limits", {})
    web_search["provider_query_limits"] = {
        "duckduckgo_lite": min(max(int(current_limits.get("duckduckgo_lite", 0) or 0), provider_budget), provider_budget),
        "google_news_rss": min(max(int(current_limits.get("google_news_rss", 0) or 0), provider_budget), provider_budget),
        "gdelt": min(max(int(current_limits.get("gdelt", 0) or 0), provider_budget), provider_budget),
        "hacker_news": min(max(int(current_limits.get("hacker_news", 0) or 0), provider_budget), provider_budget),
        "google_cse": min(max(int(current_limits.get("google_cse", 0) or 0), provider_budget), provider_budget),
        "brave": min(max(int(current_limits.get("brave", 0) or 0), provider_budget), provider_budget),
    }
    query_budget = int((45 if is_deep else 24) * budget_multiplier)
    record_budget = int((420 if is_deep else 220) * budget_multiplier)
    web_search["max_queries"] = min(len(web_search["queries"]), min(query_budget, max(12, len(search_domains) * 7 + len(brand_terms) * 3)))
    web_search["max_records"] = min(record_budget, max(60, len(search_domains) * 24 + len(brand_terms) * 10))
    if budget_seconds:
        web_search["max_queries"] = min(len(web_search["queries"]), max(web_search["max_queries"], min(120, len(search_domains) * 10 + len(brand_terms) * 5)))
        web_search["max_records"] = min(1200, max(web_search["max_records"], len(search_domains) * 40 + len(brand_terms) * 18))

    osint = config.setdefault("osint_public", {})
    osint["enabled"] = True
    osint["domains"] = search_domains
    osint["max_records"] = min(2200 if budget_seconds else 1500, max(30, int(len(search_domains) * 20 * budget_multiplier)))
    osint["max_indexes"] = 1

    osint_tools = config.setdefault("osint_tools", {})
    osint_tools["enabled"] = True
    osint_tools["targets"] = _osint_tool_targets(search_domains, brand_terms)
    osint_tools["tools"] = osint_tools.get("tools") or ["sherlock", "user-scanner"]
    osint_tools["priority"] = bool(osint_tools.get("priority", is_deep))
    osint_tools["max_records"] = min(2200 if budget_seconds else 1500, max(30, int((len(search_domains) * 18 + len(brand_terms) * 12) * budget_multiplier)))
    osint_timeout = 28 if is_deep else 18
    if budget_seconds:
        osint_timeout = max(osint_timeout, int(min(180, budget_seconds * 0.18)))
    osint_tools["timeout_seconds"] = min(180 if budget_seconds else 90 if is_deep else 45, max(int(osint_tools.get("timeout_seconds", 20) or 20), osint_timeout))

    kali_surface = config.setdefault("kali_surface", {})
    kali_surface["enabled"] = True
    kali_surface["domains"] = domains
    kali_surface["mode"] = kali_surface.get("mode", "light")
    kali_surface["max_hosts"] = min(48 if budget_seconds else 24, max(12, int(len(domains) * 5 * budget_multiplier)))
    kali_surface["max_records"] = min(4200 if budget_seconds else 2500, max(60, int(len(domains) * 60 * budget_multiplier)))
    kali_timeout = 34 if is_deep else 22
    if budget_seconds:
        kali_timeout = max(kali_timeout, int(min(300, budget_seconds * 0.20)))
    kali_surface["timeout_seconds"] = min(300 if budget_seconds else 90 if is_deep else 45, max(int(kali_surface.get("timeout_seconds", 26) or 26), kali_timeout))

    spiderfoot = config.setdefault("spiderfoot", {})
    spiderfoot["enabled"] = True
    spiderfoot["domains"] = domains
    spiderfoot["max_records"] = min(3000 if budget_seconds else 1200 if is_deep else 500, max(80, int(len(domains) * 60 * budget_multiplier)))
    spiderfoot["depth"] = spiderfoot.get("depth", "deep")
    spider_timeout = 50 if is_deep else 28
    if budget_seconds:
        spider_waves = max(1, (len(domains) + 1) // 2)
        spider_timeout = max(spider_timeout, int(min(600, max(45, (budget_seconds * 0.92 - 25) / spider_waves))))
    spiderfoot["timeout_seconds"] = min(600 if budget_seconds else 180 if is_deep else 90, max(int(spiderfoot.get("timeout_seconds", 28 if is_deep else 20)), spider_timeout))
    spiderfoot["max_threads"] = int(spiderfoot.get("max_threads", 4))
    spiderfoot["include_raw"] = False

    socmint = config.setdefault("socmint_public", {})
    socmint["keywords"] = _socmint_terms(search_domains, brand_terms, subject_type)
    socmint["max_queries"] = min(len(socmint["keywords"]), min(700 if budget_seconds else 500, max(3, int((len(search_domains) * 4 + len(brand_terms) * 3) * budget_multiplier))))
    socmint["max_records"] = min(2200 if budget_seconds else 1500, max(25, int((len(search_domains) * 16 + len(brand_terms) * 10) * budget_multiplier)))

    urlscan = config.setdefault("urlscan", {})
    urlscan["enabled"] = True
    urlscan["terms"] = _unique_ordered([*search_domains, *brand_terms])
    urlscan["max_records"] = min(650 if budget_seconds else 400 if is_deep else 180, max(20, int((len(search_domains) * 10 + len(brand_terms) * 6) * budget_multiplier)))
    urlscan["timeout_seconds"] = min(12 if is_deep else 8, max(int(urlscan.get("timeout_seconds", 8) or 8), 8))

    otx = config.setdefault("otx", {})
    otx["enabled"] = True
    otx["domains"] = search_domains
    otx["max_records"] = min(500 if budget_seconds else 300 if is_deep else 120, max(20, int(len(search_domains) * 8 * budget_multiplier)))
    otx["timeout_seconds"] = min(12 if is_deep else 8, max(int(otx.get("timeout_seconds", 8) or 8), 8))

    ransomware = config.setdefault("ransomware_live", {})
    ransomware["search_terms"] = _unique_ordered([*search_domains, *brand_terms])
    ransomware["max_records"] = min(2000 if budget_seconds else 1500, max(20, int((len(search_domains) * 12 + len(brand_terms) * 8) * budget_multiplier)))

    evidence_explorer = config.setdefault("evidence_explorer", {})
    evidence_explorer["enabled"] = bool(evidence_explorer.get("enabled", True))
    evidence_explorer["domains"] = search_domains
    evidence_explorer["terms"] = _unique_ordered([*search_domains, *brand_terms])
    evidence_explorer["max_urls"] = min(80 if budget_seconds else 45 if is_deep else 24, max(12, int((len(search_domains) * 5 + len(brand_terms) * 2) * budget_multiplier)))
    evidence_explorer["timeout_seconds"] = min(18 if budget_seconds else 10 if is_deep else 8, max(int(evidence_explorer.get("timeout_seconds", 8) or 8), 8))
    config["scan_budget"] = {
        "minutes": scan_time_budget_minutes,
        "seconds": budget_seconds,
        "mode": "user_defined" if budget_seconds else "auto",
    }
    return config


def _strategic_market_queries(
    subject_terms: Iterable[str],
    domains: Iterable[str],
    country: str | None,
    sector: str | None,
    context: Dict[str, Any],
) -> List[str]:
    """Build evidence-seeking PESTEL/Porter queries from declared scope only."""
    subjects = _unique_ordered([*subject_terms, *domains])
    if not subjects:
        return []
    primary = subjects[0]
    geography = _unique_ordered([country or "", *context.get("countries_of_operation", [])])
    competitors = _unique_ordered([*context.get("declared_competitors", []), *context.get("competitor_domains", [])])
    suppliers = _unique_ordered(context.get("critical_suppliers", []))
    products = _unique_ordered([*context.get("products", []), *context.get("strategic_assets", [])])
    queries = [
        f'"{primary}" ciberseguridad OR cybersecurity OR riesgo digital',
        f'"{primary}" regulacion OR politica publica OR sancion OR litigio',
        f'"{primary}" resultados financieros OR inversion OR costos OR fraude',
        f'"{primary}" reputacion OR confianza OR clientes OR conflicto laboral',
        f'"{primary}" tecnologia OR nube OR vulnerabilidad OR interrupcion digital',
        f'"{primary}" continuidad OR ambiente OR sostenibilidad OR transicion',
        f'"{primary}" competidor OR mercado OR adquisicion OR consolidacion',
        f'"{primary}" nuevo entrante OR barrera de entrada OR plataforma alternativa',
        f'"{primary}" proveedor OR tercero OR cadena de suministro OR dependencia tecnologica',
        f'"{primary}" clientes OR canales OR cambio de proveedor OR exigencia de seguridad',
        f'"{primary}" sustituto OR alternativa digital OR nueva tecnologia',
    ]
    if sector:
        queries.extend([
            f'"{primary}" "{sector}" ciberseguridad OR riesgo digital',
            f'"{sector}" regulacion OR geopolitica OR economia digital OR continuidad',
            f'"{sector}" competencia OR nuevos entrantes OR proveedores OR sustitutos',
        ])
    for location in geography:
        queries.append(f'"{primary}" "{location}" regulacion OR economia OR ciberseguridad OR continuidad')
    for competitor in competitors:
        queries.append(f'"{primary}" "{competitor}" competencia OR mercado OR tecnologia OR ciberseguridad')
    for supplier in suppliers:
        queries.append(f'"{primary}" "{supplier}" proveedor OR interrupcion OR dependencia OR ciberseguridad')
    for product in products:
        queries.append(f'"{primary}" "{product}" mercado OR clientes OR sustituto OR riesgo digital')
    return _unique_ordered(queries)


def _scan_budget_seconds(minutes: int | None) -> int:
    try:
        value = int(minutes or 0)
    except (TypeError, ValueError):
        return 0
    if value <= 0:
        return 0
    return max(300, min(14_400, value * 60))


def _budget_multiplier(budget_seconds: int) -> float:
    if budget_seconds <= 0:
        return 1.0
    return min(2.4, max(1.15, budget_seconds / 1800))


def _is_colombia(country: str | None) -> bool:
    normalized = (country or "").strip().lower()
    return normalized in {"co", "col", "colombia", "colombia, co"}


def _socmint_terms(domains: Iterable[str], brand_terms: Iterable[str], subject_type: str = "organization") -> List[str]:
    terms: List[str] = []
    for value in [*domains, *brand_terms]:
        qualifiers = (
            ["perfil", "username", "mencion", "suplantacion", "instagram facebook x tiktok linkedin"]
            if subject_type == "person"
            else ["fraude", "farsa", "queja", "denuncia", "phishing", "instagram facebook x tiktok linkedin"]
        )
        terms.extend([value, *(f"{value} {qualifier}" for qualifier in qualifiers)])
    seen = set()
    unique_terms = []
    for term in terms:
        key = re.sub(r"\s+", " ", term.lower()).strip()
        if key and key not in seen:
            seen.add(key)
            unique_terms.append(term)
    return unique_terms


def _osint_tool_targets(domains: Iterable[str], brand_terms: Iterable[str]) -> List[str]:
    candidates: List[str] = []
    for domain in domains:
        label = domain.split(".", 1)[0]
        candidates.append(label)
        candidates.append(label.replace("-", ""))
    for term in brand_terms:
        normalized = re.sub(r"[^a-z0-9_.-]+", "", term.lower())
        if normalized:
            candidates.append(normalized)
        for token in re.split(r"[^a-z0-9]+", term.lower()):
            if len(token) >= 4:
                candidates.append(token)
    safe = []
    for candidate in candidates:
        cleaned = candidate.strip("._-").lower()
        if 2 <= len(cleaned) <= 64 and re.match(r"^[a-z0-9_.-]+$", cleaned):
            safe.append(cleaned)
    return _unique_ordered(safe)


def _scoped_brand_terms(
    domains: Iterable[str],
    organization_name: str | None = None,
    aliases: Iterable[str] | None = None,
) -> List[str]:
    domain_list = list(domains)
    return _unique_ordered([*_brand_terms(domain_list, organization_name), *(aliases or [])])


def _unique_ordered(values: Iterable[str]) -> List[str]:
    seen = set()
    output = []
    for value in values:
        key = re.sub(r"\s+", " ", value.lower()).strip()
        if key and key not in seen:
            seen.add(key)
            output.append(value)
    return output


def _brand_terms(domains: Iterable[str], organization_name: str | None = None) -> List[str]:
    terms: List[str] = []
    if organization_name and organization_name.strip():
        terms.append(organization_name.strip())
    for domain in domains:
        label = domain.split(".", 1)[0].replace("-", " ").strip()
        if len(label) >= 4:
            terms.append(label)
    seen = set()
    unique_terms = []
    for term in terms:
        key = re.sub(r"\s+", " ", term.lower()).strip()
        if key and key not in seen:
            seen.add(key)
            unique_terms.append(term)
    return unique_terms


def build_organization_profile(request: DomainAnalysisRequest, domains: List[str]) -> Dict[str, object]:
    name = request.subject_name or f"Domain Intelligence: {', '.join(domains[:3])}"
    allow_tor = bool(request.authorized_scope and request.allow_tor)
    return {
        "organization": {
            "name": name,
            "entity_type": request.subject_type,
            "subject_aliases": request.person_aliases if request.subject_type == "person" else [],
            "legal_name": request.legal_name,
            "sector": request.sector,
            "subsector": request.subsector,
            "country": request.country,
            "author": request.author,
            "language": request.language,
            "authorized_scope": request.authorized_scope,
            "allow_tor": allow_tor,
            "analysis_window": request.analysis_window,
            "lookback_hours": request.lookback_hours,
            "lookback_days": request.lookback_days,
            "scan_time_budget_minutes": request.scan_time_budget_minutes,
            "report_display_at": request.report_display_at,
            "primary_domains": domains,
            "comparison_domains": request.competitor_domains,
            "business_units": [],
            "brands": request.brands,
            "subsidiaries": request.subsidiaries,
            "parent_organizations": request.parent_organizations,
            "joint_ventures": [],
            "products": request.products,
            "strategic_assets": request.strategic_assets,
            "critical_suppliers": request.critical_suppliers,
            "declared_competitors": request.declared_competitors,
            "countries_of_operation": request.countries_of_operation,
            "entity_aliases": request.entity_aliases,
            "crown_jewels": domains,
            "technologies": [],
            "risk_appetite": {},
            # Internal maturity cannot be inferred from public domain evidence.
            "control_maturity": {},
            "fraud_maturity": {},
        },
        "sources": {
            "allow_passive_external_exposure": False,
            "allow_socmint_public": True,
            "allow_darkweb_authorized_import": False,
            "allow_tor": allow_tor,
        },
    }


def slug_from_domains(domains: List[str]) -> str:
    seed = "-".join(domains[:3])
    return re.sub(r"[^a-z0-9-]+", "-", seed.lower()).strip("-")[:80] or "domains"
