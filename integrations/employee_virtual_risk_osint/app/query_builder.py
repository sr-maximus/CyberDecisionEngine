from __future__ import annotations

from typing import Dict, List

from .models import Employee, QuerySpec
from .privacy import email_domain


def _quote(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    return f'"{value}"'


def _add(specs: List[QuerySpec], employee: Employee, query: str, dimension_key: str, dimension_label: str, keyword: str, query_type: str) -> None:
    query = " ".join(str(query or "").split()).strip()
    if not query:
        return
    specs.append(QuerySpec(
        query=query,
        employee_id=employee.employee_id,
        dimension_key=dimension_key,
        dimension_label=dimension_label,
        keyword=keyword,
        query_type=query_type,
    ))


def build_identity_discovery_queries(employee: Employee, allow_personal_email: bool = False) -> List[QuerySpec]:
    """Consultas amplias de descubrimiento.

    Estas consultas replican el comportamiento humano inicial: primero buscar el nombre exacto,
    luego perfilar superficies probables. Se clasifican como informativas y no suman al riesgo total.
    """
    specs: List[QuerySpec] = []
    full_name = employee.full_name.strip()
    org = employee.organization.strip()
    corp_email = employee.corporate_email.strip()
    personal_email = employee.personal_email.strip()
    corp_domain = email_domain(corp_email)
    dim_key = "digital_identity_discovery"
    dim_label = "Descubrimiento de identidad digital"

    if full_name:
        _add(specs, employee, _quote(full_name), dim_key, dim_label, "exact_name", "identity_name")
        if org:
            _add(specs, employee, f"{_quote(full_name)} {_quote(org)}", dim_key, dim_label, "name_organization", "identity_name_org")
        if corp_domain:
            _add(specs, employee, f"{_quote(full_name)} {_quote(corp_domain)}", dim_key, dim_label, "name_domain", "identity_name_domain")
        # Superficies de perfil. No son acusatorias; ayudan a ubicar contexto y homónimos.
        for site, keyword in [
            ("linkedin.com", "site_linkedin"),
            ("github.com", "site_github"),
            ("facebook.com", "site_facebook"),
            ("instagram.com", "site_instagram"),
            ("x.com", "site_x"),
            ("twitter.com", "site_twitter"),
        ]:
            _add(specs, employee, f"{_quote(full_name)} site:{site}", dim_key, dim_label, keyword, "identity_name_site")

    if corp_email:
        _add(specs, employee, _quote(corp_email), dim_key, dim_label, "corporate_email_exact", "identity_corporate_email")
    if allow_personal_email and employee.authorized_personal_email and personal_email:
        _add(specs, employee, _quote(personal_email), dim_key, dim_label, "personal_email_exact_authorized", "identity_personal_email_authorized")
    return specs


def build_queries(
    employee: Employee,
    keyword_catalog: Dict,
    allow_personal_email: bool = False,
    max_keywords_per_dimension: int = 20,
    max_queries_per_employee: int = 500,
    include_identity_discovery: bool = True,
) -> List[QuerySpec]:
    """Construye consultas conservadoras para búsqueda OSINT autorizada.

    El documento de identificación no se usa para búsquedas. El correo personal solo se usa
    cuando hay autorización explícita por fila y flag CLI.
    """
    specs: List[QuerySpec] = []
    if include_identity_discovery:
        specs.extend(build_identity_discovery_queries(employee, allow_personal_email=allow_personal_email))

    full_name = employee.full_name.strip()
    corp_email = employee.corporate_email.strip()
    personal_email = employee.personal_email.strip()
    org = employee.organization.strip()
    corp_domain = email_domain(corp_email)

    dimensions = keyword_catalog.get("dimensions", {})
    for dimension_key, dim in dimensions.items():
        label = dim.get("label", dimension_key)
        keywords = list(dim.get("keywords", []))[:max_keywords_per_dimension]
        for keyword in keywords:
            keyword_q = _quote(keyword)
            if full_name:
                _add(specs, employee, f"{_quote(full_name)} {keyword_q}", dimension_key, label, keyword, "name_keyword")
            if full_name and org:
                _add(specs, employee, f"{_quote(full_name)} {_quote(org)} {keyword_q}", dimension_key, label, keyword, "name_org_keyword")
            if corp_email:
                _add(specs, employee, f"{_quote(corp_email)} {keyword_q}", dimension_key, label, keyword, "corporate_email_keyword")
            if full_name and corp_domain:
                _add(specs, employee, f"{_quote(full_name)} {_quote(corp_domain)} {keyword_q}", dimension_key, label, keyword, "name_domain_keyword")
            if allow_personal_email and employee.authorized_personal_email and personal_email:
                _add(specs, employee, f"{_quote(personal_email)} {keyword_q}", dimension_key, label, keyword, "personal_email_keyword_authorized")

    # Deduplicación preservando orden. Las consultas de identidad quedan primero.
    seen = set()
    unique: List[QuerySpec] = []
    for spec in specs:
        key = (spec.query.lower(), spec.dimension_key, spec.keyword, spec.query_type)
        if key in seen:
            continue
        seen.add(key)
        unique.append(spec)
        if len(unique) >= max_queries_per_employee:
            break
    return unique
