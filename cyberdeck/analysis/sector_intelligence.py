from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import urlparse

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


_ASSURED_STATUSES = {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
_EXCLUDED_STATUSES = {EvidenceStatus.FALSE_POSITIVE, EvidenceStatus.DISCARDED}
_OFFICIAL_HINTS = {"annual_report", "official_record", "regulatory", "corporate", "official_source"}

# ISIC sections A-U. Patterns intentionally use sector-specific phrases and avoid
# generic cyber terms such as "technology", "software" or "infrastructure".
_SECTOR_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "code": "A",
        "en": "Agriculture, forestry and fishing",
        "es": "Agricultura, silvicultura y pesca",
        "patterns": (
            r"\bagricultur",
            r"\bagropecuar",
            r"\bagroindustrial",
            r"\bforestry\b",
            r"\bsilvicultur",
            r"\bfishing\b",
            r"\bpesca\b",
        ),
    },
    {
        "code": "B",
        "en": "Mining and quarrying",
        "es": "Explotación de minas y canteras",
        "patterns": (
            r"\boil and gas\b",
            r"\boil producer",
            r"\bpetroleum\b",
            r"\bpetrole",
            r"\bhydrocarbon",
            r"\bhidrocarbur",
            r"\bcrude oil\b",
            r"\bupstream\b",
            r"\bdrilling\b",
            r"\bmining\b",
            r"\bmineria\b",
            r"\bquarr",
        ),
    },
    {
        "code": "C",
        "en": "Manufacturing",
        "es": "Industrias manufactureras",
        "patterns": (
            r"\bmanufactur",
            r"\bfabricacion\b",
            r"\bfactory\b",
            r"\bindustrial plant\b",
            r"\bplanta de produccion\b",
        ),
    },
    {
        "code": "D",
        "en": "Electricity, gas, steam and air conditioning supply",
        "es": "Suministro de electricidad, gas, vapor y aire acondicionado",
        "patterns": (
            r"\belectric utilit",
            r"\bpower generation\b",
            r"\belectricity generation\b",
            r"\bgeneracion electrica\b",
            r"\benergia renovable\b",
            r"\brenewable energy\b",
            r"\bsolar farm\b",
            r"\bwind farm\b",
            r"\btransmision electrica\b",
        ),
    },
    {
        "code": "E",
        "en": "Water supply, sewerage, waste management and remediation",
        "es": "Agua, saneamiento, residuos y remediación",
        "patterns": (
            r"\bwater utilit",
            r"\bwater supply\b",
            r"\bwastewater\b",
            r"\bsewerage\b",
            r"\bsaneamiento\b",
            r"\bacueducto\b",
            r"\bwaste management\b",
            r"\bgestion de residuos\b",
        ),
    },
    {
        "code": "F",
        "en": "Construction",
        "es": "Construcción",
        "patterns": (
            r"\bconstruction compan",
            r"\bconstruction sector\b",
            r"\bconstruccion\b",
            r"\bcivil engineering\b",
            r"\binfraestructura vial\b",
        ),
    },
    {
        "code": "G",
        "en": "Wholesale and retail trade; repair of motor vehicles and motorcycles",
        "es": "Comercio y reparación de vehículos y motocicletas",
        "patterns": (
            r"\bretailer",
            r"\bretail chain\b",
            r"\bwholesale\b",
            r"\bcomercio minorista\b",
            r"\bcomercio mayorista\b",
            r"\be-?commerce\b",
            r"\bsupermercado",
        ),
    },
    {
        "code": "H",
        "en": "Transportation and storage",
        "es": "Transporte y almacenamiento",
        "patterns": (
            r"\bport operator\b",
            r"\bport terminal\b",
            r"\bpuerto\b",
            r"\bportuari",
            r"\bshipping\b",
            r"\bcargo terminal\b",
            r"\blogistic",
            r"\btransport",
            r"\bstorage terminal\b",
            r"\bpipeline\b",
            r"\boleoducto\b",
            r"\bgasoducto\b",
            r"\bmidstream\b",
        ),
    },
    {
        "code": "I",
        "en": "Accommodation and food service activities",
        "es": "Alojamiento y servicios de comida",
        "patterns": (
            r"\bhotel chain\b",
            r"\bhospitality\b",
            r"\btourism\b",
            r"\bturismo\b",
            r"\brestaurant chain\b",
            r"\bservicios de alojamiento\b",
        ),
    },
    {
        "code": "J",
        "en": "Information and communication",
        "es": "Información y comunicaciones",
        "patterns": (
            r"\btelecom operator\b",
            r"\btelecommunications compan",
            r"\boperador de telecomunicaciones\b",
            r"\binternet service provider\b",
            r"\bdata center operator\b",
            r"\bbroadcasting compan",
            r"\bempresa de comunicaciones\b",
        ),
    },
    {
        "code": "K",
        "en": "Financial and insurance activities",
        "es": "Actividades financieras y de seguros",
        "patterns": (
            r"\bbank(?:ing|s)?\b",
            r"\bbancari",
            r"\bfinancial institution\b",
            r"\binstitucion financiera\b",
            r"\bfintech\b",
            r"\binsurance compan",
            r"\basegurador",
            r"\bcredit union\b",
        ),
    },
    {
        "code": "L",
        "en": "Real estate activities",
        "es": "Actividades inmobiliarias",
        "patterns": (
            r"\breal estate\b",
            r"\binmobiliar",
            r"\bproperty developer\b",
            r"\bdesarrollador inmobiliario\b",
        ),
    },
    {
        "code": "M",
        "en": "Professional, scientific and technical activities",
        "es": "Actividades profesionales, científicas y técnicas",
        "patterns": (
            r"\bconsulting firm\b",
            r"\bconsultoria\b",
            r"\bprofessional services firm\b",
            r"\bscientific research\b",
            r"\blaw firm\b",
            r"\bfirma de abogados\b",
            r"\baudit firm\b",
        ),
    },
    {
        "code": "N",
        "en": "Administrative and support service activities",
        "es": "Servicios administrativos y de apoyo",
        "patterns": (
            r"\bbusiness process outsourcing\b",
            r"\bbpo compan",
            r"\bcall cent(?:er|re)\b",
            r"\bfacilit(?:y|ies) management\b",
            r"\bprivate security compan",
            r"\btravel agency\b",
            r"\brental services\b",
        ),
    },
    {
        "code": "O",
        "en": "Public administration and defence",
        "es": "Administración pública y defensa",
        "patterns": (
            r"\bgovernment ministr",
            r"\bpublic administration\b",
            r"\bgobierno nacional\b",
            r"\bgobierno municipal\b",
            r"\bministerio\b",
            r"\bdefen[cs]e agency\b",
        ),
    },
    {
        "code": "P",
        "en": "Education",
        "es": "Educación",
        "patterns": (
            r"\buniversity\b",
            r"\buniversidad\b",
            r"\beducation sector\b",
            r"\bsector educativo\b",
            r"\bschool district\b",
            r"\bcollege\b",
        ),
    },
    {
        "code": "Q",
        "en": "Human health and social work activities",
        "es": "Salud humana y asistencia social",
        "patterns": (
            r"\bhospital\b",
            r"\bhealthcare provider\b",
            r"\bhealth system\b",
            r"\bsector salud\b",
            r"\bmedical clinic\b",
            r"\bclinica\b",
            r"\bpharmaceutical compan",
        ),
    },
    {
        "code": "R",
        "en": "Arts, entertainment and recreation",
        "es": "Artes, entretenimiento y recreación",
        "patterns": (
            r"\bsports league\b",
            r"\bentertainment compan",
            r"\bvideo game compan",
            r"\bgaming operator\b",
            r"\bcasino\b",
            r"\barts organization\b",
        ),
    },
    {
        "code": "S",
        "en": "Other service activities",
        "es": "Otras actividades de servicios",
        "patterns": (
            r"\bnonprofit\b",
            r"\bnon-profit\b",
            r"\borganizacion sin animo de lucro\b",
            r"\btrade association\b",
            r"\bmembership organization\b",
            r"\bpersonal services\b",
        ),
    },
    {
        "code": "T",
        "en": "Activities of households as employers",
        "es": "Actividades de los hogares como empleadores",
        "patterns": (
            r"\bhousehold employer\b",
            r"\bdomestic worker\b",
            r"\bservicio domestico\b",
        ),
    },
    {
        "code": "U",
        "en": "Activities of extraterritorial organizations and bodies",
        "es": "Organizaciones y órganos extraterritoriales",
        "patterns": (
            r"\bembassy\b",
            r"\bconsulate\b",
            r"\bunited nations agency\b",
            r"\binternational organization\b",
            r"\bmultilateral organization\b",
            r"\borganismo internacional\b",
        ),
    },
)


def build_sector_intelligence(
    events: list[ThreatEvent],
    organization: OrganizationProfile,
) -> dict[str, Any]:
    evidence_rows: dict[str, dict[str, Any]] = {}
    contextual_rows: dict[str, dict[str, Any]] = {}

    for event in events:
        if event.evidence_status in _EXCLUDED_STATUSES:
            continue
        matched = _sectors_in_event(event)
        if not matched:
            continue
        related = event.relationship_to_scope in {"direct", "related"}
        event_id = event.canonical_id or event.id
        for sector in matched:
            target = evidence_rows if related else contextual_rows
            row = target.setdefault(sector["code"], _new_row(sector, organization.language))
            if event_id in row["_seen_ids"]:
                continue
            row["_seen_ids"].add(event_id)
            row["records"] += 1
            if event.relationship_to_scope == "direct":
                row["direct_records"] += 1
            if event.evidence_status in _ASSURED_STATUSES:
                row["assured_records"] += 1
            if _is_official(event):
                row["official_records"] += 1
            _append_unique(row["evidence_ids"], event_id)
            _append_unique(row["evidence_urls"], event.evidence_url or "")
            marker = f"{'sector_mention' if related else 'sector_context'}:{sector['code']}"
            if marker not in event.tags:
                event.tags.append(marker)

    evidence_supported = _finalize_rows(evidence_rows, organization.language)
    contextual = _finalize_rows(contextual_rows, organization.language)
    return {
        "declared_sectors": _split_declared(organization.sector),
        "declared_subsector": organization.subsector or "",
        "evidence_supported_sectors": evidence_supported,
        "contextual_sector_mentions": contextual,
        "evidence_supported_count": len(evidence_supported),
        "method": (
            "Declared sectors remain separate from sectors explicitly identified in each scope-related record. "
            "Counts are deduplicated by evidence identifier and preserve source URLs."
            if organization.language == "en"
            else "Los sectores declarados se mantienen separados de los sectores identificados explícitamente en cada "
            "registro relacionado con el alcance. Los conteos se deduplican por ID de evidencia y conservan las URL."
        ),
        "limitations": (
            "A sector mention describes evidence context; it does not by itself prove that the organization operates in "
            "that sector, is targeted, or faces a materialized risk."
            if organization.language == "en"
            else "Una mención sectorial describe el contexto de la evidencia; por sí sola no demuestra que la organización "
            "opere en ese sector, sea objetivo o enfrente un riesgo materializado."
        ),
        "taxonomy": "ISIC sections A-U with conservative bilingual evidence patterns",
    }


def _new_row(sector: dict[str, Any], language: str) -> dict[str, Any]:
    return {
        "code": sector["code"],
        "sector": sector["en"] if language == "en" else sector["es"],
        "records": 0,
        "direct_records": 0,
        "assured_records": 0,
        "official_records": 0,
        "evidence_ids": [],
        "evidence_urls": [],
        "evidence_links": [],
        "status": "observed_context",
        "what_it_demonstrates": (
            "Scope-related collected material explicitly contains terminology associated with this economic sector."
            if language == "en"
            else "El material recolectado relacionado con el alcance contiene terminología asociada explícitamente con este sector económico."
        ),
        "what_it_does_not_demonstrate": (
            "It does not by itself prove organizational activity, targeting, compromise or impact in this sector."
            if language == "en"
            else "Por sí solo no prueba actividad organizacional, direccionamiento, compromiso ni impacto en este sector."
        ),
        "_seen_ids": set(),
    }


def _finalize_rows(rows: dict[str, dict[str, Any]], language: str) -> list[dict[str, Any]]:
    output = []
    for row in rows.values():
        row.pop("_seen_ids", None)
        if row["assured_records"] > 0 and (row["direct_records"] > 0 or row["official_records"] > 0):
            row["status"] = "supported_sector_context"
            row["what_it_demonstrates"] = (
                "Direct or assured scope-related evidence supports this sector as relevant analytical context."
                if language == "en"
                else "Evidencia directa o asegurada y relacionada con el alcance sustenta este sector como contexto analítico relevante."
            )
        row["evidence_links"] = [
            {"url": url, "label": _url_label(url)}
            for url in row["evidence_urls"][:5]
            if url
        ]
        output.append(row)
    return sorted(
        output,
        key=lambda item: (
            item["status"] == "supported_sector_context",
            item["assured_records"],
            item["direct_records"],
            item["records"],
            item["sector"],
        ),
        reverse=True,
    )


def _sectors_in_event(event: ThreatEvent) -> list[dict[str, Any]]:
    normalized = _normalize(_event_text(event))
    explicit = _explicit_sector_values(event.tags)
    matched = []
    for sector in _SECTOR_CATALOG:
        labels = {_normalize(sector["en"]), _normalize(sector["es"])}
        if any(re.search(pattern, normalized) for pattern in sector["patterns"]) or labels.intersection(explicit):
            matched.append(sector)
    return matched


def _event_text(event: ThreatEvent) -> str:
    validation = event.technical_validation or {}
    tags = [
        tag
        for tag in event.tags or []
        if not str(tag).lower().startswith(("query:", "sector:", "country:", "tool:", "source:"))
    ]
    return " ".join(
        [
            event.title,
            event.category,
            event.asset or "",
            event.host or "",
            event.evidence_url or "",
            " ".join(tags),
            str(validation.get("summary") or ""),
            str(validation.get("description") or ""),
            str(validation.get("original_response") or ""),
        ]
    )


def _explicit_sector_values(tags: list[str]) -> set[str]:
    values = set()
    for tag in tags or []:
        lowered = str(tag or "").strip().lower()
        if lowered.startswith(("sector_observed:", "industry_observed:")):
            values.add(_normalize(lowered.split(":", 1)[1]))
    return values


def _is_official(event: ThreatEvent) -> bool:
    tags = {str(tag).lower() for tag in event.tags or []}
    evidence_type = getattr(event.evidence_type, "value", str(event.evidence_type or ""))
    return bool(tags.intersection(_OFFICIAL_HINTS)) or (
        event.relationship_to_scope == "direct"
        and evidence_type in {"official_record", "document"}
        and event.evidence_status in _ASSURED_STATUSES
    )


def _split_declared(value: str) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in re.split(r"[,;|]", value or "") if item.strip()))


def _url_label(value: str) -> str:
    try:
        host = urlparse(value).netloc.lower().removeprefix("www.")
    except ValueError:
        host = ""
    return host or "source"


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _normalize(value: str) -> str:
    folded = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"\s+", " ", folded.lower()).strip()
