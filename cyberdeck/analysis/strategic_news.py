from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, Field

from cyberdeck.schemas import OrganizationProfile, ThreatEvent
from cyberdeck.settings import PROJECT_ROOT


STRATEGIC_DATA_DIR = PROJECT_ROOT / "data" / "strategic"
MODEL_VERSION = "strategic-evidence-v1.3.0"
PESTEL_DIMENSIONS = ("cyber_geopolitics", "cyber_economy", "cyber_human", "cyber_technology", "cyber_resilience", "cyber_legal")
PORTER_DIMENSIONS = ("cyber_rivalry", "cyber_new_entrants", "cyber_suppliers", "cyber_customers", "cyber_substitutes")
LEGACY_DIMENSION_IDS = {
    "political": "cyber_geopolitics", "economic": "cyber_economy", "social": "cyber_human",
    "technological": "cyber_technology", "environmental": "cyber_resilience", "legal": "cyber_legal",
    "rivalry": "cyber_rivalry", "new_entrants": "cyber_new_entrants", "supplier_power": "cyber_suppliers",
    "customer_power": "cyber_customers", "substitutes": "cyber_substitutes",
}
CANONICAL_TO_LEGACY = {value: key for key, value in LEGACY_DIMENSION_IDS.items()}
DIMENSION_NAMES = {
    "cyber_geopolitics": "Geopolítica, política pública y amenaza estatal",
    "cyber_economy": "Economía digital, fraude y presión financiera",
    "cyber_human": "Factor humano, confianza digital y manipulación social",
    "cyber_technology": "Dependencia tecnológica, vulnerabilidades y superficie de ataque",
    "cyber_resilience": "Resiliencia física, energética, ambiental y continuidad digital",
    "cyber_legal": "Regulación, privacidad, cumplimiento y responsabilidad cibernética",
    "cyber_rivalry": "Rivalidad digital y presión competitiva de ciberseguridad",
    "cyber_new_entrants": "Nuevos entrantes digitales y expansión de la superficie de ataque",
    "cyber_suppliers": "Poder y dependencia cibernética de proveedores y terceros",
    "cyber_customers": "Poder y exigencia de seguridad de clientes, aliados y canales",
    "cyber_substitutes": "Sustitución tecnológica y desplazamiento del riesgo cibernético",
}
DIMENSION_SHORT_NAMES = {
    "cyber_geopolitics": "Geopolítica y amenaza estatal", "cyber_economy": "Economía digital y fraude",
    "cyber_human": "Factor humano y manipulación", "cyber_technology": "Tecnología y superficie",
    "cyber_resilience": "Resiliencia y continuidad", "cyber_legal": "Regulación y responsabilidad",
    "cyber_rivalry": "Rivalidad digital", "cyber_new_entrants": "Nuevos entrantes",
    "cyber_suppliers": "Proveedores y terceros", "cyber_customers": "Clientes y aliados",
    "cyber_substitutes": "Sustitución tecnológica",
}


class OrganizationEntity(BaseModel):
    entity_id: str
    legal_name: str
    commercial_name: Optional[str] = None
    country: Optional[str] = None
    sector: Optional[str] = None
    subsector: Optional[str] = None


class BrandEntity(BaseModel):
    entity_id: str
    name: str
    organization_id: str


class DomainEntity(BaseModel):
    entity_id: str
    domain: str
    organization_id: str
    relationship: str = "primary"


class SubsidiaryRelationship(BaseModel):
    parent_id: str
    subsidiary_id: str
    validation_status: str = "declared"


class ParentRelationship(BaseModel):
    entity_id: str
    parent_id: str
    validation_status: str = "declared"


class SupplierRelationship(BaseModel):
    organization_id: str
    supplier_id: str
    criticality: str = "declared_critical"


class CompetitorRelationship(BaseModel):
    organization_id: str
    competitor_id: str
    validation_status: str = "declared"


class ProductEntity(BaseModel):
    entity_id: str
    name: str
    organization_id: str


class StrategicAssetEntity(BaseModel):
    entity_id: str
    name: str
    organization_id: str


class EntityAlias(BaseModel):
    alias: str
    canonical_entity_id: str
    alias_type: str
    country: Optional[str] = None
    sector: Optional[str] = None
    language: Optional[str] = None
    required_context: List[str] = Field(default_factory=list)
    exclusion_expressions: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    validation_status: str = "declared"
    relationship: str = "direct"


class EntityDisambiguationRule(BaseModel):
    alias: str
    require_context_for_short_alias: bool = True
    minimum_context_matches: int = 1
    exclusion_expressions: List[str] = Field(default_factory=list)


class NewsSource(BaseModel):
    source_id: str
    source_name: str
    source_type: str
    reliability_score: float
    source_tier: str
    independence_score: float
    factual_reliability: float
    bias_or_interest: str
    validation_status: str
    self_reported: bool = False


class NewsEntityMatch(BaseModel):
    matched_entity_id: str
    match_method: str
    match_text: str
    match_confidence: float
    directness_score: float
    relationship: str
    ambiguity_detected: bool = False
    disambiguation_result: str = "accepted"
    analyst_review_status: str = "not_reviewed"


class NewsArticle(BaseModel):
    article_id: str
    canonical_url: str
    original_url: str
    source_id: str
    source_name: str
    title: str
    summary: str = ""
    body_hash: str
    published_at: str
    collected_at: str
    language: str
    country: Optional[str] = None
    author: Optional[str] = None
    source_type: str = "public_news"
    raw_reference: str
    license_or_usage_note: str = "Public reference and metadata only; original publisher terms apply."
    duplicate_status: str = "unique"
    event_cluster_id: Optional[str] = None
    matched_entities: List[NewsEntityMatch] = Field(default_factory=list)
    directness: str = "unrelated"
    event_type: Optional[str] = None
    event_magnitude: float = 0.0
    pressure_direction: float = 0.0
    source_quality: float = 0.0
    recency_weight: float = 0.0
    novelty_weight: float = 1.0
    corroboration: float = 0.0
    extraction_confidence: float = 0.0
    pestel_mappings: List[str] = Field(default_factory=list)
    porter_mappings: List[str] = Field(default_factory=list)
    evidence_status: str = "collected"
    analyst_review_status: str = "not_reviewed"


class StrategicEvent(BaseModel):
    event_id: str
    article_id: str
    event_type: str
    affected_entities: List[str]
    event_magnitude: float
    pressure_direction: float
    extraction_confidence: float
    validation_status: str = "deterministic_extraction"


class StrategicContradiction(BaseModel):
    contradiction_id: str
    event_cluster_id: str
    evidence_ids: List[str]
    description: str
    status: str = "unresolved"


class StrategicAnalystReview(BaseModel):
    review_id: str
    object_id: str
    status: str = "not_reviewed"
    reviewer: Optional[str] = None
    notes: Optional[str] = None


class SourceReliabilityRegistry(BaseModel):
    version: str
    default: Dict[str, Any]
    rules: List[Dict[str, Any]]


class StrategicEventTaxonomy(BaseModel):
    version: str
    description: str
    events: List[Dict[str, Any]]


class StrategicMappingMatrix(BaseModel):
    version: str
    approved_by: str
    mappings: List[Dict[str, Any]]
    base_weights: Dict[str, Dict[str, float]]
    tau: Dict[str, float]


class StrategicEventCluster(BaseModel):
    event_cluster_id: str
    canonical_event_name: str
    event_type: str
    affected_entities: List[str]
    affected_countries: List[str]
    first_seen: str
    last_seen: str
    independent_source_count: int
    article_count: int
    validated_evidence_count: int
    primary_sources: List[str]
    corroborating_sources: List[str]
    contradiction_status: str
    event_magnitude: float
    analyst_status: str
    article_ids: List[str]
    evidence_urls: List[str]
    relationship: str
    directness_score: float
    match_confidence: float
    source_quality: float
    source_tier: str
    recency_weight: float
    novelty_weight: float
    corroboration: float
    extraction_confidence: float
    pressure_direction: float
    self_reported: bool = False


class StrategicEventMapping(BaseModel):
    event_type: str
    model: Literal["pestel", "porter"]
    dimension: str
    base_strength: float
    direction: float
    conditions: List[str] = Field(default_factory=list)
    exclusions: List[str] = Field(default_factory=list)
    justification: str
    version: str
    validation_status: str = "approved_configuration"


class StrategicScoreContribution(BaseModel):
    contribution_id: str
    event_cluster_id: str
    model: str
    dimension: str
    base_weight: float
    magnitude: float
    direction: float
    signed_contribution: float
    relationship: str
    mapping_justification: str
    evidence_ids: List[str]
    evidence_urls: List[str]


class StrategicScoreSnapshot(BaseModel):
    snapshot_id: str
    model: str
    window_days: int
    period: str
    score: Optional[float]
    confidence: float
    coverage_ratio: float
    evidence_coverage_ratio: float = 0.0
    assessment_status: str
    dimension_scores: Dict[str, Optional[float]]
    created_at: str
    version: str = MODEL_VERSION


class EntityResolutionGraph(BaseModel):
    version: str = MODEL_VERSION
    organization: OrganizationEntity
    brands: List[BrandEntity] = Field(default_factory=list)
    domains: List[DomainEntity] = Field(default_factory=list)
    aliases: List[EntityAlias] = Field(default_factory=list)
    subsidiaries: List[SubsidiaryRelationship] = Field(default_factory=list)
    parents: List[ParentRelationship] = Field(default_factory=list)
    suppliers: List[SupplierRelationship] = Field(default_factory=list)
    competitors: List[CompetitorRelationship] = Field(default_factory=list)
    products: List[ProductEntity] = Field(default_factory=list)
    strategic_assets: List[StrategicAssetEntity] = Field(default_factory=list)
    disambiguation_rules: List[EntityDisambiguationRule] = Field(default_factory=list)

    def resolve(self, title: str, url: str, tags: Sequence[str]) -> List[NewsEntityMatch]:
        text = _normalize_text(" ".join([title, url, *tags]))
        matches: List[NewsEntityMatch] = []
        for alias in self.aliases:
            token = _normalize_text(alias.alias)
            if not token or not _contains_phrase(text, token):
                continue
            excluded = any(_contains_phrase(text, _normalize_text(value)) for value in alias.exclusion_expressions)
            context_hits = sum(1 for value in alias.required_context if _contains_phrase(text, _normalize_text(value)))
            short_alias = len(token.replace(" ", "")) <= 3
            if excluded or (short_alias and alias.alias_type != "domain" and context_hits < 1):
                matches.append(
                    NewsEntityMatch(
                        matched_entity_id=alias.canonical_entity_id,
                        match_method="ambiguous_alias_rejected",
                        match_text=alias.alias,
                        match_confidence=0.0,
                        directness_score=0.0,
                        relationship=alias.relationship,
                        ambiguity_detected=True,
                        disambiguation_result="rejected_insufficient_context",
                    )
                )
                continue
            directness = {"direct": 1.0, "group": 0.85, "supplier": 0.70, "competitor": 0.70}.get(alias.relationship, 0.0)
            matches.append(
                NewsEntityMatch(
                    matched_entity_id=alias.canonical_entity_id,
                    match_method="exact_domain" if alias.alias_type == "domain" else "validated_alias_context",
                    match_text=alias.alias,
                    match_confidence=alias.confidence,
                    directness_score=directness,
                    relationship=alias.relationship,
                    ambiguity_detected=False,
                    disambiguation_result="accepted_strong_condition",
                )
            )
        accepted = [match for match in matches if match.match_confidence > 0]
        if accepted:
            return _unique_matches(accepted)
        countries = _scope_terms(self.organization.country or "")
        sectors = _scope_terms(self.organization.sector or "")
        matched_country = next((value for value in countries if _contains_phrase(text, value)), None)
        matched_sector = next((value for value in sectors if _contains_phrase(text, value)), None)
        if matched_country and matched_sector:
            return [NewsEntityMatch(matched_entity_id=self.organization.entity_id, match_method="sector_country_context", match_text=f"{matched_sector} + {matched_country}", match_confidence=0.55, directness_score=0.40, relationship="sector")]
        if matched_sector:
            return [NewsEntityMatch(matched_entity_id=self.organization.entity_id, match_method="global_sector_context", match_text=matched_sector, match_confidence=0.35, directness_score=0.20, relationship="global")]
        return matches


def build_entity_resolution_graph(organization: OrganizationProfile) -> EntityResolutionGraph:
    org_id = _stable_id("org", organization.name, *organization.primary_domains)
    legal_name = organization.legal_name or organization.name
    graph = EntityResolutionGraph(
        organization=OrganizationEntity(
            entity_id=org_id,
            legal_name=legal_name,
            commercial_name=organization.name,
            country=organization.country or None,
            sector=organization.sector or None,
            subsector=organization.subsector or None,
        )
    )
    context = [*_scope_terms(organization.country), *_scope_terms(organization.sector)]
    if organization.name and not organization.name.lower().startswith("domain intelligence:"):
        graph.aliases.append(EntityAlias(alias=organization.name, canonical_entity_id=org_id, alias_type="commercial_name", country=organization.country or None, sector=organization.sector or None, language=organization.language, required_context=context if len(_normalize_text(organization.name)) <= 3 else [], confidence=0.95, relationship="direct"))
        declared_components = [value.strip() for value in re.split(r"\s*(?:,|;|\by\b|\band\b)\s*", organization.name, flags=re.IGNORECASE) if value.strip()]
        if len(declared_components) > 1:
            for component in declared_components:
                graph.aliases.append(EntityAlias(alias=component, canonical_entity_id=_stable_id("declared-entity", component), alias_type="declared_organization_component", country=organization.country or None, sector=organization.sector or None, language=organization.language, required_context=context if len(_normalize_text(component).replace(" ", "")) <= 3 else [], confidence=0.90, relationship="direct"))
    if legal_name and legal_name != organization.name:
        graph.aliases.append(EntityAlias(alias=legal_name, canonical_entity_id=org_id, alias_type="legal_name", country=organization.country or None, sector=organization.sector or None, language=organization.language, required_context=context if len(_normalize_text(legal_name)) <= 3 else [], confidence=1.0, relationship="direct"))
    for domain in organization.primary_domains:
        entity_id = _stable_id("domain", domain)
        graph.domains.append(DomainEntity(entity_id=entity_id, domain=domain.lower(), organization_id=org_id))
        graph.aliases.append(EntityAlias(alias=domain.lower(), canonical_entity_id=entity_id, alias_type="domain", confidence=1.0, relationship="direct"))
    for domain in organization.comparison_domains:
        entity_id = _stable_id("competitor-domain", domain)
        graph.domains.append(DomainEntity(entity_id=entity_id, domain=domain.lower(), organization_id=org_id, relationship="competitor"))
        graph.competitors.append(CompetitorRelationship(organization_id=org_id, competitor_id=entity_id))
        graph.aliases.append(EntityAlias(alias=domain.lower(), canonical_entity_id=entity_id, alias_type="domain", confidence=1.0, relationship="competitor"))
    _add_named_entities(graph, organization.brands, "brand", "direct", org_id)
    _add_named_entities(graph, organization.subsidiaries, "subsidiary", "group", org_id)
    _add_named_entities(graph, organization.parent_organizations, "parent", "group", org_id)
    _add_named_entities(graph, organization.critical_suppliers, "supplier", "supplier", org_id)
    _add_named_entities(graph, organization.declared_competitors, "competitor", "competitor", org_id)
    _add_named_entities(graph, organization.products, "product", "direct", org_id)
    _add_named_entities(graph, organization.strategic_assets, "strategic_asset", "direct", org_id)
    for raw in organization.entity_aliases:
        if not isinstance(raw, dict) or not raw.get("alias"):
            continue
        graph.aliases.append(
            EntityAlias(
                alias=str(raw["alias"]),
                canonical_entity_id=str(raw.get("canonical_entity_id") or org_id),
                alias_type=str(raw.get("type") or "managed_alias"),
                country=str(raw.get("country") or organization.country or "") or None,
                sector=str(raw.get("sector") or organization.sector or "") or None,
                language=str(raw.get("language") or organization.language),
                required_context=[str(value) for value in raw.get("required_context", [])],
                exclusion_expressions=[str(value) for value in raw.get("exclusion_expressions", [])],
                confidence=float(raw.get("confidence", 0.8)),
                validation_status=str(raw.get("validation_status") or "declared"),
                relationship=str(raw.get("relationship") or "direct"),
            )
        )
    graph.disambiguation_rules = [EntityDisambiguationRule(alias=alias.alias, exclusion_expressions=alias.exclusion_expressions) for alias in graph.aliases if len(_normalize_text(alias.alias).replace(" ", "")) <= 3]
    return graph


def build_strategic_intelligence(
    events: Sequence[ThreatEvent],
    organization: OrganizationProfile,
    created_at: str | None = None,
) -> Dict[str, Any]:
    graph = build_entity_resolution_graph(organization)
    taxonomy = StrategicEventTaxonomy(**_load_json("strategic_event_taxonomy.json")).model_dump(mode="json")
    mapping_config = StrategicMappingMatrix(**_load_json("strategic_mapping_matrix.json")).model_dump(mode="json")
    source_registry = SourceReliabilityRegistry(**_load_json("source_reliability_registry.json")).model_dump(mode="json")
    scenario_context_registry = _load_json("scenario_strategic_context_mapping.json")
    mappings = [StrategicEventMapping(version=mapping_config["version"], **{**item, "dimension": LEGACY_DIMENSION_IDS.get(item.get("dimension"), item.get("dimension"))}) for item in mapping_config.get("mappings", [])]
    snapshot_created_at = created_at or datetime.now(timezone.utc).isoformat()
    articles, sources, rejected = _build_articles(
        events,
        organization,
        graph,
        taxonomy,
        mappings,
        source_registry,
        collected_at=snapshot_created_at,
    )
    clusters, contradictions = _cluster_articles(articles, sources, organization)
    window_days = max(1, int(organization.lookback_days or 30))
    pestel = _score_model("pestel", PESTEL_DIMENSIONS, clusters, mappings, mapping_config, window_days)
    porter = _score_model("porter", PORTER_DIMENSIONS, clusters, mappings, mapping_config, window_days)
    pestel["modelVersion"] = MODEL_VERSION
    porter["modelVersion"] = MODEL_VERSION
    _enrich_dimension_contract(pestel, organization, clusters)
    _enrich_dimension_contract(porter, organization, clusters)
    market_scope = _build_market_scope(organization, snapshot_created_at)
    analysis_basis = _build_analysis_basis(organization, market_scope)
    pestel["analysisBasis"] = analysis_basis
    porter["analysisBasis"] = analysis_basis
    porter["marketScope"] = market_scope
    if market_scope["confidence"] < 50:
        porter["validatedPressure"] = None
        porter["overall_score"] = None
        porter["index"] = None
        porter["overall_status"] = "under_review" if porter.get("signalScore") is not None else "no_data"
    snapshots = []
    for days in (7, 30, 90, 365):
        for model, dimensions in (("pestel", PESTEL_DIMENSIONS), ("porter", PORTER_DIMENSIONS)):
            window_result = _score_model(model, dimensions, clusters, mappings, mapping_config, days)
            snapshots.append(
                StrategicScoreSnapshot(
                    snapshot_id=_stable_id("snapshot", model, str(days), *[cluster.event_cluster_id for cluster in clusters]),
                    model=model,
                    window_days=days,
                    period="current",
                    score=window_result["signalScore"],
                    confidence=window_result["overall_confidence"],
                    coverage_ratio=window_result["coverage_ratio"],
                    evidence_coverage_ratio=window_result["evidence_coverage_ratio"],
                    assessment_status=window_result["overall_status"],
                    dimension_scores={row["key"]: row["signalScore"] for row in window_result["dimensions"]},
                    created_at=snapshot_created_at,
                ).model_dump(mode="json")
            )
    queries = build_strategic_queries(graph, organization, articles)
    return {
        "version": MODEL_VERSION,
        "taxonomy_version": taxonomy.get("version"),
        "mapping_version": mapping_config.get("version"),
        "source_registry_version": source_registry.get("version"),
        "scenario_context_mapping_version": scenario_context_registry.get("version"),
        "scenario_context_mappings": scenario_context_registry.get("mappings", []),
        "scenario_context_policy": "Only approved mappings can adjust an already supported or validated scenario, with a multiplier limited to 0.90-1.10. Strategic context never creates or promotes a scenario.",
        "calculation_mode": "deterministic_reproducible",
        "entity_graph": graph.model_dump(mode="json"),
        "query_log": queries,
        "articles": [article.model_dump(mode="json") for article in articles],
        "clusters": [cluster.model_dump(mode="json") for cluster in clusters],
        "contradictions": [item.model_dump(mode="json") for item in contradictions],
        "snapshots": snapshots,
        "rejected_articles": rejected,
        "pestel": pestel,
        "porter": porter,
        "marketScope": market_scope,
        "analysisBasis": analysis_basis,
        "limitations": [
            "PESTEL y Porter representan presion estrategica contextual; no son riesgo, cumplimiento, madurez, incidente ni probabilidad de ataque.",
            "La cobertura de evidencia puede ser mayor que cero aunque la presion permanezca sin publicar; cobertura no equivale a impacto ni riesgo.",
            "La ausencia de evidencia suficiente produce score nulo y estado insufficient_evidence, nunca un cero artificial.",
            "La clasificacion automatica es determinista y debe revisarse cuando exista ambiguedad o contradiccion.",
        ],
    }


def _build_analysis_basis(organization: OrganizationProfile, market_scope: Dict[str, Any]) -> Dict[str, Any]:
    def declared_values(*values: Any) -> List[str]:
        unique: Dict[str, str] = {}
        for value in values:
            text = str(value or "").strip()
            if text:
                unique.setdefault(_normalize_text(text), text)
        return list(unique.values())

    fields = {
        "organization": declared_values(organization.legal_name, organization.name),
        "domains": declared_values(*organization.primary_domains),
        "brands": declared_values(*organization.brands),
        "subsidiaries": declared_values(*organization.subsidiaries),
        "sector": declared_values(organization.sector, organization.subsector),
        "geography": declared_values(*market_scope.get("geography", [])),
        "competitors": declared_values(*market_scope.get("competitors", [])),
        "suppliers": declared_values(*organization.critical_suppliers),
        "products_and_assets": declared_values(*organization.products, *organization.strategic_assets, *organization.crown_jewels),
    }
    populated = sum(1 for values in fields.values() if values)
    return {
        "context": fields,
        "declared_context_coverage": round(100 * populated / len(fields), 2),
        "evidence_policy": "Declared context defines the search and entity-resolution scope; only evidence collected and validated in the current run contributes to scores.",
        "historical_evidence_reused": False,
    }


def _enrich_dimension_contract(result: Dict[str, Any], organization: OrganizationProfile, clusters: Sequence[StrategicEventCluster]) -> None:
    clusters_by_evidence: Dict[str, List[StrategicEventCluster]] = defaultdict(list)
    for cluster in clusters:
        for evidence_id in cluster.article_ids:
            clusters_by_evidence[evidence_id].append(cluster)
    declared_assets = list(dict.fromkeys([*organization.strategic_assets, *organization.crown_jewels, *organization.technologies]))
    for row in result.get("dimensions", []):
        related_clusters = {
            cluster.event_cluster_id: cluster
            for evidence_id in row.get("evidence_ids", [])
            for cluster in clusters_by_evidence.get(evidence_id, [])
        }
        cluster_rows = list(related_clusters.values())
        row["summary"] = row.get("why") or "N/D — sin evidencia suficiente en la cobertura disponible"
        row["cyberMechanism"] = "; ".join(
            dict.fromkeys(
                str(item.get("mapping_reason") or "").strip()
                for item in [*row.get("drivers", []), *row.get("reducers", [])]
                if str(item.get("mapping_reason") or "").strip()
            )
        ) or None
        row["affectedAssets"] = declared_assets
        row["affectedEntities"] = sorted({entity for cluster in cluster_rows for entity in cluster.affected_entities})
        row["counterEvidenceIds"] = sorted({evidence_id for cluster in cluster_rows if cluster.contradiction_status != "none" for evidence_id in cluster.article_ids})
        row["sourceFamilies"] = sorted({source for cluster in cluster_rows for source in [*cluster.primary_sources, *cluster.corroborating_sources]})
        row["limitations"] = [row["what_it_does_not_mean"]]
        if row.get("validatedPressure") is None and row.get("signalScore") is not None:
            row["limitations"].append("La señal permanece en revisión: no cumple todavía el umbral de presión validada.")
        if row.get("signalScore") is None:
            row["limitations"].append("N/D — sin evidencia suficiente en la cobertura disponible.")
        row["decisionImplications"] = [row.get("decision")] if row.get("decision") else []


def _build_market_scope(organization: OrganizationProfile, created_at: str) -> Dict[str, Any]:
    try:
        end = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        end = datetime.now(timezone.utc)
    start = end - timedelta(days=max(1, int(organization.lookback_days or 30)))
    explicit_fields = [
        bool(organization.sector),
        bool(organization.subsector),
        bool(organization.country or organization.countries_of_operation),
        bool(organization.business_units or organization.products),
        bool(organization.declared_competitors or organization.comparison_domains),
    ]
    confidence = round(100 * sum(explicit_fields) / len(explicit_fields), 2)
    geography = list(dict.fromkeys([organization.country, *organization.countries_of_operation]))
    geography = [item for item in geography if item]
    competitors = list(dict.fromkeys([*organization.declared_competitors, *organization.comparison_domains]))
    product_or_service = (organization.products or organization.business_units or [None])[0]
    business_unit = (organization.business_units or [None])[0]
    return {
        "marketScopeId": _stable_id("market", organization.name, organization.sector, organization.subsector or "", *geography),
        "organizationId": _stable_id("org", organization.legal_name or organization.name),
        "businessUnit": business_unit,
        "productOrService": product_or_service,
        "sector": organization.sector or None,
        "subsector": organization.subsector,
        "geography": geography,
        "competitors": competitors,
        "suppliers": list(organization.critical_suppliers),
        "customers": [],
        "substitutes": [],
        "periodStart": start.date().isoformat(),
        "periodEnd": end.date().isoformat(),
        "definitionEvidenceIds": [],
        "confidence": confidence,
        "status": "defined" if confidence >= 50 else "provisional",
        "limitations": [] if confidence >= 50 else ["El mercado no está suficientemente delimitado; las fuerzas se muestran como provisionales y no se publica índice agregado."],
    }


def build_strategic_queries(graph: EntityResolutionGraph, organization: OrganizationProfile, articles: Sequence[NewsArticle] = ()) -> List[Dict[str, Any]]:
    terms: List[Tuple[str, str, List[str]]] = []
    for alias in graph.aliases:
        if alias.alias_type in {"domain", "legal_name", "commercial_name", "brand", "subsidiary", "parent", "product", "strategic_asset"}:
            terms.append((alias.alias, "direct", [alias.canonical_entity_id]))
        elif alias.relationship in {"supplier", "competitor"}:
            terms.append((alias.alias, "group", [alias.canonical_entity_id]))
    if organization.sector and organization.country:
        terms.append((f'"{organization.sector}" "{organization.country}" regulacion tecnologia continuidad fraude', "contextual", [graph.organization.entity_id]))
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for term, query_type, entity_ids in terms:
        query = term if query_type == "contextual" else f'"{term}" noticias OR news OR regulacion OR sancion OR incidente OR inversion OR adquisicion'
        key = _normalize_text(query)
        if key in seen:
            continue
        seen.add(key)
        result_count = sum(1 for article in articles if _contains_phrase(_normalize_text(f"{article.title} {article.original_url}"), _normalize_text(term.strip('"'))))
        rows.append({"query_id": _stable_id("query", query), "query_text": query, "query_type": query_type, "entity_ids": entity_ids, "language": organization.language, "country": organization.country or None, "sector": organization.sector or None, "date_window": organization.analysis_window, "source_group": "strategic_public_evidence", "executed_at": None, "result_count": result_count, "error_status": None, "execution_status": "represented_in_collection_scope"})
    return rows


def export_strategic_scores(strategic: Dict[str, Any], report_path: Path) -> Dict[str, str]:
    json_path = report_path.with_name(f"{report_path.stem}_strategic_scores.json")
    csv_path = report_path.with_name(f"{report_path.stem}_strategic_scores.csv")
    json_path.write_text(json.dumps(strategic, ensure_ascii=False, indent=2), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "model",
                "dimension",
                "signal_score",
                "validated_pressure",
                "confidence",
                "evidence_coverage_percent",
                "status",
                "delta",
                "cluster_count",
                "independent_source_count",
                "evidence_ids",
                "evidence_urls",
            ],
        )
        writer.writeheader()
        for model_name in ("pestel", "porter"):
            for dimension in strategic.get(model_name, {}).get("dimensions", []):
                writer.writerow({
                    "model": model_name,
                    "dimension": dimension.get("key"),
                    "signal_score": dimension.get("signalScore", dimension.get("signal_score")),
                    "validated_pressure": dimension.get("validatedPressure", dimension.get("score")),
                    "confidence": dimension.get("confidence"),
                    "evidence_coverage_percent": dimension.get("evidence_coverage_percent"),
                    "status": dimension.get("status"),
                    "delta": dimension.get("delta"),
                    "cluster_count": dimension.get("cluster_count"),
                    "independent_source_count": dimension.get("independent_source_count"),
                    "evidence_ids": "|".join(dimension.get("evidence_ids", [])),
                    "evidence_urls": "|".join(dimension.get("evidence_urls", [])),
                })
    return {"strategic_json": str(json_path), "strategic_csv": str(csv_path)}


def apply_strategic_context_to_scenarios(
    scenarios: Sequence[Dict[str, Any]],
    strategic: Dict[str, Any],
    mappings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Apply only approved causal context to scenarios that already have evidence support."""
    dimensions = {
        row["key"]: row
        for model in ("pestel", "porter")
        for row in (strategic.get(model, {}) or {}).get("dimensions", [])
    }
    output: List[Dict[str, Any]] = []
    for original in scenarios:
        scenario = json.loads(json.dumps(original))
        status = str(scenario.get("status") or "candidate")
        before = float((scenario.get("scores", {}) or {}).get("likelihood", scenario.get("likelihood", 0.0)) or 0.0)
        eligible = status in {"supported", "evidence_supported", "validated"}
        approved = [
            row
            for row in mappings
            if row.get("scenario_id") == scenario.get("id")
            and row.get("validation_status") == "approved"
            and row.get("strategic_dimension") in dimensions
        ]
        numerator = 0.0
        denominator = 0.0
        applied: List[Dict[str, Any]] = []
        if eligible:
            for mapping in approved:
                dimension = dimensions[mapping["strategic_dimension"]]
                score = dimension.get("score")
                confidence = float(dimension.get("confidence", 0) or 0)
                if score is None or confidence < 60:
                    continue
                coefficient = float(mapping.get("relevance_coefficient", 0) or 0)
                numerator += coefficient * ((float(score) - 50) / 50) * (confidence / 100)
                denominator += abs(coefficient)
                applied.append(mapping)
        signal = numerator / max(1e-9, denominator) if denominator else 0.0
        multiplier = max(0.90, min(1.10, 1 + 0.10 * signal)) if applied else 1.0
        after = max(0.0, min(1.0, before * multiplier))
        scenario["strategic_context"] = {
            "eligible": eligible,
            "mapping_count": len(applied),
            "context_signal": round(signal, 6),
            "likelihood_multiplier": round(multiplier, 6),
            "likelihood_before": round(before, 6),
            "likelihood_after": round(after, 6),
            "status_unchanged": status,
            "limitation": "Strategic context cannot create evidence support or promote a candidate/preventive scenario.",
        }
        output.append(scenario)
    return output


def _build_articles(
    events: Sequence[ThreatEvent],
    organization: OrganizationProfile,
    graph: EntityResolutionGraph,
    taxonomy: Dict[str, Any],
    mappings: Sequence[StrategicEventMapping],
    source_registry: Dict[str, Any],
    *,
    collected_at: str,
) -> Tuple[List[NewsArticle], Dict[str, NewsSource], List[Dict[str, Any]]]:
    articles: List[NewsArticle] = []
    sources: Dict[str, NewsSource] = {}
    rejected: List[Dict[str, Any]] = []
    for event in events:
        if event.demo or not event.evidence_url:
            continue
        content_title = _event_content_title(event.title)
        content_summary = str(event.technical_validation.get("summary") or "")
        matches = graph.resolve(f"{content_title} {content_summary}", event.evidence_url, event.tags)
        accepted = [match for match in matches if match.match_confidence > 0]
        if not accepted:
            rejected.append({"evidence_id": event.id, "title": event.title, "reason": "unrelated_or_ambiguous_entity", "ambiguity_detected": any(match.ambiguity_detected for match in matches)})
            continue
        event_type = _classify_event_type(event, taxonomy)
        if not event_type:
            rejected.append({"evidence_id": event.id, "title": event.title, "reason": "no_strategic_event_type", "ambiguity_detected": False})
            continue
        canonical_url = _canonical_url(event.evidence_url)
        source = _source_for(event, canonical_url, organization, source_registry)
        sources[source.source_id] = source
        relationship = max(accepted, key=lambda item: item.directness_score).relationship
        magnitude = _event_magnitude(event)
        direction = _event_direction(event)
        age_days = max(0, int(event.age_days or 0))
        half_life = _half_life(event_type, taxonomy)
        article_id = event.canonical_id or event.id
        article = NewsArticle(
            article_id=article_id,
            canonical_url=canonical_url,
            original_url=event.evidence_url,
            source_id=source.source_id,
            source_name=source.source_name,
            title=content_title,
            summary=content_summary,
            body_hash=event.content_hash or hashlib.sha256(_normalize_text(f"{content_title} {content_summary}").encode("utf-8")).hexdigest(),
            published_at=event.observed_at,
            collected_at=collected_at,
            language=organization.language,
            country=organization.country or None,
            raw_reference=event.id,
            matched_entities=accepted,
            directness=relationship,
            event_type=event_type,
            event_magnitude=magnitude,
            pressure_direction=direction,
            source_quality=source.reliability_score,
            recency_weight=2 ** (-age_days / max(1, half_life)),
            extraction_confidence=max(0.0, min(1.0, event.confidence_score)),
            pestel_mappings=[mapping.dimension for mapping in mappings if mapping.event_type == event_type and mapping.model == "pestel"],
            porter_mappings=[mapping.dimension for mapping in mappings if mapping.event_type == event_type and mapping.model == "porter"],
            evidence_status=str(event.evidence_status.value if hasattr(event.evidence_status, "value") else event.evidence_status),
        )
        articles.append(article)
    return articles, sources, rejected


def _cluster_articles(articles: List[NewsArticle], sources: Dict[str, NewsSource], organization: OrganizationProfile) -> Tuple[List[StrategicEventCluster], List[StrategicContradiction]]:
    grouped: List[List[NewsArticle]] = []
    for article in sorted(articles, key=lambda item: (item.event_type or "", item.published_at, item.article_id)):
        target: Optional[List[NewsArticle]] = None
        for candidate in grouped:
            anchor = candidate[0]
            same_entities = {match.matched_entity_id for match in anchor.matched_entities} == {match.matched_entity_id for match in article.matched_entities}
            same_content = anchor.body_hash == article.body_hash or anchor.canonical_url == article.canonical_url
            similar_title = _jaccard(anchor.title, article.title) >= 0.72
            if anchor.event_type == article.event_type and same_entities and (same_content or similar_title):
                target = candidate
                break
        if target is None:
            grouped.append([article])
        else:
            article.duplicate_status = "duplicate_event"
            target.append(article)
    clusters: List[StrategicEventCluster] = []
    contradictions: List[StrategicContradiction] = []
    for group in grouped:
        origin_keys: Dict[str, NewsArticle] = {}
        for article in group:
            source = sources[article.source_id]
            key = article.body_hash if len(group) > 1 and article.body_hash == group[0].body_hash else _source_origin(article)
            if source.self_reported:
                key = f"self:{key}"
            origin_keys.setdefault(key, article)
        independent = [article for key, article in origin_keys.items() if not key.startswith("self:")]
        independent_count = len(independent)
        source_rows = [sources[item.source_id] for item in group]
        primary = max(group, key=lambda item: sources[item.source_id].reliability_score)
        accepted_matches = [match for item in group for match in item.matched_entities]
        best_match = max(accepted_matches, key=lambda item: item.directness_score * item.match_confidence)
        directions = [item.pressure_direction for item in group if item.pressure_direction != 0]
        contradiction = bool(directions and min(directions) < 0 < max(directions))
        cluster_id = _stable_id("cluster", primary.event_type or "unknown", primary.body_hash, *sorted({match.matched_entity_id for match in accepted_matches}))
        for article in group:
            article.event_cluster_id = cluster_id
            article.corroboration = min(1.0, 0.55 + 0.15 * max(0, independent_count - 1)) if independent_count else 0.45
            article.novelty_weight = max(0.55, 1.0 - 0.05 * max(0, len(group) - 1))
        if contradiction:
            contradictions.append(StrategicContradiction(contradiction_id=_stable_id("contradiction", cluster_id), event_cluster_id=cluster_id, evidence_ids=[item.article_id for item in group], description="Independent public records propose opposing pressure directions for the same event cluster."))
        clusters.append(
            StrategicEventCluster(
                event_cluster_id=cluster_id,
                canonical_event_name=primary.title,
                event_type=primary.event_type or "unknown",
                affected_entities=sorted({match.matched_entity_id for match in accepted_matches}),
                affected_countries=[organization.country] if organization.country else [],
                first_seen=min(item.published_at for item in group),
                last_seen=max(item.published_at for item in group),
                independent_source_count=independent_count,
                article_count=len(group),
                validated_evidence_count=sum(1 for item in group if item.evidence_status in {"direct", "validated", "confirmed"}),
                primary_sources=[primary.source_name],
                corroborating_sources=sorted({item.source_name for item in independent if item.source_id != primary.source_id}),
                contradiction_status="unresolved" if contradiction else "none",
                event_magnitude=max(item.event_magnitude for item in group),
                analyst_status="not_reviewed",
                article_ids=[item.article_id for item in group],
                evidence_urls=sorted({item.original_url for item in group}),
                relationship=best_match.relationship,
                directness_score=best_match.directness_score,
                match_confidence=best_match.match_confidence,
                source_quality=sum(item.reliability_score for item in source_rows) / max(1, len(source_rows)),
                source_tier=min((item.source_tier for item in source_rows), default="E"),
                recency_weight=max(item.recency_weight for item in group),
                novelty_weight=primary.novelty_weight,
                corroboration=primary.corroboration,
                extraction_confidence=sum(item.extraction_confidence for item in group) / max(1, len(group)),
                pressure_direction=(sum(directions) / len(directions)) if directions else 0.0,
                self_reported=all(item.self_reported for item in source_rows),
            )
        )
    return clusters, contradictions


def _score_model(model: str, dimensions: Sequence[str], clusters: Sequence[StrategicEventCluster], mappings: Sequence[StrategicEventMapping], config: Dict[str, Any], window_days: int) -> Dict[str, Any]:
    current = [cluster for cluster in clusters if _cluster_age_days(cluster) < window_days]
    previous = [cluster for cluster in clusters if window_days <= _cluster_age_days(cluster) < window_days * 2]
    current_rows, current_contributions = _score_dimensions(model, dimensions, current, mappings, config)
    previous_rows, _ = _score_dimensions(model, dimensions, previous, mappings, config)
    previous_by_key = {row["key"]: row for row in previous_rows}
    for row in current_rows:
        previous_score = previous_by_key.get(row["key"], {}).get("score")
        row["previous_score"] = previous_score
        row["delta"] = round(row["score"] - previous_score, 2) if row["score"] is not None and previous_score is not None else None
        row["what_changed"] = _what_changed(row, previous_by_key.get(row["key"]), window_days)
    weights = config.get("base_weights", {}).get(model, {})
    def dimension_weight(key: str) -> float:
        return float(weights.get(key, weights.get(CANONICAL_TO_LEGACY.get(key, ""), 1.0)))
    valid = [row for row in current_rows if row["score"] is not None]
    total_weight = sum(dimension_weight(key) for key in dimensions)
    coverage_ratio = sum(dimension_weight(row["key"]) for row in valid) / max(1e-9, total_weight)
    evidence_coverage_ratio = sum(
        dimension_weight(row["key"]) * float(row.get("evidence_coverage_percent", 0.0)) / 100
        for row in current_rows
    ) / max(1e-9, total_weight)
    effective = [(dimension_weight(row["key"]) * row["confidence"] / 100, row) for row in valid]
    overall_score = sum(weight * row["validatedPressure"] for weight, row in effective) / max(1e-9, sum(weight for weight, _ in effective)) if effective else None
    signal_rows = [row for row in current_rows if row["signalScore"] is not None]
    overall_signal = sum(dimension_weight(row["key"]) * row["signalScore"] for row in signal_rows) / max(1e-9, sum(dimension_weight(row["key"]) for row in signal_rows)) if signal_rows else None
    overall_confidence = sum(dimension_weight(row["key"]) * row["confidence"] for row in current_rows) / max(1e-9, total_weight)
    publish_overall = coverage_ratio >= 0.60 and overall_confidence >= 50 and len(valid) > len(dimensions) / 2
    if not publish_overall:
        overall_score = None
    assessment_status = "assessed" if valid else "evidence_available_unscored" if current else "insufficient_evidence"
    return {
        "model": model,
        "index": round(overall_score, 2) if overall_score is not None else None,
        "overall_score": round(overall_score, 2) if overall_score is not None else None,
        "signal_score": round(overall_signal, 2) if overall_signal is not None else None,
        "signalScore": round(overall_signal, 2) if overall_signal is not None else None,
        "validatedPressure": round(overall_score, 2) if overall_score is not None else None,
        "overall_confidence": round(overall_confidence, 2),
        "coverage_ratio": round(coverage_ratio, 4),
        "evidence_coverage_ratio": round(evidence_coverage_ratio, 4),
        "assessment_status": assessment_status,
        "overall_status": "validated" if publish_overall else "under_review" if signal_rows else "no_data",
        "is_risk_score": False,
        "signal_count": len({item.event_cluster_id for item in current}),
        "cluster_count": len(current),
        "article_count": sum(item.article_count for item in current),
        "record_count": sum(item.article_count for item in current),
        "window_days": window_days,
        "base_weights": weights,
        "math_model": {
            "version": MODEL_VERSION,
            "contribution_quality": "q_i = 0.18M_i + 0.16Q_i + 0.10R_i + 0.16D_i + 0.08N_i + 0.12C_i + 0.10X_i + 0.10G_i",
            "evidence_mass": "m_d = sum(q_i * magnitude_i)",
            "coverage": "coverage_d = 1 - exp(-m_d / tau_d)",
            "signal_score": "SignalScore_d = 100 * (0.65*coverage_d + 0.20*directness_d + 0.15*min(1,n_d/4))",
            "confidence": "Confidence_d = 100 * (0.20*coverage_d + 0.80*(0.20*diversity_d + 0.30*directness_d + 0.20*agreement_d + 0.30*extraction_d))",
            "validated_pressure": "Pressure_d = 50 + 50*tanh(1.5*z_d), z_d = sum(signed_i)/m_d",
            "publication_gate": "m_d >= 0.15 and ((direct_clusters >= 2 and independent_sources >= 2) or official_critical_event)",
        },
        "interpretation": "Modelo de intensidad de señal cibernética basado en registros relacionados y trazables. SignalScore expresa intensidad analítica; confianza y cobertura se publican por separado; validatedPressure exige soporte más estricto. No mide probabilidad de ataque, cumplimiento ni madurez.",
        "insufficient_evidence_message": "No hay evidencia suficiente para calcular esta dimension en la ventana analizada.",
        "dimensions": current_rows,
        "contributions": [item.model_dump(mode="json") for item in current_contributions],
        "scenarios": [],
    }


def _score_dimensions(model: str, dimensions: Sequence[str], clusters: Sequence[StrategicEventCluster], mappings: Sequence[StrategicEventMapping], config: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[StrategicScoreContribution]]:
    by_dimension: Dict[str, List[StrategicScoreContribution]] = defaultdict(list)
    cluster_by_id = {cluster.event_cluster_id: cluster for cluster in clusters}
    for cluster in clusters:
        for mapping in mappings:
            if mapping.model != model or mapping.event_type != cluster.event_type or mapping.dimension not in dimensions:
                continue
            direction = cluster.pressure_direction if cluster.pressure_direction != 0 else mapping.direction
            factors = (
                (cluster.match_confidence, 0.18), (cluster.source_quality, 0.16), (cluster.recency_weight, 0.10),
                (cluster.directness_score, 0.16), (cluster.novelty_weight, 0.08), (cluster.corroboration, 0.12),
                (cluster.extraction_confidence, 0.10), (mapping.base_strength, 0.10),
            )
            base = sum(max(0.0, min(1.0, value)) * weight for value, weight in factors)
            if cluster.contradiction_status != "none":
                base *= 0.65
            contribution = StrategicScoreContribution(
                contribution_id=_stable_id("contribution", cluster.event_cluster_id, model, mapping.dimension),
                event_cluster_id=cluster.event_cluster_id,
                model=model,
                dimension=mapping.dimension,
                base_weight=base,
                magnitude=cluster.event_magnitude,
                direction=max(-1.0, min(1.0, direction)),
                signed_contribution=base * cluster.event_magnitude * max(-1.0, min(1.0, direction)),
                relationship=cluster.relationship,
                mapping_justification=mapping.justification,
                evidence_ids=cluster.article_ids,
                evidence_urls=cluster.evidence_urls,
            )
            by_dimension[mapping.dimension].append(contribution)
    rows: List[Dict[str, Any]] = []
    all_contributions: List[StrategicScoreContribution] = []
    for dimension in dimensions:
        contributions = _apply_context_caps(by_dimension.get(dimension, []), cluster_by_id)
        contributions = _apply_single_cluster_cap(contributions, cluster_by_id)
        all_contributions.extend(contributions)
        evidence_mass = sum(item.base_weight * item.magnitude for item in contributions)
        direct_clusters = {item.event_cluster_id for item in contributions if cluster_by_id[item.event_cluster_id].directness_score >= 0.70}
        independent_sources = {source for item in contributions for source in cluster_by_id[item.event_cluster_id].primary_sources + cluster_by_id[item.event_cluster_id].corroborating_sources if not cluster_by_id[item.event_cluster_id].self_reported}
        official_critical = any(cluster_by_id[item.event_cluster_id].source_tier == "A" and cluster_by_id[item.event_cluster_id].directness_score >= 0.70 and cluster_by_id[item.event_cluster_id].event_magnitude >= 0.75 and cluster_by_id[item.event_cluster_id].validated_evidence_count > 0 for item in contributions)
        sufficient = evidence_mass >= 0.15 and ((len(direct_clusters) >= 2 and len(independent_sources) >= 2) or official_critical)
        signed = sum(item.signed_contribution for item in contributions)
        z_score = max(-1.0, min(1.0, signed / max(1e-9, evidence_mass))) if evidence_mass else 0.0
        validated_pressure = max(0.0, min(100.0, 50 + 50 * math.tanh(1.5 * z_score))) if sufficient else None
        source_diversity = min(1.0, len(independent_sources) / 3)
        directness = _weighted_average([(cluster_by_id[item.event_cluster_id].directness_score, item.base_weight * item.magnitude) for item in contributions])
        directions = [(item.direction, item.base_weight * item.magnitude) for item in contributions]
        agreement = 1 - min(1.0, _weighted_variance(directions))
        extraction = _weighted_average([(cluster_by_id[item.event_cluster_id].extraction_confidence, item.base_weight * item.magnitude) for item in contributions])
        tau_config = config.get("tau", {})
        tau = float(tau_config.get(dimension, tau_config.get(CANONICAL_TO_LEGACY.get(dimension, ""), 1.2)))
        coverage = 1 - math.exp(-evidence_mass / max(1e-9, tau))
        quality_support = 0.20 * source_diversity + 0.30 * directness + 0.20 * agreement + 0.30 * extraction
        confidence = max(0.0, min(100.0, 100 * (0.20 * coverage + 0.80 * quality_support))) if contributions else 0.0
        signal_score = max(0.0, min(100.0, 100 * (0.65 * coverage + 0.20 * directness + 0.15 * min(1.0, len(contributions) / 4)))) if contributions else None
        clusters_for_dimension = [cluster_by_id[item.event_cluster_id] for item in contributions]
        if any(cluster.contradiction_status != "none" for cluster in clusters_for_dimension):
            confidence *= 0.65
        evidence_ids = sorted({value for item in contributions for value in item.evidence_ids})
        evidence_urls = sorted({value for item in contributions for value in item.evidence_urls})
        rows.append({
            "name": DIMENSION_NAMES[dimension],
            "key": dimension,
            "dimensionId": dimension,
            "displayName": DIMENSION_NAMES[dimension],
            "shortName": DIMENSION_SHORT_NAMES[dimension],
            "score": round(validated_pressure, 2) if validated_pressure is not None else None,
            "signal_score": round(signal_score, 2) if signal_score is not None else None,
            "signalScore": round(signal_score, 2) if signal_score is not None else None,
            "validatedPressure": round(validated_pressure, 2) if validated_pressure is not None else None,
            "confidence": round(confidence, 2),
            "coverage": round(coverage * 100, 2),
            "status": "supported" if sufficient else "candidate" if contributions else "no_data",
            "evidence_state": "sufficient_for_pressure" if sufficient else "partial_evidence" if contributions else "no_evidence",
            "evidence_coverage_percent": round(coverage * 100, 2),
            "evidence_mass": round(evidence_mass, 6),
            "calculation": {
                "model_version": MODEL_VERSION,
                "evidence_mass": round(evidence_mass, 6),
                "signed_mass": round(signed, 6),
                "direction_index": round(z_score, 6) if evidence_mass else None,
                "source_diversity": round(source_diversity, 6),
                "weighted_directness": round(directness, 6),
                "direction_agreement": round(agreement, 6),
                "extraction_quality": round(extraction, 6),
                "tau": round(tau, 6),
                "contribution_count": len(contributions),
                "publication_gate_passed": sufficient,
                "official_critical_event": official_critical,
            },
            "cluster_count": len({item.event_cluster_id for item in contributions}),
            "independent_source_count": len(independent_sources),
            "direct_count": sum(1 for item in clusters_for_dimension if item.relationship == "direct"),
            "group_count": sum(1 for item in clusters_for_dimension if item.relationship == "group"),
            "supplier_count": sum(1 for item in clusters_for_dimension if item.relationship == "supplier"),
            "sector_count": sum(1 for item in clusters_for_dimension if item.relationship == "sector"),
            "global_count": sum(1 for item in clusters_for_dimension if item.relationship == "global"),
            "drivers": [_cluster_card(item, contributions) for item in sorted(clusters_for_dimension, key=lambda row: row.event_magnitude * row.source_quality, reverse=True) if _cluster_direction(item, contributions) > 0][:5],
            "reducers": [_cluster_card(item, contributions) for item in sorted(clusters_for_dimension, key=lambda row: row.event_magnitude * row.source_quality, reverse=True) if _cluster_direction(item, contributions) < 0][:5],
            "evidence_ids": evidence_ids,
            "evidence_urls": evidence_urls,
            "why": _dimension_explanation(dimension, sufficient, clusters_for_dimension),
            "decision": "Review the linked events and their operating implications; this result does not prescribe a control or confirm an incident." if sufficient else "Review the available records and collect at least two independent, directly related event clusters or one validated high-magnitude official event." if contributions else "Collect directly related public, corporate, regulatory or sector evidence for this dimension.",
            "what_it_does_not_mean": "No demuestra una vulnerabilidad, un incidente, una probabilidad de ataque, cumplimiento ni madurez interna.",
        })
    return rows, all_contributions


def _apply_context_caps(items: List[StrategicScoreContribution], clusters: Dict[str, StrategicEventCluster]) -> List[StrategicScoreContribution]:
    copied = [item.model_copy(deep=True) for item in items]
    primary_mass = sum(item.base_weight * item.magnitude for item in copied if clusters[item.event_cluster_id].relationship not in {"sector", "global"})
    if primary_mass <= 0:
        return copied
    _scale_relation(copied, clusters, "sector", primary_mass * 0.25)
    _scale_relation(copied, clusters, "global", primary_mass * (0.05 / 0.95))
    return copied


def _apply_single_cluster_cap(items: List[StrategicScoreContribution], clusters: Dict[str, StrategicEventCluster]) -> List[StrategicScoreContribution]:
    copied = [item.model_copy(deep=True) for item in items]
    if len(copied) <= 1:
        return copied
    total = sum(item.base_weight * item.magnitude for item in copied)
    for item in copied:
        cluster = clusters[item.event_cluster_id]
        if cluster.source_tier == "A" and cluster.directness_score >= 0.70 and cluster.event_magnitude >= 0.75 and cluster.validated_evidence_count > 0:
            continue
        mass = item.base_weight * item.magnitude
        max_mass = max(0.0, 0.30 * total)
        if mass > max_mass and item.magnitude > 0:
            ratio = max_mass / mass
            item.base_weight *= ratio
            item.signed_contribution *= ratio
    return copied


def _scale_relation(items: List[StrategicScoreContribution], clusters: Dict[str, StrategicEventCluster], relationship: str, max_mass: float) -> None:
    relation_items = [item for item in items if clusters[item.event_cluster_id].relationship == relationship]
    mass = sum(item.base_weight * item.magnitude for item in relation_items)
    if mass <= max_mass or mass <= 0:
        return
    ratio = max_mass / mass
    for item in relation_items:
        item.base_weight *= ratio
        item.signed_contribution *= ratio


def _cluster_card(cluster: StrategicEventCluster, contributions: Sequence[StrategicScoreContribution]) -> Dict[str, Any]:
    matching = [item for item in contributions if item.event_cluster_id == cluster.event_cluster_id]
    return {
        "cluster_id": cluster.event_cluster_id,
        "what_happened": cluster.canonical_event_name,
        "affected_entities": cluster.affected_entities,
        "relationship": cluster.relationship,
        "direction": "increases_pressure" if _cluster_direction(cluster, matching) > 0 else "reduces_pressure",
        "magnitude": _magnitude_label(cluster.event_magnitude),
        "confidence": round(100 * cluster.match_confidence * cluster.source_quality * cluster.extraction_confidence, 2),
        "independent_sources": cluster.independent_source_count,
        "article_count": cluster.article_count,
        "evidence_urls": cluster.evidence_urls,
        "mapping_reason": matching[0].mapping_justification if matching else "",
        "what_it_does_not_mean": "This event does not by itself prove a cyber incident, vulnerability, or control failure.",
    }


def _what_changed(current: Dict[str, Any], previous: Optional[Dict[str, Any]], window_days: int) -> str:
    if current.get("score") is None:
        return f"Insufficient directly related evidence in the current {window_days}-day window."
    if not previous or previous.get("score") is None:
        return "A comparable prior score is unavailable; no temporal significance is claimed."
    delta = current["score"] - previous["score"]
    if current.get("confidence", 0) < 60:
        return f"Observed delta {delta:+.1f}, but confidence is too low to claim a significant change."
    return f"Pressure changed {delta:+.1f} points against the equivalent previous window."


def _dimension_explanation(dimension: str, sufficient: bool, clusters: Sequence[StrategicEventCluster]) -> str:
    if not sufficient:
        if clusters:
            return f"Hay {len(clusters)} clústeres de evidencia relacionados con {DIMENSION_NAMES[dimension]}, pero todavía no cumplen corroboración, relación directa o masa mínima para publicar presión."
        return "No hay evidencia suficiente para calcular esta dimension en la ventana analizada."
    return f"{DIMENSION_NAMES[dimension]} is reconstructed from {len(clusters)} mapped evidence clusters, after entity resolution, source weighting, deduplication, recency and corroboration controls."


def _source_for(event: ThreatEvent, canonical_url: str, organization: OrganizationProfile, registry: Dict[str, Any]) -> NewsSource:
    haystack = _normalize_text(f"{event.source} {canonical_url}")
    values = dict(registry.get("default", {}))
    for rule in registry.get("rules", []):
        if any(_contains_phrase(haystack, _normalize_text(token)) for token in rule.get("match", [])):
            values.update({key: value for key, value in rule.items() if key != "match"})
            break
    host = (urlsplit(canonical_url).hostname or "").lower()
    self_reported = any(host == domain or host.endswith(f".{domain}") for domain in [*organization.primary_domains, *organization.comparison_domains])
    if self_reported:
        values.update({"reliability_score": max(0.90, float(values.get("reliability_score", 0))), "source_tier": "A", "independence_score": 0.0, "factual_reliability": 0.90, "bias_or_interest": "self_reported", "validation_status": "self_reported_fact"})
    return NewsSource(source_id=_stable_id("source", host or event.source), source_name=event.source, source_type="official" if values.get("source_tier") == "A" else "public_news", self_reported=self_reported, **values)


def _classify_event_type(event: ThreatEvent, taxonomy: Dict[str, Any]) -> Optional[str]:
    for tag in event.tags:
        if tag.lower().startswith("event_type:"):
            candidate = tag.split(":", 1)[1].strip()
            if any(row.get("id") == candidate for row in taxonomy.get("events", [])):
                return candidate
    text = _normalize_text(" ".join([_event_content_title(event.title), *event.tags, str(event.technical_validation.get("summary") or "")]))
    ranked: List[Tuple[int, str]] = []
    for row in taxonomy.get("events", []):
        for keyword in row.get("keywords", []):
            token = _normalize_text(keyword)
            if _contains_phrase(text, token):
                ranked.append((len(token.split()), row["id"]))
    return max(ranked, default=(0, None))[1]


def _event_content_title(value: str) -> str:
    """Remove collector query metadata so it cannot become evidence."""
    return re.split(r"\s+\|\s+query:\s*", value or "", maxsplit=1, flags=re.IGNORECASE)[0].strip()


def _event_direction(event: ThreatEvent) -> float:
    for tag in event.tags:
        lowered = tag.lower()
        if lowered in {"pressure:reduce", "pressure:decrease", "pressure:-1"}:
            return -1.0
        if lowered in {"pressure:increase", "pressure:+1", "pressure:1"}:
            return 1.0
        if lowered.startswith("pressure:"):
            try:
                return max(-1.0, min(1.0, float(lowered.split(":", 1)[1])))
            except ValueError:
                pass
    return 0.0


def _event_magnitude(event: ThreatEvent) -> float:
    labels = {"low": 0.30, "medium": 0.55, "high": 0.80, "critical": 1.0, "baja": 0.30, "media": 0.55, "alta": 0.80, "critica": 1.0}
    for tag in event.tags:
        if tag.lower().startswith("magnitude:"):
            value = tag.split(":", 1)[1].strip().lower()
            if value in labels:
                return labels[value]
    return max(0.20, min(1.0, float(event.severity)))


def _half_life(event_type: str, taxonomy: Dict[str, Any]) -> int:
    return next((int(item.get("half_life_days", 30)) for item in taxonomy.get("events", []) if item.get("id") == event_type), 30)


def _add_named_entities(graph: EntityResolutionGraph, names: Iterable[str], entity_type: str, relationship: str, org_id: str) -> None:
    for raw_name in names:
        name = str(raw_name).strip()
        if not name:
            continue
        entity_id = _stable_id(entity_type, name)
        graph.aliases.append(EntityAlias(alias=name, canonical_entity_id=entity_id, alias_type=entity_type, confidence=0.90, relationship=relationship, required_context=[value for value in [graph.organization.country, graph.organization.sector] if value] if len(_normalize_text(name).replace(" ", "")) <= 3 else []))
        if entity_type == "brand":
            graph.brands.append(BrandEntity(entity_id=entity_id, name=name, organization_id=org_id))
        elif entity_type == "subsidiary":
            graph.subsidiaries.append(SubsidiaryRelationship(parent_id=org_id, subsidiary_id=entity_id))
        elif entity_type == "parent":
            graph.parents.append(ParentRelationship(entity_id=org_id, parent_id=entity_id))
        elif entity_type == "supplier":
            graph.suppliers.append(SupplierRelationship(organization_id=org_id, supplier_id=entity_id))
        elif entity_type == "competitor":
            graph.competitors.append(CompetitorRelationship(organization_id=org_id, competitor_id=entity_id))
        elif entity_type == "product":
            graph.products.append(ProductEntity(entity_id=entity_id, name=name, organization_id=org_id))
        elif entity_type == "strategic_asset":
            graph.strategic_assets.append(StrategicAssetEntity(entity_id=entity_id, name=name, organization_id=org_id))


def _cluster_age_days(cluster: StrategicEventCluster) -> int:
    try:
        value = datetime.fromisoformat(cluster.last_seen.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - value).days)
    except (TypeError, ValueError):
        return 0


def _cluster_direction(cluster: StrategicEventCluster, contributions: Sequence[StrategicScoreContribution]) -> float:
    values = [item.direction for item in contributions if item.event_cluster_id == cluster.event_cluster_id]
    return sum(values) / len(values) if values else cluster.pressure_direction


def _source_origin(article: NewsArticle) -> str:
    return (urlsplit(article.canonical_url).hostname or article.source_name).lower()


def _weighted_average(rows: Sequence[Tuple[float, float]]) -> float:
    total = sum(weight for _, weight in rows)
    return sum(value * weight for value, weight in rows) / total if total else 0.0


def _weighted_variance(rows: Sequence[Tuple[float, float]]) -> float:
    if not rows:
        return 1.0
    mean = _weighted_average(rows)
    total = sum(weight for _, weight in rows)
    return sum(weight * (value - mean) ** 2 for value, weight in rows) / total if total else 1.0


def _magnitude_label(value: float) -> str:
    if value >= 0.85:
        return "critical"
    if value >= 0.65:
        return "high"
    if value >= 0.40:
        return "medium"
    return "low"


def _canonical_url(url: str) -> str:
    parts = urlsplit(url.strip())
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid"}]
    return urlunsplit((parts.scheme.lower() or "https", parts.netloc.lower(), parts.path.rstrip("/") or "/", urlencode(sorted(query)), ""))


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "").encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9.]+", " ", normalized).strip()


def _scope_terms(value: str) -> List[str]:
    return [_normalize_text(item) for item in re.split(r"\s*[,;/|]\s*", value or "") if _normalize_text(item)]


def _contains_phrase(text: str, phrase: str) -> bool:
    if not phrase:
        return False
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", text))


def _jaccard(left: str, right: str) -> float:
    first = set(_normalize_text(left).split())
    second = set(_normalize_text(right).split())
    return len(first & second) / max(1, len(first | second))


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(_normalize_text(str(part)) for part in parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def _unique_matches(matches: Sequence[NewsEntityMatch]) -> List[NewsEntityMatch]:
    rows: Dict[Tuple[str, str], NewsEntityMatch] = {}
    for match in matches:
        key = (match.matched_entity_id, match.relationship)
        if key not in rows or match.match_confidence > rows[key].match_confidence:
            rows[key] = match
    return list(rows.values())


def _load_json(name: str) -> Dict[str, Any]:
    return json.loads((STRATEGIC_DATA_DIR / name).read_text(encoding="utf-8"))
