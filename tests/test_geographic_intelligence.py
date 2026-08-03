from cyberdeck.analysis.geographic_intelligence import build_geographic_intelligence
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


def _organization() -> OrganizationProfile:
    return OrganizationProfile(
        name="Example Energy",
        sector="Energy",
        country="CA",
        countries_of_operation=["CO"],
        author="test",
        language="es",
        authorized_scope=True,
        primary_domains=["example.ca"],
    )


def test_geography_separates_declared_scope_from_supported_and_contextual_mentions():
    official = ThreatEvent(
        id="official-colombia",
        title="Example Energy operations in Colombia",
        category="official_record",
        source="Corporate filing",
        evidence_url="https://example.ca/annual-report.pdf",
        relationship_to_scope="direct",
        evidence_status=EvidenceStatus.VALIDATED,
        validation_result="validated",
        tags=["domain:example.ca", "annual_report", "official_source"],
    )
    contextual = ThreatEvent(
        id="context-mexico",
        title="Energy market trends in Mexico",
        category="strategic_news",
        source="Industry news",
        evidence_url="https://news.example/energy-mexico",
        relationship_to_scope="contextual",
        tags=["sector:energy"],
    )

    result = build_geographic_intelligence([official, contextual], _organization())

    assert result["declared_countries_of_operation"] == ["CA", "CO"]
    assert result["declared_country_labels"] == ["Canadá", "Colombia"]
    colombia = next(row for row in result["evidence_supported_countries"] if row["code"] == "CO")
    canada_inventory = next(row for row in result["country_inventory"] if row["code"] == "CA")
    colombia_inventory = next(row for row in result["country_inventory"] if row["code"] == "CO")
    mexico = next(row for row in result["contextual_country_mentions"] if row["code"] == "MX")
    assert colombia["status"] == "supported_operational_context"
    assert colombia["evidence_ids"] == ["official-colombia"]
    assert canada_inventory["status"] == "declared_scope"
    assert colombia_inventory["status"] == "supported_operational_context"
    assert colombia_inventory["declared"] is True
    assert mexico["status"] == "mention_only"
    assert "operaciones corporativas" in mexico["what_it_does_not_demonstrate"]


def test_country_mention_does_not_become_operation_without_assured_official_evidence():
    mention = ThreatEvent(
        id="mention-brazil",
        title="Example Energy mentioned alongside Brazil",
        category="web_search",
        source="Public search",
        evidence_url="https://search.example/result",
        relationship_to_scope="related",
        tags=["domain:example.ca"],
    )

    result = build_geographic_intelligence([mention], _organization())
    brazil = next(row for row in result["evidence_supported_countries"] if row["code"] == "BR")

    assert brazil["status"] == "mention_only"
    assert brazil["official_records"] == 0
    assert not any(tag.startswith("country_operation_supported:") for tag in mention.tags)


def test_geographic_method_uses_the_organization_language():
    organization = _organization()
    organization.language = "es"

    result = build_geographic_intelligence([], organization)

    assert result["method"].startswith("Los países declarados")
    assert result["limitations"].startswith("La ubicación de la fuente")


def test_country_code_top_level_domain_is_not_a_country_mention():
    event = ThreatEvent(
        id="tld-only",
        title="Indexed corporate page",
        category="web_search",
        source="Public search",
        evidence_url="https://example.ca/contact",
        relationship_to_scope="related",
        tags=["domain:example.ca"],
    )

    result = build_geographic_intelligence([event], _organization())

    assert result["evidence_supported_countries"] == []
    assert [row["code"] for row in result["country_inventory"]] == ["CA", "CO"]


def test_country_inventory_includes_every_declared_and_related_country_once():
    ecuador = ThreatEvent(
        id="ecuador-operations",
        title="Example Energy reports operations in Ecuador",
        category="official_record",
        source="Corporate filing",
        evidence_url="https://example.ca/ecuador.pdf",
        relationship_to_scope="direct",
        evidence_status=EvidenceStatus.VALIDATED,
        tags=["annual_report", "official_source"],
    )
    duplicate = ecuador.model_copy(update={"id": "ecuador-duplicate"})

    result = build_geographic_intelligence([ecuador, duplicate], _organization())

    assert [row["code"] for row in result["country_inventory"]] == ["EC", "CA", "CO"]
    ecuador_row = result["country_inventory"][0]
    assert ecuador_row["records"] == 2
    assert ecuador_row["status"] == "supported_operational_context"
