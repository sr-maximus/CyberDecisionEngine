from cyberdeck.analysis.public_entities import build_public_entity_intelligence
from cyberdeck.schemas import OrganizationProfile, ThreatEvent


def test_public_entity_inventory_keeps_evidence_and_limitations():
    event = ThreatEvent(
        id="public-profile",
        title="Jane Doe - Security Director",
        category="social_signal",
        source="Public search",
        evidence_url="https://www.linkedin.com/in/jane-doe/",
        relationship_to_scope="related",
        tags=[
            "person_candidate:Jane Doe",
            "email:jane.doe@example.com",
            "phone:+573001234567",
        ],
    )
    organization = OrganizationProfile(
        name="Example",
        sector="",
        country="CO",
        author="test",
        language="es",
        authorized_scope=True,
        primary_domains=["example.com"],
    )

    result = build_public_entity_intelligence([event], organization)

    assert result["total_candidates"] == 3
    assert result["emails"] == 1
    assert result["phones"] == 1
    assert result["people_profiles"] == 1
    person = next(row for row in result["rows"] if row["type"] == "person")
    assert person["evidence_urls"] == ["https://www.linkedin.com/in/jane-doe/"]
    assert "empleo vigente" in person["what_it_does_not_demonstrate"]
