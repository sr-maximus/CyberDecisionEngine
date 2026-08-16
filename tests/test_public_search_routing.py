from cyberdeck.collectors.web_search import _classify_search_result, _parse_google_cse, _public_entity_candidates
from cyberdeck.reporting.html_report import _search_groups


def test_public_entity_candidates_extract_contacts_and_linkedin_profile_without_asserting_employment():
    tags, entities = _public_entity_candidates(
        "Synthetic Person - Security Director | Public profile",
        "https://www.linkedin.com/in/synthetic-person/",
        "Contact: synthetic-person@example.invalid +1 202 555 0100",
    )

    assert "email:synthetic-person@example.invalid" in tags
    assert "phone:+12025550100" in tags
    assert "person_candidate:Synthetic Person" in tags
    assert {item["status"] for item in entities} == {"public_contact_candidate", "public_profile_candidate"}


def test_social_urls_found_by_web_search_are_routed_to_socmint():
    events = _parse_google_cse(
        "organization.example.invalid public profile",
        {
            "items": [
                {
                    "title": "Authorized Organization public profile",
                    "link": "https://www.linkedin.com/company/synthetic-organization/",
                    "snippet": "Perfil publico oficial y menciones de marca.",
                }
            ]
        },
        5,
    )

    assert events
    assert events[0].category == "social_signal"
    assert "socmint_public" in events[0].tags
    assert "platform_linkedin" in events[0].tags

    groups = _search_groups([events[0].model_dump()])
    assert groups["socmint"]["count"] == 1
    assert groups["internet"]["count"] == 0


def test_brand_fraud_terms_are_classified_as_actionable_brand_protection():
    category, tags, technique = _classify_search_result(
        "Synthetic Brand farsa y soporte falso",
        "synthetic brand farsa",
        "https://x.com/synthetic-brand/status/123",
        "Usuarios reportan posible estafa y suplantacion de marca.",
    )

    assert category == "phishing"
    assert technique == "T1566"
    assert {"brand_protection", "brand_impersonation", "socmint_public", "platform_x"}.issubset(set(tags))


def test_reputation_checker_result_is_validation_context_not_phishing():
    category, tags, technique = _classify_search_result(
        "Check if organization.example.invalid is legit or a scam - Reputation Checker",
        '"organization.example.invalid"',
        "https://checker.example.invalid/url-checker/organization",
        "Free URL checker reputation page.",
    )

    assert category == "brand_reputation"
    assert technique is None
    assert "reputation_checker" in tags
    assert "validation_required" in tags
    assert "fraud" not in tags


def test_fake_recruitment_is_classified_as_brand_fraud():
    category, tags, technique = _classify_search_result(
        "Alerta: falsa oferta de empleo suplanta a Empresa Ejemplo",
        '"empresa.example" empleo falso',
        "https://news.example/falsa-oferta-empleo",
        "La organización advirtió sobre una estafa de reclutamiento.",
    )

    assert category == "fake_recruitment"
    assert "fake_recruitment" in tags
    assert "brand_impersonation" in tags
    assert technique == "T1566"


def test_query_intent_does_not_become_observed_classification():
    category, tags, technique = _classify_search_result(
        "Example Energy - official corporate site",
        '"example.com" phishing fraude ransomware',
        "https://example.com/",
        "Corporate information and investor relations.",
    )

    assert category == "web_search"
    assert technique is None
    assert "fraud" not in tags


def test_search_result_keeps_query_as_metadata_not_title():
    event = _parse_google_cse(
        '"example.com" financial results',
        {
            "items": [
                {
                    "title": "Example Energy publishes financial results",
                    "link": "https://example.com/investors/results",
                    "snippet": "Official net income and investment update.",
                }
            ]
        },
        1,
    )[0]

    assert "| query:" not in event.title
    assert event.technical_validation["query"] == '"example.com" financial results'
    assert event.technical_validation["summary"] == "Official net income and investment update."
