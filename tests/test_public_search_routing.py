from cyberdeck.collectors.web_search import _classify_search_result, _parse_google_cse
from cyberdeck.reporting.html_report import _search_groups


def test_social_urls_found_by_web_search_are_routed_to_socmint():
    events = _parse_google_cse(
        "grupoaval.com facebook instagram",
        {
            "items": [
                {
                    "title": "Grupo Aval en Instagram",
                    "link": "https://www.instagram.com/grupoaval/",
                    "snippet": "Perfil publico oficial y menciones de marca.",
                }
            ]
        },
        5,
    )

    assert events
    assert events[0].category == "social_signal"
    assert "socmint_public" in events[0].tags
    assert "platform_instagram" in events[0].tags

    groups = _search_groups([events[0].model_dump()])
    assert groups["socmint"]["count"] == 1
    assert groups["internet"]["count"] == 0


def test_brand_fraud_terms_are_classified_as_actionable_brand_protection():
    category, tags, technique = _classify_search_result(
        "Avvillas farsa y soporte falso",
        "avvillas farsa",
        "https://x.com/example/status/123",
        "Usuarios reportan posible estafa y suplantacion de marca.",
    )

    assert category == "phishing"
    assert technique == "T1566"
    assert {"brand_protection", "brand_impersonation", "socmint_public", "platform_x"}.issubset(set(tags))


def test_reputation_checker_result_is_validation_context_not_phishing():
    category, tags, technique = _classify_search_result(
        "Check if odl.com.co is legit or a scam - EmailVeritas",
        '"odl.com.co"',
        "https://www.emailveritas.com/url-checker/odl-com-co",
        "Free URL checker reputation page.",
    )

    assert category == "brand_reputation"
    assert technique is None
    assert "reputation_checker" in tags
    assert "validation_required" in tags
    assert "fraud" not in tags


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
