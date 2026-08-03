from cyberdeck_api.domain_scope import build_organization_profile, build_source_config, normalize_domains
from cyberdeck_api.models import DomainAnalysisRequest, normalize_analysis_window


def test_normalize_domains_accepts_urls_and_dedupes():
    domains = normalize_domains(
        [
            "https://www.Example.com/login",
            "example.com",
            "*.sub.example.org:443",
        ]
    )

    assert domains == ["example.com", "sub.example.org"]


def test_normalize_domains_rejects_invalid_values():
    try:
        normalize_domains(["not a domain"])
    except ValueError as exc:
        assert "Invalid domain" in str(exc)
    else:
        raise AssertionError("Expected invalid domain to raise ValueError")


def test_build_source_config_injects_domain_queries():
    config = build_source_config(
        {"web_search": {"enabled": False}},
        ["example.com"],
        "Example Holding",
        ["competitor.com"],
        country="Colombia",
        sector="Energy",
        strategic_context={
            "declared_competitors": ["Market Rival"],
            "critical_suppliers": ["Cloud Supplier"],
            "products": ["Digital Platform"],
            "countries_of_operation": ["Canada"],
        },
    )

    assert config["web_search"]["enabled"] is True
    assert '"example.com" phishing' in config["web_search"]["queries"]
    assert '"competitor.com" phishing' in config["web_search"]["queries"]
    assert '"Example Holding" fraude OR phishing OR suplantacion' in config["web_search"]["queries"]
    assert '"Example Holding" "Energy" ciberseguridad OR riesgo digital' in config["web_search"]["queries"]
    assert '"Example Holding" "Market Rival" competencia digital OR mercado OR tecnologia OR ciberseguridad' in config["web_search"]["queries"]
    assert '"Example Holding" "Cloud Supplier" proveedor tecnologico OR interrupcion OR dependencia OR cadena de suministro de software OR ciberseguridad' in config["web_search"]["queries"]
    assert '"Example Holding" "Digital Platform" mercado OR clientes OR sustituto OR riesgo digital' in config["web_search"]["queries"]
    assert any("site:example.com" in query for query in config["web_search"]["queries"])
    assert any("credential" in query for query in config["web_search"]["queries"])
    assert config["osint_public"]["domains"] == ["example.com", "competitor.com"]
    assert config["osint_public"]["enabled"] is True
    assert config["osint_tools"]["enabled"] is True
    assert {"example", "competitor", "exampleholding"}.issubset(set(config["osint_tools"]["targets"]))
    assert config["kali_surface"]["domains"] == ["example.com"]
    assert config["kali_surface"]["mode"] == "deep"
    assert config["kali_surface"]["web_crawl"] is True
    assert config["kali_surface"]["crawl_depth"] == 2
    assert config["spiderfoot"]["domains"] == ["example.com"]
    assert config["spiderfoot"]["depth"] == "deep"
    assert config["spiderfoot"]["include_raw"] is False
    assert {"example.com", "competitor.com", "Example Holding", "example", "competitor"}.issubset(set(config["urlscan"]["terms"]))
    assert config["otx"]["domains"] == ["example.com", "competitor.com"]
    assert "Example Holding" in config["socmint_public"]["keywords"]
    assert {"example.com", "competitor.com", "Example Holding", "example", "competitor"}.issubset(set(config["socmint_public"]["keywords"]))


def test_build_source_config_honors_scan_time_budget():
    domains = ["example.com", "example.org", "example.net"]
    config = build_source_config({"web_search": {"enabled": False}}, domains, "Example Holding", [], "CO", "deep", 30)

    assert config["scan_budget"]["minutes"] == 30
    assert config["scan_budget"]["mode"] == "user_defined"
    assert config["web_search"]["collection_timeout_seconds"] >= 600
    assert config["spiderfoot"]["timeout_seconds"] == 0
    assert config["spiderfoot"]["completion_policy"] == "wait_until_configured_modules_finish"
    assert config["kali_surface"]["timeout_seconds"] >= 300
    assert config["osint_tools"]["timeout_seconds"] >= 180
    assert all(domain in config["spiderfoot"]["domains"] for domain in domains)


def test_default_collection_waits_for_configured_plan_completion():
    config = build_source_config({"web_search": {"enabled": False}}, ["example.com"], "Example Holding")

    assert config["scan_budget"]["mode"] == "until_complete"
    assert config["web_search"]["collection_timeout_seconds"] == 0
    assert config["spiderfoot"]["timeout_seconds"] == 0


def test_build_source_config_injects_colombia_public_queries():
    config = build_source_config({"web_search": {"enabled": False}}, ["grupoaval.com"], "Grupo Aval", [], "CO")

    queries = config["web_search"]["queries"]
    assert '"Grupo Aval" site:colcert.gov.co' in queries
    assert '"Grupo Aval" site:cc-csirt.policia.gov.co' in queries
    assert '"Grupo Aval" site:csirtsalud.gov.co' in queries
    assert '"Grupo Aval" site:superfinanciera.gov.co' in queries
    assert '"grupoaval.com" Colombia phishing OR fraude OR suplantacion' in queries


def test_actionable_queries_precede_broad_strategic_context():
    config = build_source_config(
        {"web_search": {"enabled": False}},
        ["example.com"],
        "Example Group",
        [],
        "Colombia",
        sector="financial",
    )
    queries = config["web_search"]["queries"]

    fake_job_index = queries.index(
        '"example.com" "oferta laboral falsa" OR "empleo falso" OR "fake job" OR "recruitment scam"'
    )
    strategic_index = queries.index(
        '"Example Group" regulator OR regulacion OR regulation OR gobierno'
    )
    assert fake_job_index < strategic_index


def test_build_source_config_does_not_truncate_many_domains():
    domains = [f"brand{i}.example.com" for i in range(1, 21)]
    config = build_source_config({"web_search": {"enabled": False}}, domains, "Holding Regional", [], "CO")

    queries = config["web_search"]["queries"]
    assert all(f'"{domain}" phishing' in queries for domain in domains)
    assert all(domain in config["osint_public"]["domains"] for domain in domains)
    assert all(domain in config["kali_surface"]["domains"] for domain in domains)
    assert all(domain in config["spiderfoot"]["domains"] for domain in domains)
    assert all(domain.split(".", 1)[0] in config["osint_tools"]["targets"] for domain in domains)
    assert config["web_search"]["max_queries"] == 0
    assert config["web_search"]["max_records"] == 0
    assert config["scan_budget"]["mode"] == "until_complete"
    assert config["osint_tools"]["max_records"] >= len(domains)


def test_build_source_config_supports_brand_only_scope():
    config = build_source_config({"web_search": {"enabled": False}}, [], "Grupo Aval", [], "CO")

    assert '"Grupo Aval" fraude OR phishing OR suplantacion' in config["web_search"]["queries"]
    assert "Grupo Aval" in config["socmint_public"]["keywords"]
    assert "grupoaval" in config["osint_tools"]["targets"]
    assert config["kali_surface"]["domains"] == []
    assert config["spiderfoot"]["domains"] == []


def test_analysis_window_is_normalized_into_org_profile():
    request = DomainAnalysisRequest(
        domains=["example.com"],
        organization_name="Example Holding",
        sector="financial",
        country="CO",
        analysis_window="1h",
        lookback_hours=8760,
        lookback_days=365,
        scan_time_budget_minutes=30,
        report_display_at="2026-02-03T14:45",
        authorized_scope=True,
    )

    normalize_analysis_window(request)
    profile = build_organization_profile(request, ["example.com"])

    assert request.lookback_hours == 1
    assert request.lookback_days == 1
    assert profile["organization"]["analysis_window"] == "1h"
    assert profile["organization"]["lookback_hours"] == 1
    assert profile["organization"]["scan_time_budget_minutes"] == 30
    assert profile["organization"]["primary_domains"] == ["example.com"]
    assert profile["organization"]["comparison_domains"] == []
    assert profile["organization"]["report_display_at"] == "2026-02-03T14:45"
    assert profile["organization"]["allow_tor"] is True
    assert profile["sources"]["allow_tor"] is True


def test_organization_profile_can_disable_tor_lookup():
    request = DomainAnalysisRequest(
        domains=["example.com"],
        organization_name="Example Holding",
        authorized_scope=True,
        allow_tor=False,
    )

    profile = build_organization_profile(request, ["example.com"])

    assert profile["organization"]["allow_tor"] is False
    assert profile["sources"]["allow_tor"] is False


def test_report_display_date_rejects_invalid_datetime():
    try:
        DomainAnalysisRequest(
            domains=["example.com"],
            organization_name="Example Holding",
            authorized_scope=True,
            report_display_at="not-a-date",
        )
    except ValueError as exc:
        assert "report_display_at" in str(exc)
    else:
        raise AssertionError("Expected invalid report_display_at to raise ValueError")


def test_domain_analysis_request_accepts_organization_without_domains():
    request = DomainAnalysisRequest(
        domains=[],
        organization_name="Grupo Aval",
        authorized_scope=True,
    )

    assert request.domains == []
    assert request.organization_name == "Grupo Aval"


def test_person_scope_is_first_class_and_uses_person_queries():
    request = DomainAnalysisRequest(
        domains=[],
        subject_type="person",
        person_name="Ada Example",
        person_aliases=["ada_example"],
        country="CO",
        authorized_scope=True,
    )

    config = build_source_config(
        {"web_search": {"enabled": False}},
        [],
        request.subject_name,
        [],
        request.country,
        "deep",
        0,
        "",
        request.subject_type,
        request.person_aliases,
    )
    profile = build_organization_profile(request, [])

    assert request.subject_name == "Ada Example"
    assert '"Ada Example" perfil OR profile OR biografia OR biography' in config["web_search"]["queries"]
    assert '"ada_example" username OR usuario OR alias' in config["web_search"]["queries"]
    assert "Ada Example perfil" in config["socmint_public"]["keywords"]
    assert config["kali_surface"]["domains"] == []
    assert config["spiderfoot"]["domains"] == []
    assert profile["organization"]["entity_type"] == "person"
    assert profile["organization"]["subject_aliases"] == ["ada_example"]


def test_request_infers_person_scope_for_api_clients_that_send_person_name():
    request = DomainAnalysisRequest(person_name="Grace Example", authorized_scope=True)

    assert request.subject_type == "person"
    assert request.subject_name == "Grace Example"


def test_unrelated_multidomain_scope_has_no_fixture_specific_targets():
    domains = ["example.org", "iana.org", "example.net"]
    config = build_source_config({"web_search": {"enabled": False}}, domains, "Independent Research Group")
    serialized = str(config).lower()

    assert all(domain in config["osint_public"]["domains"] for domain in domains)
    assert all(f'"{domain}" phishing' in config["web_search"]["queries"] for domain in domains)
    assert "puertobahia" not in serialized
    assert "fronteraenergy" not in serialized
    assert "parexresources" not in serialized
