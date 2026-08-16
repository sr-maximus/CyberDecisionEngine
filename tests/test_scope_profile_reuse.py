from cyberdeck_api.jobs import _reuse_exact_scope_profile
from cyberdeck_api.models import DomainAnalysisRequest, RunRecord


def _completed_run(run_id: str, domains: list[str], **request_overrides: object) -> RunRecord:
    request = DomainAnalysisRequest(
        domains=domains,
        organization_name="Authorized Organization",
        legal_name="Authorized Organization",
        sector="Energy infrastructure",
        subsector="Ports, pipelines and logistics",
        country="Canada",
        brands=["Primary Brand", "Secondary Brand", "Service Brand"],
        strategic_assets=["Primary Platform", "Distribution Platform"],
        countries_of_operation=["Colombia", "Canada"],
        authorized_scope=True,
        **request_overrides,
    )
    return RunRecord(id=run_id, status="completed", request=request, domains=domains)


def test_request_defaults_are_strategic_and_consistent_across_api_clients():
    request = DomainAnalysisRequest(domains=["example.org"], authorized_scope=True)

    assert request.mode == "deep"
    assert request.analysis_window == "365d"
    assert request.lookback_hours == 8760
    assert request.lookback_days == 365
    assert request.scan_time_budget_minutes == 30


def test_exact_domain_scope_reuses_only_missing_declared_profile_fields():
    domains = [
        "organization.example.invalid",
        "secondary.example.invalid",
        "service.example.invalid",
    ]
    prior = _completed_run("prior-scope", domains)
    request = DomainAnalysisRequest(
        domains=list(reversed(domains)),
        country="Colombia",
        authorized_scope=True,
    )

    hydrated = _reuse_exact_scope_profile(request, request.domains, [prior])

    assert hydrated.organization_name == "Authorized Organization"
    assert hydrated.sector == "Energy infrastructure"
    assert hydrated.country == "Colombia"
    assert hydrated.brands == ["Primary Brand", "Secondary Brand", "Service Brand"]
    assert hydrated.scope_profile_source_run_id == "prior-scope"
    assert "organization_name" in hydrated.scope_profile_applied_fields
    assert "country" not in hydrated.scope_profile_applied_fields


def test_profile_is_not_reused_for_partial_or_different_scope():
    prior = _completed_run("prior-scope", ["example.org", "example.net"])
    request = DomainAnalysisRequest(domains=["example.org"], authorized_scope=True)

    hydrated = _reuse_exact_scope_profile(request, request.domains, [prior])

    assert hydrated.organization_name is None
    assert hydrated.scope_profile_source_run_id is None
    assert hydrated.scope_profile_applied_fields == []
