import pytest
from pydantic import ValidationError

from cyberdeck.analysis.period import select_period_events
from cyberdeck.collectors.web_search import WebSearchCollector
from cyberdeck.reporting.html_report import _report_scope
from cyberdeck.schemas import OrganizationProfile, RunContext, ThreatEvent
from cyberdeck_api.domain_scope import build_organization_profile
from cyberdeck_api.models import DomainAnalysisRequest, normalize_analysis_window


def request(**changes):
    return DomainAnalysisRequest(organization_name="Example Energy", domains=["example.com"], authorized_scope=True,
        **{"analysis_start_date": "2026-01-01", "analysis_end_date": "2026-06-30", **changes})


def test_calendar_semester_is_not_a_rolling_180_day_window():
    req = normalize_analysis_window(request())
    assert req.analysis_window == "custom"
    assert req.lookback_days == 181
    profile = build_organization_profile(req, req.domains)["organization"]
    assert profile["analysis_start_date"] == "2026-01-01"
    assert profile["analysis_end_date"] == "2026-06-30"


@pytest.mark.parametrize("changes", [
    {"analysis_start_date": None}, {"analysis_end_date": "2025-12-31"},
    {"analysis_start_date": "invalid"}, {"analysis_end_date": "2099-01-01"},
])
def test_invalid_period_is_rejected(changes):
    with pytest.raises(ValidationError):
        request(**changes)


def test_inclusive_boundaries_undated_included_and_outside_retained():
    org = OrganizationProfile(name="Example", sector="energy", country="CO", author="test",
        analysis_start_date="2026-01-01", analysis_end_date="2026-06-30")
    context = RunContext(organization=org, mode="deep", lookback_days=181)
    dates = ["2026-01-01T00:00:00Z", "2026-06-30T23:59:59Z", "2026-07-01T00:00:00Z", "2025-12-31T23:59:59Z", None, "not-a-date"]
    events = [ThreatEvent(id=str(index), title="Evidence", category="threat_intel", source="fixture", published_at=stamp) for index, stamp in enumerate(dates)]
    selected = select_period_events(context, events)
    assert [event.id for event in selected] == ["0", "1", "4", "5"]
    assert selected[0].age_days == 180
    assert selected[1].age_days == 0
    assert "period_membership_unverified" in selected[2].tags
    assert {event.id for event in context.excluded_period_events} == {"2", "3"}
    assert context.metrics["analysis_period"]["undated_records"] == 2
    assert context.metrics["analysis_period"]["dated_in_period_records"] == 2
    scope = _report_scope(context.model_dump(mode="json"), "es")
    assert "2026-01-01 a 2026-06-30" in scope["analysis_window"]
    assert scope["analysis_period"]["undated_records"] == 2


def test_search_requests_include_calendar_bounds():
    collector = WebSearchCollector(["Example Energy"], start_date="2026-01-01", end_date="2026-06-30")
    assert collector._dated_query("Example Energy").endswith("after:2025-12-31 before:2026-07-01")
    assert collector._date_params("gdelt") == {"startdatetime": "20260101000000", "enddatetime": "20260630235959"}
    assert collector._date_params("hacker_news") == {"numericFilters": "created_at_i>=1767225600,created_at_i<1782864000"}
