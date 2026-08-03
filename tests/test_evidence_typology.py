from cyberdeck.reporting.html_report import (
    _evidence_rows,
    _evidence_type_summary,
    _executive_evidence_sample,
    _scope_filtered_events,
)
from cyberdeck.schemas import EvidenceType, ThreatEvent


def event(**overrides):
    values = {
        "id": "EV-1",
        "title": "Public record",
        "category": "osint",
        "source": "Public Search",
        "evidence_url": "https://example.test/page",
    }
    values.update(overrides)
    return ThreatEvent(**values)


def test_evidence_typology_uses_observable_record_attributes():
    assert event(evidence_url="https://example.test/report.pdf").evidence_type == EvidenceType.DOCUMENT
    assert event(source="SOCMINT", evidence_url="https://linkedin.com/company/example").evidence_type == EvidenceType.SOCIAL_MEDIA
    assert event(source="NVD", category="vulnerability").evidence_type == EvidenceType.OFFICIAL_RECORD
    assert event(source="SpiderFoot", category="attack_surface_dns").evidence_type == EvidenceType.TECHNOLOGY_INFRASTRUCTURE
    assert event(tags=["rss"], category="strategic_news").evidence_type == EvidenceType.NEWS
    assert event(title="TikTok changes its market policy", tags=["rss"], category="strategic_news").evidence_type == EvidenceType.NEWS
    assert (
        event(
            title="La empresa reportó cambios en inversiones",
            tags=["internet_search", "google_news_rss"],
            evidence_url="https://news.google.com/rss/articles/example",
            evidence_type=EvidenceType.TECHNOLOGY_INFRASTRUCTURE,
        ).evidence_type
        == EvidenceType.NEWS
    )
    assert event(category="darkweb_index", evidence_url="http://sample.onion").evidence_type == EvidenceType.AUTHORIZED_DARK_WEB
    assert event().evidence_type == EvidenceType.WEB_PAGE


def test_reports_count_all_evidence_and_keep_executive_sample_representative():
    events = []
    for index in range(210):
        suffix = ".pdf" if index < 5 else ""
        events.append(
            event(
                id=f"EV-{index}",
                title=f"Record {index}",
                evidence_url=f"https://example.test/record-{index}{suffix}",
            ).model_dump(mode="json")
        )
    rows = _evidence_rows(events, "es")
    sample = _executive_evidence_sample(rows)
    summary = {item["key"]: item["count"] for item in _evidence_type_summary(rows, "es")}

    assert len(rows) == 210
    assert len(sample) == 40
    assert {row["evidence_type"] for row in sample} == {"document", "web_page"}
    assert summary == {"web_page": 205, "document": 5}


def test_report_scope_includes_declared_brand_news_without_global_noise():
    relevant = event(
        id="NEWS-1",
        title="Frontera Energy reportó cambios en inversión",
        tags=["google_news_rss"],
        evidence_url="https://news.google.com/rss/articles/relevant",
    ).model_dump(mode="json")
    unrelated = event(
        id="NEWS-2",
        title="Cambios generales del mercado",
        tags=["google_news_rss"],
        evidence_url="https://news.google.com/rss/articles/unrelated",
    ).model_dump(mode="json")
    payload = {
        "report_scope": {"primary_domains": ["fronteraenergy.ca"]},
        "organization": {
            "name": "Frontera Energy Corporation",
            "brands": ["Frontera Energy", "ODL"],
        },
        "raw_events": [relevant, unrelated],
    }

    assert [row["id"] for row in _scope_filtered_events(payload, "es")] == ["NEWS-1"]
