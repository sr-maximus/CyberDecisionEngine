from __future__ import annotations

import csv
import json
from datetime import datetime, timezone

from cyberdeck.analysis.strategic_news import apply_strategic_context_to_scenarios, build_strategic_intelligence, export_strategic_scores
from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, ThreatEvent


def _organization(**overrides) -> OrganizationProfile:
    values = {
        "name": "Example Energy",
        "legal_name": "Example Energy S.A.",
        "sector": "energy",
        "country": "Colombia",
        "author": "test",
        "language": "es",
        "lookback_days": 30,
        "primary_domains": ["example.com"],
        "comparison_domains": ["competitor.example"],
        "critical_suppliers": ["CloudCo"],
    }
    values.update(overrides)
    return OrganizationProfile(**values)


def _news(event_id: str, title: str, url: str, **overrides) -> ThreatEvent:
    values = {
        "id": event_id,
        "title": title,
        "category": "news",
        "source": "Public News",
        "evidence_url": url,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "confidence_score": 0.88,
        "severity": 0.80,
        "evidence_status": EvidenceStatus.VALIDATED,
        "validation_result": "validated",
        "tags": [],
    }
    values.update(overrides)
    return ThreatEvent(**values)


def _dimension(result: dict, model: str, key: str) -> dict:
    return next(row for row in result[model]["dimensions"] if row["key"] == key)


def test_ambiguous_short_alias_is_rejected_without_context():
    organization = _organization(name="ODL", legal_name=None, primary_domains=["odl.com.co"])
    event = _news("odl-other", "ODL launches a developer library", "https://technology.example/odl-library", tags=["event_type:technology_adoption"])

    result = build_strategic_intelligence([event], organization)

    assert result["articles"] == []
    assert result["rejected_articles"][0]["reason"] == "unrelated_or_ambiguous_entity"
    assert result["pestel"]["index"] is None


def test_twenty_syndicated_copies_form_one_cluster_and_do_not_multiply_impact():
    events = [
        _news(
            f"copy-{index}",
            "Example Energy faces a technology outage at its main platform",
            f"https://news-{index}.example/story",
            content_hash="same-syndicated-body",
            source=f"Local News {index}",
            tags=["event_type:technology_disruption"],
        )
        for index in range(20)
    ]

    result = build_strategic_intelligence(events, _organization())

    assert result["pestel"]["modelVersion"] == "strategic-evidence-v1.3.0"
    assert result["porter"]["modelVersion"] == "strategic-evidence-v1.3.0"
    assert len(result["articles"]) == 20
    assert len(result["clusters"]) == 1
    assert result["clusters"][0]["article_count"] == 20
    assert result["clusters"][0]["independent_source_count"] == 1
    technology = _dimension(result, "pestel", "cyber_technology")
    assert technology["validatedPressure"] is None
    assert technology["signalScore"] > 0
    assert technology["cluster_count"] == 1
    assert technology["calculation"]["evidence_mass"] > 0
    assert technology["calculation"]["publication_gate_passed"] is False
    assert result["pestel"]["math_model"]["version"] == "strategic-evidence-v1.3.0"


def test_official_direct_environmental_sanction_is_traceable():
    event = _news(
        "official-sanction",
        "Environmental regulator imposes environmental sanction on Example Energy",
        "https://regulator.gov.co/resolutions/example-energy-sanction",
        source="Environmental regulator government",
        tags=["event_type:environmental_sanction", "magnitude:high"],
    )

    result = build_strategic_intelligence([event], _organization())
    environmental = _dimension(result, "pestel", "cyber_resilience")
    legal = _dimension(result, "pestel", "cyber_legal")

    assert environmental["score"] is not None
    assert legal["score"] is not None
    assert environmental["confidence"] > 0
    assert environmental["evidence_ids"] == ["official-sanction"]
    assert event.evidence_url in environmental["evidence_urls"]
    assert result["pestel"]["scenarios"] == []


def test_global_sector_news_is_context_only_without_organizational_score():
    event = _news(
        "global-sector",
        "Energy Colombia sector reviews a new regulation",
        "https://regulator.gov.co/energy-sector-rule",
        source="Government regulator",
        tags=["event_type:new_regulation"],
    )

    result = build_strategic_intelligence([event], _organization())

    assert result["articles"][0]["directness"] == "sector"
    assert _dimension(result, "pestel", "cyber_legal")["validatedPressure"] is None
    assert result["pestel"]["index"] is None


def test_declared_competitor_substitute_increases_porter_without_sentiment_logic():
    event = _news(
        "competitor-substitute",
        "competitor.example announces substitute technology for industrial energy clients",
        "https://competitor.example/news/substitute-platform",
        source="Competitor official newsroom",
        tags=["event_type:substitute_technology", "magnitude:high"],
    )

    result = build_strategic_intelligence([event], _organization())
    substitutes = _dimension(result, "porter", "cyber_substitutes")

    assert substitutes["score"] is not None
    assert substitutes["score"] > 50
    assert substitutes["drivers"][0]["relationship"] == "competitor"


def test_contradictory_sources_reduce_agreement_and_are_exposed():
    first = _news(
        "contradiction-a",
        "Example Energy supplier disruption has a high operating impact",
        "https://reuters.example/example-supplier-impact",
        source="Reuters",
        tags=["event_type:supplier_disruption", "pressure:increase"],
    )
    second = _news(
        "contradiction-b",
        "Example Energy supplier disruption has a low operating impact",
        "https://bbc.example/example-supplier-impact",
        source="BBC News",
        tags=["event_type:supplier_disruption", "pressure:reduce"],
    )

    result = build_strategic_intelligence([first, second], _organization())

    assert len(result["clusters"]) == 1
    assert result["clusters"][0]["contradiction_status"] == "unresolved"
    assert len(result["contradictions"]) == 1
    assert _dimension(result, "porter", "cyber_suppliers")["confidence"] < 60


def test_no_relevant_news_returns_null_scores_not_neutral_fifty():
    result = build_strategic_intelligence([], _organization())

    assert result["pestel"]["index"] is None
    assert result["porter"]["index"] is None
    assert all(row["signalScore"] is None and row["validatedPressure"] is None and row["status"] == "no_data" for row in result["pestel"]["dimensions"])
    assert result["pestel"]["evidence_coverage_ratio"] == 0
    assert result["analysisBasis"]["historical_evidence_reused"] is False
    assert result["analysisBasis"]["context"]["domains"] == ["example.com"]
    assert result["analysisBasis"]["context"]["sector"] == ["energy"]


def test_corporate_and_regulatory_records_contribute_coverage_without_forcing_pressure():
    event = _news(
        "official-results",
        "Example Energy publishes financial results and infrastructure investment",
        "https://example.com/investors/financial-results",
        category="web_search",
        source="Official corporate publication",
        tags=["internet_search"],
        technical_validation={"summary": "Net income and infrastructure investment were published for the current period.", "query": '"Example Energy" financial results'},
    )

    result = build_strategic_intelligence([event], _organization())
    economic = _dimension(result, "pestel", "cyber_economy")

    assert result["articles"][0]["title"] == event.title
    assert economic["evidence_coverage_percent"] > 0
    assert economic["evidence_state"] in {"partial_evidence", "sufficient_for_pressure"}
    assert event.evidence_url in economic["evidence_urls"]


def test_spanish_corporate_variants_are_classified_without_query_text():
    events = [
        _news(
            "acquisition-es",
            "Example Energy adquiere activos de exploracion",
            "https://news.example/adquiere-activos",
            tags=[],
        ),
        _news(
            "financial-es",
            "Example Energy publica resultados financieros con perdidas",
            "https://example.com/resultados-financieros",
            tags=[],
        ),
        _news(
            "sustainability-es",
            "Example Energy publica su estrategia de sostenibilidad",
            "https://example.com/sostenibilidad",
            tags=[],
        ),
    ]

    result = build_strategic_intelligence(events, _organization())
    event_types = {article["event_type"] for article in result["articles"]}

    assert event_types == {"acquisition_or_consolidation", "financial_performance", "sustainability_transition"}
    assert _dimension(result, "pestel", "cyber_economy")["evidence_coverage_percent"] > 0
    assert _dimension(result, "pestel", "cyber_resilience")["evidence_coverage_percent"] > 0
    assert _dimension(result, "porter", "cyber_rivalry")["evidence_coverage_percent"] > 0


def test_strategic_snapshot_is_reproducible_for_the_same_collection_timestamp():
    event = _news(
        "stable-strategic-record",
        "Example Energy publica resultados financieros e inversiones",
        "https://example.com/investors/results",
    )
    collected_at = "2026-07-20T08:00:00+00:00"

    first = build_strategic_intelligence([event], _organization(), created_at=collected_at)
    second = build_strategic_intelligence([event], _organization(), created_at=collected_at)

    assert first == second
    assert first["version"] == "strategic-evidence-v1.3.0"
    assert first["articles"][0]["collected_at"] == collected_at


def test_analysis_basis_deduplicates_equal_legal_and_display_names():
    organization = _organization()
    organization.legal_name = organization.name

    result = build_strategic_intelligence([], organization, created_at="2026-07-20T08:00:00+00:00")

    assert result["analysisBasis"]["context"]["organization"] == [organization.name]


def test_one_supplier_event_relates_to_multiple_entities_without_duplicate_clusters():
    event = _news(
        "supplier-group",
        "CloudCo outage affects Example Energy services at example.com",
        "https://status.cloudco.example/incident",
        source="CloudCo official status",
        tags=["event_type:supplier_disruption"],
    )

    result = build_strategic_intelligence([event], _organization())

    assert len(result["clusters"]) == 1
    assert len(result["clusters"][0]["affected_entities"]) >= 2
    assert result["clusters"][0]["article_count"] == 1


def test_strategic_json_and_csv_export_same_dimension_values(tmp_path):
    event = _news(
        "export-sanction",
        "Environmental regulator imposes environmental sanction on Example Energy",
        "https://regulator.gov.co/example-energy",
        source="Government regulator",
        tags=["event_type:environmental_sanction", "magnitude:critical"],
    )
    result = build_strategic_intelligence([event], _organization())

    paths = export_strategic_scores(result, tmp_path / "report.html")
    payload = json.loads((tmp_path / "report_strategic_scores.json").read_text(encoding="utf-8"))
    with (tmp_path / "report_strategic_scores.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    environmental = _dimension(payload, "pestel", "cyber_resilience")
    csv_environmental = next(row for row in rows if row["model"] == "pestel" and row["dimension"] == "cyber_resilience")

    assert paths["strategic_json"].endswith("_strategic_scores.json")
    assert float(csv_environmental["signal_score"]) == environmental["signalScore"]
    assert csv_environmental["validated_pressure"] == (
        "" if environmental["validatedPressure"] is None else str(environmental["validatedPressure"])
    )
    assert float(csv_environmental["confidence"]) == environmental["confidence"]
    assert csv_environmental["evidence_ids"] == "export-sanction"


def test_strategic_context_never_promotes_candidates_and_is_limited_to_ten_percent():
    strategic = {
        "pestel": {"dimensions": [{"key": "legal", "score": 100, "confidence": 100}]},
        "porter": {"dimensions": []},
    }
    mappings = [{"scenario_id": "S-1", "strategic_dimension": "legal", "relevance_coefficient": 8.0, "validation_status": "approved"}]
    scenarios = [
        {"id": "S-1", "status": "candidate", "scores": {"likelihood": 0.50}},
        {"id": "S-1", "status": "supported", "scores": {"likelihood": 0.50}},
    ]

    candidate, supported = apply_strategic_context_to_scenarios(scenarios, strategic, mappings)

    assert candidate["status"] == "candidate"
    assert candidate["strategic_context"]["likelihood_multiplier"] == 1.0
    assert supported["status"] == "supported"
    assert supported["strategic_context"]["likelihood_multiplier"] == 1.1
    assert supported["strategic_context"]["likelihood_after"] == 0.55
