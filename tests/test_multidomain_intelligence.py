import asyncio
import json
from pathlib import Path

from cyberdeck.analysis.multidomain import (
    PUBLIC_CAPABILITIES,
    PUBLIC_FOOTPRINT_DISCLAIMER_ES,
    SCENARIO_TEMPLATES,
    enrich_multidomain_findings,
    enrich_multidomain_intelligence,
    project_context_by_intelligence_filters,
    sanitize_public_payload,
)
from cyberdeck.schemas import (
    EvidenceStatus,
    OrganizationProfile,
    PublicAttributionStatus,
    RiskFinding,
    RunContext,
    TechnologyDomain,
    ThreatEvent,
)


def _organization() -> OrganizationProfile:
    return OrganizationProfile(
        name="Example Group",
        sector="technology",
        country="CO",
        author="Test",
        authorized_scope=True,
        primary_domains=["example.com"],
    )


def _event(event_id: str, title: str, **overrides) -> ThreatEvent:
    values = {
        "id": event_id,
        "title": title,
        "category": "public_observation",
        "source": "Public source",
        "host": "example.com",
        "evidence_url": f"https://example.com/{event_id}",
        "evidence_status": EvidenceStatus.DIRECT,
        "relationship_to_scope": "direct",
        "confidence_score": 0.8,
        "source_refs": ["publisher-a"],
    }
    values.update(overrides)
    return ThreatEvent(**values)


def _finding(event_id: str) -> RiskFinding:
    return RiskFinding(
        title="Public service requires validation",
        category="attack_surface",
        likelihood=0.5,
        impact=0.5,
        inherent_risk=25,
        residual_risk=25,
        matrix_score=4,
        matrix_label="medium",
        linked_evidence_ids=[event_id],
    )


def test_plc_mention_is_classified_but_does_not_confirm_ot_or_activate_scenario():
    event = _event("plc", "Article mentions a PLC", evidence_status=EvidenceStatus.RAW)
    summary = enrich_multidomain_intelligence([event], _organization())

    assert TechnologyDomain.OT in event.technology_domains
    assert event.public_attribution_status == PublicAttributionStatus.POSSIBLE
    assert event.attack_mapping_status == "preventive_reference"
    assert summary["scenario_candidates"] == []


def test_single_direct_record_is_observed_but_two_independent_refs_can_be_corroborated():
    single = _event("single", "Public HTTPS service")
    corroborated = _event(
        "corroborated",
        "Public HTTPS service",
        source_refs=["publisher-a", "publisher-b"],
    )
    enrich_multidomain_intelligence([single, corroborated], _organization())

    assert single.public_attribution_status == PublicAttributionStatus.OBSERVED_PUBLIC
    assert corroborated.public_attribution_status == PublicAttributionStatus.CORROBORATED_PUBLIC


def test_multidomain_and_fraud_dimensions_can_coexist():
    event = _event(
        "mixed",
        "Industrial IoT gateway using Modbus appears in a fake support campaign",
    )
    enrich_multidomain_intelligence([event], _organization())

    assert {TechnologyDomain.IOT, TechnologyDomain.OT}.issubset(set(event.technology_domains))
    assert "fake_support" in event.fraud_refs
    assert {domain.value for domain in event.analysis_domains}.issuperset({"cyber", "fraud"})


def test_product_without_version_does_not_activate_applicable_cve_scenario():
    event = _event(
        "cve-candidate",
        "Product advisory",
        cve="CVE-2026-0001",
        technical_validation={"product": "Example Product"},
    )
    summary = enrich_multidomain_intelligence([event], _organization())

    assert "CDE-MD-006" not in {row["scenario_id"] for row in summary["scenario_candidates"]}

    event.version = "1.2.3"
    summary = enrich_multidomain_intelligence([event], _organization())
    assert "CDE-MD-006" in {row["scenario_id"] for row in summary["scenario_candidates"]}


def test_relationships_require_a_shared_observed_entity():
    first = _event("first", "Same words in a document", host="one.example.com")
    second = _event("second", "Same words in a document", host="two.example.com")
    summary = enrich_multidomain_intelligence([first, second], _organization())
    assert summary["relationships"] == []

    second.host = first.host
    summary = enrich_multidomain_intelligence([first, second], _organization())
    assert summary["relationships"][0]["basis"] == "shared_observed_entity"


def test_filter_projection_is_reproducible_and_does_not_mutate_source():
    it_event = _event("it", "HTTPS API service")
    ot_event = _event("ot", "PLC speaks Modbus", host="plc.example.com")
    context = RunContext(
        organization=_organization(),
        mode="deep",
        lookback_days=365,
        raw_events=[it_event, ot_event],
        risk_findings=[_finding("it"), _finding("ot")],
    )
    projected = project_context_by_intelligence_filters(context, ["ot"], ["cyber"])

    assert len(context.raw_events) == 2
    assert len(projected.raw_events) == 1
    assert projected.raw_events[0].id == "ot"
    assert projected.processing_summary["filtered_projection"]["mutates_source_run"] is False


def test_public_payload_removes_internal_provider_and_collection_fields():
    event = _event(
        "provider",
        "Observed service",
        source="SpiderFoot Passive Sidecar",
        evidence_url="https://urlscan.io/result/internal-id/",
        technical_validation={
            "target_url": "https://example.com/service",
            "internal_command": "secret",
            "provider": "duckduckgo_lite",
        },
    )
    enrich_multidomain_intelligence([event], _organization())
    public = sanitize_public_payload(event.model_dump(mode="json"))
    serialized = json.dumps(public).lower()

    assert "spiderfoot" not in serialized
    assert "duckduckgo" not in serialized
    assert "internal_command" not in serialized
    assert "provider" not in public["technical_validation"]
    assert public["id"].startswith("CDE-EV-")
    assert public["evidence_url"] == "https://example.com/service"


def test_public_payload_preserves_verifiable_collection_urls_without_provider_labels():
    public = sanitize_public_payload(
        {
            "source": "SpiderFoot Passive Sidecar",
            "public_capability_label": "CyberDecisionEngine — Inteligencia web pública",
            "urls": [
                "https://urlscan.io/result/public-reference/",
                "https://capacidad de inteligencia pública/result/broken/",
            ],
        }
    )

    assert public["source"] == "CyberDecisionEngine — Inteligencia web pública"
    assert public["urls"] == ["https://urlscan.io/result/public-reference/"]


def test_public_payload_keeps_nested_evidence_references_consistent():
    payload = {
        "records": [
            {
                "id": "SPIDERFOOT-6516029",
                "canonical_id": "different-canonical-value",
                "evidence_status": "validated",
                "record_kind": "evidence",
            }
        ],
        "claims": [{"evidence_ids": ["SPIDERFOOT-6516029"]}],
        "links": [{"evidence_id": "SPIDERFOOT-6516029"}],
    }

    public = sanitize_public_payload(payload)
    public_id = public["records"][0]["id"]

    assert public_id.startswith("CDE-EV-")
    assert public["claims"][0]["evidence_ids"] == [public_id]
    assert public["links"][0]["evidence_id"] == public_id
    assert "SPIDERFOOT" not in json.dumps(public)


def test_public_evidence_ids_remain_unique_when_source_ids_collide():
    first = _event("WEB-GNEWS-1234567", "First public record")
    first.canonical_id = "evd-first"
    first.content_hash = "hash-first"
    second = _event("WEB-GNEWS-1234567", "Second public record")
    second.canonical_id = "evd-second"
    second.content_hash = "hash-second"

    enrich_multidomain_intelligence([first, second], _organization())
    public = sanitize_public_payload(
        {"records": [first.model_dump(mode="json"), second.model_dump(mode="json")]}
    )

    public_ids = [item["id"] for item in public["records"]]
    assert len(public_ids) == len(set(public_ids)) == 2
    assert all(item.startswith("CDE-EV-") for item in public_ids)


def test_unknown_controls_do_not_publish_residual_risk_as_known():
    event = _event("risk", "HTTPS API service")
    finding = _finding(event.id)
    enrich_multidomain_intelligence([event], _organization())
    enrich_multidomain_findings([finding], [event])

    assert finding.residual_risk_status == "insufficient_control_evidence"
    assert PUBLIC_FOOTPRINT_DISCLAIMER_ES.startswith("Este análisis se basa en evidencia pública")


def test_public_capability_labels_are_stable_and_provider_neutral():
    labels = {item["label"] for item in PUBLIC_CAPABILITIES.values()}
    assert labels == {
        "CyberDecisionEngine — Inteligencia web pública",
        "CyberDecisionEngine — Exposición tecnológica pública",
        "CyberDecisionEngine — Inteligencia de vulnerabilidades",
        "CyberDecisionEngine — Inteligencia de amenazas",
        "CyberDecisionEngine — Inteligencia ciberfísica",
        "CyberDecisionEngine — Inteligencia de fraude",
        "CyberDecisionEngine — Inteligencia histórica",
        "CyberDecisionEngine — Evidencia pública corroborada",
    }


def test_generated_library_contains_the_25_versioned_multidomain_templates():
    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / "data/scenarios/cyber_scenario_library.json").read_text())
    scenarios = payload["scenarios"]
    multidomain = [item for item in scenarios if str(item.get("id", "")).startswith("CDE-MD-")]

    assert len(scenarios) == 1141
    assert len(multidomain) == len(SCENARIO_TEMPLATES) == 25
    assert {item["id"] for item in multidomain} == {item["id"] for item in SCENARIO_TEMPLATES}
    assert all(item["status"] == "preventive_template" for item in multidomain)


def test_functional_manuals_and_readme_do_not_expose_internal_providers():
    root = Path(__file__).resolve().parents[1]
    public_documents = [root / "README.md", *sorted((root / "docs/manual").glob("*.md"))]
    forbidden = {
        "spiderfoot",
        "urlscan",
        "shodan",
        "censys",
        "virustotal",
        "greynoise",
        "abuseipdb",
        "openclaw",
        "ollama",
        "opencti",
        "alienvault",
        "sherlock",
        "kali-surface",
    }

    for document in public_documents:
        text = document.read_text(encoding="utf-8").lower()
        leaked = sorted(term for term in forbidden if term in text)
        assert not leaked, f"{document.name} exposes internal providers: {leaked}"


def test_frontend_and_public_assets_do_not_expose_internal_provider_names():
    root = Path(__file__).resolve().parents[1]
    public_files = [
        *sorted((root / "web/src").rglob("*.ts")),
        *sorted((root / "web/src").rglob("*.tsx")),
        *sorted((root / "web/public").rglob("*.html")),
    ]
    forbidden = {
        "spiderfoot",
        "urlscan.io",
        "shodan",
        "censys",
        "virustotal",
        "greynoise",
        "abuseipdb",
        "openclaw",
        "ollama",
        "opencti",
        "alienvault",
        "subfinder",
        "dnsrecon",
        "sslscan",
        "wafw00f",
        "whatweb",
        "nuclei",
        "duckduckgo",
        "kali surface",
    }

    for public_file in public_files:
        text = public_file.read_text(encoding="utf-8").lower()
        leaked = sorted(term for term in forbidden if term in text)
        assert not leaked, f"{public_file.relative_to(root)} exposes internal providers: {leaked}"


def test_public_ai_config_exposes_capability_status_without_provider_details(monkeypatch):
    from cyberdeck_api import main

    async def orchestration_status():
        return {"ready": True, "runtime_status": "ready", "model_status": "ready", "model": "internal-model"}

    async def local_status(_model_env: str):
        return {"ready": False, "runtime_status": "disabled", "model_status": "not_checked"}

    monkeypatch.setattr(main, "openclaw_runtime_status", orchestration_status)
    monkeypatch.setattr(main, "ollama_runtime_status", local_status)
    payload = asyncio.run(main.ai_config())
    serialized = json.dumps(payload).lower()

    assert payload["analysis_runtime"]["profile"] == "CyberDecision AI"
    assert payload["analysis_runtime"]["ready"] is True
    assert "provider_catalog" not in payload
    assert "internal-model" not in serialized
    assert "openclaw" not in serialized
    assert "ollama" not in serialized


def test_default_json_response_enforces_public_boundary():
    from cyberdeck_api.main import PublicJSONResponse

    response = PublicJSONResponse(
        content={
            "events": [
                {
                    "id": "WEB-DDG-123",
                    "canonical_id": "evd-internal",
                    "content_hash": "abc",
                    "record_kind": "related_evidence",
                    "evidence_status": "related",
                    "source": "SpiderFoot Passive Sidecar",
                    "tags": ["duckduckgo_lite", "public_record"],
                    "technical_validation": {"provider": "duckduckgo_lite"},
                    "evidence_url": "https://urlscan.io/result/internal/",
                }
            ]
        }
    )
    payload = json.loads(response.body)
    serialized = json.dumps(payload).lower()

    assert payload["events"][0]["id"].startswith("CDE-EV-")
    assert payload["events"][0]["tags"] == ["public_record"]
    assert "canonical_id" not in payload["events"][0]
    assert "provider" not in payload["events"][0]["technical_validation"]
    assert "spiderfoot" not in serialized
    assert "duckduckgo" not in serialized
    assert payload["events"][0]["evidence_url"] == "https://urlscan.io/result/internal/"
