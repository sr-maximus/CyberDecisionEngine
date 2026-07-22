import json
from pathlib import Path

from cyberdeck.analysis.mitre_mapping import _attack_catalog, build_atlas_profile
from cyberdeck.schemas import EvidenceStatus, ThreatEvent


def test_atlas_profile_ignores_substring_matches():
    profile = build_atlas_profile(
        [
            ThreatEvent(
                id="evt-1",
                title="Brand impersonation campaign targets customers",
                category="fraud",
                source="osint",
            )
        ]
    )

    assert profile["ai_signal_observed"] is False
    assert profile["matched_signals"] == []


def test_atlas_profile_detects_explicit_ai_signals():
    profile = build_atlas_profile(
        [
            ThreatEvent(
                id="evt-1",
                title="AI-enabled threat intelligence mentions LLM prompt abuse",
                category="threat_intel",
                source="osint",
                evidence_status=EvidenceStatus.DIRECT,
                tags=["atlas_signal"],
            )
        ]
    )

    assert profile["ai_signal_observed"] is True
    assert set(profile["matched_signals"]) >= {"ai", "llm", "prompt"}


def test_attack_catalog_uses_current_stix_tactics_and_relationships():
    _attack_catalog.cache_clear()
    tactics, names, relationships = _attack_catalog()

    assert "Stealth" in tactics
    assert "Defense Impairment" in tactics
    assert "Defense Evasion" not in tactics
    assert names["T1078"] == "Valid Accounts"
    assert "Stealth" in relationships["T1078"]


def test_scenario_library_is_preventive_and_has_no_synthetic_probability():
    payload = json.loads(Path("data/scenarios/cyber_scenario_library.json").read_text(encoding="utf-8"))

    assert payload["scenario_count"] == 1500
    assert payload["math_model"]["formula"] == "scenario_support = assured_current_run_evidence_only"
    assert all(item["status"] == "preventive_template" for item in payload["scenarios"])
    assert all(item["scores"]["likelihood"] == 0 for item in payload["scenarios"])
    assert all(item["scores"]["residual_risk"] == 0 for item in payload["scenarios"])


def test_scenario_api_does_not_present_reference_templates_as_executable():
    from cyberdeck_api.scenarios import load_scenario_library

    load_scenario_library.cache_clear()
    result = load_scenario_library()
    assert result["reference_template_count"] == 1500
    assert result["scenario_count"] == 0
    assert result["executable_scenario_count"] == 0
    assert result["tested_scenario_count"] == 0
    assert result["object_type"] == "reference_template"
