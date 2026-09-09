import json
from pathlib import Path

from cyberdeck.analysis.mitre_mapping import _attack_catalog, build_atlas_profile, build_mitre_profile
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


def test_surface_control_is_not_presented_as_attack_technique():
    profile = build_mitre_profile(
        [
            ThreatEvent(
                id="surface-control",
                title="DMARC no observado",
                category="attack_surface",
                source="surface",
                technique="T1589",
                tags=["external_surface", "email_security"],
                evidence_status=EvidenceStatus.DIRECT,
                attack_mapping_status="potentially_relevant_technique",
            )
        ]
    )

    assert profile["coverage_count"] == 0
    assert profile["technique_counts"] == {}
    assert profile["suppressed_control_reference_count"] == 1


def test_scenario_library_is_preventive_and_has_no_synthetic_probability():
    payload = json.loads(Path("data/scenarios/cyber_scenario_library.json").read_text(encoding="utf-8"))

    expected = sum(
        count
        for name, count in payload["catalog_counts"].items()
        if name != "MITRE D3FEND controls"
    )
    assert payload["scenario_count"] == expected
    assert payload["scenario_count"] == len(payload["scenarios"])
    assert payload["math_model"]["formula"] == "scenario_support = assured_current_run_evidence_only"
    assert all(item["status"] == "preventive_template" for item in payload["scenarios"])
    assert all(item["scores"]["likelihood"] == 0 for item in payload["scenarios"])
    assert all(item["scores"]["residual_risk"] == 0 for item in payload["scenarios"])


def test_scenario_api_does_not_present_reference_templates_as_executable():
    from cyberdeck_api.scenarios import load_scenario_library

    load_scenario_library.cache_clear()
    result = load_scenario_library()
    library = json.loads(Path("data/scenarios/cyber_scenario_library.json").read_text(encoding="utf-8"))
    assert result["reference_template_count"] == library["scenario_count"]
    assert result["scenario_count"] == 0
    assert result["executable_scenario_count"] == 0
    assert result["tested_scenario_count"] == 0
    assert result["object_type"] == "reference_template"
    for key in (
        "attack_techniques",
        "attack_ics_templates",
        "attack_mobile_templates",
        "d3fend_controls",
        "atlas_tactics",
        "disarm_techniques",
        "f3_techniques",
        "emb3d_templates",
        "aadapt_templates",
        "capec_templates",
        "cwe_templates",
        "inform_templates",
    ):
        assert result["framework_counts"][key] > 0
