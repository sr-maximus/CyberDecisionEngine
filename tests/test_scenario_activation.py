from cyberdeck.reporting.html_report import _score_report_scenario


SCENARIO = {
    "id": "CDE-SCN-TEST",
    "title_es": "Escenario controlado",
    "title_en": "Controlled scenario",
    "frameworks": {
        "attack": {"id": "T1566", "name": "Phishing"},
        "d3fend": {"id": "D3-PH", "name": "Phishing Detection"},
        "atlas": {"id": "AML.TA0004", "name": "Initial Access"},
        "disarm": {"id": "T2001.001", "name": "Account Asset", "tactic": "Observed Asset"},
        "f3": {"id": "F1032", "name": "Impersonate Business"},
    },
}


def _signal(**overrides):
    signal = {
        "id": "evd-1",
        "title": "Evidence",
        "source": "source-a",
        "source_refs": ["source-a"],
        "technique": None,
        "domains": ["example.com"],
        "evidence_status": "validated",
        "confidence_score": 0.8,
        "attack_mapping_status": "potentially_relevant_technique",
        "disarm_signal": False,
        "atlas_signal": False,
        "f3_signal": False,
        "framework_ids": set(),
    }
    signal.update(overrides)
    return signal


def test_attack_scenario_requires_observed_adversary_behavior():
    contextual = _signal(technique="T1566")
    assert _score_report_scenario(SCENARIO, [contextual], ["example.com"], "", "es") is None

    observed = _signal(technique="T1566", attack_mapping_status="observed_adversary_behavior")
    match = _score_report_scenario(SCENARIO, [observed], ["example.com"], "", "es")
    assert match is not None
    assert match["primary_framework"] == "attack"
    assert match["status"] == "evidence_supported"


def test_disarm_scenario_requires_exact_id_and_two_independent_sources():
    first = _signal(
        id="evd-a",
        disarm_signal=True,
        framework_ids={"T2001.001"},
        source="source-a",
        source_refs=["source-a"],
    )
    same_source = _signal(
        id="evd-b",
        disarm_signal=True,
        framework_ids={"T2001.001"},
        source="source-a",
        source_refs=["source-a"],
    )
    assert _score_report_scenario(SCENARIO, [first, same_source], ["example.com"], "", "es") is None

    independent = _signal(
        id="evd-c",
        disarm_signal=True,
        framework_ids={"T2001.001"},
        source="source-b",
        source_refs=["source-b"],
    )
    match = _score_report_scenario(SCENARIO, [first, independent], ["example.com"], "", "es")
    assert match is not None
    assert match["primary_framework"] == "disarm"
    assert match["evidence_count"] == 2


def test_atlas_scenario_requires_exact_id_and_high_confidence():
    generic_ai = _signal(atlas_signal=True, confidence_score=0.9)
    assert _score_report_scenario(SCENARIO, [generic_ai], ["example.com"], "", "es") is None

    low_confidence = _signal(atlas_signal=True, confidence_score=0.5, framework_ids={"AML.TA0004"})
    assert _score_report_scenario(SCENARIO, [low_confidence], ["example.com"], "", "es") is None

    supported = _signal(atlas_signal=True, confidence_score=0.8, framework_ids={"AML.TA0004"})
    match = _score_report_scenario(SCENARIO, [supported], ["example.com"], "", "es")
    assert match is not None
    assert match["primary_framework"] == "atlas"


def test_d3fend_mapping_alone_does_not_activate_a_scenario():
    evidence = _signal(framework_ids={"D3-PH"})
    assert _score_report_scenario(SCENARIO, [evidence], ["example.com"], "", "es") is None


def test_f3_scenario_requires_exact_current_run_mapping():
    generic = _signal(framework_ids={"F1032"})
    assert _score_report_scenario(SCENARIO, [generic], ["example.com"], "", "es") is None

    supported = _signal(f3_signal=True, framework_ids={"F1032"})
    match = _score_report_scenario(SCENARIO, [supported], ["example.com"], "", "es")
    assert match is not None
    assert match["primary_framework"] == "f3"
    assert match["evidence_ids"] == ["evd-1"]
