from cyberdeck.analysis.layered_scenario_risk import calculate_layered_scenario_risk


def test_layered_scenario_requires_explicit_inputs() -> None:
    result = calculate_layered_scenario_risk({})

    assert result["status"] == "no_data"
    assert result["missing_inputs"] == ["scenarios"]


def test_layered_scenario_calculates_general_organization_barriers() -> None:
    result = calculate_layered_scenario_risk(
        {
            "scenarios": [
                {
                    "scenario_name": "Interruption of a critical digital service",
                    "initiating_event_frequency": 2,
                    "consequence_value": 100_000,
                    "currency": "USD",
                    "protection_layers": [
                        {"name": "Prevention", "probability_of_failure": 0.1, "cyber_degradation": 0.2},
                        {"name": "Detection and response", "probability_of_failure": 0.2, "cyber_degradation": 0.25},
                    ],
                }
            ]
        }
    )

    assert result["status"] == "calculated"
    assert result["scenario_count"] == 1
    scenario = result["scenarios"][0]
    assert scenario["combined_layer_failure_probability"] == 0.112
    assert scenario["resulting_event_frequency"] == 0.224
    assert scenario["relative_risk_reduction"] == 0.888
    assert scenario["expected_annual_loss"] == 22_400
    assert result["aggregate_expected_annual_loss"] == 22_400


def test_layered_scenario_does_not_sum_mixed_currencies() -> None:
    common = {
        "initiating_event_frequency": 1,
        "consequence_value": 1_000,
        "protection_layers": [{"name": "Control", "probability_of_failure": 0.5}],
    }
    result = calculate_layered_scenario_risk(
        {
            "scenarios": [
                {**common, "scenario_name": "USD scenario", "currency": "USD"},
                {**common, "scenario_name": "COP scenario", "currency": "COP"},
            ]
        }
    )

    assert result["status"] == "calculated"
    assert result["currency"] == "MIXED"
    assert result["aggregate_expected_annual_loss"] is None
