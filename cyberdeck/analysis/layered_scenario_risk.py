from __future__ import annotations

from math import prod
from typing import Any, Mapping, Sequence


MODEL_VERSION = "CDE-LAYERED-SCENARIO-1.0"
REQUIRED_SCENARIO_INPUTS = (
    "scenario_name",
    "initiating_event_frequency",
    "consequence_value",
    "protection_layers",
)


def calculate_layered_scenario_risk(values: Mapping[str, Any] | None) -> dict[str, Any]:
    inputs = dict(values or {})
    raw_scenarios = inputs.get("scenarios")
    if raw_scenarios is None and inputs:
        raw_scenarios = [inputs]
    if not isinstance(raw_scenarios, Sequence) or isinstance(raw_scenarios, (str, bytes)) or not raw_scenarios:
        return _no_data(["scenarios"])

    rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    for index, raw_scenario in enumerate(raw_scenarios):
        if not isinstance(raw_scenario, Mapping):
            invalid_rows.append({"index": index, "reason": "scenario_must_be_an_object"})
            continue
        result = _calculate_scenario(dict(raw_scenario), index)
        if result["status"] == "calculated":
            rows.append(result)
        else:
            invalid_rows.append(result)

    if not rows:
        return {
            "status": "invalid_data",
            "model_version": MODEL_VERSION,
            "method": "Layered scenario analysis",
            "scenarios": [],
            "invalid_scenarios": invalid_rows,
            "limitations": _limitations(),
        }

    currencies = {str(row["currency"]) for row in rows}
    total_expected_loss = (
        round(sum(float(row["expected_annual_loss"]) for row in rows), 2)
        if len(currencies) == 1
        else None
    )
    return {
        "status": "calculated",
        "model_version": MODEL_VERSION,
        "method": "Layered scenario analysis",
        "scenario_count": len(rows),
        "currency": next(iter(currencies)) if len(currencies) == 1 else "MIXED",
        "aggregate_expected_annual_loss": total_expected_loss,
        "scenarios": sorted(rows, key=lambda row: float(row["expected_annual_loss"]), reverse=True),
        "invalid_scenarios": invalid_rows,
        "limitations": _limitations(),
    }


def _calculate_scenario(inputs: dict[str, Any], index: int) -> dict[str, Any]:
    missing = [name for name in REQUIRED_SCENARIO_INPUTS if name not in inputs]
    if missing:
        return {"status": "invalid_data", "index": index, "missing_inputs": missing}

    layers = inputs.get("protection_layers")
    if not isinstance(layers, Sequence) or isinstance(layers, (str, bytes)) or not layers:
        return {"status": "invalid_data", "index": index, "reason": "protection_layers_required"}

    try:
        initiating_frequency = float(inputs["initiating_event_frequency"])
        consequence_value = float(inputs["consequence_value"])
    except (TypeError, ValueError):
        return {"status": "invalid_data", "index": index, "reason": "non_numeric_scenario_input"}
    if initiating_frequency < 0 or consequence_value < 0:
        return {"status": "invalid_data", "index": index, "reason": "negative_scenario_input"}

    normalized_layers: list[dict[str, Any]] = []
    for layer_index, raw_layer in enumerate(layers):
        if not isinstance(raw_layer, Mapping):
            return {"status": "invalid_data", "index": index, "reason": f"layer_{layer_index}_must_be_an_object"}
        try:
            probability_of_failure = float(raw_layer["probability_of_failure"])
            cyber_degradation = float(raw_layer.get("cyber_degradation", 0.0))
        except (KeyError, TypeError, ValueError):
            return {"status": "invalid_data", "index": index, "reason": f"layer_{layer_index}_invalid"}
        if not 0 <= probability_of_failure <= 1 or not 0 <= cyber_degradation <= 1:
            return {"status": "invalid_data", "index": index, "reason": f"layer_{layer_index}_out_of_range"}

        effective_failure = probability_of_failure + (1 - probability_of_failure) * cyber_degradation
        normalized_layers.append(
            {
                "name": str(raw_layer.get("name") or f"Layer {layer_index + 1}"),
                "probability_of_failure": round(probability_of_failure, 6),
                "cyber_degradation": round(cyber_degradation, 6),
                "effective_failure_probability": round(effective_failure, 6),
            }
        )

    combined_failure = prod(float(layer["effective_failure_probability"]) for layer in normalized_layers)
    resulting_frequency = initiating_frequency * combined_failure
    expected_annual_loss = resulting_frequency * consequence_value
    return {
        "status": "calculated",
        "scenario_name": str(inputs["scenario_name"]).strip() or f"Scenario {index + 1}",
        "currency": str(inputs.get("currency") or "USD").upper(),
        "initiating_event_frequency": round(initiating_frequency, 8),
        "consequence_value": round(consequence_value, 2),
        "combined_layer_failure_probability": round(combined_failure, 8),
        "resulting_event_frequency": round(resulting_frequency, 8),
        "relative_risk_reduction": round(1 - combined_failure, 8),
        "expected_annual_loss": round(expected_annual_loss, 2),
        "protection_layers": normalized_layers,
    }


def _no_data(missing: list[str]) -> dict[str, Any]:
    return {
        "status": "no_data",
        "missing_inputs": missing,
        "model_version": MODEL_VERSION,
        "method": "Layered scenario analysis",
        "scenarios": [],
        "limitations": _limitations(),
    }


def _limitations() -> list[str]:
    return [
        "All frequencies, consequences and layer effectiveness values must be explicitly supplied.",
        "The model assumes statistical independence between protection layers.",
        "Outputs are scenario estimates for decision support, not calibrated attack predictions.",
        "Public intelligence may inform scenario selection but does not populate financial values automatically.",
    ]
