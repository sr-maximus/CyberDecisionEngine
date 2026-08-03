from __future__ import annotations

from typing import Any, Mapping


REQUIRED_FINANCIAL_INPUTS = ("asset_value", "exposure_factor", "annual_rate_of_occurrence")


def calculate_financial_risk(values: Mapping[str, Any] | None) -> dict[str, Any]:
    inputs = dict(values or {})
    missing = [name for name in REQUIRED_FINANCIAL_INPUTS if name not in inputs]
    if missing:
        return {
            "status": "no_data",
            "missing_inputs": missing,
            "model_version": "CDE-QRA-1.0",
            "method": "SLE/ALE/ROSI",
            "limitations": [
                "Financial exposure is not inferred from public intelligence.",
                "Asset value, exposure factor and annual rate of occurrence must be explicitly supplied.",
            ],
        }

    try:
        asset_value = float(inputs["asset_value"])
        exposure_factor = float(inputs["exposure_factor"])
        annual_rate = float(inputs["annual_rate_of_occurrence"])
        control_reduction = float(inputs.get("control_risk_reduction", 0.0))
        control_cost = float(inputs.get("control_cost", 0.0))
    except (TypeError, ValueError):
        return {"status": "invalid_data", "model_version": "CDE-QRA-1.0", "method": "SLE/ALE/ROSI"}

    if (
        asset_value < 0
        or not 0 <= exposure_factor <= 1
        or annual_rate < 0
        or not 0 <= control_reduction <= 1
        or control_cost < 0
    ):
        return {"status": "invalid_data", "model_version": "CDE-QRA-1.0", "method": "SLE/ALE/ROSI"}

    sle = asset_value * exposure_factor
    ale_before = sle * annual_rate
    ale_after = ale_before * (1 - control_reduction)
    reduction = ale_before - ale_after
    rosi = ((reduction - control_cost) / control_cost) * 100 if control_cost > 0 else None
    return {
        "status": "calculated",
        "currency": str(inputs.get("currency") or "USD").upper(),
        "asset_value": round(asset_value, 2),
        "exposure_factor": round(exposure_factor, 6),
        "annual_rate_of_occurrence": round(annual_rate, 6),
        "single_loss_expectancy": round(sle, 2),
        "annualized_loss_expectancy_before": round(ale_before, 2),
        "annualized_loss_expectancy_after": round(ale_after, 2),
        "control_risk_reduction": round(control_reduction, 6),
        "control_cost": round(control_cost, 2),
        "risk_reduction_value": round(reduction, 2),
        "rosi_percent": round(rosi, 2) if rosi is not None else None,
        "model_version": "CDE-QRA-1.0",
        "method": "SLE/ALE/ROSI",
        "formulas": {
            "sle": "asset_value * exposure_factor",
            "ale": "single_loss_expectancy * annual_rate_of_occurrence",
            "risk_reduction": "ale_before - ale_after",
            "rosi": "((risk_reduction - control_cost) / control_cost) * 100",
        },
        "limitations": [
            "Values are scenario estimates, not loss predictions.",
            "ROSI is only calculated when a positive control cost is supplied.",
        ],
    }
