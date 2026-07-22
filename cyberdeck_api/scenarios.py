from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from cyberdeck.settings import PROJECT_ROOT


SCENARIO_PATH = PROJECT_ROOT / "data" / "scenarios" / "cyber_scenario_library.json"


@lru_cache(maxsize=1)
def load_scenario_library() -> dict[str, Any]:
    if not SCENARIO_PATH.exists():
        return {
            "scenario_count": 0,
            "reference_template_count": 0,
            "defined_scenario_count": 0,
            "executable_scenario_count": 0,
            "tested_scenario_count": 0,
            "triggered_scenario_count": 0,
            "sources": [],
            "math_model": {},
            "framework_counts": {},
            "scenarios": [],
        }

    payload = json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))
    scenarios = payload.get("scenarios", [])
    framework_sets = {
        "attack": set(),
        "d3fend": set(),
        "atlas": set(),
        "disarm": set(),
    }
    for scenario in scenarios:
        frameworks = scenario.get("frameworks", {})
        for key in framework_sets:
            item = frameworks.get(key, {})
            if item.get("id"):
                framework_sets[key].add(item["id"])

    sorted_scenarios = sorted(
        scenarios,
        key=lambda item: item.get("scores", {}).get("residual_risk", 0),
        reverse=True,
    )
    reference_template_count = sum(1 for item in scenarios if item.get("status") == "preventive_template")
    return {
        # Kept for API compatibility; it now means executable definitions, not catalog combinations.
        "scenario_count": 0,
        "reference_template_count": reference_template_count,
        "defined_scenario_count": 0,
        "executable_scenario_count": 0,
        "tested_scenario_count": 0,
        "triggered_scenario_count": 0,
        "object_type": "reference_template",
        "sources": payload.get("sources", []),
        "math_model": payload.get("math_model", {}),
        "framework_counts": {
            "reference_templates": reference_template_count,
            "attack_techniques": len(framework_sets["attack"]),
            "d3fend_controls": len(framework_sets["d3fend"]),
            "atlas_tactics": len(framework_sets["atlas"]),
            "disarm_techniques": len(framework_sets["disarm"]),
        },
        "scenarios": sorted_scenarios,
    }
