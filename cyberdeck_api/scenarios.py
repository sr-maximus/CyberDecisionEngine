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
        "f3": set(),
        "attack_ics": set(),
        "attack_mobile": set(),
        "emb3d": set(),
        "aadapt": set(),
        "capec": set(),
        "cwe": set(),
        "inform": set(),
    }
    for scenario in scenarios:
        frameworks = scenario.get("frameworks", {})
        for key in framework_sets:
            item = frameworks.get(key, {})
            if item.get("id"):
                framework_sets[key].add(item["id"])
        for mapping in scenario.get("framework_mappings", []):
            framework_name = str(mapping.get("framework") or "")
            if "D3FEND" in framework_name:
                framework_sets["d3fend"].add(str(scenario.get("id") or framework_name))
            if "ATT&CK ICS" in framework_name:
                framework_sets["attack_ics"].add(str(scenario.get("id") or framework_name))
            if "ATT&CK Mobile" in framework_name:
                framework_sets["attack_mobile"].add(str(scenario.get("id") or framework_name))
            if "EMB3D" in framework_name:
                framework_sets["emb3d"].add(str(scenario.get("id") or framework_name))
            if "AADAPT" in framework_name:
                framework_sets["aadapt"].add(str(scenario.get("id") or framework_name))
            if "CAPEC" in framework_name:
                framework_sets["capec"].add(str(scenario.get("id") or framework_name))
            if "CWE" in framework_name:
                framework_sets["cwe"].add(str(scenario.get("id") or framework_name))
            if "INFORM" in framework_name:
                framework_sets["inform"].add(str(scenario.get("id") or framework_name))

    sorted_scenarios = sorted(
        scenarios,
        key=lambda item: item.get("scores", {}).get("residual_risk", 0),
        reverse=True,
    )
    reference_template_count = sum(
        1 for item in scenarios if item.get("status") == "preventive_template"
    )
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
            "f3_techniques": len(framework_sets["f3"]),
            "attack_ics_templates": len(framework_sets["attack_ics"]),
            "attack_mobile_templates": len(framework_sets["attack_mobile"]),
            "emb3d_templates": len(framework_sets["emb3d"]),
            "aadapt_templates": len(framework_sets["aadapt"]),
            "capec_templates": len(framework_sets["capec"]),
            "cwe_templates": len(framework_sets["cwe"]),
            "inform_templates": len(framework_sets["inform"]),
            "multidomain_templates": sum(
                1 for item in scenarios if str(item.get("id", "")).startswith("CDE-MD-")
            ),
        },
        "scenarios": sorted_scenarios,
    }
