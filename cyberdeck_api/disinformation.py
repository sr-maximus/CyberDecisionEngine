from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from cyberdeck.settings import PROJECT_ROOT


FRAMEWORK_DIR = PROJECT_ROOT / "data" / "frameworks"
SCENARIO_DIR = PROJECT_ROOT / "data" / "scenarios"


@lru_cache(maxsize=1)
def load_disinformation_framework() -> dict[str, Any]:
    disarm_path = FRAMEWORK_DIR / "disarm_observable.json"
    scenario_path = SCENARIO_DIR / "cyber_scenario_library.json"
    disarm = json.loads(disarm_path.read_text(encoding="utf-8")) if disarm_path.exists() else {"tactics": [], "techniques": []}
    scenarios = json.loads(scenario_path.read_text(encoding="utf-8")) if scenario_path.exists() else {"scenario_count": 0, "scenarios": []}
    top_scenarios = sorted(
        scenarios.get("scenarios", []),
        key=lambda item: item.get("scores", {}).get("residual_risk", 0),
        reverse=True,
    )[:40]
    tactic_counts: dict[str, int] = {}
    for technique in disarm.get("techniques", []):
        tactic = technique.get("tactic") or "Unmapped"
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    return {
        "source": disarm.get("source"),
        "source_url": disarm.get("source_url"),
        "tactics": disarm.get("tactics", []),
        "techniques": disarm.get("techniques", []),
        "tactic_counts": [{"name": name, "value": value} for name, value in sorted(tactic_counts.items(), key=lambda item: item[1], reverse=True)],
        "scenario_count": scenarios.get("scenario_count", 0),
        "math_model": scenarios.get("math_model", {}),
        "top_scenarios": top_scenarios,
    }
