from __future__ import annotations

from typing import Dict, List


def posture_transition(state: List[float], action: List[float], threat_pressure: float) -> List[float]:
    next_state = []
    for index, value in enumerate(state):
        control_effect = action[index] if index < len(action) else 0.0
        next_state.append(max(0.0, min(1.0, 0.82 * value - 0.28 * control_effect + 0.18 * threat_pressure)))
    return next_state


def prioritize_actions(state: List[float]) -> Dict[str, float]:
    names = ["patching", "hardening", "monitoring", "training"]
    return {name: round(score, 3) for name, score in sorted(zip(names, state), key=lambda pair: pair[1], reverse=True)}
