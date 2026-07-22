from __future__ import annotations

from typing import Dict


def minimax_recommendations(expected_loss: float, control_cost: float) -> Dict[str, object]:
    portfolios = [
        ("identity_hardening", expected_loss * 0.58 + control_cost * 0.80),
        ("vulnerability_prioritization", expected_loss * 0.62 + control_cost * 0.55),
        ("fraud_graph_monitoring", expected_loss * 0.54 + control_cost * 0.70),
        ("incident_response_drills", expected_loss * 0.68 + control_cost * 0.45),
    ]
    ranked = sorted(portfolios, key=lambda item: item[1])
    return {
        "objective": "argmin_U max_A ExpectedLoss(A,U)+ControlCost(U)",
        "ranked_controls": [{"control": name, "minimax_score": round(score, 2)} for name, score in ranked],
    }


def attacker_defender_utility(expected_gain: float, attack_cost: float, detection_penalty: float, expected_loss: float, control_cost: float, resilience_benefit: float) -> Dict[str, float]:
    return {
        "attacker_utility": round(expected_gain - attack_cost - detection_penalty, 2),
        "defender_utility": round(-expected_loss - control_cost + resilience_benefit, 2),
    }
