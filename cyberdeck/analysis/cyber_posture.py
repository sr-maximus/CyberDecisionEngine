from __future__ import annotations

from typing import Dict

from cyberdeck.analysis.risk_engine import cyber_posture_index
from cyberdeck.utils.scoring import clamp


def calculate_posture(control_maturity: Dict[str, float], fraud_maturity: Dict[str, float], threat_intel: float = 0.62) -> float:
    identity = clamp((fraud_maturity.get("identity_proofing", 0.55) + fraud_maturity.get("device_intelligence", 0.55)) / 2)
    detection_response = clamp(
        (
            control_maturity.get("attack_detection_coverage", 0.5)
            + control_maturity.get("incident_response_maturity", 0.5)
        )
        / 2
    )
    return cyber_posture_index(
        nist=control_maturity.get("nist_csf_score", 0.5),
        iso=control_maturity.get("iso27001_score", 0.5),
        soc2=control_maturity.get("soc2_score", 0.5),
        identity=identity,
        vuln_hygiene=0.64,
        detection_response=detection_response,
        cloud=0.58,
        third_party=0.55,
        threat_intel=threat_intel,
    )
