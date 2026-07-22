from __future__ import annotations

from typing import Dict, List


def build_systemic_model(crown_jewels: List[str], technologies: List[str]) -> Dict[str, object]:
    dependencies = [
        {"asset": asset, "depends_on": technologies[:4], "feedback_loop": "deteccion -> respuesta -> hardening -> menor exposicion"}
        for asset in crown_jewels[:8]
    ]
    return {
        "assets": crown_jewels,
        "technologies": technologies,
        "dependencies": dependencies,
        "control_loops": [
            "patching reduce vulnerabilidad explotable",
            "telemetria mejora deteccion y reduce dwell time",
            "fraud case feedback recalibra reglas y modelos",
            "awareness reduce tasa de exito de ingenieria social",
        ],
    }
