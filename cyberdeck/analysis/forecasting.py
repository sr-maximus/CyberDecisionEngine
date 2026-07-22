from __future__ import annotations

import math
from typing import Dict, Union

def build_forecast(kev_signal: float, sector_signal: float, socmint_signal: float, darkweb_signal: float) -> Dict[str, Dict[str, Union[float, str, bool]]]:
    daily_signal_rate = min(
        0.04,
        0.002
        + 0.008 * max(0.0, min(1.0, kev_signal))
        + 0.004 * max(0.0, min(1.0, sector_signal))
        + 0.006 * max(0.0, min(1.0, socmint_signal))
        + 0.008 * max(0.0, min(1.0, darkweb_signal)),
    )
    forecast: Dict[str, Dict[str, Union[float, str, bool]]] = {}
    for days in (7, 14, 30):
        # This bounded transform is a prioritization index. It intentionally is
        # not presented as an attack probability because the platform does not
        # yet have a labelled historical outcome set for calibration.
        pressure = 1.0 - math.exp(-daily_signal_rate * days)
        forecast[str(days)] = {
            "signal_pressure_index": round(pressure, 4),
            "lower_sensitivity": round(max(0.0, pressure * 0.72), 4),
            "base_sensitivity": round(pressure, 4),
            "upper_sensitivity": round(min(1.0, pressure * 1.32), 4),
            # Compatibility fields are sensitivity bands, never confidence intervals.
            "p10": round(max(0.0, pressure * 0.72), 4),
            "p50": round(pressure, 4),
            "p90": round(min(1.0, pressure * 1.32), 4),
            "prediction_is_calibrated": False,
            "target": "presion relativa de senales publicas",
            "band_semantics": "sensitivity_not_confidence_interval",
            "language": "Indice relativo de presion de senales; no es una probabilidad de ataque ni una prediccion calibrada.",
        }
    return forecast
