from __future__ import annotations

import math
import random
from statistics import quantiles
from typing import Dict, Iterable, Mapping, Sequence, Union


def clip(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, float(value)))


def normalize(x: float, min: float, max: float) -> float:
    if max == min:
        return 0.0
    return clip((x - min) / (max - min), 0.0, 1.0)


def log_norm(x: float, x_max: float) -> float:
    if x_max <= 0:
        return 0.0
    return clip(math.log(1 + max(0.0, x)) / math.log(1 + x_max), 0.0, 1.0)


def decay(days: float, half_life: float) -> float:
    if half_life <= 0:
        return 0.0
    return math.exp(-math.log(2) * max(0.0, days) / half_life)


def threat_activity_score(events: Iterable[Mapping[str, float]]) -> float:
    total = 0.0
    for event in events:
        total += (
            float(event.get("source_weight", 0.5))
            * float(event.get("confidence", 0.5))
            * decay(float(event.get("age_days", 0)), float(event.get("half_life", 14)))
        )
    return clip(1 - math.exp(-0.35 * total), 0.0, 1.0)


def contextual_likelihood(A: float, E: float, V: float, P: float, K: float, T: float, S: float, G: float, C: float, D: float, R: float) -> float:
    p_safe = clip(P, 0.001, 0.999)
    logit = math.log(p_safe / (1 - p_safe))
    z = (
        -2.10
        + 0.70 * clip(A)
        + 0.85 * clip(E)
        + 0.75 * clip(V)
        + 0.90 * logit / 6
        + 0.85 * clip(K)
        + 0.70 * clip(T)
        + 0.55 * clip(S)
        + 0.35 * clip(G)
        - 0.80 * clip(C)
        - 0.60 * clip(D)
        - 0.45 * clip(R)
    )
    return clip(1 / (1 + math.exp(-z)), 0.0, 1.0)


def business_impact(financial: float, operational: float, confidentiality: float, integrity: float, availability: float, legal: float, reputational: float) -> float:
    return clip(
        0.25 * financial
        + 0.20 * operational
        + 0.20 * confidentiality
        + 0.15 * integrity
        + 0.10 * availability
        + 0.05 * legal
        + 0.05 * reputational,
        0.0,
        1.0,
    )


def control_effectiveness(iso: float, nist: float, soc2: float, d3fend: float, attack_detection: float, ir: float) -> float:
    return clip(
        0.25 * iso
        + 0.25 * nist
        + 0.15 * soc2
        + 0.15 * d3fend
        + 0.10 * attack_detection
        + 0.10 * ir,
        0.0,
        1.0,
    )


def inherent_risk(likelihood: float, impact: float) -> float:
    return 100 * clip(likelihood) * clip(impact)


def residual_risk(inherent: float, CE: float) -> float:
    return max(0.0, inherent) * (1 - min(0.85, clip(CE)))


def _index(value: float) -> int:
    return max(1, min(4, math.ceil(4 * clip(value))))


def matrix_4x4(likelihood: float, impact: float) -> Dict[str, Union[int, str]]:
    likelihood_index = _index(likelihood)
    impact_index = _index(impact)
    score = likelihood_index * impact_index
    if score <= 3:
        label = "Bajo"
    elif score <= 7:
        label = "Medio"
    elif score <= 11:
        label = "Alto"
    else:
        label = "Critico"
    return {
        "likelihood_index": likelihood_index,
        "impact_index": impact_index,
        "matrix_score": score,
        "label": label,
    }


def cyber_posture_index(nist: float, iso: float, soc2: float, identity: float, vuln_hygiene: float, detection_response: float, cloud: float, third_party: float, threat_intel: float) -> float:
    return 100 * clip(
        0.20 * nist
        + 0.18 * iso
        + 0.12 * soc2
        + 0.12 * identity
        + 0.10 * vuln_hygiene
        + 0.10 * detection_response
        + 0.08 * cloud
        + 0.05 * third_party
        + 0.05 * threat_intel,
        0.0,
        1.0,
    )


def pestel_cyber_index(political: float, economic: float, social: float, technological: float, environmental: float, legal: float) -> float:
    return 100 * (
        0.15 * clip(political)
        + 0.15 * clip(economic)
        + 0.15 * clip(social)
        + 0.25 * clip(technological)
        + 0.05 * clip(environmental)
        + 0.25 * clip(legal)
    )


def porter_cyber_index(rivalry: float, supplier: float, customer: float, substitute: float, new_entrant: float) -> float:
    return 100 * (
        0.20 * clip(rivalry)
        + 0.20 * clip(supplier)
        + 0.20 * clip(customer)
        + 0.20 * clip(substitute)
        + 0.20 * clip(new_entrant)
    )


def bayesian_update(prior: float, likelihood_ratio: float) -> float:
    prior_safe = clip(prior, 0.001, 0.999)
    prior_odds = prior_safe / (1 - prior_safe)
    posterior_odds = prior_odds * max(0.0, likelihood_ratio)
    return clip(posterior_odds / (1 + posterior_odds), 0.0, 1.0)


def poisson_forecast(lambda_t: float, days: float) -> float:
    return clip(1 - math.exp(-max(0.0, lambda_t) * max(0.0, days)), 0.0, 1.0)


def forecast_lambda(lambda_previous: float, baseline: float, kev_signal: float, sector_signal: float, socmint_signal: float, darkweb_signal: float, alpha: float = 0.65, beta1: float = 0.18, beta2: float = 0.14, beta3: float = 0.10, beta4: float = 0.12) -> float:
    return max(
        0.0,
        alpha * lambda_previous
        + (1 - alpha) * baseline
        + beta1 * clip(kev_signal)
        + beta2 * clip(sector_signal)
        + beta3 * clip(socmint_signal)
        + beta4 * clip(darkweb_signal),
    )


def monte_carlo_risk(likelihood: float, impact: float, control_effectiveness: float, n: int = 10000) -> dict[str, float]:
    rng = random.Random(42)
    samples = []
    sample_count = max(100, int(n))
    for _ in range(sample_count):
        l_sample = rng.betavariate(1 + 10 * clip(likelihood), 1 + 10 * (1 - clip(likelihood)))
        i_sample = rng.betavariate(1 + 10 * clip(impact), 1 + 10 * (1 - clip(impact)))
        ce_sample = rng.betavariate(
            1 + 10 * clip(control_effectiveness),
            1 + 10 * (1 - clip(control_effectiveness)),
        )
        samples.append(100 * l_sample * i_sample * (1 - min(0.85, ce_sample)))
    samples.sort()
    q = quantiles(samples, n=10)
    return {
        "p10": round(q[0], 2),
        "p50": round(samples[len(samples) // 2], 2),
        "p90": round(q[8], 2),
    }


def entropy(probabilities: Sequence[float]) -> float:
    total = sum(max(0.0, p) for p in probabilities)
    if total == 0:
        return 0.0
    normalized = [max(0.0, p) / total for p in probabilities]
    return -sum(p * math.log2(p) for p in normalized if p > 0)
