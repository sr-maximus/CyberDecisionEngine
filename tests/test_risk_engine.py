from cyberdeck.analysis.risk_engine import (
    bayesian_update,
    business_impact,
    contextual_likelihood,
    control_effectiveness,
    decay,
    inherent_risk,
    log_norm,
    monte_carlo_risk,
    normalize,
    poisson_forecast,
    residual_risk,
    threat_activity_score,
)


def test_core_risk_formulas_are_bounded():
    assert normalize(5, 0, 10) == 0.5
    assert 0 < log_norm(10, 100) < 1
    assert round(decay(14, 14), 2) == 0.5
    activity = threat_activity_score([{"source_weight": 0.9, "confidence": 0.8, "age_days": 0, "half_life": 14}])
    likelihood = contextual_likelihood(0.8, 0.7, 0.9, 0.2, 1, activity, 0.8, 0.5, 0.6, 0.5, 0.6)
    impact = business_impact(0.8, 0.7, 0.6, 0.6, 0.5, 0.4, 0.7)
    ce = control_effectiveness(0.6, 0.6, 0.5, 0.5, 0.5, 0.7)
    inherent = inherent_risk(likelihood, impact)
    residual = residual_risk(inherent, ce)
    assert 0 <= activity <= 1
    assert 0 <= likelihood <= 1
    assert 0 <= impact <= 1
    assert 0 <= residual <= inherent <= 100


def test_bayesian_and_poisson_outputs():
    assert bayesian_update(0.2, 3.0) > 0.2
    assert 0 < poisson_forecast(0.02, 30) < 1


def test_pcider_likelihood_excludes_controls_from_inherent_score():
    baseline = contextual_likelihood(
        0.8, 0.7, 0.9, 0.2, 1, 0.4, 0.8, 0.5, 0.0, 0.0, 0.0
    )
    controlled = contextual_likelihood(
        0.8, 0.7, 0.9, 0.2, 1, 0.4, 0.8, 0.5, 1.0, 1.0, 1.0
    )
    assert controlled == baseline


def test_pcider_monte_carlo_reports_decision_risk_and_traceability():
    result = monte_carlo_risk(0.45, 0.70, 0.40, n=250)
    assert result["iterations"] == 250
    assert result["model_version"] == "1.0.0"
    assert result["p10"] <= result["p50"] <= result["p90"]
    assert result["decision_risk"] == result["residual_mean"]
