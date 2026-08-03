from cyberdeck.analysis.financial_risk import calculate_financial_risk
from cyberdeck.analysis.vulnerability_scoring import calculate_cvss_v4, calculate_owasp_risk
from cyberdeck.collectors.exploit_db import _event_from_reference


def test_financial_risk_uses_only_explicit_values() -> None:
    missing = calculate_financial_risk({})
    assert missing["status"] == "no_data"

    result = calculate_financial_risk(
        {
            "asset_value": 500_000,
            "exposure_factor": 0.4,
            "annual_rate_of_occurrence": 0.3,
            "control_risk_reduction": 0.6,
            "control_cost": 20_000,
            "currency": "USD",
        }
    )
    assert result["single_loss_expectancy"] == 200_000
    assert result["annualized_loss_expectancy_before"] == 60_000
    assert result["annualized_loss_expectancy_after"] == 24_000
    assert result["rosi_percent"] == 80


def test_cvss_v4_preserves_vector_and_official_score() -> None:
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"
    result = calculate_cvss_v4(vector)

    assert result["status"] == "calculated"
    assert result["vector"] == vector
    assert result["score"] == 9.9
    assert result["model_version"] == "FIRST-CVSS-4.0"


def test_owasp_risk_requires_all_sixteen_factors() -> None:
    incomplete = calculate_owasp_risk({"skill_level": 5})
    assert incomplete["status"] == "no_data"
    assert len(incomplete["missing_factors"]) == 15

    complete = calculate_owasp_risk(
        {
            "skill_level": 6,
            "motive": 6,
            "opportunity": 6,
            "size": 6,
            "ease_of_discovery": 6,
            "ease_of_exploit": 6,
            "awareness": 6,
            "intrusion_detection": 6,
            "loss_of_confidentiality": 6,
            "loss_of_integrity": 6,
            "loss_of_availability": 6,
            "loss_of_accountability": 6,
            "financial_damage": 6,
            "reputation_damage": 6,
            "non_compliance": 6,
            "privacy_violation": 6,
        }
    )
    assert complete["status"] == "calculated"
    assert complete["severity"] == "critical"


def test_exploit_db_reference_is_context_not_applicability() -> None:
    event = _event_from_reference(
        {
            "cve": "CVE-2026-1234",
            "edb_id": "12345",
            "title": "Reference title",
            "url": "https://www.exploit-db.com/exploits/12345",
        }
    )

    assert event.vulnerability_status == "cve_candidate"
    assert event.cvss == 0
    assert event.epss == 0
    assert event.technical_validation["direct_relationship"] is False
