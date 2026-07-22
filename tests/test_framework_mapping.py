from cyberdeck.frameworks.sync import mappings


def test_attack_to_control_mappings_include_fraud_relevant_phishing():
    data = mappings()
    assert "T1566" in data["attack_to_defend"]
    assert "PR.AT" in data["attack_to_nist"]["T1566"]
    assert "Security" in data["attack_to_soc2"]["T1566"]
