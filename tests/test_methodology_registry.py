from cyberdeck.methodology import load_methodology_registry


def test_methodology_registry_is_unique_and_versioned():
    registry = load_methodology_registry()
    identifiers = [item.methodId for item in registry.methods]
    assert registry.registryVersion
    assert len(identifiers) == len(set(identifiers))
    assert all(item.version and item.effectiveFrom for item in registry.methods)


def test_active_methods_have_tests_and_implementations():
    registry = load_methodology_registry()
    active = [item for item in registry.methods if item.status == "active"]
    assert active
    assert all(item.implementationReference and item.testReferences for item in active)


def test_business_and_control_weights_are_normalized():
    registry = load_methodology_registry()
    by_id = {item.methodId: item for item in registry.methods}
    assert round(sum(by_id["risk.business_impact"].weights.values()), 10) == 1.0
    assert round(sum(by_id["risk.control_effectiveness"].weights.values()), 10) == 1.0


def test_reference_methods_are_not_advertised_as_active():
    registry = load_methodology_registry()
    by_id = {item.methodId: item for item in registry.methods}
    assert by_id["forecast.poisson_reference"].status == "reference_only"
    assert by_id["strategy.legacy_weighted_indices"].status == "inactive"
