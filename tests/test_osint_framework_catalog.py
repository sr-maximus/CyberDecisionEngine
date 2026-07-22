import importlib.util
from pathlib import Path


def _load_sidecar_module():
    module_path = Path(__file__).resolve().parents[1] / "infra" / "osint-tools" / "app" / "main.py"
    spec = importlib.util.spec_from_file_location("cde_osint_tools_sidecar", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_osint_framework_catalog_loads_reference_resources():
    sidecar = _load_sidecar_module()
    summary = sidecar._osint_framework_summary()
    resources = sidecar._load_osint_framework_resources()

    assert summary["available"] is True
    assert summary["resources"] == len(resources)
    assert summary["resources"] > 1000
    assert summary["google_dorks"] > 0
    assert all(item["url"].startswith("http") for item in resources[:25])


def test_osint_framework_scope_filters_domain_and_person_resources():
    sidecar = _load_sidecar_module()
    resources = sidecar._load_osint_framework_resources()

    domain_matches = [item for item in resources if sidecar._catalog_matches_scope(item, "domain")]
    person_matches = [item for item in resources if sidecar._catalog_matches_scope(item, "person")]

    assert domain_matches
    assert person_matches
    assert any("domain" in sidecar._catalog_haystack(item) for item in domain_matches[:20])
    assert any("username" in sidecar._catalog_haystack(item) or "email" in sidecar._catalog_haystack(item) for item in person_matches[:50])
