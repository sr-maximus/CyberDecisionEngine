from __future__ import annotations

import pytest

from cyberdeck.cti import framework_catalog as catalog_module
from cyberdeck.cti.framework_catalog import FRAMEWORKS, framework_catalog_index, load_framework_family

# Full upstream catalogs are optional runtime downloads, never collection exports.
_full_catalogs_available = all((catalog_module.PROJECT_ROOT / row["path"]).exists() for row in FRAMEWORKS)
requires_full_catalogs = pytest.mark.skipif(
    not _full_catalogs_available,
    reason="Requires optional official framework downloads; run scripts/sync_cti_knowledge.py first",
)


EXPECTED_FAMILIES = {
    "attack-enterprise",
    "attack-mobile",
    "attack-ics",
    "atlas",
    "f3",
    "aadapt",
    "d3fend",
    "emb3d",
    "capec",
    "cwe",
    "inform",
    "disarm",
}


@requires_full_catalogs
def test_catalog_exposes_every_supported_family_as_active() -> None:
    catalog = framework_catalog_index()
    families = {row["id"]: row for row in catalog["families"]}

    assert set(families) == EXPECTED_FAMILIES
    assert all(row["status"] == "active" for row in families.values())
    assert "reference knowledge" in catalog["interpretation"]


@requires_full_catalogs
def test_attack_domains_preserve_platforms_and_bidirectional_entity_mapping() -> None:
    expected_platforms = {
        "attack-enterprise": {"Windows", "Linux", "macOS"},
        "attack-mobile": {"Android", "iOS"},
        "attack-ics": {"ICS/OT"},
    }
    for family_id, required_platforms in expected_platforms.items():
        family = load_framework_family(family_id)
        platforms = {
            platform
            for technique in family["techniques"]
            for platform in technique.get("platforms", [])
        }
        assert required_platforms <= platforms
        assert family["counts"]["tactics"] >= 10
        assert family["counts"]["techniques"] >= 90

    enterprise = load_framework_family("attack-enterprise")
    group = next(entity for entity in enterprise["entities"] if entity["entity_id"] == "G0018")
    assert len(group["technique_ids"]) > 10
    technique = next(row for row in enterprise["techniques"] if row["technique_id"] == group["technique_ids"][0])
    assert any(entity["entity_id"] == "G0018" for entity in technique["entities"])


@requires_full_catalogs
def test_non_attack_families_keep_their_native_information_model() -> None:
    assert load_framework_family("f3")["counts"]["techniques"] >= 120
    assert load_framework_family("aadapt")["counts"]["techniques"] >= 60
    assert load_framework_family("d3fend")["view_type"] == "defensive_matrix"

    emb3d = load_framework_family("emb3d")
    assert emb3d["view_type"] == "relationship_model"
    assert len(emb3d["collections"]["threats"]) >= 80
    assert len(emb3d["relationships"]) >= 300

    assert load_framework_family("capec")["counts"]["techniques"] >= 600
    assert load_framework_family("cwe")["counts"]["techniques"] >= 900
    inform = load_framework_family("inform")
    assert inform["view_type"] == "maturity"
    assert inform["counts"]["items"] == 81
    disarm = load_framework_family("disarm")
    assert disarm["view_type"] == "matrix"
    assert disarm["counts"]["tactics"] >= 10
    assert disarm["counts"]["techniques"] >= 300


def test_missing_catalogs_do_not_invent_techniques(tmp_path, monkeypatch):
    monkeypatch.setattr(catalog_module, "PROJECT_ROOT", tmp_path)
    catalog = framework_catalog_index()
    assert {row["id"] for row in catalog["families"]} == EXPECTED_FAMILIES
    for family_id in EXPECTED_FAMILIES:
        family = load_framework_family(family_id)
        assert family["status"] != "active"
        assert not family.get("techniques")
