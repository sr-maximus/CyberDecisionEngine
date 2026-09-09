from __future__ import annotations

import io
import json

from cyberdeck.cti import knowledge
from cyberdeck.cti.attack_profiles import build_attack_profile_catalog


def test_attack_profile_catalog_preserves_entity_kind_and_full_technique_set() -> None:
    payload = {
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--one",
                "name": "Example Group",
                "aliases": ["Example Alias"],
                "description": "Documented group profile.",
                "created": "2024-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "G9999",
                        "url": "https://attack.mitre.org/groups/G9999/",
                    }
                ],
            },
            {
                "type": "campaign",
                "id": "campaign--one",
                "name": "Example Campaign",
                "first_seen": "2025-01-01T00:00:00Z",
                "last_seen": "2025-06-01T00:00:00Z",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "C9999",
                        "url": "https://attack.mitre.org/campaigns/C9999/",
                    }
                ],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--impact",
                "name": "Impact",
                "x_mitre_shortname": "impact",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--parent",
                "name": "Parent Technique",
                "kill_chain_phases": [{"phase_name": "impact"}],
                "x_mitre_platforms": ["Windows"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999",
                        "url": "https://attack.mitre.org/techniques/T9999/",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--child",
                "name": "Child Technique",
                "kill_chain_phases": [{"phase_name": "impact"}],
                "x_mitre_platforms": ["Linux"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999.001",
                        "url": "https://attack.mitre.org/techniques/T9999/001/",
                    }
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--subtechnique",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--child",
                "target_ref": "attack-pattern--parent",
            },
            *[
                {
                    "type": "relationship",
                    "id": f"relationship--uses-{index}",
                    "relationship_type": "uses",
                    "source_ref": source,
                    "target_ref": target,
                    "description": "Documented use relationship.",
                    "external_references": [
                        {"source_name": "report", "url": f"https://example.test/{index}"}
                    ],
                }
                for index, (source, target) in enumerate(
                    [
                        ("intrusion-set--one", "attack-pattern--parent"),
                        ("intrusion-set--one", "attack-pattern--child"),
                        ("campaign--one", "attack-pattern--child"),
                    ],
                    start=1,
                )
            ],
        ]
    }

    catalog = build_attack_profile_catalog(payload)
    group = catalog["profiles"]["intrusion-set--one"]
    campaign = catalog["profiles"]["campaign--one"]

    assert group["entity_type"] == "threat_group"
    assert group["description"] == "Documented group profile."
    assert {row["technique_id"] for row in group["techniques"]} == {
        "T9999",
        "T9999.001",
    }
    child = next(row for row in group["techniques"] if row["technique_id"] == "T9999.001")
    assert child["parent_technique_id"] == "T9999"
    assert child["platforms"] == ["Linux"]
    assert child["relationship_references"] == ["https://example.test/2"]
    assert campaign["entity_type"] == "campaign"
    assert campaign["first_seen"] == "2025-01-01T00:00:00Z"


def test_knowledge_sync_is_atomic_and_rollback_restores_last_known_good(
    tmp_path, monkeypatch
) -> None:
    source = {
        "id": "attack-test",
        "name": "ATT&CK test",
        "family": "ATT&CK",
        "url": "https://example.test/attack.json",
        "path": "data/attack.json",
        "format": "json",
        "required": True,
        "download": True,
        "version": "test",
    }
    destination = tmp_path / source["path"]
    destination.parent.mkdir(parents=True)
    destination.write_text(json.dumps({"objects": [{"id": "old"}]}), encoding="utf-8")
    payload = json.dumps({"objects": [{"id": "new-1"}, {"id": "new-2"}]}).encode()

    monkeypatch.setattr(knowledge, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(knowledge, "_source_config", lambda: [source])
    monkeypatch.setattr(knowledge, "urlopen", lambda *_args, **_kwargs: io.BytesIO(payload))

    manifest = knowledge.sync_knowledge_sources()

    assert manifest["status"] == "ready"
    assert manifest["sources"][0]["record_count"] == 2
    assert destination.with_suffix(".json.lkg").is_file()

    restored = knowledge.rollback_knowledge_source("attack-test")

    assert restored["status"] == "active"
    assert json.loads(destination.read_text(encoding="utf-8"))["objects"] == [{"id": "old"}]


def test_reference_source_and_sparql_binding_count_are_explicit(tmp_path, monkeypatch) -> None:
    reference = {
        "id": "tie",
        "name": "Technique Inference Engine",
        "family": "TIE",
        "url": "https://example.test/tie",
        "path": "data/tie.txt",
        "download": False,
    }
    sparql_path = tmp_path / "d3fend.json"
    sparql_path.write_text(
        json.dumps({"head": {}, "results": {"bindings": [{"id": 1}, {"id": 2}]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(knowledge, "PROJECT_ROOT", tmp_path)

    assert knowledge._source_manifest(reference)["status"] == "reference"
    assert knowledge._record_count(sparql_path) == 2
