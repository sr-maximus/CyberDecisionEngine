import cyberdeck.cti.analysis as cti_analysis
from cyberdeck.cti.analysis import CTI_STATES, build_cti_snapshot
from cyberdeck.cti.knowledge import build_knowledge_manifest
from cyberdeck.reporting.validator import _validate_cti_snapshot
from cyberdeck.schemas import (
    EvidenceStatus,
    OrganizationProfile,
    PublicAttributionStatus,
    ThreatEvent,
)


def _organization() -> OrganizationProfile:
    return OrganizationProfile(
        name="Synthetic Aviation Group",
        sector="Transportation and storage",
        country="CO",
        countries_of_operation=["US"],
        author="test-suite",
        authorized_scope=True,
        primary_domains=["example-air.test"],
    )


def _event(*, observed: bool = False) -> ThreatEvent:
    return ThreatEvent(
        id="CTI-EV-1",
        title="Example Actor phishing attack campaign against aviation organizations",
        category="threat actor phishing campaign",
        source="fixture-threat-news",
        original_publisher="Fixture publisher",
        evidence_url="https://example.test/intelligence/example-actor",
        evidence_status=EvidenceStatus.CONFIRMED if observed else EvidenceStatus.VALIDATED,
        confidence_score=0.88,
        relationship_to_scope="sector",
        actor="Example Actor",
        technique="T1566",
        technique_refs=["T1566"],
        framework_refs=["MITRE ATT&CK"],
        technical_validation={"campaign": "Synthetic Flight Campaign", "country": "CO"},
        public_attribution_status=(
            PublicAttributionStatus.CORROBORATED_PUBLIC
            if observed
            else PublicAttributionStatus.POSSIBLE
        ),
        attribution_basis=["fixture explicit attribution"],
        attack_mapping_status="observed_attack" if observed else "evidence_supported_candidate",
        incident_confirmed=observed,
        age_days=3,
        demo=True,
    )


def test_cti_contextual_record_never_becomes_observed_without_telemetry() -> None:
    snapshot = build_cti_snapshot([_event()], [], _organization())

    assert snapshot["actors"][0]["state"] == "INFERRED"
    assert snapshot["campaigns"][0]["state"] == "INFERRED"
    assert snapshot["overview"]["observed_count"] == 0
    assert snapshot["graph"]["nodes"][0]["state"] == "REFERENCE"
    evidence = snapshot["evidence"][0]
    assert evidence["actors"] == ["Example Actor"]
    assert evidence["campaigns"] == ["Synthetic Flight Campaign"]
    assert "T1566" in evidence["techniques"]


def test_cti_observed_requires_confirmed_adversary_telemetry() -> None:
    snapshot = build_cti_snapshot([_event(observed=True)], [], _organization())

    assert snapshot["actors"][0]["state"] == "OBSERVED"
    assert snapshot["actors"][0]["observed_attack_count"] == 1
    assert snapshot["campaigns"][0]["state"] == "OBSERVED"
    assert snapshot["overview"]["observed_count"] == 2


def test_cti_score_and_counts_are_mathematically_coherent() -> None:
    snapshot = build_cti_snapshot([_event()], [], _organization())
    overview = snapshot["overview"]
    state_counts = snapshot["quality"]["state_counts"]

    assert abs(sum(snapshot["relevance_model"]["weights"].values()) - 1.0) < 0.001
    assert 0 <= snapshot["actors"][0]["relevance_score"] <= 100
    assert overview["actor_count"] == len(snapshot["actors"])
    assert overview["campaign_count"] == len(snapshot["campaigns"])
    assert overview["technique_count"] == len(snapshot["techniques"])
    assert sum(state_counts[state] for state in CTI_STATES) == (
        len(snapshot["actors"]) + len(snapshot["campaigns"]) + len(snapshot["techniques"])
    )


def test_cti_actor_preserves_every_evidence_backed_technique() -> None:
    event = _event()
    event.technique_refs = ["T1078", "T1566"]

    snapshot = build_cti_snapshot([event], [], _organization())

    assert snapshot["actors"][0]["techniques"] == ["T1078", "T1566"]
    techniques = {row["technique_id"]: row for row in snapshot["techniques"]}
    assert set(techniques) == {"T1078", "T1566"}
    assert all(row["actors"] == ["Example Actor"] for row in techniques.values())
    assert set(snapshot["evidence"][0]["techniques"]) == {"T1078", "T1566"}


def test_cti_graph_traces_actor_campaign_techniques_and_d3fend() -> None:
    event = _event()
    event.technique_refs = ["T1078", "T1566"]

    snapshot = build_cti_snapshot([event], [], _organization())
    graph = snapshot["graph"]
    edge_keys = {(edge["type"], edge["source"], edge["target"]) for edge in graph["edges"]}
    node_ids = {node["id"] for node in graph["nodes"]}

    assert ("uses", "actor:example-actor", "technique:T1078") in edge_keys
    assert ("uses", "actor:example-actor", "technique:T1566") in edge_keys
    assert ("uses", "campaign:synthetic-flight-campaign", "technique:T1078") in edge_keys
    assert ("uses", "campaign:synthetic-flight-campaign", "technique:T1566") in edge_keys
    assert any(edge[0] == "countered_by" and edge[1] == "technique:T1078" for edge in edge_keys)
    assert any(edge[0] == "countered_by" and edge[1] == "technique:T1566" for edge in edge_keys)
    assert any(node_id.startswith("defense:D3-") for node_id in node_ids)
    assert graph["layout"] == "force_static_after_stabilization"


def test_cti_graph_edges_keep_traceable_evidence_references() -> None:
    snapshot = build_cti_snapshot([_event()], [], _organization())
    related_edges = [edge for edge in snapshot["graph"]["edges"] if edge["type"] != "countered_by"]

    assert related_edges
    assert all("CTI-EV-1" in edge["evidence_ids"] for edge in related_edges)


def test_cti_validator_rejects_observed_without_telemetry_and_orphan_evidence() -> None:
    snapshot = build_cti_snapshot([_event()], [], _organization())
    snapshot["actors"][0]["state"] = "OBSERVED"
    snapshot["actors"][0]["observed_attack_count"] = 0
    snapshot["actors"][0]["evidence_ids"] = ["missing-evidence"]
    snapshot["quality"]["state_counts"] = {
        "OBSERVED": 1,
        "INFERRED": 1,
        "RELATED": 1,
        "REFERENCE": 0,
    }
    issues = []

    _validate_cti_snapshot({"cti_snapshot": snapshot}, issues)

    codes = {issue.code for issue in issues}
    assert "CTI_OBSERVED_WITHOUT_TELEMETRY" in codes
    assert "CTI_EVIDENCE_ORPHAN" in codes


def test_cti_knowledge_manifest_uses_unique_versioned_sources() -> None:
    manifest = build_knowledge_manifest()
    source_ids = [row["source_id"] for row in manifest["sources"]]

    assert len(source_ids) == len(set(source_ids))
    assert {"attack-enterprise", "attack-ics", "attack-mobile"}.issubset(source_ids)
    assert manifest["schema_version"] == "cti-knowledge-manifest-v1"


def test_cti_keeps_run_techniques_separate_from_attack_reference(
    monkeypatch,
) -> None:
    def fake_profiles(names, *, allowed_types=None):
        profile = {
            "entity_type": "threat_group",
            "external_id": "G9999",
            "aliases": ["Example Actor"],
            "description": "Official profile context.",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "url": "https://attack.mitre.org/groups/G9999/",
            "version": "1.0",
            "domains": ["enterprise-attack"],
            "contributors": ["Fixture contributor"],
            "external_references": [],
            "knowledge_source": "MITRE ATT&CK Enterprise",
            "techniques": [
                {
                    "technique_id": "T1566",
                    "name": "Phishing",
                    "tactics": ["Initial Access"],
                    "url": "https://attack.mitre.org/techniques/T1566/",
                    "relationship_references": ["https://example.test/report-1"],
                },
                {
                    "technique_id": "T1087.001",
                    "name": "Local Account",
                    "tactics": ["Discovery"],
                    "platforms": ["Windows"],
                    "url": "https://attack.mitre.org/techniques/T1087/001/",
                    "relationship_references": ["https://example.test/report-2"],
                    "parent_technique_id": "T1087",
                },
            ],
        }
        if allowed_types == {"campaign"}:
            return {}
        return {name: profile for name in names if name == "Example Actor"}

    monkeypatch.setattr(cti_analysis, "resolve_attack_entity_profiles", fake_profiles)
    snapshot = build_cti_snapshot([_event()], [], _organization())

    actor = snapshot["actors"][0]
    assert actor["entity_type"] == "threat_group"
    assert actor["run_techniques"] == ["T1566"]
    assert actor["documented_techniques"] == ["T1566", "T1087.001"]
    assert set(actor["techniques"]) == {"T1566", "T1087.001"}
    techniques = {row["technique_id"]: row for row in snapshot["techniques"]}
    assert techniques["T1566"]["run_supported"] is True
    assert techniques["T1566"]["reference_supported"] is True
    assert techniques["T1087.001"]["state"] == "REFERENCE"
    assert techniques["T1087.001"]["record_count"] == 0
    edge = next(
        row
        for row in snapshot["graph"]["edges"]
        if row["source"] == "actor:example-actor"
        and row["target"] == "technique:T1087.001"
    )
    assert edge["state"] == "REFERENCE"
    assert edge["evidence_ids"] == []
    assert "https://example.test/report-2" in edge["knowledge_urls"]
    assert snapshot["attack_matrix"]["run_technique_count"] == 1
    assert snapshot["attack_matrix"]["reference_technique_count"] == 2
